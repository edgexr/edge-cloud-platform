// Copyright 2024 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package k8spm provides a Kubernetes platform manager for
// deploying applications
package k8spm

import (
	"context"
	"fmt"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	ssh "github.com/edgexr/golang-ssh"
	v1 "k8s.io/api/core/v1"
)

// ClusterAccess interface defines APIs for gaining access to a cluster
type ClusterAccess interface {
	// GetClusterClient gets an ssh client to access the
	// node that will have the local kubeconfig and manifest files.
	GetClusterClient(ctx context.Context, clusterInst *edgeproto.ClusterInst) (ssh.Client, error)
	// GetClusterCredentials retrieves kubeconfig credentials from the cluster
	GetClusterCredentials(ctx context.Context, clusterInst *edgeproto.ClusterInst) ([]byte, error)
	// GetClusterName gets the name used for the cluster
	GetClusterName(clusterInst *edgeproto.ClusterInst) string
}

type K8sPlatformMgr struct {
	clusterAccess ClusterAccess
	features      *edgeproto.PlatformFeatures
	commonPf      *infracommon.CommonPlatform
	wm            k8smgmt.WorkloadMgr
}

func (m *K8sPlatformMgr) Init(clusterAccess ClusterAccess, features *edgeproto.PlatformFeatures, commonPf *infracommon.CommonPlatform, wm k8smgmt.WorkloadMgr) {
	m.clusterAccess = clusterAccess
	m.features = features
	m.commonPf = commonPf
	m.wm = wm
}

func (m *K8sPlatformMgr) CreateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateSender edgeproto.AppInstInfoSender) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateAppInst", "appInst", appInst)
	updateSender.SendStatus(edgeproto.UpdateTask, "Creating AppInst")

	client, err := m.clusterAccess.GetClusterClient(ctx, clusterInst)
	if err != nil {
		return err
	}
	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return err
	}
	err = m.ensureKubeconfigs(ctx, client, clusterInst, names)
	if err != nil {
		return err
	}
	features := m.features

	nsLabels, err := m.commonPf.Properties.GetJSONMapValue(cloudcommon.NamespaceLabels)
	if err != nil {
		return err
	}

	updateSender.SendStatus(edgeproto.UpdateTask, "Creating Namespaces")
	err = k8smgmt.CreateAllNamespaces(ctx, client, names, nsLabels)
	if err != nil {
		return err
	}
	updateSender.SendStatus(edgeproto.UpdateTask, "Creating Registry Secret")
	for _, imagePath := range names.ImagePaths {
		err = infracommon.CreateDockerRegistrySecret(ctx, client, k8smgmt.GetKconfName(clusterInst), imagePath, app.Key, m.commonPf.PlatformConfig.AccessApi, names, nil)
		if err != nil {
			return err
		}
	}

	updateSender.SendStatus(edgeproto.UpdateTask, "Deploying App Instance")
	// TODO: We should handle helm the same as a
	// manifest-based appinst inside the workload manager,
	// so that the surrounding handlers for namespaces and
	// policies are common to both.
	switch app.Deployment {
	case cloudcommon.DeploymentTypeKubernetes:
		err = k8smgmt.CreateAppInst(ctx, m.commonPf.PlatformConfig.AccessApi, client, names, clusterInst, app, appInst, k8smgmt.WithWorkloadManager(m.wm), k8smgmt.WithAppInstUpdateSender(updateSender))
	case cloudcommon.DeploymentTypeHelm:
		err = k8smgmt.CreateHelmAppInst(ctx, m.commonPf.PlatformConfig.AccessApi, client, names, clusterInst, app, appInst)
	default:
		err = fmt.Errorf("unsupported deployment type %s", app.Deployment)
	}
	if err != nil {
		return err
	}
	updateSender.SendStatus(edgeproto.UpdateTask, "Waiting for External IPs")

	// set up dns
	getDnsAction := func(svc v1.Service) (*infracommon.DnsSvcAction, error) {
		action := infracommon.DnsSvcAction{}
		externalIP, hostName, err := infracommon.GetSvcExternalIpOrHost(ctx, client, names, svc.ObjectMeta.Name)
		if err != nil {
			return nil, err
		}
		if externalIP != "" {
			action.ExternalIP = externalIP
		} else if hostName != "" {
			action.Hostname = hostName
		} else {
			return nil, fmt.Errorf("Did not get either an IP or a hostname from GetSvcExternalIpOrHost")
		}
		action.AddDNS = !app.InternalPorts && features.IpAllocatedPerService
		return &action, nil
	}
	err = m.commonPf.CreateAppDNSAndPatchKubeSvc(ctx, client, names, infracommon.NoDnsOverride, getDnsAction)
	if err != nil {
		return err
	}
	// set up ingress
	if features.UsesIngress && appInst.UsesHTTP() {
		ingress, err := k8smgmt.CreateIngress(ctx, client, names, appInst)
		if err != nil {
			return err
		}
		ip, err := k8smgmt.GetIngressExternalIP(ctx, client, names, ingress.ObjectMeta.Name)
		if err != nil {
			return err
		}
		fqdn := names.AppURI
		fqdn = strings.TrimPrefix(fqdn, "https://")
		fqdn = strings.TrimPrefix(fqdn, "http://")
		// register DNS for ingress
		// note that we do not register DNS based on the presence of
		// ingress objects via CreateAppDNSAndPatchKubeSvc,
		// because helm charts may create ingress objects, but they
		// won't be using our host names.
		action := infracommon.DnsSvcAction{
			ExternalIP: ip,
		}
		if err := m.commonPf.AddDNS(ctx, fqdn, &action); err != nil {
			return err
		}
	}
	return nil
}

func (m *K8sPlatformMgr) DeleteAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteAppInst", "appInst", appInst)
	var err error
	client, err := m.clusterAccess.GetClusterClient(ctx, clusterInst)
	if err != nil {
		return err
	}
	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return err
	}
	// regenerate kconf in case CCRM was restarted
	err = m.ensureKubeconfigs(ctx, client, clusterInst, names)
	if err != nil {
		return err
	}
	if !app.InternalPorts {
		if err = m.commonPf.DeleteAppDNS(ctx, client, names, infracommon.NoDnsOverride); err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "warning, cannot delete DNS record", "error", err)
		}
	}
	if m.features.UsesIngress && appInst.UsesHTTP() {
		fqdn := names.AppURI
		fqdn = strings.TrimPrefix(fqdn, "https://")
		fqdn = strings.TrimPrefix(fqdn, "http://")
		err := m.commonPf.DeleteDNSRecords(ctx, fqdn)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "warning, cannot delete DNS record", "fqdn", fqdn, "error", err)
		}
		if err = k8smgmt.DeleteIngress(ctx, client, names, appInst); err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "warning, cannot delete ingress", "error", err)
		}
	}

	switch app.Deployment {
	case cloudcommon.DeploymentTypeKubernetes:
		err = k8smgmt.DeleteAppInst(ctx, m.commonPf.PlatformConfig.AccessApi, client, names, clusterInst, app, appInst, k8smgmt.WithWorkloadManager(m.wm))
	case cloudcommon.DeploymentTypeHelm:
		err = k8smgmt.DeleteHelmAppInst(ctx, client, names, clusterInst)
	default:
		err = fmt.Errorf("unsupported deployment type %s", app.Deployment)
	}
	if err != nil {
		return err
	}
	// In case of using an external workload manager that does not
	// use the config dir, but we applied an ingress which did
	// create the config dir, make sure it is removed now.
	// This is a no-op if the config dir has already been removed.
	err = k8smgmt.RemoveConfigDir(ctx, client, names)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "warning, failed to clean up config dir", "error", err)
	}
	return nil
}

func (m *K8sPlatformMgr) GetAppInstRuntime(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) (*edgeproto.AppInstRuntime, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetAppInstRuntime", "appInst", appInst)
	client, err := m.clusterAccess.GetClusterClient(ctx, clusterInst)
	if err != nil {
		return nil, err
	}
	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return nil, err
	}
	err = m.ensureKubeconfigs(ctx, client, clusterInst, names)
	if err != nil {
		return nil, err
	}
	return k8smgmt.GetAppInstRuntime(ctx, client, names, app, appInst)
}

func (m *K8sPlatformMgr) UpdateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "UpdateAppInst", "appInst", appInst)
	updateCallback(edgeproto.UpdateTask, "Updating AppInst")
	client, err := m.clusterAccess.GetClusterClient(ctx, clusterInst)
	if err != nil {
		return err
	}
	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return err
	}
	err = m.ensureKubeconfigs(ctx, client, clusterInst, names)
	if err != nil {
		return err
	}
	return k8smgmt.UpdateAppInst(ctx, m.commonPf.PlatformConfig.AccessApi, client, names, clusterInst, app, appInst, k8smgmt.WithWorkloadManager(m.wm))
}

func (m *K8sPlatformMgr) ensureKubeconfigs(ctx context.Context, client ssh.Client, clusterInst *edgeproto.ClusterInst, names *k8smgmt.KubeNames) error {
	kconfData, err := m.clusterAccess.GetClusterCredentials(ctx, clusterInst)
	if err != nil {
		return fmt.Errorf("unable to get cluster %s credentials %v", clusterInst.Key.GetKeyString(), err)
	}
	return k8smgmt.EnsureKubeconfigs(ctx, client, names, kconfData)
}

func (m *K8sPlatformMgr) GetContainerCommand(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, req *edgeproto.ExecRequest) (string, error) {
	return k8smgmt.GetContainerCommand(ctx, clusterInst, app, appInst, req)
}

func (m *K8sPlatformMgr) GetConsoleUrl(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst) (string, error) {
	return "", fmt.Errorf("Unsupported command for platform")
}

func (m *K8sPlatformMgr) SetPowerState(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("Unsupported command for platform")
}

func (m *K8sPlatformMgr) HandleFedAppInstCb(ctx context.Context, msg *edgeproto.FedAppInstEvent) {
}

func (v *K8sPlatformMgr) ChangeAppInstDNS(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst, OldURI string, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("Updating DNS is not supported")
}
