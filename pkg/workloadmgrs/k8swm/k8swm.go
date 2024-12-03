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

// Package k8swm provides a Kubernetes workload manager.
package k8swm

import (
	"context"
	"fmt"
	"io/fs"
	"os"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	ssh "github.com/edgexr/golang-ssh"
	v1 "k8s.io/api/core/v1"
)

type ClusterAccess interface {
	// GetClusterPlatformClient gets an ssh client to access the
	// node that will have the local kubeconfig and manifest files.
	GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error)
	// GetClusterCredentials retrieves kubeconfig credentials from the cluster
	GetClusterCredentials(ctx context.Context, clusterInst *edgeproto.ClusterInst) ([]byte, error)
}

type K8sWorkloadMgr struct {
	clusterAccess ClusterAccess
	features      *edgeproto.PlatformFeatures
	commonPf      *infracommon.CommonPlatform
}

const KconfPerms fs.FileMode = 0644

func (m *K8sWorkloadMgr) Init(clusterAccess ClusterAccess, features *edgeproto.PlatformFeatures, commonPf *infracommon.CommonPlatform) {
	m.clusterAccess = clusterAccess
	m.features = features
	m.commonPf = commonPf
}

func (m *K8sWorkloadMgr) CreateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateSender edgeproto.AppInstInfoSender) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateAppInst", "appInst", appInst)
	updateSender.SendStatus(edgeproto.UpdateTask, "Creating AppInst")

	if err := m.SetupKconf(ctx, clusterInst); err != nil {
		return fmt.Errorf("can't set up kconf, %s", err.Error())
	}
	client, err := m.clusterAccess.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return err
	}
	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return err
	}
	features := m.features

	err = k8smgmt.CreateAllNamespaces(ctx, client, names)
	if err != nil {
		return err
	}
	updateSender.SendStatus(edgeproto.UpdateTask, "Creating Registry Secret")
	for _, imagePath := range names.ImagePaths {
		err = infracommon.CreateDockerRegistrySecret(ctx, client, k8smgmt.GetKconfName(clusterInst), imagePath, m.commonPf.PlatformConfig.AccessApi, names, nil)
		if err != nil {
			return err
		}
	}

	switch deployment := app.Deployment; deployment {
	case cloudcommon.DeploymentTypeKubernetes:
		err = k8smgmt.CreateAppInst(ctx, m.commonPf.PlatformConfig.AccessApi, client, names, app, appInst, flavor)
		if err == nil {
			updateSender.SendStatus(edgeproto.UpdateTask, "Waiting for AppInst to Start")

			err = k8smgmt.WaitForAppInst(ctx, client, names, app, k8smgmt.WaitRunning)
		}
	default:
		err = fmt.Errorf("unsupported deployment type %s", deployment)
	}
	if err != nil {
		return err
	}
	updateSender.SendStatus(edgeproto.UpdateTask, "Waiting for Load Balancer External IP")

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
	return nil
}

func (m *K8sWorkloadMgr) DeleteAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteAppInst", "appInst", appInst)
	var err error
	// regenerate kconf in case CRM was restarted
	if err = m.SetupKconf(ctx, clusterInst); err != nil {
		return fmt.Errorf("can't set up kconf, %s", err.Error())
	}
	client, err := m.clusterAccess.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return err
	}
	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return err
	}
	if !app.InternalPorts {
		if err = m.commonPf.DeleteAppDNS(ctx, client, names, infracommon.NoDnsOverride); err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "warning, cannot delete DNS record", "error", err)
		}
	}

	switch deployment := app.Deployment; deployment {
	case cloudcommon.DeploymentTypeKubernetes:
		err = k8smgmt.DeleteAppInst(ctx, m.commonPf.PlatformConfig.AccessApi, client, names, app, appInst)
	default:
		err = fmt.Errorf("unsupported deployment type %s", deployment)
	}
	return err
}

func (m *K8sWorkloadMgr) GetAppInstRuntime(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) (*edgeproto.AppInstRuntime, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetAppInstRuntime", "appInst", appInst)
	if err := m.SetupKconf(ctx, clusterInst); err != nil {
		return nil, fmt.Errorf("can't set up kconf, %s", err.Error())
	}
	client, err := m.clusterAccess.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return nil, err
	}

	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return nil, err
	}
	return k8smgmt.GetAppInstRuntime(ctx, client, names, app, appInst)
}

func (m *K8sWorkloadMgr) UpdateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "UpdateAppInst", "appInst", appInst)
	updateCallback(edgeproto.UpdateTask, "Updating AppInst")
	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return err
	}
	client, err := m.clusterAccess.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return err
	}

	err = k8smgmt.UpdateAppInst(ctx, m.commonPf.PlatformConfig.AccessApi, client, names, app, appInst, flavor)
	if err == nil {
		updateCallback(edgeproto.UpdateTask, "Waiting for AppInst to Start")
		err = k8smgmt.WaitForAppInst(ctx, client, names, app, k8smgmt.WaitRunning)
	}
	return err
}

func (m *K8sWorkloadMgr) SetupKconf(ctx context.Context, clusterInst *edgeproto.ClusterInst) error {
	targetFile := k8smgmt.GetKconfName(clusterInst)

	if _, err := os.Stat(targetFile); err == nil {
		// already exists
		return nil
	}
	return m.SetupClusterKconf(ctx, clusterInst, targetFile)
}

func (m *K8sWorkloadMgr) SetupClusterKconf(ctx context.Context, clusterInst *edgeproto.ClusterInst, targetFile string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SetupKconf", "cluster", clusterInst.Key, "targetFile", targetFile)
	kconfData, err := m.clusterAccess.GetClusterCredentials(ctx, clusterInst)
	if err != nil {
		return fmt.Errorf("unable to get cluster %s credentials %v", clusterInst.Key.GetKeyString(), err)
	}
	err = os.WriteFile(targetFile, kconfData, KconfPerms)
	if err != nil {
		return fmt.Errorf("failed to write cluster %s kubeconfig %s, %s", clusterInst.Key.GetKeyString(), targetFile, err)
	}
	return nil
}

func (m *K8sWorkloadMgr) GetContainerCommand(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, req *edgeproto.ExecRequest) (string, error) {
	return k8smgmt.GetContainerCommand(ctx, clusterInst, app, appInst, req)
}

func (m *K8sWorkloadMgr) GetConsoleUrl(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst) (string, error) {
	return "", fmt.Errorf("Unsupported command for platform")
}

func (m *K8sWorkloadMgr) SetPowerState(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("Unsupported command for platform")
}

func (m *K8sWorkloadMgr) HandleFedAppInstCb(ctx context.Context, msg *edgeproto.FedAppInstEvent) {
}

func (v *K8sWorkloadMgr) ChangeAppInstDNS(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst, OldURI string, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("Updating DNS is not supported")
}
