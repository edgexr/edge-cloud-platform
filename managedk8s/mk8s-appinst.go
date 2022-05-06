// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package managedk8s

import (
	"context"
	"fmt"
	"os"

	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	v1 "k8s.io/api/core/v1"
)

func (m *ManagedK8sPlatform) CreateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateAppInst", "appInst", appInst)
	updateCallback(edgeproto.UpdateTask, "Creating AppInst")

	if err := m.SetupKconf(ctx, clusterInst); err != nil {
		return fmt.Errorf("can't set up kconf, %s", err.Error())
	}
	client, err := m.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return err
	}
	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return err
	}
	features := m.GetFeatures()

	updateCallback(edgeproto.UpdateTask, "Creating Registry Secret")
	for _, imagePath := range names.ImagePaths {
		err = infracommon.CreateDockerRegistrySecret(ctx, client, k8smgmt.GetKconfName(clusterInst), imagePath, m.CommonPf.PlatformConfig.AccessApi, names, nil)
		if err != nil {
			return err
		}
	}

	switch deployment := app.Deployment; deployment {
	case cloudcommon.DeploymentTypeKubernetes:
		err = k8smgmt.CreateAppInst(ctx, m.CommonPf.PlatformConfig.AccessApi, client, names, app, appInst, flavor)
		if err == nil {
			updateCallback(edgeproto.UpdateTask, "Waiting for AppInst to Start")

			err = k8smgmt.WaitForAppInst(ctx, client, names, app, k8smgmt.WaitRunning)
		}
	default:
		err = fmt.Errorf("unsupported deployment type %s", deployment)
	}
	if err != nil {
		return err
	}
	updateCallback(edgeproto.UpdateTask, "Waiting for Load Balancer External IP")

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
		action.AddDNS = !app.InternalPorts && features.IPAllocatedPerService
		return &action, nil
	}
	err = m.CommonPf.CreateAppDNSAndPatchKubeSvc(ctx, client, names, infracommon.NoDnsOverride, getDnsAction)
	if err != nil {
		return err
	}
	return nil
}

func (m *ManagedK8sPlatform) DeleteAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteAppInst", "appInst", appInst)
	var err error
	// regenerate kconf in case CRM was restarted
	if err = m.SetupKconf(ctx, clusterInst); err != nil {
		return fmt.Errorf("can't set up kconf, %s", err.Error())
	}
	client, err := m.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return err
	}
	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return err
	}
	if !app.InternalPorts {
		if err = m.CommonPf.DeleteAppDNS(ctx, client, names, infracommon.NoDnsOverride); err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "warning, cannot delete DNS record", "error", err)
		}
	}

	switch deployment := app.Deployment; deployment {
	case cloudcommon.DeploymentTypeKubernetes:
		err = k8smgmt.DeleteAppInst(ctx, client, names, app, appInst)
	default:
		err = fmt.Errorf("unsupported deployment type %s", deployment)
	}
	return err
}

func (m *ManagedK8sPlatform) GetAppInstRuntime(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) (*edgeproto.AppInstRuntime, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetAppInstRuntime", "appInst", appInst)
	if err := m.SetupKconf(ctx, clusterInst); err != nil {
		return nil, fmt.Errorf("can't set up kconf, %s", err.Error())
	}
	client, err := m.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return nil, err
	}

	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return nil, err
	}
	return k8smgmt.GetAppInstRuntime(ctx, client, names, app, appInst)
}

func (m *ManagedK8sPlatform) UpdateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "UpdateAppInst", "appInst", appInst)
	updateCallback(edgeproto.UpdateTask, "Updating AppInst")
	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return err
	}
	client, err := m.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return err
	}

	err = k8smgmt.UpdateAppInst(ctx, m.CommonPf.PlatformConfig.AccessApi, client, names, app, appInst, flavor)
	if err == nil {
		updateCallback(edgeproto.UpdateTask, "Waiting for AppInst to Start")
		err = k8smgmt.WaitForAppInst(ctx, client, names, app, k8smgmt.WaitRunning)
	}
	return err
}

func (m *ManagedK8sPlatform) SetupKconf(ctx context.Context, clusterInst *edgeproto.ClusterInst) error {
	targetFile := k8smgmt.GetKconfName(clusterInst)
	log.SpanLog(ctx, log.DebugLevelInfra, "SetupKconf", "targetFile", targetFile)

	if _, err := os.Stat(targetFile); err == nil {
		// already exists
		return nil
	}
	clusterName := m.Provider.NameSanitize(k8smgmt.GetCloudletClusterName(&clusterInst.Key))
	if err := m.Provider.GetCredentials(ctx, clusterName); err != nil {
		return fmt.Errorf("unable to get credentials %v", err)
	}
	src := infracommon.DefaultKubeconfig()
	if err := infracommon.CopyFile(src, targetFile); err != nil {
		return fmt.Errorf("can't copy %s, %v", src, err)
	}
	return nil
}

func (m *ManagedK8sPlatform) GetContainerCommand(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, req *edgeproto.ExecRequest) (string, error) {
	return k8smgmt.GetContainerCommand(ctx, clusterInst, app, appInst, req)
}

func (m *ManagedK8sPlatform) GetConsoleUrl(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst) (string, error) {
	return "", fmt.Errorf("Unsupported command for platform")
}

func (m *ManagedK8sPlatform) SetPowerState(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("Unsupported command for platform")
}

func (m *ManagedK8sPlatform) CreatePlatformApp(ctx context.Context, name string, kconf string, accessApi platform.AccessApi, pfConfig *edgeproto.PlatformConfig) error {
	// TODO: we can either create the crm app directly here on the cloudlet cluster, or we can create some kind
	// of chef sidecar app that then runs and creates/maintains the crm pod
	return fmt.Errorf("CreatePlatformApp not yet implemented")
}
