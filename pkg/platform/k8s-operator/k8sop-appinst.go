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

package k8sop

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	v1 "k8s.io/api/core/v1"
)

func (s *K8sOperator) CreateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateAppInst", "appInst", appInst)
	updateCallback(edgeproto.UpdateTask, "Creating AppInst")
	if app.Deployment != cloudcommon.DeploymentTypeKubernetes && app.Deployment != cloudcommon.DeploymentTypeHelm {
		return fmt.Errorf("unsupported deployment type %s", app.Deployment)
	}

	if err := s.SetupKconf(ctx, clusterInst); err != nil {
		return fmt.Errorf("can't set up kconf, %s", err.Error())
	}
	client := s.getClient()

	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return err
	}
	features := s.GetFeatures()

	updateCallback(edgeproto.UpdateTask, "Creating Registry Secret")
	for _, imagePath := range names.ImagePaths {
		err = k8smgmt.CreateAllNamespaces(ctx, client, names)
		if err != nil {
			return err
		}
		err = infracommon.CreateDockerRegistrySecret(ctx, client, k8smgmt.GetKconfName(clusterInst), imagePath, s.CommonPf.PlatformConfig.AccessApi, names, nil)
		if err != nil {
			return err
		}
	}

	err = k8smgmt.CreateAppInst(ctx, s.CommonPf.PlatformConfig.AccessApi, client, names, app, appInst, flavor)
	if err == nil {
		updateCallback(edgeproto.UpdateTask, "Waiting for AppInst to Start")

		err = k8smgmt.WaitForAppInst(ctx, client, names, app, k8smgmt.WaitRunning)
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
		action.AddDNS = !app.InternalPorts && features.IpAllocatedPerService
		return &action, nil
	}
	err = s.CommonPf.CreateAppDNSAndPatchKubeSvc(ctx, client, names, infracommon.NoDnsOverride, getDnsAction)
	if err != nil {
		return err
	}
	return nil
}

func (s *K8sOperator) DeleteAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteAppInst", "appInst", appInst)
	var err error

	if err := s.SetupKconf(ctx, clusterInst); err != nil {
		return fmt.Errorf("can't set up kconf, %s", err.Error())
	}
	client := s.getClient()
	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return err
	}
	if !app.InternalPorts {
		if err = s.CommonPf.DeleteAppDNS(ctx, client, names, infracommon.NoDnsOverride); err != nil {
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

func (s *K8sOperator) GetAppInstRuntime(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) (*edgeproto.AppInstRuntime, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetAppInstRuntime", "appInst", appInst)
	if err := s.SetupKconf(ctx, clusterInst); err != nil {
		return nil, fmt.Errorf("can't set up kconf, %s", err.Error())
	}
	client := s.getClient()
	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return nil, err
	}
	return k8smgmt.GetAppInstRuntime(ctx, client, names, app, appInst)
}

func (s *K8sOperator) UpdateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "UpdateAppInst", "appInst", appInst)
	updateCallback(edgeproto.UpdateTask, "Updating AppInst")
	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return err
	}
	client := s.getClient()

	err = k8smgmt.UpdateAppInst(ctx, s.CommonPf.PlatformConfig.AccessApi, client, names, app, appInst, flavor)
	if err == nil {
		updateCallback(edgeproto.UpdateTask, "Waiting for AppInst to Start")
		err = k8smgmt.WaitForAppInst(ctx, client, names, app, k8smgmt.WaitRunning)
	}
	return err
}

var defaultKconf = `apiVersion: v1
kind: Config
clusters:
- name: local
contexts:
- context:
    namespace: default
  name: local
current-context: local
`

func (s *K8sOperator) SetupKconf(ctx context.Context, clusterInst *edgeproto.ClusterInst) error {
	targetFile := WorkingDir + "/" + k8smgmt.GetKconfName(clusterInst)
	log.SpanLog(ctx, log.DebugLevelInfra, "SetupKconf", "targetFile", targetFile)

	if _, err := os.Stat(targetFile); err == nil {
		// already exists
		return nil
	}
	err := ioutil.WriteFile(targetFile, []byte(defaultKconf), 0644)
	if err != nil {
		return fmt.Errorf("Failed to write %s: %s", targetFile, err)
	}
	return nil
}

func (s *K8sOperator) GetContainerCommand(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, req *edgeproto.ExecRequest) (string, error) {
	return k8smgmt.GetContainerCommand(ctx, clusterInst, app, appInst, req)
}

func (s *K8sOperator) GetConsoleUrl(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst) (string, error) {
	return "", fmt.Errorf("Unsupported command for platform")
}

func (s *K8sOperator) SetPowerState(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("Unsupported command for platform")
}
