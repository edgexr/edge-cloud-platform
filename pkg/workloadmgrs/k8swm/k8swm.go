// Copyright 2025 EdgeXR, Inc
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

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	"github.com/edgexr/edge-cloud-platform/pkg/workloadmgrs"
)

type K8sWorkloadMgr struct {
	clusterAccess workloadmgrs.ClusterAccess
	commonPf      *infracommon.CommonPlatform
}

func NewK8sWorkloadMgr(clusterAccess workloadmgrs.ClusterAccess, commonPf *infracommon.CommonPlatform) *K8sWorkloadMgr {
	return &K8sWorkloadMgr{
		clusterAccess: clusterAccess,
		commonPf:      commonPf,
	}
}

func (m *K8sWorkloadMgr) CreateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateSender edgeproto.AppInstInfoSender) error {
	var err error
	client, err := m.clusterAccess.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return err
	}
	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return err
	}

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

	updateSender.SendStatus(edgeproto.UpdateTask, "Deploying App Instance")
	switch deployment := app.Deployment; deployment {
	case cloudcommon.DeploymentTypeKubernetes:
		err = k8smgmt.CreateAppInst(ctx, m.commonPf.PlatformConfig.AccessApi, client, names, app, appInst)
	case cloudcommon.DeploymentTypeHelm:
		err = k8smgmt.CreateHelmAppInst(ctx, client, names, clusterInst, app, appInst)
	default:
		err = fmt.Errorf("unsupported deployment type %s", deployment)
	}
	if err != nil {
		return err
	}
	return nil
}

func (m *K8sWorkloadMgr) DeleteAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	var err error
	client, err := m.clusterAccess.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return err
	}
	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return err
	}

	switch deployment := app.Deployment; deployment {
	case cloudcommon.DeploymentTypeKubernetes:
		err = k8smgmt.DeleteAppInst(ctx, m.commonPf.PlatformConfig.AccessApi, client, names, app, appInst)
	case cloudcommon.DeploymentTypeHelm:
		err = k8smgmt.DeleteHelmAppInst(ctx, client, names, clusterInst)
	default:
		err = fmt.Errorf("unsupported deployment type %s", deployment)
	}
	return err
}

func (m *K8sWorkloadMgr) UpdateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return err
	}
	client, err := m.clusterAccess.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return err
	}

	err = k8smgmt.UpdateAppInst(ctx, m.commonPf.PlatformConfig.AccessApi, client, names, app, appInst)
	if err == nil {
		updateCallback(edgeproto.UpdateTask, "Waiting for AppInst to Start")
		err = k8smgmt.WaitForAppInst(ctx, client, names, app, k8smgmt.WaitRunning)
	}
	return err
}
