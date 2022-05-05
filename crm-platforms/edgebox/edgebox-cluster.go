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

package edgebox

import (
	"context"
	"fmt"
	"time"

	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
)

func (e *EdgeboxPlatform) UpdateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("update not implemented")
}

func (e *EdgeboxPlatform) GetCloudletInfraResources(ctx context.Context) (*edgeproto.InfraResourcesSnapshot, error) {
	return e.generic.GetCloudletInfraResources(ctx)
}

func (e *EdgeboxPlatform) GetClusterInfraResources(ctx context.Context, clusterKey *edgeproto.ClusterInstKey) (*edgeproto.InfraResources, error) {
	return e.generic.GetClusterInfraResources(ctx, clusterKey)
}

func (e *EdgeboxPlatform) CreateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) error {
	err := e.generic.CreateClusterInst(ctx, clusterInst, updateCallback, timeout)
	if err != nil {
		return err
	}
	// The rest is k8s specific
	if clusterInst.Deployment == cloudcommon.DeploymentTypeDocker {
		return nil
	}
	client, err := e.generic.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return err
	}
	clusterName := clusterInst.Key.ClusterKey.Name

	err = infracommon.CreateClusterConfigMap(ctx, client, clusterInst)
	if err != nil {
		return fmt.Errorf("cannot create ConfigMap for: %s, err: %v", clusterName, err)
	}
	return nil
}

func (e *EdgeboxPlatform) DeleteClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return e.generic.DeleteClusterInst(ctx, clusterInst, updateCallback)
}
