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

package k8sbm

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
)

func (k *K8sBareMetalPlatform) CreateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) (map[string]string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateClusterInst")
	if strings.HasPrefix(clusterInst.Key.Name, cloudcommon.DefaultMultiTenantCluster) && edgeproto.IsEdgeCloudOrg(clusterInst.Key.Organization) {
		// The cluster that represents this Cloudlet's cluster.
		// This is a no-op as the cluster already exists.
		return nil, nil
	}
	return nil, errors.New("CreateClusterInst not supported on " + platformName())
}

func (k *K8sBareMetalPlatform) UpdateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) (map[string]string, error) {
	return nil, errors.New("UpdateClusterInst not supported on " + platformName())
}

func (k *K8sBareMetalPlatform) DeleteClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return errors.New("DeleteClusterInst not supported on " + platformName())
}

func (s *K8sBareMetalPlatform) ChangeClusterInstDNS(ctx context.Context, clusterInst *edgeproto.ClusterInst, oldFqdn string, updateCallback edgeproto.CacheUpdateCallback) error {
	return errors.New("ChangeClusterInstDNS not supported on " + platformName())
}

func (s *K8sBareMetalPlatform) GetCloudletManagedClusters(ctx context.Context) ([]*edgeproto.CloudletManagedCluster, error) {
	return nil, errors.New("not supported")
}

func (s *K8sBareMetalPlatform) GetCloudletManagedClusterInfo(ctx context.Context, in *edgeproto.ClusterInst) (*edgeproto.CloudletManagedClusterInfo, error) {
	return nil, errors.New("not supported")
}
