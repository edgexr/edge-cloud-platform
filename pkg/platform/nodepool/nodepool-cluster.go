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

package sitenodepool

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
)

func (s *SiteNodePool) CreateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) (map[string]string, error) {
	// TODO
	return nil, errors.New("TODO")
}

func (s *SiteNodePool) DeleteClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return errors.New("TODO")
}

func (s *SiteNodePool) UpdateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) (map[string]string, error) {
	return nil, errors.New("TODO")
}

func (s *SiteNodePool) ChangeClusterInstDNS(ctx context.Context, clusterInst *edgeproto.ClusterInst, oldFqdn string, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("cluster dns change not supported")
}

func (s *SiteNodePool) GetClusterInfraResources(ctx context.Context, cluster *edgeproto.ClusterInst) (*edgeproto.InfraResources, error) {
	return nil, nil
}

func (s *SiteNodePool) GetClusterName(cluster *edgeproto.ClusterInst) string {
	// GetClusterName is used for OSMWM,
	// but SiteNodePool does not support OSM
	return "not-supported"
}

func (s *SiteNodePool) GetCloudletManagedClusters(ctx context.Context) ([]*edgeproto.CloudletManagedCluster, error) {
	return nil, errors.New("not supported")
}

func (s *SiteNodePool) GetCloudletManagedClusterInfo(ctx context.Context, in *edgeproto.ClusterInst) (*edgeproto.CloudletManagedClusterInfo, error) {
	return nil, errors.New("not supported")
}
