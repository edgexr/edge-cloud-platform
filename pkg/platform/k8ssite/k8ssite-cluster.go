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

package k8ssite

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
)

func (s *K8sSite) CreateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) (map[string]string, error) {
	return nil, errors.New("create cluster not supported")
}

func (s *K8sSite) DeleteClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return errors.New("delete cluster not supported")
}

func (s *K8sSite) UpdateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) (map[string]string, error) {
	return nil, errors.New("update cluster not supported")
}

func (s *K8sSite) ChangeClusterInstDNS(ctx context.Context, clusterInst *edgeproto.ClusterInst, oldFqdn string, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("cluster dns change not supported")
}

func (s *K8sSite) GetClusterInfraResources(ctx context.Context, cluster *edgeproto.ClusterInst) (*edgeproto.InfraResources, error) {
	return nil, fmt.Errorf("GetClusterInfraResources not supported")
}

func (s *K8sSite) GetClusterName(cluster *edgeproto.ClusterInst) string {
	// GetClusterName is used for OSMWM,
	// but k8ssite does not support OSM
	return "not-supported"
}
