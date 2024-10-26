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
	"errors"
	"fmt"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
)

func (s *K8sOperator) CreateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) (map[string]string, error) {
	return nil, errors.New("create cluster should not be called for k8s operator")
}

func (s *K8sOperator) DeleteClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return errors.New("delete cluster should not be called for k8s operator")
}

func (s *K8sOperator) UpdateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) (map[string]string, error) {
	return nil, errors.New("update cluster should not be called for k8s operator")
}

func (s *K8sOperator) ChangeClusterInstDNS(ctx context.Context, clusterInst *edgeproto.ClusterInst, oldFqdn string, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("cluster dns change should not be called for k8s operator")
}

func (s *K8sOperator) GetClusterInfraResources(ctx context.Context, cluster *edgeproto.ClusterInst) (*edgeproto.InfraResources, error) {
	return nil, fmt.Errorf("GetClusterInfraResources not implemented for k8s operator")
}
