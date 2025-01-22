// Copyright 2024 EdgeXR, Inc
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

package osmk8s

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/osmano/osmclient"
)

func (s *Platform) CreateClusterPrerequisites(ctx context.Context, clusterName string) error {
	return nil
}

func (s *Platform) RunClusterCreateCommand(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst) (map[string]string, error) {
	id, err := s.osmClient.CreateCluster(ctx, clusterName, clusterInst)
	if err != nil {
		return nil, err
	}
	infraAnnotations := map[string]string{
		osmclient.ClusterIDAnnotation: id,
	}
	return infraAnnotations, nil
}

func (s *Platform) RunClusterDeleteCommand(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst) error {
	err := s.osmClient.DeleteCluster(ctx, clusterName, clusterInst)
	if err != nil {
		return err
	}
	return nil
}

var allowedClusterUpdateFields = edgeproto.NewFieldMap(map[string]struct{}{
	edgeproto.ClusterInstFieldNodePoolsNumNodes: {},
})

func (s *Platform) RunClusterUpdateCommand(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst) (map[string]string, error) {
	// only allow node scaling
	if err := clusterInst.ValidateUpdateFieldsCustom(allowedClusterUpdateFields); err != nil {
		return nil, err
	}

	fmap := edgeproto.MakeFieldMap(clusterInst.Fields)
	if fmap.Has(edgeproto.ClusterInstFieldNodePoolsNumNodes) {
		err := s.osmClient.ScaleCluster(ctx, clusterName, clusterInst)
		if err != nil {
			return nil, err
		}
	}
	return nil, nil
}

func (s *Platform) GetCredentials(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst) ([]byte, error) {
	return s.osmClient.GetCredentials(ctx, clusterName, clusterInst)
}

func (a *Platform) GetClusterAddonInfo(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst) (*k8smgmt.ClusterAddonInfo, error) {
	info := k8smgmt.ClusterAddonInfo{}
	return &info, nil
}

func (s *Platform) GetCloudletInfraResourcesInfo(ctx context.Context) ([]edgeproto.InfraResource, error) {
	return []edgeproto.InfraResource{}, nil
}

// GetClusterAdditionalResources is called by controller, make sure it doesn't make any calls to infra API
func (s *Platform) GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource) map[string]edgeproto.InfraResource {
	return nil
}

func (s *Platform) GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error {
	return nil
}
