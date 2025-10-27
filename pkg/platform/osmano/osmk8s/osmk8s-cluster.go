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
	"errors"
	"fmt"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/osmano/osmclient"
)

func (s *Platform) CreateClusterPrerequisites(ctx context.Context, clusterName string) error {
	return nil
}

func (s *Platform) RunClusterCreateCommand(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) (map[string]string, error) {
	id, err := s.osmClient.CreateCluster(ctx, clusterName, clusterInst)
	if err != nil {
		return nil, err
	}
	infraAnnotations := map[string]string{
		osmclient.ClusterIDAnnotation: id,
	}
	return infraAnnotations, nil
}

func (s *Platform) RunClusterDeleteCommand(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	err := s.osmClient.DeleteCluster(ctx, clusterName, clusterInst)
	if err != nil {
		return err
	}
	return nil
}

func (s *Platform) RunClusterUpdateCommand(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) (map[string]string, error) {
	// only perform node scaling
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

func (s *Platform) GetAllClusters(ctx context.Context) ([]*edgeproto.CloudletManagedCluster, error) {
	clusters, err := s.osmClient.ListClusters(ctx)
	if err != nil {
		return nil, err
	}
	cloudletManagedClusters := []*edgeproto.CloudletManagedCluster{}
	for _, cluster := range clusters {
		cmc := &edgeproto.CloudletManagedCluster{}
		cmc.Key.Id = cluster.ID
		cmc.Key.Name = cluster.Name
		cmc.KubernetesVersion = cluster.K8SVersion
		cmc.RegionOrLocation = cluster.RegionName
		cmc.ResourceGroup = cluster.ResourceGroup
		cmc.State = cluster.State + "," + cluster.ResourceState
		cmc.OperationalState = cluster.OperatingState
		cloudletManagedClusters = append(cloudletManagedClusters, cmc)
	}
	return cloudletManagedClusters, nil
}

func (s *Platform) RegisterCluster(ctx context.Context, clusterName string, in *edgeproto.ClusterInst) (map[string]string, error) {
	if in.CloudletManagedClusterId == "" && in.CloudletManagedClusterName == "" {
		return nil, errors.New("either cloudlet cluster id or cloudlet cluster name must be specified")
	}
	var clusterInfo *osmclient.GetClusterInfo
	var err error
	var lookupKey string
	if in.CloudletManagedClusterId != "" {
		lookupKey = in.CloudletManagedClusterId
		clusterInfo, _, err = s.osmClient.GetClusterInfo(ctx, in.CloudletManagedClusterId)
	} else {
		lookupKey = in.CloudletManagedClusterName
		clusterInfo, err = s.osmClient.FindClusterInfo(ctx, in.CloudletManagedClusterName)
	}
	if err == nil && clusterInfo == nil {
		err = fmt.Errorf("infra cluster %s not found", lookupKey)
	}
	if err != nil {
		return nil, err
	}
	infraAnnotations := map[string]string{
		osmclient.ClusterIDAnnotation: clusterInfo.ID,
	}
	return infraAnnotations, nil
}
