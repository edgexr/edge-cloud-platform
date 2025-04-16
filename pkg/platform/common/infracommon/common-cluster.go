// Copyright 2025 EdgeXR, Inc
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

package infracommon

import (
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
)

// FilterCloudletManagedClusters takes as input a list of
// clusters taken from the underlying infra platform. It then
// checks which clusters were created by Edge Cloud, which
// clusters were created externally and are registered, and
// which clusters were created externally but not registered.
// It returns all the externally created clusters by removing
// clusters that were created by Edge Cloud.
func FilterCloudletManagedClusters(cloudletKey *edgeproto.CloudletKey, cmcClusters []*edgeproto.CloudletManagedCluster, cache *edgeproto.ClusterInstCache, getInfraClusterName func(ci *edgeproto.ClusterInst) string) ([]*edgeproto.CloudletManagedCluster, error) {
	type clusterInfo struct {
		clusterKey       edgeproto.ClusterKey
		isManagedCluster bool
		reservable       bool
		multiTenant      bool
	}
	ecClusters := map[string]clusterInfo{}
	err := cache.Show(&edgeproto.ClusterInst{}, func(ci *edgeproto.ClusterInst) error {
		if !ci.CloudletKey.Matches(cloudletKey) {
			return nil
		}
		clusterInfo := clusterInfo{
			clusterKey:       ci.Key,
			isManagedCluster: ci.IsCloudletManaged(),
			reservable:       ci.Reservable,
			multiTenant:      ci.MultiTenant,
		}
		clusterName := getInfraClusterName(ci)
		ecClusters[clusterName] = clusterInfo
		return nil
	})
	if err != nil {
		return nil, err
	}

	cmcClustersOut := []*edgeproto.CloudletManagedCluster{}
	for _, cmcCluster := range cmcClusters {
		cinfo, found := ecClusters[cmcCluster.Key.Name]
		if found {
			if !cinfo.isManagedCluster {
				// skip cluster that was created by Edge Cloud
				continue
			}
			// cluster is registered, fill in info for
			// associated ClusterInst.
			cmcCluster.CloudletKey = *cloudletKey
			cmcCluster.ClusterKey = cinfo.clusterKey
			cmcCluster.Reservable = cinfo.reservable
			cmcCluster.MultiTenant = cinfo.multiTenant
		}
		cmcClustersOut = append(cmcClustersOut, cmcCluster)
	}
	return cmcClustersOut, nil
}
