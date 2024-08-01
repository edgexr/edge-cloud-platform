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

package platform

import "github.com/edgexr/edge-cloud-platform/api/edgeproto"

// BuildCaches can be used for unit tests
func BuildCaches() *Caches {
	caches := &Caches{
		SettingsCache:             &edgeproto.SettingsCache{},
		FlavorCache:               &edgeproto.FlavorCache{},
		TrustPolicyCache:          &edgeproto.TrustPolicyCache{},
		TrustPolicyExceptionCache: &edgeproto.TrustPolicyExceptionCache{},
		ClusterInstCache:          &edgeproto.ClusterInstCache{},
		AppInstCache:              &edgeproto.AppInstCache{},
		AppCache:                  &edgeproto.AppCache{},
		ResTagTableCache:          &edgeproto.ResTagTableCache{},
		CloudletCache:             &edgeproto.CloudletCache{},
		CloudletInternalCache:     &edgeproto.CloudletInternalCache{},
		VMPoolCache:               &edgeproto.VMPoolCache{},
		VMPoolInfoCache:           &edgeproto.VMPoolInfoCache{},
		GPUDriverCache:            &edgeproto.GPUDriverCache{},
		NetworkCache:              &edgeproto.NetworkCache{},
	}
	edgeproto.InitSettingsCache(caches.SettingsCache)
	edgeproto.InitFlavorCache(caches.FlavorCache)
	edgeproto.InitTrustPolicyCache(caches.TrustPolicyCache)
	edgeproto.InitTrustPolicyExceptionCache(caches.TrustPolicyExceptionCache)
	edgeproto.InitClusterInstCache(caches.ClusterInstCache)
	edgeproto.InitAppInstCache(caches.AppInstCache)
	edgeproto.InitAppCache(caches.AppCache)
	edgeproto.InitResTagTableCache(caches.ResTagTableCache)
	edgeproto.InitCloudletCache(caches.CloudletCache)
	edgeproto.InitCloudletInternalCache(caches.CloudletInternalCache)
	edgeproto.InitVMPoolCache(caches.VMPoolCache)
	edgeproto.InitVMPoolInfoCache(caches.VMPoolInfoCache)
	edgeproto.InitGPUDriverCache(caches.GPUDriverCache)
	edgeproto.InitNetworkCache(caches.NetworkCache)
	return caches
}
