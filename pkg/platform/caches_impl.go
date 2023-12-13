package platform

import "github.com/edgexr/edge-cloud-platform/api/edgeproto"

// BuildCaches can be used for unit tests
func BuildCaches() *Caches {
	caches := &Caches{
		SettingsCache:             &edgeproto.SettingsCache{},
		FlavorCache:               &edgeproto.FlavorCache{},
		TrustPolicyCache:          &edgeproto.TrustPolicyCache{},
		TrustPolicyExceptionCache: &edgeproto.TrustPolicyExceptionCache{},
		CloudletPoolCache:         &edgeproto.CloudletPoolCache{},
		ClusterInstCache:          &edgeproto.ClusterInstCache{},
		ClusterInstInfoCache:      &edgeproto.ClusterInstInfoCache{},
		AppInstCache:              &edgeproto.AppInstCache{},
		AppInstInfoCache:          &edgeproto.AppInstInfoCache{},
		AppCache:                  &edgeproto.AppCache{},
		ResTagTableCache:          &edgeproto.ResTagTableCache{},
		CloudletCache:             &edgeproto.CloudletCache{},
		CloudletInternalCache:     &edgeproto.CloudletInternalCache{},
		VMPoolCache:               &edgeproto.VMPoolCache{},
		VMPoolInfoCache:           &edgeproto.VMPoolInfoCache{},
		GPUDriverCache:            &edgeproto.GPUDriverCache{},
		NetworkCache:              &edgeproto.NetworkCache{},
		CloudletInfoCache:         &edgeproto.CloudletInfoCache{},
	}
	edgeproto.InitSettingsCache(caches.SettingsCache)
	edgeproto.InitFlavorCache(caches.FlavorCache)
	edgeproto.InitTrustPolicyCache(caches.TrustPolicyCache)
	edgeproto.InitTrustPolicyExceptionCache(caches.TrustPolicyExceptionCache)
	edgeproto.InitCloudletPoolCache(caches.CloudletPoolCache)
	edgeproto.InitClusterInstCache(caches.ClusterInstCache)
	edgeproto.InitClusterInstInfoCache(caches.ClusterInstInfoCache)
	edgeproto.InitAppInstCache(caches.AppInstCache)
	edgeproto.InitAppInstInfoCache(caches.AppInstInfoCache)
	edgeproto.InitAppCache(caches.AppCache)
	edgeproto.InitResTagTableCache(caches.ResTagTableCache)
	edgeproto.InitCloudletCache(caches.CloudletCache)
	edgeproto.InitCloudletInternalCache(caches.CloudletInternalCache)
	edgeproto.InitVMPoolCache(caches.VMPoolCache)
	edgeproto.InitVMPoolInfoCache(caches.VMPoolInfoCache)
	edgeproto.InitGPUDriverCache(caches.GPUDriverCache)
	edgeproto.InitNetworkCache(caches.NetworkCache)
	edgeproto.InitCloudletInfoCache(caches.CloudletInfoCache)
	return caches
}
