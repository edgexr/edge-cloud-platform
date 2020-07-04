package main

import (
	"testing"

	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_platform/shepherd_unittest"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/testutil"
	"github.com/stretchr/testify/assert"
)

// Test the types of appInstances that will create a scrapePoint
func TestCollectProxyStats(t *testing.T) {
	ctx := setupLog()
	defer log.FinishTracer()
	myPlatform = &shepherd_unittest.Platform{}
	InitProxyScraper()
	edgeproto.InitAppInstCache(&AppInstCache)
	edgeproto.InitAppCache(&AppCache)
	edgeproto.InitClusterInstCache(&ClusterInstCache)

	//Create all clusters, apps, appInstances
	for ii, obj := range testutil.ClusterInstData {
		// default all to dedicated access
		if obj.IpAccess == edgeproto.IpAccess_IP_ACCESS_UNKNOWN {
			obj.IpAccess = edgeproto.IpAccess_IP_ACCESS_DEDICATED
		}
		ClusterInstCache.Update(ctx, &testutil.ClusterInstData[ii], 0)
	}
	for ii, obj := range testutil.ClusterInstAutoData {
		// default all to dedicated access
		if obj.IpAccess == edgeproto.IpAccess_IP_ACCESS_UNKNOWN {
			obj.IpAccess = edgeproto.IpAccess_IP_ACCESS_DEDICATED
		}
		ClusterInstCache.Update(ctx, &testutil.ClusterInstAutoData[ii], 0)
	}

	for ii, _ := range testutil.AppData {
		AppCache.Update(ctx, &testutil.AppData[ii], 0)
	}
	// Now test each enty in AppInstData
	for ii, obj := range testutil.AppInstData {
		// set mapped ports and state
		app := edgeproto.App{}
		found := AppCache.Get(&obj.Key.AppKey, &app)
		if !found {
			continue
		}
		ports, _ := edgeproto.ParseAppPorts(app.AccessPorts)
		obj.MappedPorts = ports
		obj.State = edgeproto.TrackedState_READY

		// For each appInst in testutil.AppInstData the reslt might differ
		switch ii {
		case 0, 1, 2, 3, 4, 6, 7:
			// tcp,udp,http ports, load-balancer access
			// dedicated access k8s
			// We should write a targets file and get a scrape point
			target := CollectProxyStats(ctx, &obj)
			assert.NotEmpty(t, target)
		case 5:
			// udp load-balancer
			// dedicated helm access
			target := CollectProxyStats(ctx, &obj)
			assert.Empty(t, target)
		case 8:
			// dedicated, no ports
			target := CollectProxyStats(ctx, &obj)
			assert.Empty(t, target)
		}
		AppInstCache.Update(ctx, &testutil.AppInstData[ii], 0)
	}
}
