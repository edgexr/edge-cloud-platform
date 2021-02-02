package main

import (
	"testing"

	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_platform/shepherd_unittest"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/testutil"
	"github.com/stretchr/testify/require"
)

// Test the types of appInstances that will create a scrapePoint
func TestCollectProxyStats(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelMetrics)
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
	// Now test each entry in AppInstData
	for ii, obj := range testutil.CreatedAppInstData() {
		// set mapped ports and state
		app := edgeproto.App{}
		found := AppCache.Get(&obj.Key.AppKey, &app)
		if !found {
			continue
		}
		ports, _ := edgeproto.ParseAppPorts(app.AccessPorts)
		obj.MappedPorts = ports
		obj.State = edgeproto.TrackedState_READY

		// For each appInst in testutil.AppInstData the result might differ
		switch ii {
		case 0, 1, 3, 4, 6, 7:
			// tcp,udp,http ports, load-balancer access
			// dedicated access k8s
			// We should write a targets file and get a scrape point
			target := CollectProxyStats(ctx, &obj)
			require.NotEmpty(t, target)
			// CollectProxyStats should return empty when running on the same
			// object that we already have
			target = CollectProxyStats(ctx, &obj)
			require.Empty(t, target)
		case 2:
			// Same app, but different cloudlets - map entry is the same
			target := CollectProxyStats(ctx, &obj)
			require.Empty(t, target)
		case 5:
			// udp load-balancer
			// dedicated helm access
			target := CollectProxyStats(ctx, &obj)
			require.NotEmpty(t, target)
		case 8:
			// dedicated, no ports
			target := CollectProxyStats(ctx, &obj)
			require.Empty(t, target)
		case 11:
			// vm app being a lb
			target := CollectProxyStats(ctx, &obj)
			require.NotEmpty(t, target)
		}
		AppInstCache.Update(ctx, &testutil.AppInstData[ii], 0)
	}
	// Test removal of each entry
	for ii, obj := range testutil.AppInstData {
		// set mapped ports and state
		app := edgeproto.App{}
		found := AppCache.Get(&obj.Key.AppKey, &app)
		if !found {
			continue
		}
		ports, _ := edgeproto.ParseAppPorts(app.AccessPorts)
		obj.MappedPorts = ports
		obj.State = edgeproto.TrackedState_DELETING

		// For each appInst in testutil.AppInstData the result might differ
		switch ii {
		case 0, 1, 3, 4, 6, 7:
			// tcp,udp,http ports, load-balancer access
			// dedicated access k8s
			// We should write a targets file and get a scrape point
			target := CollectProxyStats(ctx, &obj)
			require.NotEmpty(t, target)
			// CollectProxyStats should return empty when running on the same
			// object that we already have
			target = CollectProxyStats(ctx, &obj)
			require.Empty(t, target)
		case 2:
			// Same app, but different cloudlets - map entry is the same
			target := CollectProxyStats(ctx, &obj)
			require.Empty(t, target)
		case 5:
			// udp load-balancer
			// dedicated helm access
			target := CollectProxyStats(ctx, &obj)
			require.NotEmpty(t, target)
		case 8:
			// dedicated, no ports
			target := CollectProxyStats(ctx, &obj)
			require.Empty(t, target)
		case 11:
			// vm app behind lb
			target := CollectProxyStats(ctx, &obj)
			require.NotEmpty(t, target)
		}
		AppInstCache.Delete(ctx, &testutil.AppInstData[ii], 0)
	}
	// test an entry that has a failing platform client
	myPlatform = &shepherd_unittest.Platform{FailPlatformClient: true}
	appInst := testutil.AppInstData[0]
	// set mapped ports and state
	app := edgeproto.App{}
	found := AppCache.Get(&appInst.Key.AppKey, &app)
	if !found {
		require.Fail(t, "Could not find app for appinst")
	}
	ports, _ := edgeproto.ParseAppPorts(app.AccessPorts)
	appInst.MappedPorts = ports
	appInst.State = edgeproto.TrackedState_READY
	// scrape point should still be created
	target := CollectProxyStats(ctx, &appInst)
	require.NotEmpty(t, target)
	require.Nil(t, ProxyMap[target].Client)
	// Set myPlatform to return client now and create appInst again
	myPlatform = &shepherd_unittest.Platform{FailPlatformClient: false}
	// Create scrape point again
	target = CollectProxyStats(ctx, &appInst)
	require.NotEmpty(t, target)
	require.NotNil(t, ProxyMap[target].Client)
}
