// Copyright 2022 MobiledgeX, Inc
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

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/edgexr/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/edgexr/edge-cloud-infra/shepherd/shepherd_platform/shepherd_unittest"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/testutil"
	"github.com/stretchr/testify/require"
)

var testEnvoyProxyData = `cluster.backend443.upstream_cx_active: 10
cluster.backend443.upstream_cx_total: 15
cluster.backend443.upstream_cx_connect_fail: 0
cluster.backend443.upstream_cx_tx_bytes_total: 1000
cluster.backend443.upstream_cx_rx_bytes_total: 100
cluster.backend443.upstream_cx_length_ms: No recorded values
cluster.backend10002.upstream_cx_active: 7
cluster.backend10002.upstream_cx_total: 10
cluster.backend10002.upstream_cx_connect_fail: 1
cluster.backend10002.upstream_cx_tx_bytes_total: 2000
cluster.backend10002.upstream_cx_rx_bytes_total: 200
cluster.backend10002.upstream_cx_length_ms: P0(nan,2) P25(nan,5.1) P50(nan,11) P75(nan,105) P90(nan,182) P95(nan,186) P99(nan,189.2) P99.5(nan,189.6) P99.9(nan,189.92) P100(nan,190)
cluster.udp_backend10002.upstream_cx_tx_bytes_total: 100
cluster.udp_backend10002.upstream_cx_rx_bytes_total: 50
cluster.udp_backend10002.udp.sess_tx_datagrams: 3
cluster.udp_backend10002.udp.sess_rx_datagrams: 4
cluster.udp_backend10002.udp.sess_tx_errors: 5
cluster.udp_backend10002.udp.sess_rx_errors: 6
cluster.udp_backend10002.upstream_cx_overflow: 7
cluster.udp_backend10002.upstream_cx_none_healthy: 8
cluster.backend80.upstream_cx_active: 10
cluster.backend80.upstream_cx_total: 15
cluster.backend80.upstream_cx_connect_fail: 0
cluster.backend80.upstream_cx_tx_bytes_total: 3000
cluster.backend80.upstream_cx_rx_bytes_total: 300
cluster.backend80.upstream_cx_length_ms: No recorded values
cluster.backend65535.upstream_cx_active: 7
cluster.backend65535.upstream_cx_total: 10
cluster.backend65535.upstream_cx_connect_fail: 1
cluster.backend65535.upstream_cx_tx_bytes_total: 4000
cluster.backend65535.upstream_cx_rx_bytes_total: 400
cluster.backend65535.upstream_cx_length_ms: P0(nan,2) P25(nan,5.1) P50(nan,11) P75(nan,105) P90(nan,182) P95(nan,186) P99(nan,189.2) P99.5(nan,189.6) P99.9(nan,189.92) P100(nan,190)
cluster.udp_backend8001.upstream_cx_tx_bytes_total: 1
cluster.udp_backend8001.upstream_cx_rx_bytes_total: 2
cluster.udp_backend8001.udp.sess_tx_datagrams: 200
cluster.udp_backend8001.udp.sess_rx_datagrams: 60
cluster.udp_backend8001.udp.sess_tx_errors: 5
cluster.udp_backend8001.udp.sess_rx_errors: 6
cluster.udp_backend8001.upstream_cx_overflow: 7
cluster.udp_backend8001.upstream_cx_none_healthy: 8`

// Test the types of appInstances that will create a scrapePoint
func TestCollectProxyStats(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelMetrics)
	ctx := setupLog()
	defer log.FinishTracer()
	myPlatform = &shepherd_unittest.Platform{}
	db := testProxyMetricsdb{}
	db.Init()
	InitProxyScraper(time.Second, time.Second, db.Update)
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
	for ii, obj := range testutil.CreatedAppInstData() {
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

	// Add a second appinst to the same cluster to test cluster net stats
	appInst = testutil.AppInstData[7]
	// set mapped ports and state
	app = edgeproto.App{}
	found = AppCache.Get(&appInst.Key.AppKey, &app)
	if !found {
		require.Fail(t, "Could not find app for appinst")
	}
	ports, _ = edgeproto.ParseAppPorts(app.AccessPorts)
	appInst.MappedPorts = ports
	appInst.State = edgeproto.TrackedState_READY
	// scrape point should still be created
	target = CollectProxyStats(ctx, &appInst)
	require.NotEmpty(t, target)
	require.NotNil(t, ProxyMap[target].Client)

	// test ProxyScraper
	testProxyScraper(ctx, &db, t)
}

// Test ProxyScraper thread
func testProxyScraper(ctx context.Context, db *testProxyMetricsdb, t *testing.T) {
	// start a handler for envoy stats requests
	testEnvoyStatsEndpointServer := httptest.NewServer(http.HandlerFunc(envoyProxyHandler))
	envoyUnitTestPort, _ := strconv.ParseInt(strings.Split(testEnvoyStatsEndpointServer.URL, ":")[2], 10, 32)
	cloudcommon.ProxyMetricsPort = int32(envoyUnitTestPort)

	defer testEnvoyStatsEndpointServer.Close()

	// enable scraping
	shepherd_common.ShepherdPlatformActive = true
	StartProxyScraper(db.done)
	// Wait for some stats to be collected
	db.WaitForClusterMetrics(ctx)
	// Verify collected stats
	require.Equal(t, 2, len(db.appStats))
	for k, v := range db.appStats {
		if k.AppKey == testutil.AppInstData[7].Key.AppKey {
			require.Equal(t, 3050, v.NetSent)
			require.Equal(t, 400, v.NetRecv)
		} else if k.AppKey == testutil.AppInstData[0].Key.AppKey {
			require.Equal(t, 7002, v.NetSent)
			require.Equal(t, 701, v.NetRecv)
		}
	}
	require.Equal(t, 1, len(db.clusterStats))
	stat, found := db.clusterStats[testutil.ClusterInstData[0].Key]
	require.True(t, found)
	require.Equal(t, uint64(1101), stat.NetRecv)
	require.Equal(t, uint64(10052), stat.NetSent)
}

func envoyProxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.String() == "/stats" {
		w.Write([]byte(testEnvoyProxyData))
	}
}

type testProxyMetricsdb struct {
	appStats     map[edgeproto.AppInstKey]shepherd_common.ClusterNetMetrics
	clusterStats map[edgeproto.ClusterInstKey]shepherd_common.ClusterNetMetrics
	mux          sync.Mutex
	done         chan bool
}

func (n *testProxyMetricsdb) Init() {
	n.appStats = make(map[edgeproto.AppInstKey]shepherd_common.ClusterNetMetrics)
	n.clusterStats = make(map[edgeproto.ClusterInstKey]shepherd_common.ClusterNetMetrics)
	n.done = make(chan bool, 1)
}

func (n *testProxyMetricsdb) Update(ctx context.Context, metric *edgeproto.Metric) bool {
	n.mux.Lock()
	if metric.Name == "appinst-network" {
		key, stat := ProxyAppInstNetMeticToStat(metric)
		if key != nil {
			n.appStats[*key] = *stat
		}
	} else if metric.Name == "cluster-network" {
		key, stat := ProxyClusterNetMeticToStat(metric)
		if key != nil && stat != nil {
			n.clusterStats[*key] = *stat
			// got cluster stats - just wait for a first net stats
			close(n.done)
		}
	}
	// ignore other metrics
	n.mux.Unlock()
	return true
}

func (n *testProxyMetricsdb) WaitForClusterMetrics(ctx context.Context) {
	select {
	case <-time.After(20 * time.Second):
		log.DebugLog(log.DebugLevelInfo, "Timeout while waiting for metrics")
	case <-n.done:
		log.DebugLog(log.DebugLevelInfo, "Got cluster metrics")
	}
}
