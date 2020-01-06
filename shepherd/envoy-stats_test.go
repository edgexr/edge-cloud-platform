package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_platform/shepherd_unittest"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	dme "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/stretchr/testify/assert"
)

// Health check vars
var (
	testEnvoyHealthCheckGood       = `backend1234::10.192.1.2:1234::health_flags::healthy`
	testEnvoyHealthCheckBad        = `backend1234::10.192.1.2:1234::health_flags::/failed_active_hc`
	testEnvoy2PortsHealthCheckGood = `
backend1234::10.192.1.2:1234::health_flags::healthy
backend4321::10.192.1.2:4321::health_flags::healthy`
	testEnvoy2PortsHealthCheck1Bad = `
backend1234::10.192.1.2:1234::health_flags::healthy
backend4321::10.192.1.2:4321::health_flags::/failed_active_hc`

	// Current state
	testEnvoyHealthCheckCurrent = testEnvoyHealthCheckGood

	// Test App/Cluster state data
	testOperatorKey = edgeproto.OperatorKey{Name: "testoper"}
	testCloudletKey = edgeproto.CloudletKey{
		OperatorKey: testOperatorKey,
		Name:        "testcloudlet",
	}
	testClusterKey     = edgeproto.ClusterKey{Name: "testcluster"}
	testClusterInstKey = edgeproto.ClusterInstKey{
		ClusterKey:  testClusterKey,
		CloudletKey: testCloudletKey,
		Developer:   "",
	}
	testClusterInst = edgeproto.ClusterInst{
		Key:        testClusterInstKey,
		Deployment: cloudcommon.AppDeploymentTypeDocker,
	}
	testAppKey = edgeproto.AppKey{
		Name: "App",
	}
	testApp = edgeproto.App{
		Key:         testAppKey,
		AccessPorts: "tcp:1234",
	}
	testAppInstKey = edgeproto.AppInstKey{
		AppKey:         testAppKey,
		ClusterInstKey: testClusterInstKey,
	}
	testAppInst = edgeproto.AppInst{
		Key:         testAppInstKey,
		State:       edgeproto.TrackedState_READY,
		HealthCheck: edgeproto.HealthCheck_HEALTH_CHECK_OK,
		MappedPorts: []dme.AppPort{
			dme.AppPort{
				Proto:      dme.LProto_L_PROTO_TCP,
				PublicPort: 1234,
			},
		},
	}
)

var testEnvoyData = `cluster.backend1234.upstream_cx_active: 10
cluster.backend1234.upstream_cx_total: 15
cluster.backend1234.upstream_cx_connect_fail: 0
cluster.backend4321.upstream_cx_active: 7
cluster.backend4321.upstream_cx_total: 10
cluster.backend4321.upstream_cx_connect_fail: 1`

func setupLog() context.Context {
	log.InitTracer("")
	ctx := log.StartTestSpan(context.Background())
	return ctx
}
func startServer() *httptest.Server {
	fakeEnvoyTestServer := httptest.NewServer(http.HandlerFunc(envoyHandler))
	envoyUnitTestPort, _ := strconv.ParseInt(strings.Split(fakeEnvoyTestServer.URL, ":")[2], 10, 32)
	cloudcommon.ProxyMetricsPort = int32(envoyUnitTestPort)
	return fakeEnvoyTestServer
}

func TestEnvoyStats(t *testing.T) {

	testScrapePoint := ProxyScrapePoint{
		App:     "UnitTestApp",
		Cluster: "UnitTestCluster",
		Dev:     "UnitTestDev",
		Ports:   []int32{1234, 4321},
		Client:  &shepherd_unittest.UTClient{},
	}
	ctx := setupLog()
	fakeEnvoyTestServer := startServer()
	defer log.FinishTracer()
	defer fakeEnvoyTestServer.Close()

	testMetrics, err := QueryProxy(ctx, &testScrapePoint)

	assert.Nil(t, err, "Test Querying Envoy")
	assert.Equal(t, uint64(10), testMetrics.EnvoyStats[1234].ActiveConn)
	assert.Equal(t, uint64(15), testMetrics.EnvoyStats[1234].Accepts)
	assert.Equal(t, uint64(15), testMetrics.EnvoyStats[1234].HandledConn)
	// These three below are not implemented yet but coming soon, leave at 0 for now
	assert.Equal(t, uint64(0), testMetrics.EnvoyStats[1234].AvgSessionTime)
	assert.Equal(t, uint64(0), testMetrics.EnvoyStats[1234].AvgBytesSent)
	assert.Equal(t, uint64(0), testMetrics.EnvoyStats[1234].AvgBytesRecvd)

	assert.Equal(t, uint64(7), testMetrics.EnvoyStats[4321].ActiveConn)
	assert.Equal(t, uint64(10), testMetrics.EnvoyStats[4321].Accepts)
	assert.Equal(t, uint64(9), testMetrics.EnvoyStats[4321].HandledConn)
	assert.Equal(t, uint64(0), testMetrics.EnvoyStats[4321].AvgSessionTime)
	assert.Equal(t, uint64(0), testMetrics.EnvoyStats[4321].AvgBytesSent)
	assert.Equal(t, uint64(0), testMetrics.EnvoyStats[4321].AvgBytesRecvd)
}

// Tests a healthy and reachable app
func testHealthCheckOK(t *testing.T, ctx context.Context) {
	scrapePoints := copyMapValues()
	// Should only be a single point
	assert.Equal(t, 1, len(scrapePoints))
	_, err := QueryProxy(ctx, &scrapePoints[0])
	assert.Nil(t, err)
	// failure count should be 0
	scrapePoint := ProxyMap[getProxyKey(&testAppInstKey)]
	assert.Equal(t, 0, scrapePoint.FailedChecksCount)
	// AlertCache Should not have the appInst as a key
	alert := getAlertFromAppInst(&testAppInstKey)
	assert.False(t, AlertCache.HasKey(alert.GetKey()))
}

// Test retry count and failure case
func testHealthCheckFail(t *testing.T, ctx context.Context, healthCheck edgeproto.HealthCheck, retires int) {
	// run ShepherdHealthCheckRetries - 1 times
	for i := 1; i < retires; i++ {
		scrapePoints := copyMapValues()
		// Should only be a single point
		assert.Equal(t, 1, len(scrapePoints))
		QueryProxy(ctx, &scrapePoints[0])
		// failure count should be i
		scrapePoint := ProxyMap[getProxyKey(&testAppInstKey)]
		assert.Equal(t, i, scrapePoint.FailedChecksCount)
		// AlertCache Still Should not have the appInst as a key
		alert := getAlertFromAppInst(&testAppInstKey)
		assert.False(t, AlertCache.HasKey(alert.GetKey()))
	}
	// Trigger alert now
	scrapePoints := copyMapValues()
	_, err := QueryProxy(ctx, &scrapePoints[0])
	// Check that for RootLb failure QueryProxy returns an error
	if healthCheck == edgeproto.HealthCheck_HEALTH_CHECK_FAIL_ROOTLB_OFFLINE {
		assert.NotNil(t, err)
	}
	// failure count should be reset to 0 now
	scrapePoint := ProxyMap[getProxyKey(&testAppInstKey)]
	assert.Equal(t, 0, scrapePoint.FailedChecksCount)
	// AlertCache Should have the alert now
	alert := getAlertFromAppInst(&testAppInstKey)
	found := AlertCache.Get(alert.GetKey(), alert)
	assert.True(t, found)
	val, found := alert.Annotations[cloudcommon.AlertHealthCheckStatus]
	assert.True(t, found)
	assert.Equal(t, strconv.Itoa(int(healthCheck)), val)
}

func TestHealthChecks(t *testing.T) {
	ctx := setupLog()
	defer log.FinishTracer()

	edgeproto.InitClusterInstCache(&ClusterInstCache)
	ClusterInstCache.Update(ctx, &testClusterInst, 0)
	edgeproto.InitAppCache(&AppCache)
	AppCache.Update(ctx, &testApp, 0)

	edgeproto.InitAppInstCache(&AppInstCache)
	AppInstCache.Update(ctx, &testAppInst, 0)
	edgeproto.InitAlertCache(&AlertCache)
	myPlatform = &shepherd_unittest.Platform{}

	InitProxyScraper()
	// Add appInst to proxyMap
	CollectProxyStats(ctx, &testAppInst)

	fakeEnvoyTestServer := startServer()
	defer fakeEnvoyTestServer.Close()

	testHealthCheckOK(t, ctx)

	// RootLB health check failure
	fakeEnvoyTestServer.Close()
	testHealthCheckFail(t, ctx, edgeproto.HealthCheck_HEALTH_CHECK_FAIL_ROOTLB_OFFLINE, cloudcommon.ShepherdHealthCheckRetries)
	// Emulate controller setting appInst health check state
	testAppInst.HealthCheck = edgeproto.HealthCheck_HEALTH_CHECK_FAIL_ROOTLB_OFFLINE
	AppInstCache.Update(ctx, &testAppInst, 0)
	// restart server and check that we are passing health check
	fakeEnvoyTestServer = startServer()
	testHealthCheckOK(t, ctx)
	// Emulate controller setting appInst health check state
	testAppInst.HealthCheck = edgeproto.HealthCheck_HEALTH_CHECK_OK
	AppInstCache.Update(ctx, &testAppInst, 0)

	// Test envoy health check functionality now
	testEnvoyHealthCheckCurrent = testEnvoyHealthCheckBad
	testHealthCheckFail(t, ctx, edgeproto.HealthCheck_HEALTH_CHECK_FAIL_SERVER_FAIL, 1)
	// Emulate controller setting appInst health check state
	testAppInst.HealthCheck = edgeproto.HealthCheck_HEALTH_CHECK_FAIL_SERVER_FAIL
	AppInstCache.Update(ctx, &testAppInst, 0)
	// set the Envoy response sting to a good one and check that we are passing health check
	testEnvoyHealthCheckCurrent = testEnvoyHealthCheckGood
	testHealthCheckOK(t, ctx)
	// Emulate controller setting appInst health check state
	testAppInst.HealthCheck = edgeproto.HealthCheck_HEALTH_CHECK_OK
	AppInstCache.Update(ctx, &testAppInst, 0)

	// Test two ports in an app with a single one failing
	// Delete and re-createe the appInst
	testAppInst.State = edgeproto.TrackedState_DELETING
	CollectProxyStats(ctx, &testAppInst)
	AppInstCache.Delete(ctx, &testAppInst, 0)
	testAppInst.MappedPorts = append(testAppInst.MappedPorts, dme.AppPort{
		Proto:      dme.LProto_L_PROTO_TCP,
		PublicPort: 4321,
	})
	testAppInst.State = edgeproto.TrackedState_READY
	AppInstCache.Update(ctx, &testAppInst, 0)
	// Add back into the scrapePoints
	CollectProxyStats(ctx, &testAppInst)
	testEnvoyHealthCheckCurrent = testEnvoy2PortsHealthCheckGood
	testHealthCheckOK(t, ctx)
	// set one port to fail and see that the whole app goes into health check fail state
	testEnvoyHealthCheckCurrent = testEnvoy2PortsHealthCheck1Bad
	testHealthCheckFail(t, ctx, edgeproto.HealthCheck_HEALTH_CHECK_FAIL_SERVER_FAIL, 1)
	// Emulate controller setting appInst health check state
	testAppInst.HealthCheck = edgeproto.HealthCheck_HEALTH_CHECK_FAIL_SERVER_FAIL
	AppInstCache.Update(ctx, &testAppInst, 0)
	// set the Envoy response sting to a good one and check that we are passing health check
	testEnvoyHealthCheckCurrent = testEnvoy2PortsHealthCheckGood
	testHealthCheckOK(t, ctx)
	// Emulate controller setting appInst health check state
	testAppInst.HealthCheck = edgeproto.HealthCheck_HEALTH_CHECK_OK
	AppInstCache.Update(ctx, &testAppInst, 0)

}

func envoyHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.String() == "/stats" {
		w.Write([]byte(testEnvoyData))
	}
	// For health checking
	if r.URL.String() == "/clusters" {
		w.Write([]byte(testEnvoyHealthCheckCurrent))
	}
}
