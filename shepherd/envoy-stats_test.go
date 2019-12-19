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
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/stretchr/testify/assert"
)

var testEnvoyData = `cluster.backend1234.upstream_cx_active: 10
cluster.backend1234.upstream_cx_total: 15
cluster.backend1234.upstream_cx_connect_fail: 0
cluster.backend4321.upstream_cx_active: 7
cluster.backend4321.upstream_cx_total: 10
cluster.backend4321.upstream_cx_connect_fail: 1`

func TestEnvoyStats(t *testing.T) {
	log.InitTracer("")
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	testScrapePoint := ProxyScrapePoint{
		App:     "UnitTestApp",
		Cluster: "UnitTestCluster",
		Dev:     "UnitTestDev",
		Ports:   []int32{1234, 4321},
		Client:  &shepherd_unittest.UTClient{},
	}

	fakeEnvoyTestServer := httptest.NewServer(http.HandlerFunc(envoyHandler))
	defer fakeEnvoyTestServer.Close()

	envoyUnitTestPort, _ := strconv.ParseInt(strings.Split(fakeEnvoyTestServer.URL, ":")[2], 10, 32)
	cloudcommon.ProxyMetricsPort = int32(envoyUnitTestPort)

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

func envoyHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.String() == "/stats" {
		w.Write([]byte(testEnvoyData))
	}
}
