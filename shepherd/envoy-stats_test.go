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
cluster.backend1234.upstream_cx_tx_bytes_total: 16
cluster.backend1234.upstream_cx_rx_bytes_total: 30
cluster.backend1234.upstream_cx_length_ms: No recorded values
cluster.backend4321.upstream_cx_active: 7
cluster.backend4321.upstream_cx_total: 10
cluster.backend4321.upstream_cx_connect_fail: 1
cluster.backend4321.upstream_cx_tx_bytes_total: 21
cluster.backend4321.upstream_cx_rx_bytes_total: 28
cluster.backend4321.upstream_cx_length_ms: P0(nan,2) P25(nan,5.1) P50(nan,11) P75(nan,105) P90(nan,182) P95(nan,186) P99(nan,189.2) P99.5(nan,189.6) P99.9(nan,189.92) P100(nan,190)`

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
		App:        "UnitTestApp",
		Cluster:    "UnitTestCluster",
		ClusterOrg: "UnitTestDev",
		Ports:      []int32{1234, 4321},
		Client:     &shepherd_unittest.UTClient{},
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
	assert.Equal(t, uint64(16), testMetrics.EnvoyStats[1234].BytesSent)
	assert.Equal(t, uint64(30), testMetrics.EnvoyStats[1234].BytesRecvd)
	// "No recorded values" should default to all zeros
	for _, v := range testMetrics.EnvoyStats[1234].SessionTime {
		assert.Equal(t, float64(0), v)
	}

	assert.Equal(t, uint64(7), testMetrics.EnvoyStats[4321].ActiveConn)
	assert.Equal(t, uint64(10), testMetrics.EnvoyStats[4321].Accepts)
	assert.Equal(t, uint64(9), testMetrics.EnvoyStats[4321].HandledConn)
	assert.Equal(t, uint64(21), testMetrics.EnvoyStats[4321].BytesSent)
	assert.Equal(t, uint64(28), testMetrics.EnvoyStats[4321].BytesRecvd)
	assert.Equal(t, float64(2), testMetrics.EnvoyStats[4321].SessionTime["P0"])
	assert.Equal(t, float64(5.1), testMetrics.EnvoyStats[4321].SessionTime["P25"])
	assert.Equal(t, float64(11), testMetrics.EnvoyStats[4321].SessionTime["P50"])
	assert.Equal(t, float64(105), testMetrics.EnvoyStats[4321].SessionTime["P75"])
	assert.Equal(t, float64(182), testMetrics.EnvoyStats[4321].SessionTime["P90"])
	assert.Equal(t, float64(186), testMetrics.EnvoyStats[4321].SessionTime["P95"])
	assert.Equal(t, float64(189.2), testMetrics.EnvoyStats[4321].SessionTime["P99"])
	assert.Equal(t, float64(189.6), testMetrics.EnvoyStats[4321].SessionTime["P99.5"])
	assert.Equal(t, float64(189.92), testMetrics.EnvoyStats[4321].SessionTime["P99.9"])
	assert.Equal(t, float64(190), testMetrics.EnvoyStats[4321].SessionTime["P100"])
}
func envoyHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.String() == "/stats" {
		w.Write([]byte(testEnvoyData))
	}
}
