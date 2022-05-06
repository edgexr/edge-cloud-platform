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
	"testing"

	"github.com/edgexr/edge-cloud-infra/shepherd/shepherd_platform/shepherd_unittest"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/log"
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
cluster.backend4321.upstream_cx_length_ms: P0(nan,2) P25(nan,5.1) P50(nan,11) P75(nan,105) P90(nan,182) P95(nan,186) P99(nan,189.2) P99.5(nan,189.6) P99.9(nan,189.92) P100(nan,190)
cluster.udp_backend5678.upstream_cx_tx_bytes_total: 1
cluster.udp_backend5678.upstream_cx_rx_bytes_total: 2
cluster.udp_backend5678.udp.sess_tx_datagrams: 3
cluster.udp_backend5678.udp.sess_rx_datagrams: 4
cluster.udp_backend5678.udp.sess_tx_errors: 5
cluster.udp_backend5678.udp.sess_rx_errors: 6
cluster.udp_backend5678.upstream_cx_overflow: 7
cluster.udp_backend5678.upstream_cx_none_healthy: 8
cluster.udp_backend8765.upstream_cx_tx_bytes_total: 9
cluster.udp_backend8765.upstream_cx_rx_bytes_total: 10
cluster.udp_backend8765.udp.sess_tx_datagrams: 11
cluster.udp_backend8765.udp.sess_rx_datagrams: 12
cluster.udp_backend8765.udp.sess_tx_errors: 13
cluster.udp_backend8765.udp.sess_rx_errors: 14
cluster.udp_backend8765.upstream_cx_overflow: 15
cluster.udp_backend8765.upstream_cx_none_healthy: 16`

func setupLog() context.Context {
	log.InitTracer(nil)
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
		App:            "UnitTestApp",
		Cluster:        "UnitTestCluster",
		ClusterOrg:     "UnitTestDev",
		TcpPorts:       []int32{1234, 4321},
		UdpPorts:       []int32{5678, 8765},
		Client:         &shepherd_unittest.UTClient{},
		ListenEndpoint: cloudcommon.ProxyMetricsDefaultListenIP,
	}
	ctx := setupLog()
	fakeEnvoyTestServer := startServer()
	defer log.FinishTracer()
	defer fakeEnvoyTestServer.Close()

	testMetrics, err := QueryProxy(ctx, &testScrapePoint)

	assert.Nil(t, err, "Test Querying Envoy")
	assert.Equal(t, uint64(10), testMetrics.EnvoyTcpStats[1234].ActiveConn)
	assert.Equal(t, uint64(15), testMetrics.EnvoyTcpStats[1234].Accepts)
	assert.Equal(t, uint64(15), testMetrics.EnvoyTcpStats[1234].HandledConn)
	assert.Equal(t, uint64(16), testMetrics.EnvoyTcpStats[1234].BytesSent)
	assert.Equal(t, uint64(30), testMetrics.EnvoyTcpStats[1234].BytesRecvd)
	// "No recorded values" should default to all zeros
	for _, v := range testMetrics.EnvoyTcpStats[1234].SessionTime {
		assert.Equal(t, float64(0), v)
	}

	assert.Equal(t, uint64(7), testMetrics.EnvoyTcpStats[4321].ActiveConn)
	assert.Equal(t, uint64(10), testMetrics.EnvoyTcpStats[4321].Accepts)
	assert.Equal(t, uint64(9), testMetrics.EnvoyTcpStats[4321].HandledConn)
	assert.Equal(t, uint64(21), testMetrics.EnvoyTcpStats[4321].BytesSent)
	assert.Equal(t, uint64(28), testMetrics.EnvoyTcpStats[4321].BytesRecvd)
	assert.Equal(t, float64(2), testMetrics.EnvoyTcpStats[4321].SessionTime["P0"])
	assert.Equal(t, float64(5.1), testMetrics.EnvoyTcpStats[4321].SessionTime["P25"])
	assert.Equal(t, float64(11), testMetrics.EnvoyTcpStats[4321].SessionTime["P50"])
	assert.Equal(t, float64(105), testMetrics.EnvoyTcpStats[4321].SessionTime["P75"])
	assert.Equal(t, float64(182), testMetrics.EnvoyTcpStats[4321].SessionTime["P90"])
	assert.Equal(t, float64(186), testMetrics.EnvoyTcpStats[4321].SessionTime["P95"])
	assert.Equal(t, float64(189.2), testMetrics.EnvoyTcpStats[4321].SessionTime["P99"])
	assert.Equal(t, float64(189.6), testMetrics.EnvoyTcpStats[4321].SessionTime["P99.5"])
	assert.Equal(t, float64(189.92), testMetrics.EnvoyTcpStats[4321].SessionTime["P99.9"])
	assert.Equal(t, float64(190), testMetrics.EnvoyTcpStats[4321].SessionTime["P100"])

	assert.Equal(t, uint64(1), testMetrics.EnvoyUdpStats[5678].RecvBytes)
	assert.Equal(t, uint64(2), testMetrics.EnvoyUdpStats[5678].SentBytes)
	assert.Equal(t, uint64(3), testMetrics.EnvoyUdpStats[5678].RecvDatagrams)
	assert.Equal(t, uint64(4), testMetrics.EnvoyUdpStats[5678].SentDatagrams)
	assert.Equal(t, uint64(5), testMetrics.EnvoyUdpStats[5678].RecvErrs)
	assert.Equal(t, uint64(6), testMetrics.EnvoyUdpStats[5678].SentErrs)
	assert.Equal(t, uint64(7), testMetrics.EnvoyUdpStats[5678].Overflow)
	assert.Equal(t, uint64(8), testMetrics.EnvoyUdpStats[5678].Missed)
	assert.Equal(t, uint64(9), testMetrics.EnvoyUdpStats[8765].RecvBytes)
	assert.Equal(t, uint64(10), testMetrics.EnvoyUdpStats[8765].SentBytes)
	assert.Equal(t, uint64(11), testMetrics.EnvoyUdpStats[8765].RecvDatagrams)
	assert.Equal(t, uint64(12), testMetrics.EnvoyUdpStats[8765].SentDatagrams)
	assert.Equal(t, uint64(13), testMetrics.EnvoyUdpStats[8765].RecvErrs)
	assert.Equal(t, uint64(14), testMetrics.EnvoyUdpStats[8765].SentErrs)
	assert.Equal(t, uint64(15), testMetrics.EnvoyUdpStats[8765].Overflow)
	assert.Equal(t, uint64(16), testMetrics.EnvoyUdpStats[8765].Missed)
}
func envoyHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.String() == "/stats" {
		w.Write([]byte(testEnvoyData))
	}
}
