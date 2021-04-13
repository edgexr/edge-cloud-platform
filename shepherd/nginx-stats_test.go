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

var testNginxData = "Active connections: 10\nserver accepts handled requests\n 101 202 303\nReading: 5 Writing: 4 Waiting: 3"

func TestNginxStats(t *testing.T) {
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	testScrapePoint := ProxyScrapePoint{
		App:        "UnitTestApp",
		Cluster:    "UnitTestCluster",
		ClusterOrg: "UnitTestDev",
		Client:     &shepherd_unittest.UTClient{},
		ListenIP:   cloudcommon.ProxyMetricsDefaultListenIP,
	}

	fakeNginxTestServer := httptest.NewServer(http.HandlerFunc(nginxHandler))
	defer fakeNginxTestServer.Close()

	nginxUnitTestPort, _ := strconv.ParseInt(strings.Split(fakeNginxTestServer.URL, ":")[2], 10, 32)
	cloudcommon.ProxyMetricsPort = int32(nginxUnitTestPort)

	testMetrics, err := QueryNginx(ctx, &testScrapePoint)

	assert.Nil(t, err, "Test Querying Nginx")
	assert.Equal(t, uint64(10), testMetrics.ActiveConn)
	assert.Equal(t, uint64(101), testMetrics.Accepts)
	assert.Equal(t, uint64(202), testMetrics.HandledConn)
	assert.Equal(t, uint64(303), testMetrics.Requests)
	assert.Equal(t, uint64(5), testMetrics.Reading)
	assert.Equal(t, uint64(4), testMetrics.Writing)
	assert.Equal(t, uint64(3), testMetrics.Waiting)
}

func nginxHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.String() == "/nginx_metrics" {
		w.Write([]byte(testNginxData))
	}
}
