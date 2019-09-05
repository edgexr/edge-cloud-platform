package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/stretchr/testify/assert"
)

var testMetricSent = 0

var testPayloadData = map[string]string{
	promQCpuClust: `{
		"status": "success",
		"data": {
		  "resultType": "vector",
		  "result": [
			{
			  "metric": {},
			  "value": [
				1549491286.389,
				"10.01"
			  ]
			}
		  ]
		}
	  }`,
	promQMemClust: `{
		"status": "success",
		"data": {
		  "resultType": "vector",
		  "result": [
			{
			  "metric": {},
			  "value": [
				1549491347.686,
				"99.99"
			  ]
			}
		  ]
		}
	  }`,
	promQDiskClust: `{
		"status": "success",
		"data": {
		  "resultType": "vector",
		  "result": [
			{
			  "metric": {},
			  "value": [
				1549491384.455,
				"50.0"
			  ]
			}
		  ]
		}
	  }`,
	promQSentBytesRateClust: `{
		"status": "success",
		"data": {
		  "resultType": "vector",
		  "result": [
			{
			  "metric": {},
			  "value": [
				1549491412.872,
				"11111"
			  ]
			}
		  ]
		}
	  }`,
	promQRecvBytesRateClust: `{
		"status": "success",
		"data": {
		  "resultType": "vector",
		  "result": [
			{
			  "metric": {},
			  "value": [
				1549491412.872,
				"22222"
			  ]
			}
		  ]
		}
	  }`,

	promQCpuPod: `{
		"status": "success",
		"data": {
		  "resultType": "vector",
		  "result": [
			{
			  "metric": {
				"pod_name": "testPod1"
			  },
			  "value": [
				1549491454.802,
				"5.0"
			  ]
			}
			]
		  }
		  }`,
	promQMemPod: `{
		"status": "success",
		"data": {
  		"resultType": "vector",
  		"result": [
			{
	  		"metric": {
				"pod_name": "testPod1"
	  		},
	  		"value": [
				1549484450.932,
				"100000000"
	  		]
			}
  		]
		}
		}`,
	promQDiskPod: `{
		"status": "success",
		"data": {
		  "resultType": "vector",
		  "result": [
			{
			  "metric": {
				"pod_name": "testPod1"
			},
			"value": [
				1549484450.932,
				"300000000"
			]
			}
		]
		}
		}`,
	promQNetSentRate: `{
		"status": "success",
		"data": {
  		"resultType": "vector",
  		"result": [
			{
	  		"metric": {
				"pod_name": "testPod1"
	  		},
	  		"value": [
				1549484450.932,
				"111111"
	  		]
			}
  		]
		}
		}`,
	promQNetRecvRate: `{
		"status": "success",
		"data": {
  		"resultType": "vector",
  		"result": [
			{
	  		"metric": {
				"pod_name": "testPod1"
	  		},
	  		"value": [
				1549484450.932,
				"222222"
	  		]
			}
  		]
		}
		}`,
}

func testMetricSend(ctx context.Context, metric *edgeproto.Metric) bool {
	testMetricSent = 1
	return true
}

func TestPromStats(t *testing.T) {
	log.InitTracer("")
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	testAppKey := shepherd_common.MetricAppInstKey{
		ClusterInstKey: edgeproto.ClusterInstKey{
			ClusterKey: edgeproto.ClusterKey{
				Name: "testcluster",
			},
			CloudletKey: edgeproto.CloudletKey{
				OperatorKey: edgeproto.OperatorKey{
					Name: "testoper",
				},
				Name: "testcloudlet",
			},
			Developer: "",
		},
	}

	testOperatorKey := edgeproto.OperatorKey{Name: "testoper"}
	testCloudletKey := edgeproto.CloudletKey{
		OperatorKey: testOperatorKey,
		Name:        "testcloudlet",
	}
	testClusterKey := edgeproto.ClusterKey{Name: "testcluster"}
	testClusterInstKey := edgeproto.ClusterInstKey{
		ClusterKey:  testClusterKey,
		CloudletKey: testCloudletKey,
		Developer:   "",
	}
	testClusterInst := edgeproto.ClusterInst{
		Key:        testClusterInstKey,
		Deployment: cloudcommon.AppDeploymentTypeKubernetes,
	}
	testClusterInstUnsupported := edgeproto.ClusterInst{
		Key:        testClusterInstKey,
		Deployment: cloudcommon.AppDeploymentTypeHelm,
	}

	*platformName = "PLATFORM_TYPE_FAKE"
	testPlatform, _ := getPlatform()

	// Skip this much of the URL
	skiplen := len("/api/v1/query?query=")
	// start up http server to serve Prometheus metrics data
	tsProm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(testPayloadData[r.URL.String()[skiplen:]]))
	}))
	defer tsProm.Close()
	// Remove the leading "http://"
	testPromStats, err := NewClusterWorker(ctx, tsProm.URL[7:], time.Second*1, testMetricSend, &testClusterInstUnsupported, testPlatform)
	assert.NotNil(t, err, "Unsupported deployment type")
	assert.Contains(t, err.Error(), "Unsupported deployment")
	testPromStats, err = NewClusterWorker(ctx, tsProm.URL[7:], time.Second*1, testMetricSend, &testClusterInst, testPlatform)
	assert.Nil(t, err, "Get a platform client for fake cloudlet")
	clusterMetrics := testPromStats.clusterStat.GetClusterStats(ctx)
	appsMetrics := testPromStats.clusterStat.GetAppStats(ctx)
	assert.NotNil(t, clusterMetrics, "Fill stats from json")
	assert.NotNil(t, appsMetrics, "Fill stats from json")
	testAppKey.Pod = "testPod1"
	stat, found := appsMetrics[testAppKey]
	// Check PodStats
	assert.True(t, found, "Pod testPod1 is not found")
	if found {
		assert.Equal(t, float64(5.0), stat.Cpu)
		assert.Equal(t, uint64(100000000), stat.Mem)
		assert.Equal(t, uint64(300000000), stat.Disk)
		assert.Equal(t, uint64(111111), stat.NetSent)
		assert.Equal(t, uint64(222222), stat.NetRecv)
	}
	// Check ClusterStats
	assert.Equal(t, float64(10.01), clusterMetrics.Cpu)
	assert.Equal(t, float64(99.99), clusterMetrics.Mem)
	assert.Equal(t, float64(50.0), clusterMetrics.Disk)
	assert.Equal(t, uint64(11111), clusterMetrics.NetSent)
	assert.Equal(t, uint64(22222), clusterMetrics.NetRecv)

	// Check callback is called
	assert.Equal(t, int(0), testMetricSent)
	testPromStats.send(ctx, MarshalClusterMetrics(clusterMetrics, testPromStats.clusterInstKey)[0])
	assert.Equal(t, int(1), testMetricSent)
}
