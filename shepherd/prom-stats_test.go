package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
}

var testAlertsData = `
{
  "status": "success",
  "data": {
    "alerts": [
      {
        "labels": {
          "alertname": "KubeControllerManagerDown",
          "severity": "critical"
        },
        "annotations": {
          "message": "KubeControllerManager has disappeared from Prometheus target discovery.",
          "runbook_url": "https://github.com/kubernetes-monitoring/kubernetes-mixin/tree/master/runbook.md#alert-name-kubecontrollermanagerdown"
        },
        "state": "firing",
        "activeAt": "2019-10-08T23:55:29.85577698Z",
        "value": 1
      },
      {
        "labels": {
          "alertname": "CPUThrottlingHigh",
          "container_name": "config-reloader",
          "namespace": "default",
          "pod": "alertmanager-mexprometheusappname-prome-alertmanager-0",
          "severity": "warning"
        },
        "annotations": {
          "message": "33% throttling of CPU in namespace default for container config-reloader in pod alertmanager-mexprometheusappname-prome-alertmanager-0.",
          "runbook_url": "https://github.com/kubernetes-monitoring/kubernetes-mixin/tree/master/runbook.md#alert-name-cputhrottlinghigh"
        },
        "state": "pending",
        "activeAt": "2019-10-09T17:24:49.472237771Z",
        "value": 33.333333333333336
      }
    ]
  }
}
`

var expectedTestAlerts = []edgeproto.Alert{
	edgeproto.Alert{
		Labels: map[string]string{
			"alertname": "KubeControllerManagerDown",
			"severity":  "critical",
		},
		Annotations: map[string]string{
			"message":     "KubeControllerManager has disappeared from Prometheus target discovery.",
			"runbook_url": "https://github.com/kubernetes-monitoring/kubernetes-mixin/tree/master/runbook.md#alert-name-kubecontrollermanagerdown",
		},
		State: "firing",
	},
	edgeproto.Alert{
		Labels: map[string]string{
			"alertname":      "CPUThrottlingHigh",
			"container_name": "config-reloader",
			"namespace":      "default",
			"pod":            "alertmanager-mexprometheusappname-prome-alertmanager-0",
			"severity":       "warning",
		},
		Annotations: map[string]string{
			"message":     "33% throttling of CPU in namespace default for container config-reloader in pod alertmanager-mexprometheusappname-prome-alertmanager-0.",
			"runbook_url": "https://github.com/kubernetes-monitoring/kubernetes-mixin/tree/master/runbook.md#alert-name-cputhrottlinghigh",
		},
		State: "pending",
	},
}

func initAppInstTestData() {
	q := fmt.Sprintf(promQAppDetailWrapperFmt, promQCpuPod)
	testPayloadData[q] = `{
		"status": "success",
		"data": {
		  "resultType": "vector",
		  "result": [
			{
			  "metric": {
                "pod": "testPod1",
                "label_mexAppName": "testPod1",
                "label_mexAppVersion": "10"
			  },
			  "value": [
				1549491454.802,
				"5.0"
			  ]
			}
			]
		  }
		  }`
	q = fmt.Sprintf(promQAppDetailWrapperFmt, promQMemPod)
	testPayloadData[q] = `{
		"status": "success",
		"data": {
  		"resultType": "vector",
  		"result": [
			{
	  		"metric": {
              "pod": "testPod1",
              "label_mexAppName": "testPod1",
              "label_mexAppVersion": "10"
	  	    },
	  		"value": [
				1549484450.932,
				"100000000"
	  		]
			}
  		]
		}
		}`
	q = fmt.Sprintf(promQAppDetailWrapperFmt, promQDiskPod)
	testPayloadData[q] = `{
		"status": "success",
		"data": {
		  "resultType": "vector",
		  "result": [
			{
			  "metric": {
				"pod": "testPod1",
				"label_mexAppName": "testPod1",
				"label_mexAppVersion": "10"
			},
			"value": [
				1549484450.932,
				"300000000"
			]
			}
		]
		}
		}`
	q = fmt.Sprintf(promQAppDetailWrapperFmt, promQNetSentRate)
	testPayloadData[q] = `{
		"status": "success",
		"data": {
  		"resultType": "vector",
  		"result": [
			{
	  		"metric": {
				"pod": "testPod1",
				"label_mexAppName": "testPod1",
				"label_mexAppVersion": "10"
	  		},
	  		"value": [
				1549484450.932,
				"111111"
	  		]
			}
  		]
		}
		}`
	q = fmt.Sprintf(promQAppDetailWrapperFmt, promQNetRecvRate)
	testPayloadData[q] = `{
		"status": "success",
		"data": {
  		"resultType": "vector",
  		"result": [
			{
	  		"metric": {
				"pod": "testPod1",
				"label_mexAppName": "testPod1",
				"label_mexAppVersion": "10"
	  		},
	  		"value": [
				1549484450.932,
				"222222"
	  		]
			}
  		]
		}
		}`
}

func testMetricSend(ctx context.Context, metric *edgeproto.Metric) bool {
	testMetricSent = 1
	return true
}

func TestPromStats(t *testing.T) {
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())
	initAppInstTestData()

	testDeveloperOrg := "testdeveloperorg"
	testCloudletKey := edgeproto.CloudletKey{
		Organization: "testoper",
		Name:         "testcloudlet",
	}
	testClusterKey := edgeproto.ClusterKey{Name: "testcluster"}
	testClusterInstKey := edgeproto.ClusterInstKey{
		ClusterKey:   testClusterKey,
		CloudletKey:  testCloudletKey,
		Organization: "MobiledgeX",
	}
	testClusterInst := edgeproto.ClusterInst{
		Key:        testClusterInstKey,
		Deployment: cloudcommon.DeploymentTypeKubernetes,
		Reservable: true,
		ReservedBy: testDeveloperOrg,
	}
	testClusterInstUnsupported := edgeproto.ClusterInst{
		Key:        testClusterInstKey,
		Deployment: cloudcommon.DeploymentTypeHelm,
	}
	testAppKey := shepherd_common.MetricAppInstKey{
		ClusterInstKey: testClusterInstKey,
	}

	*platformName = "PLATFORM_TYPE_FAKEINFRA"
	testPlatform, _ := getPlatform()

	// Skip this much of the URL
	metricsPrefix := "/api/v1/query?query="
	alertsPrefix := "/api/v1/alerts"
	skiplen := len(metricsPrefix)
	// start up http server to serve Prometheus metrics data
	tsProm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.String(), metricsPrefix) {
			w.Write([]byte(testPayloadData[r.URL.String()[skiplen:]]))
		} else if strings.HasPrefix(r.URL.String(), alertsPrefix) {
			w.Write([]byte(testAlertsData))
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("bad URL request"))
		}
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
	alerts := testPromStats.clusterStat.GetAlerts(ctx)
	assert.NotNil(t, clusterMetrics, "Fill stats from json")
	assert.NotNil(t, appsMetrics, "Fill stats from json")
	assert.NotNil(t, alerts, "Fill metrics from json")
	testAppKey.Pod = "testPod1"
	testAppKey.App = "testPod1"
	testAppKey.Version = "10"
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
	// Check Alerts - should not return pending alert
	require.Equal(t, len(expectedTestAlerts)-1, len(alerts))
	for ii := 0; ii < len(alerts); ii++ {
		expected := expectedTestAlerts[ii]
		alert := alerts[ii]
		assert.Equal(t, expected.Labels, alert.Labels)
		assert.Equal(t, expected.Annotations, alert.Annotations)
		assert.Equal(t, expected.State, alert.State)
	}

	// Check callback is called
	assert.Equal(t, int(0), testMetricSent)
	clusterMetricsData := testPromStats.MarshalClusterMetrics(clusterMetrics)
	testPromStats.send(ctx, clusterMetricsData[0])
	assert.Equal(t, int(1), testMetricSent)
	// Test the autoprov cluster - marshalled clusterorg should be the same as apporg
	for _, metric := range clusterMetricsData {
		for _, tag := range metric.Tags {
			if tag.Name == "clusterorg" {
				assert.Equal(t, testDeveloperOrg, tag.Val)
			}
		}
	}
	// Check null handling for Marshal functions
	assert.Nil(t, testPromStats.MarshalClusterMetrics(nil), "Nil metrics should marshal into a nil")
	assert.Nil(t, MarshalAppMetrics(&testAppKey, nil), "Nil metrics should marshal into a nil")
}
