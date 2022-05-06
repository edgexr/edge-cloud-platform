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
	"strings"
	"testing"
	"time"

	"github.com/edgexr/edge-cloud-infra/promutils"
	"github.com/edgexr/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/stretchr/testify/require"
)

var (
	testMetricSent = 0

	testPayloadData = map[string]string{
		promutils.PromQCpuClustUrlEncoded: `{
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
		promutils.PromQMemClustUrlEncoded: `{
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
		promutils.PromQDiskClustUrlEncoded: `{
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
		promutils.PromQSentBytesRateClustUrlEncoded: `{
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
		promutils.PromQRecvBytesRateClustUrlEncoded: `{
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

	testAlertsData = `
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

	expectedTestAlerts = []edgeproto.Alert{
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

	testDeveloperOrg = "testdeveloperorg"
	testCloudletKey  = edgeproto.CloudletKey{
		Organization: "testoper",
		Name:         "testcloudlet",
	}
	testClusterKey     = edgeproto.ClusterKey{Name: "testcluster"}
	testClusterInstKey = edgeproto.ClusterInstKey{
		ClusterKey:   testClusterKey,
		CloudletKey:  testCloudletKey,
		Organization: "MobiledgeX",
	}
	testClusterInst = edgeproto.ClusterInst{
		Key:        testClusterInstKey,
		Deployment: cloudcommon.DeploymentTypeKubernetes,
		Reservable: true,
		ReservedBy: testDeveloperOrg,
	}
	testPrometheusApp = edgeproto.App{
		Key: edgeproto.AppKey{
			Name:         cloudcommon.MEXPrometheusAppName,
			Version:      "1.0",
			Organization: cloudcommon.OrganizationMobiledgeX,
		},
		Deployment: cloudcommon.DeploymentTypeHelm,
	}
	testPrometheusAppInst = edgeproto.AppInst{
		Key: edgeproto.AppInstKey{
			AppKey: testPrometheusApp.Key,
			ClusterInstKey: edgeproto.VirtualClusterInstKey{
				CloudletKey: testClusterInstKey.CloudletKey,
			},
		},
	}
	testClusterInstUnsupported = edgeproto.ClusterInst{
		Key:        testClusterInstKey,
		Deployment: cloudcommon.DeploymentTypeHelm,
	}
	testAppKey = shepherd_common.MetricAppInstKey{
		ClusterInstKey: testClusterInstKey,
	}
)

func initAppInstTestData() {
	testPayloadData[promutils.PromQCpuPodUrlEncoded] = `{
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
	testPayloadData[promutils.PromQMemPodUrlEncoded] = `{
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
	testPayloadData[promutils.PromQDiskPodUrlEncoded] = `{
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
	testPayloadData[promutils.PromQNetSentRateUrlEncoded] = `{
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
	testPayloadData[promutils.PromQNetRecvRateUrlEncoded] = `{
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

func TestClusterWorkerTimers(t *testing.T) {
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())
	*platformName = "PLATFORM_TYPE_FAKEINFRA"
	testPlatform, _ := getPlatform()

	testClusterWorker, err := NewClusterWorker(ctx, "", 0, time.Second*1, time.Second*1,
		testMetricSend, &testClusterInst, nil, testPlatform)
	require.Nil(t, err)
	require.NotNil(t, testClusterWorker)
	require.True(t, testClusterWorker.checkAndSetLastPushMetrics(time.Now().Add(time.Second)))
	testClusterWorker.UpdateIntervals(ctx, 2*time.Minute, time.Minute)
	require.Equal(t, testClusterWorker.scrapeInterval, testClusterWorker.pushInterval)
	require.Equal(t, time.Minute, testClusterWorker.scrapeInterval)
	testClusterWorker.UpdateIntervals(ctx, 2*time.Second, time.Minute)
	require.NotEqual(t, testClusterWorker.scrapeInterval, testClusterWorker.pushInterval)
	require.Equal(t, 2*time.Second, testClusterWorker.scrapeInterval)
	require.Equal(t, time.Minute, testClusterWorker.pushInterval)
	// We push metric every pushInterval not scrapeInterval
	require.False(t, testClusterWorker.checkAndSetLastPushMetrics(time.Now().Add(testClusterWorker.scrapeInterval)))
	require.True(t, testClusterWorker.checkAndSetLastPushMetrics(time.Now().Add(testClusterWorker.pushInterval)))
}

// Tests are identical to the ones in TestClusterWorkerTimers
func TestProxyScraperTimers(t *testing.T) {
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	InitProxyScraper(time.Second, time.Second, nil)
	require.True(t, checkAndSetLastPushLbMetrics(time.Now().Add(time.Second)))
	updateProxyScraperIntervals(ctx, 2*time.Minute, time.Minute)
	require.Equal(t, rootLbScrapeInterval, rootLbMetricsPushInterval)
	require.Equal(t, time.Minute, rootLbScrapeInterval)
	updateProxyScraperIntervals(ctx, 2*time.Second, time.Minute)
	require.NotEqual(t, rootLbScrapeInterval, rootLbMetricsPushInterval)
	require.Equal(t, 2*time.Second, rootLbScrapeInterval)
	require.Equal(t, time.Minute, rootLbMetricsPushInterval)
	require.False(t, checkAndSetLastPushLbMetrics(time.Now().Add(rootLbScrapeInterval)))
	require.True(t, checkAndSetLastPushLbMetrics(time.Now().Add(rootLbMetricsPushInterval)))
}

func TestPromStats(t *testing.T) {
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())
	initAppInstTestData()

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
	testPromStats, err := NewClusterWorker(ctx, tsProm.URL[7:], 0, time.Second*1, time.Second*1, testMetricSend, &testClusterInstUnsupported, nil, testPlatform)
	require.NotNil(t, err, "Unsupported deployment type")
	require.Contains(t, err.Error(), "Unsupported deployment")
	kubeNames, err := k8smgmt.GetKubeNames(&testClusterInst, &testPrometheusApp, &testPrometheusAppInst)
	require.Nil(t, err, "Got kubeNames")
	testPromStats, err = NewClusterWorker(ctx, tsProm.URL[7:], 0, time.Second*1, time.Second*1, testMetricSend, &testClusterInst, kubeNames, testPlatform)
	require.Nil(t, err, "Get a platform client for fake cloudlet")
	clusterMetrics := testPromStats.clusterStat.GetClusterStats(ctx)
	appsMetrics := testPromStats.clusterStat.GetAppStats(ctx)
	alerts := testPromStats.clusterStat.GetAlerts(ctx)
	require.NotNil(t, clusterMetrics, "Fill stats from json")
	require.NotNil(t, appsMetrics, "Fill stats from json")
	require.NotNil(t, alerts, "Fill metrics from json")
	testAppKey.Pod = "testPod1"
	testAppKey.App = "testPod1"
	testAppKey.Version = "10"
	stat, found := appsMetrics[testAppKey]
	// Check PodStats
	require.True(t, found, "Pod testPod1 is not found")
	if found {
		require.Equal(t, float64(5.0), stat.Cpu)
		require.Equal(t, uint64(100000000), stat.Mem)
		require.Equal(t, uint64(300000000), stat.Disk)
	}
	// Check ClusterStats
	require.Equal(t, float64(10.01), clusterMetrics.Cpu)
	require.Equal(t, float64(99.99), clusterMetrics.Mem)
	require.Equal(t, float64(50.0), clusterMetrics.Disk)
	// Check Alerts - should not return pending alert
	require.Equal(t, len(expectedTestAlerts)-1, len(alerts))
	for ii := 0; ii < len(alerts); ii++ {
		expected := expectedTestAlerts[ii]
		alert := alerts[ii]
		require.Equal(t, expected.Labels, alert.Labels)
		require.Equal(t, expected.Annotations, alert.Annotations)
		require.Equal(t, expected.State, alert.State)
	}

	// Check callback is called
	require.Equal(t, int(0), testMetricSent)
	clusterMetricsData := testPromStats.MarshalClusterMetrics(clusterMetrics)
	testPromStats.send(ctx, clusterMetricsData[0])
	require.Equal(t, int(1), testMetricSent)
	// Test the autoprov cluster - marshalled clusterorg should be the same as apporg
	for _, metric := range clusterMetricsData {
		for _, tag := range metric.Tags {
			if tag.Name == "clusterorg" {
				require.Equal(t, testDeveloperOrg, tag.Val)
			}
		}
	}
	// Check null handling for Marshal functions
	require.Nil(t, testPromStats.MarshalClusterMetrics(nil), "Nil metrics should marshal into a nil")
	require.Nil(t, MarshalAppMetrics(&testAppKey, nil, ""), "Nil metrics should marshal into a nil")
}
