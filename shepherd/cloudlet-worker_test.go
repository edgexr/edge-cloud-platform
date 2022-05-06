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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gogo/protobuf/types"
	"github.com/edgexr/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/edgexr/edge-cloud-infra/shepherd/shepherd_platform/shepherd_unittest"
	"github.com/edgexr/edge-cloud-infra/shepherd/shepherd_test"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/edgexr/edge-cloud/cloudcommon"
	dme "github.com/edgexr/edge-cloud/d-match-engine/dme-proto"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/stretchr/testify/assert"
)

// Example output of resource-tracker
var testCloudletData = shepherd_common.CloudletMetrics{
	VCpuMax:         10,
	VCpuUsed:        5,
	MemMax:          500000,
	MemUsed:         1234,
	DiskMax:         400000,
	DiskUsed:        10000,
	FloatingIpsMax:  20,
	FloatingIpsUsed: 11,
	NetRecv:         123456,
	NetSent:         654321,
	Ipv4Max:         100,
	Ipv4Used:        50,
}

// Failing two alerts
var failAlerts = `{
	"status": "success",
	"data": {
	  "alerts": [
		{
		  "labels": {
			"alertname": "` + cloudcommon.AlertAppInstDown + `",
			"` + edgeproto.AppKeyTagName + `": "` + shepherd_test.TestApp.Key.Name + `",
			"` + edgeproto.AppKeyTagOrganization + `": "` + shepherd_test.TestApp.Key.Organization + `",
			"` + edgeproto.AppKeyTagVersion + `": "` + shepherd_test.TestApp.Key.Version + `",
			"` + edgeproto.CloudletKeyTagName + `": "` + shepherd_test.TestCloudletKey.Name + `",
			"` + edgeproto.CloudletKeyTagOrganization + `": "` + shepherd_test.TestCloudletKey.Organization + `",
			"` + edgeproto.ClusterKeyTagName + `": "` + shepherd_test.TestClusterKey.Name + `",
			"` + edgeproto.ClusterInstKeyTagOrganization + `": "` + shepherd_test.TestClusterInstKey.Organization + `",
			"` + cloudcommon.AlertHealthCheckStatus + `": "` + strconv.Itoa(int(dme.HealthCheck_HEALTH_CHECK_ROOTLB_OFFLINE)) + `",
			"instance": "host.docker.internal:9091",
			"job": "envoy_targets"
		  },
		  "state": "firing",
		  "activeAt": "2020-05-24T17:42:08.399557679Z",
		  "value": "0e+00"
		},
		{
		  "labels": {
			"alertname": "` + cloudcommon.AlertAppInstDown + `",
			"` + edgeproto.AppKeyTagName + `": "` + shepherd_test.TestApp.Key.Name + `",
			"` + edgeproto.AppKeyTagOrganization + `": "` + shepherd_test.TestApp.Key.Organization + `",
			"` + edgeproto.AppKeyTagVersion + `": "` + shepherd_test.TestApp.Key.Version + `",
			"` + edgeproto.CloudletKeyTagName + `": "` + shepherd_test.TestCloudletKey.Name + `",
			"` + edgeproto.CloudletKeyTagOrganization + `": "` + shepherd_test.TestCloudletKey.Organization + `",
			"` + edgeproto.ClusterKeyTagName + `": "` + shepherd_test.TestClusterKey.Name + `",
			"` + edgeproto.ClusterInstKeyTagOrganization + `": "` + shepherd_test.TestClusterInstKey.Organization + `",
			"` + cloudcommon.AlertHealthCheckStatus + `": "` + strconv.Itoa(int(dme.HealthCheck_HEALTH_CHECK_SERVER_FAIL)) + `",
			"envoy_cluster_name": "backend7777",
			"instance": "host.docker.internal:9091",
			"job": "envoy_targets"
		  },
		  "state": "firing",
		  "activeAt": "2020-05-24T17:42:53.399557679Z",
		  "value": "0e+00"
		}
	  ]
	}
}`

var noAlerts = `{
	"status": "success",
	"data": {
	  "alerts": []
	}
}`

// Start with everything healthy
var currentAlerts = noAlerts

func startAlertServer() *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(alertHandler))
	CloudletPrometheusAddr = strings.TrimPrefix(server.URL, "http://")
	return server
}

func alertHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.String() == "/api/v1/alerts" {
		w.Write([]byte(currentAlerts))
	}
}

func TestCloudletAlerts(t *testing.T) {
	ctx := setupLog()
	defer log.FinishTracer()
	fakePrometheusAlertServer := startAlertServer()
	defer fakePrometheusAlertServer.Close()

	edgeproto.InitClusterInstCache(&ClusterInstCache)
	ClusterInstCache.Update(ctx, &shepherd_test.TestClusterInst, 0)
	edgeproto.InitAppCache(&AppCache)
	AppCache.Update(ctx, &shepherd_test.TestApp, 0)

	edgeproto.InitAppInstCache(&AppInstCache)
	AppInstCache.Update(ctx, &shepherd_test.TestAppInst, 0)
	edgeproto.InitAlertCache(&AlertCache)
	myPlatform = &shepherd_unittest.Platform{}
	settings = *edgeproto.GetDefaultSettings()

	currentAlerts = noAlerts
	alerts, err := getPromAlerts(ctx, CloudletPrometheusAddr, &pc.LocalClient{})
	assert.Nil(t, err)
	assert.Equal(t, 0, len(alerts))
	UpdateAlerts(ctx, alerts, nil, pruneCloudletForeignAlerts)
	//should be no alerts
	assert.Equal(t, 0, len(AlertCache.Objs))

	// emulate alerts from shepherd
	currentAlerts = failAlerts
	alerts, err = getPromAlerts(ctx, CloudletPrometheusAddr, &pc.LocalClient{})
	assert.Nil(t, err)
	assert.Equal(t, 2, len(alerts))
	UpdateAlerts(ctx, alerts, nil, pruneCloudletForeignAlerts)
	//should be no alerts
	assert.Equal(t, 2, len(AlertCache.Objs))
	// check each alert and make sure it has correct data
	for _, alert := range AlertCache.Objs {
		assert.Equal(t, cloudcommon.AlertAppInstDown, alert.Obj.Labels["alertname"])
		assert.Equal(t, shepherd_test.TestApp.Key.Name, alert.Obj.Labels[edgeproto.AppKeyTagName])
		assert.Equal(t, shepherd_test.TestApp.Key.Organization, alert.Obj.Labels[edgeproto.AppKeyTagOrganization])
		assert.Equal(t, shepherd_test.TestApp.Key.Version, alert.Obj.Labels[edgeproto.AppKeyTagVersion])
		assert.Equal(t, shepherd_test.TestCloudletKey.Name, alert.Obj.Labels[edgeproto.CloudletKeyTagName])
		assert.Equal(t, shepherd_test.TestCloudletKey.Organization, alert.Obj.Labels[edgeproto.CloudletKeyTagOrganization])
		assert.Equal(t, shepherd_test.TestClusterKey.Name, alert.Obj.Labels[edgeproto.ClusterKeyTagName])
		assert.Equal(t, shepherd_test.TestClusterInstKey.Organization, alert.Obj.Labels[edgeproto.ClusterInstKeyTagOrganization])
		// make sure the alert status is not OK, or UNKNOWN
		assert.NotEqual(t, strconv.Itoa(int(dme.HealthCheck_HEALTH_CHECK_OK)), alert.Obj.Labels[cloudcommon.AlertHealthCheckStatus])
		assert.NotEqual(t, strconv.Itoa(int(dme.HealthCheck_HEALTH_CHECK_UNKNOWN)), alert.Obj.Labels[cloudcommon.AlertHealthCheckStatus])
	}
}

func TestCloudletStats(t *testing.T) {
	var err error
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	cloudletKey = edgeproto.CloudletKey{
		Organization: "testoperator",
		Name:         "testcloudlet",
	}

	// Test null handling
	assert.Nil(t, MarshalCloudletMetrics(nil))
	testCloudletData.CollectTime, err = types.TimestampProto(time.Now())
	assert.Nil(t, err, "Couldn't get current timestamp")
	buf, err := json.Marshal(testCloudletData)
	assert.Nil(t, err, "marshal cloudlet metrics")
	myPlatform = &shepherd_unittest.Platform{
		CloudletMetrics: string(buf),
	}

	cloudletStats, err := myPlatform.GetPlatformStats(ctx)
	assert.Nil(t, err, "Get cloudlet stats")
	metrics := MarshalCloudletMetrics(&cloudletStats)
	// Should be two measurements
	assert.Equal(t, 3, len(metrics))
	// Verify the names
	assert.Equal(t, "cloudlet-utilization", metrics[0].Name)
	assert.Equal(t, "cloudlet-network", metrics[1].Name)
	assert.Equal(t, "cloudlet-ipusage", metrics[2].Name)
	// Verify metric tags
	for _, m := range metrics {
		for _, v := range m.Tags {
			if v.Name == "operator" {
				assert.Equal(t, cloudletKey.Organization, v.Val)
			}
			if v.Name == "cloudlet" {
				assert.Equal(t, cloudletKey.Name, v.Val)
			}
		}
	}
	// Verify metric values
	for _, v := range metrics[0].Vals {
		if v.Name == "vCpuUsed" {
			assert.Equal(t, testCloudletData.VCpuUsed, v.GetIval())
		} else if v.Name == "vCpuMax" {
			assert.Equal(t, testCloudletData.VCpuMax, v.GetIval())
		} else if v.Name == "memUsed" {
			assert.Equal(t, testCloudletData.MemUsed, v.GetIval())
		} else if v.Name == "memMax" {
			assert.Equal(t, testCloudletData.MemMax, v.GetIval())
		} else if v.Name == "diskUsed" {
			assert.Equal(t, testCloudletData.DiskUsed, v.GetIval())
		} else if v.Name == "diskMax" {
			assert.Equal(t, testCloudletData.DiskMax, v.GetIval())
		} else {
			errstr := fmt.Sprintf("Unexpected value in a metric(%v) - %s", v, v.Name)
			assert.FailNow(t, errstr)
		}
	}
	for _, v := range metrics[1].Vals {
		if v.Name == "netSent" {
			assert.Equal(t, testCloudletData.NetSent, v.GetIval())
		} else if v.Name == "netRecv" {
			assert.Equal(t, testCloudletData.NetRecv, v.GetIval())
		} else {
			errstr := fmt.Sprintf("Unexpected value in a metric(%v) - %s", v, v.Name)
			assert.FailNow(t, errstr)
		}
	}
	for _, v := range metrics[2].Vals {
		if v.Name == "ipv4Max" {
			assert.Equal(t, testCloudletData.Ipv4Max, v.GetIval())
		} else if v.Name == "ipv4Used" {
			assert.Equal(t, testCloudletData.Ipv4Used, v.GetIval())
		} else if v.Name == "floatingIpsMax" {
			assert.Equal(t, testCloudletData.FloatingIpsMax, v.GetIval())
		} else if v.Name == "floatingIpsUsed" {
			assert.Equal(t, testCloudletData.FloatingIpsUsed, v.GetIval())
		} else {
			errstr := fmt.Sprintf("Unexpected value in a metric(%v) - %s", v, v.Name)
			assert.FailNow(t, errstr)
		}
	}

}
