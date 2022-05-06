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
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/edgexr/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/edgexr/edge-cloud-infra/shepherd/shepherd_platform/shepherd_unittest"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/stretchr/testify/assert"
)

// Sample output of formatted 'docker stats' cmd
// Output is a single container with no app associated with it
// and two containers associated with app testAppInstDocker2
var testDockerResults = []string{`{
	"container": "DockerApp1",
	"id": "1",
	"memory": {
	  "raw": "11.11MiB / 1.111GiB",
	  "percent": "1.11%"
	},
	"cpu": "1.11%",
	"io": {
	  "network": "111B / 1KB",
	  "block": "1B / 1B"
	}
  }`, `{
	"container": "DockerApp2Container1",
	"id": "2",
	"memory": {
	  "raw": "21.21MiB / 2.1GiB",
	  "percent": "2.1%"
	},
	"cpu": "4.2%",
	"io": {
	  "network": "21B / 21KB",
	  "block": "21B / 21B"
	}
  }`, `{
	"container": "DockerApp2Container2",
	"id":"3",
	"memory": {
	  "raw": "22.22MiB / 2.2GiB",
	  "percent": "2.2%"
	},
	"cpu": "4.4%",
	"io": {
	  "network": "22B / 22KB",
	  "block": "2B / 2B"
	}
  }`}

var testDataEmpty = ``
var testInvalidStr = `this string is invalid`
var testNetDataInvalidRecv = `  ens3: 448842invalid077 3084030    0    0    0     0          0         0 514882026 2675536    0    0    0     0       0          0`
var testNetDataInvalidSend = `  ens3: 448842077 3084030    0    0    0     0          0         0 5148invalid82026 2675536    0    0    0     0       0          0`
var testNetData = `  ens3: 448842077 3084030    0    0    0     0          0         0 514882026 2675536    0    0    0     0       0          0`

var testDiskInvalidData = "0B (virtual invalid)"
var testDiskData = "0B (virtual 55.5MB)"

var testMultiContainerDiskData = `{"container":"DockerApp1","id":"1","disk":"0B (virtual 1KB)","labels":"cluster=testcluster,mexAppName=dockerapp1,mexAppVersion=10"}
{"container":"DockerApp2Container1","id":"2","disk":"0B (virtual 2.0MB)","labels":"cluster=testcluster,mexAppName=dockerapp2,mexAppVersion=10"}
{"container":"DockerApp2Container2","id":"3","disk":"0B (virtual 3GB)","labels":"cluster=testcluster,mexAppName=dockerapp2,mexAppVersion=10"}`

// Example output of resource-tracker
var testDockerClusterData = shepherd_common.ClusterMetrics{
	Cpu:        10.10101010,
	Mem:        11.111111,
	Disk:       12.12121212,
	TcpConns:   1515,
	TcpRetrans: 16,
	UdpSent:    1717,
	UdpRecv:    1818,
	UdpRecvErr: 19,
}

func TestDockerStats(t *testing.T) {
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	testAppKey := shepherd_common.MetricAppInstKey{
		ClusterInstKey: edgeproto.ClusterInstKey{
			ClusterKey: edgeproto.ClusterKey{
				Name: "testcluster",
			},
			CloudletKey: edgeproto.CloudletKey{
				Organization: "testoperator",
				Name:         "testcloudlet",
			},
			Organization: "",
		},
	}

	testOperator := "testoperator"
	testCloudletKey := edgeproto.CloudletKey{
		Organization: testOperator,
		Name:         "testcloudlet",
	}
	testClusterKey := edgeproto.ClusterKey{Name: "testcluster"}
	testClusterInstKey := edgeproto.ClusterInstKey{
		ClusterKey:   testClusterKey,
		CloudletKey:  testCloudletKey,
		Organization: "",
	}
	testClusterInst := edgeproto.ClusterInst{
		Key:        testClusterInstKey,
		Deployment: cloudcommon.DeploymentTypeDocker,
	}
	testFlavorKey1 := edgeproto.FlavorKey{Name: "testFlavor1"}
	testFlavor1 := edgeproto.Flavor{
		Key:   testFlavorKey1,
		Vcpus: 2,
	}
	testAppInstDocker2 := edgeproto.AppInst{
		Key: edgeproto.AppInstKey{
			AppKey: edgeproto.AppKey{
				Name:    "DockerApp2",
				Version: "10",
			},
			ClusterInstKey: *testClusterInstKey.Virtual(""),
		},
		RuntimeInfo: edgeproto.AppInstRuntime{
			ContainerIds: []string{"DockerApp2Container1", "DockerApp2Container2"},
		},
		Flavor: testFlavorKey1,
	}

	// Remove all the empty space from docker test data, as that's how it gets returned by docker stats
	for i, s := range testDockerResults {
		testDockerResults[i] = regexp.MustCompile(`[\t\r\n]+`).ReplaceAllString(strings.TrimSpace(s), "")
	}
	tmpStr := strings.Join(testDockerResults, "\n")
	buf, err := json.Marshal(testDockerClusterData)
	assert.Nil(t, err, "marshal cluster metrics")
	platform := shepherd_unittest.Platform{
		DockerAppMetrics:     tmpStr,
		DockerClusterMetrics: string(buf),
		DockerContainerPid:   "0",
		CatContainerNetData:  testNetData,
		DockerPsSizeData:     testMultiContainerDiskData,
		Ncpus:                fmt.Sprintf("%d\n", testFlavor1.Vcpus),
	}
	edgeproto.InitAppInstCache(&AppInstCache)
	edgeproto.InitFlavorCache(&FlavorCache)
	FlavorCache.Update(ctx, &testFlavor1, 0)
	AppInstCache.Update(ctx, &testAppInstDocker2, 0)
	testDockerStats, err := NewClusterWorker(ctx, "", 0, time.Second*1, time.Second*1, nil, &testClusterInst, nil, &platform)
	assert.Nil(t, err, "Get a patform client for unit test cloudlet")
	clusterMetrics := testDockerStats.clusterStat.GetClusterStats(ctx)
	appsMetrics := testDockerStats.clusterStat.GetAppStats(ctx)
	assert.NotNil(t, clusterMetrics, "Fill stats from json")
	assert.NotNil(t, appsMetrics, "Fill stats from json")
	testAppKey.Pod = k8smgmt.NormalizeName("DockerApp1")
	testAppKey.App = k8smgmt.NormalizeName("DockerApp1")
	testAppKey.Version = k8smgmt.NormalizeName("10")
	stat, found := appsMetrics[testAppKey]
	// Check PodStats
	assert.True(t, found, "Container DockerApp1 is not found")
	if found {
		//divide these cpu numbers by 2 since the flavor has 2 cpus
		assert.Equal(t, float64(1.11/2), stat.Cpu)
		assert.Equal(t, uint64(11649679), stat.Mem)
		assert.Equal(t, uint64(1*1024), stat.Disk)
		assert.NotNil(t, stat.CpuTS, "CPU timestamp")
	}
	testAppKey.Pod = k8smgmt.NormalizeName("DockerApp2")
	testAppKey.App = k8smgmt.NormalizeName("DockerApp2")
	testAppKey.Version = k8smgmt.NormalizeName("10")
	stat, found = appsMetrics[testAppKey]
	// Check PodStats - should be a sum of DockerApp2Container1 and DockerApp2Container2
	assert.True(t, found, "Container DockerApp2 is not found")
	if found {
		//divide these cpu numbers by 2 since the flavor has 2 cpus
		assert.Equal(t, float64(2.1)+float64(2.2), stat.Cpu)
		assert.Equal(t, uint64(22240296+23299358), stat.Mem)
		assert.Equal(t, uint64(2*1024*1024+3*1024*1024*1024), stat.Disk)
		assert.NotNil(t, stat.CpuTS, "CPU timestamp")
	}

	// Check ClusterStats
	assert.Equal(t, testDockerClusterData.Cpu, clusterMetrics.Cpu)
	assert.NotNil(t, clusterMetrics.CpuTS, "CPU timestamp for cluster")
	assert.Equal(t, testDockerClusterData.Mem, clusterMetrics.Mem)
	assert.Equal(t, testDockerClusterData.Disk, clusterMetrics.Disk)
	assert.Equal(t, testDockerClusterData.TcpConns, clusterMetrics.TcpConns)
	assert.Equal(t, testDockerClusterData.TcpRetrans, clusterMetrics.TcpRetrans)
	assert.Equal(t, testDockerClusterData.UdpSent, clusterMetrics.UdpSent)
	assert.Equal(t, testDockerClusterData.UdpRecv, clusterMetrics.UdpRecv)
	assert.Equal(t, testDockerClusterData.UdpRecvErr, clusterMetrics.UdpRecvErr)
}

func TestParseNetData(t *testing.T) {
	data, err := parseNetData(testDataEmpty)
	assert.NotNil(t, err)
	assert.Nil(t, data)
	data, err = parseNetData(testInvalidStr)
	assert.NotNil(t, err)
	assert.Nil(t, data)
	data, err = parseNetData(testNetDataInvalidSend)
	assert.NotNil(t, err)
	assert.Nil(t, data)
	data, err = parseNetData(testNetDataInvalidRecv)
	assert.NotNil(t, err)
	assert.Nil(t, data)
	data, err = parseNetData(testNetData)
	assert.Nil(t, err)
	assert.NotNil(t, data)
	assert.Equal(t, uint64(448842077), data[0])
	assert.Equal(t, uint64(514882026), data[1])
}

func TestDiskData(t *testing.T) {
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	data, err := parseContainerDiskUsage(ctx, testDataEmpty)
	assert.NotNil(t, err)
	assert.Equal(t, uint64(0), data)
	data, err = parseContainerDiskUsage(ctx, testInvalidStr)
	assert.NotNil(t, err)
	assert.Equal(t, uint64(0), data)
	data, err = parseContainerDiskUsage(ctx, testNetDataInvalidSend)
	assert.NotNil(t, err)
	assert.Equal(t, uint64(0), data)
	data, err = parseContainerDiskUsage(ctx, testDiskData)
	assert.Nil(t, err)
	assert.Equal(t, uint64(55.5*1024*1024), data)
}
