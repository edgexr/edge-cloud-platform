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
	"testing"
	"time"

	"github.com/edgexr/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/edgexr/edge-cloud-infra/shepherd/shepherd_platform/shepherd_unittest"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/stretchr/testify/assert"
)

var testVmAppData = shepherd_common.AppMetrics{
	Cpu:  11.11,
	Mem:  1212,
	Disk: 1313,
}

func TestVmStats(t *testing.T) {
	var err error
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	testOperatorOrg := "testoper"
	testCloudletKey := edgeproto.CloudletKey{
		Organization: testOperatorOrg,
		Name:         "testcloudlet",
	}
	testClusterInstKey := edgeproto.ClusterInstKey{
		ClusterKey: edgeproto.ClusterKey{
			Name: "",
		},
		CloudletKey:  testCloudletKey,
		Organization: "",
	}
	testAppInstVm := edgeproto.AppInst{
		Key: edgeproto.AppInstKey{
			AppKey: edgeproto.AppKey{
				Name: "TestVM",
			},
			ClusterInstKey: *testClusterInstKey.Virtual(""),
		},
	}

	buf, err := json.Marshal(testVmAppData)
	assert.Nil(t, err, "marshal VM metrics")
	pf := shepherd_unittest.Platform{
		VmAppInstMetrics: string(buf),
	}
	edgeproto.InitAppInstCache(&AppInstCache)
	worker := NewAppInstWorker(ctx, time.Second*1, nil, &testAppInstVm, &pf)
	assert.NotNil(t, worker, "Get worker for unit test Vm")
	appsMetrics, err := worker.pf.GetVmStats(ctx, &testAppInstVm.Key)

	assert.Nil(t, err, "Fill stats from json")
	if err == nil {
		assert.Equal(t, float64(11.11), appsMetrics.Cpu)
		assert.Equal(t, uint64(1212), appsMetrics.Mem)
		assert.Equal(t, uint64(1313), appsMetrics.Disk)
		assert.NotNil(t, appsMetrics.CpuTS, "CPU timestamp")
	}
}
