package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_platform/shepherd_unittest"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/stretchr/testify/assert"
)

var testVmAppData = shepherd_common.AppMetrics{
	Cpu:     11.11,
	Mem:     1212,
	Disk:    1313,
	NetSent: 1414,
	NetRecv: 1515,
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
	worker, err := NewAppInstWorker(ctx, time.Second*1, nil, &testAppInstVm, &pf)
	assert.Nil(t, err, "Get worker for unit test Vm")
	appsMetrics, err := worker.pf.GetVmStats(ctx, &testAppInstVm.Key)

	assert.Nil(t, err, "Fill stats from json")
	if err == nil {
		assert.Equal(t, float64(11.11), appsMetrics.Cpu)
		assert.Equal(t, uint64(1212), appsMetrics.Mem)
		assert.Equal(t, uint64(1313), appsMetrics.Disk)
		assert.Equal(t, uint64(1414), appsMetrics.NetSent)
		assert.Equal(t, uint64(1515), appsMetrics.NetRecv)
		assert.NotNil(t, appsMetrics.CpuTS, "CPU timestamp")
	}
}
