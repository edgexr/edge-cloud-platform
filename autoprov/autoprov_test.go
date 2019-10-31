package main

import (
	"context"
	"flag"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/notify"
	"github.com/mobiledgex/edge-cloud/testutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestAutoProv(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelNotify | log.DebugLevelApi)
	log.InitTracer("")
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())
	flag.Parse() // set defaults

	*ctrlAddr = "127.0.0.1:9998"
	*notifyAddrs = "127.0.0.1:9999"

	// dummy server to recv api calls
	dc := grpc.NewServer(
		grpc.UnaryInterceptor(testutil.UnaryInterceptor),
		grpc.StreamInterceptor(testutil.StreamInterceptor),
	)
	lis, err := net.Listen("tcp", *ctrlAddr)
	require.Nil(t, err)
	ds := testutil.RegisterDummyServer(dc)
	go func() {
		dc.Serve(lis)
	}()
	defer dc.Stop()

	// dummy notify to inject alerts
	dn := notify.NewDummyHandler()
	serverMgr := notify.ServerMgr{}
	dn.RegisterServer(&serverMgr)
	serverMgr.Start(*notifyAddrs, "")
	defer serverMgr.Stop()

	start()
	defer stop()

	// initial state of ClusterInst
	cinst := testutil.ClusterInstData[2]
	numnodes := int(testutil.ClusterInstData[2].NumNodes)
	ds.ClusterInstCache.Update(ctx, &cinst, 0)

	// alert labels for ClusterInst
	keys := make(map[string]string)
	keys[cloudcommon.AlertLabelDev] = cinst.Key.Developer
	keys[cloudcommon.AlertLabelOperator] = cinst.Key.CloudletKey.OperatorKey.Name
	keys[cloudcommon.AlertLabelCloudlet] = cinst.Key.CloudletKey.Name
	keys[cloudcommon.AlertLabelCluster] = cinst.Key.ClusterKey.Name

	// scale up alert
	scaleup := edgeproto.Alert{}
	scaleup.Labels = make(map[string]string)
	scaleup.Annotations = make(map[string]string)
	scaleup.Labels["alertname"] = cloudcommon.AlertAutoScaleUp
	scaleup.State = "firing"
	for k, v := range keys {
		scaleup.Labels[k] = v
	}
	scaleup.Annotations[cloudcommon.AlertKeyNodeCount] = strconv.Itoa(numnodes)
	dn.AlertCache.Update(ctx, &scaleup, 0)
	requireClusterInstNumNodes(t, &ds.ClusterInstCache, &cinst.Key, numnodes+1)
	dn.AlertCache.Delete(ctx, &scaleup, 0)

	// scale down alert
	scaledown := edgeproto.Alert{}
	scaledown.Labels = make(map[string]string)
	scaledown.Annotations = make(map[string]string)
	scaledown.Labels["alertname"] = cloudcommon.AlertAutoScaleDown
	scaledown.Annotations[cloudcommon.AlertKeyLowCpuNodeCount] = "1"
	scaledown.Annotations[cloudcommon.AlertKeyMinNodes] = "1"
	scaledown.State = "firing"
	for k, v := range keys {
		scaledown.Labels[k] = v
	}
	scaledown.Annotations[cloudcommon.AlertKeyNodeCount] = strconv.Itoa(numnodes + 1)
	scaledown.Annotations[cloudcommon.AlertKeyLowCpuNodeCount] = "2"
	dn.AlertCache.Update(ctx, &scaledown, 0)
	requireClusterInstNumNodes(t, &ds.ClusterInstCache, &cinst.Key, numnodes-1)
	dn.AlertCache.Delete(ctx, &scaledown, 0)
}

func requireClusterInstNumNodes(t *testing.T, cache *edgeproto.ClusterInstCache, key *edgeproto.ClusterInstKey, numnodes int) {
	checkCount := -1
	for ii := 0; ii < 10; ii++ {
		cinst := edgeproto.ClusterInst{}
		if !cache.Get(key, &cinst) {
			require.True(t, false, "cluster inst should have been found, %v", key)
		}
		checkCount = int(cinst.NumNodes)
		if checkCount != numnodes {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		break
	}
	require.Equal(t, numnodes, checkCount, "ClusterInst NumNodes count mismatch")
}
