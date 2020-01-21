package main

import (
	"context"
	"encoding/json"
	"flag"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	influxdb "github.com/influxdata/influxdb/client/v2"
	"github.com/influxdata/influxdb/models"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/notify"
	"github.com/mobiledgex/edge-cloud/testutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestAutoProv(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelNotify | log.DebugLevelApi | log.DebugLevelMetrics)
	log.InitTracer("")
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())
	flag.Parse() // set defaults

	*ctrlAddr = "127.0.0.1:9998"
	*notifyAddrs = "127.0.0.1:9999"
	// httpmock doesn't work for influx client because it
	// doesn't use the default transport, so use httptest instead
	influxServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer influxServer.Close()
	*influxAddr = influxServer.URL

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

	// dummy notify to inject alerts and other objects from controller
	dn := notify.NewDummyHandler()
	serverMgr := notify.ServerMgr{}
	dn.RegisterServer(&serverMgr)
	serverMgr.Start(*notifyAddrs, "")
	defer serverMgr.Stop()

	start()
	defer stop()

	testAutoScale(t, ctx, ds, dn)
	testAutoProv(t, ctx, ds, dn, influxServer)
}

func testAutoScale(t *testing.T, ctx context.Context, ds *testutil.DummyServer, dn *notify.DummyHandler) {
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
	ds.ClusterInstCache.Delete(ctx, &cinst, 0)
	require.Equal(t, 0, len(frClusterInsts.InstsByCloudlet))
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

func testAutoProv(t *testing.T, ctx context.Context, ds *testutil.DummyServer, dn *notify.DummyHandler, influxServer *httptest.Server) {
	require.NotNil(t, autoProvAggr)
	// we will run iterations manually so set interval to large number
	autoProvAggr.UpdateSettings(ctx, 300, 0)

	// add reservable ClusterInst
	rcinst := testutil.ClusterInstData[7]
	dn.ClusterInstCache.Update(ctx, &rcinst, 0)
	cloudletKey := rcinst.Key.CloudletKey
	// add policy
	policy := testutil.AutoProvPolicyData[0]
	policy.Cloudlets = []*edgeproto.AutoProvCloudlet{
		&edgeproto.AutoProvCloudlet{
			Key: rcinst.Key.CloudletKey,
		},
	}
	dn.AutoProvPolicyCache.Update(ctx, &policy, 0)
	// add app that uses above policy
	app := testutil.AppData[11]
	dn.AppCache.Update(ctx, &app, 0)

	notify.WaitFor(&appHandler.cache, 1)
	notify.WaitFor(&autoProvPolicyHandler.cache, 1)

	// check stats exist for app, check cached policy values
	appStats, found := autoProvAggr.allStats[app.Key]
	require.True(t, found)
	require.Equal(t, policy.DeployClientCount, appStats.deployClientCount)
	require.Equal(t, policy.DeployIntervalCount, appStats.deployIntervalCount)
	// allow for testing non-trigger condition
	require.True(t, policy.DeployClientCount > 1)

	// define influxdb response
	// this will return the "count" each time it is called, for
	// the target app + cloudlet, in the form of an influxdb measurement.
	count := uint64(0)
	influxServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		row := models.Row{
			Name: "auto-prov-counts",
			Columns: []string{
				"time",
				"app",
				"cloudlet",
				"count",
				"dev",
				"oper",
				"ver",
			},
			Values: [][]interface{}{
				[]interface{}{
					time.Now().Format(time.RFC3339),
					app.Key.Name,
					cloudletKey.Name,
					count,
					app.Key.DeveloperKey.Name,
					cloudletKey.OperatorKey.Name,
					app.Key.Version,
				},
			},
		}
		res := influxdb.Result{
			Series: []models.Row{row},
		}
		dbresp := influxdb.Response{
			Results: []influxdb.Result{res},
		}
		w.Header().Set("X-Influxdb-Version", "1.0")
		w.Header().Set("Content-Type", "application/json")
		data, err := json.Marshal(dbresp)
		require.Nil(t, err)
		w.Write(data)
	})

	// expected AppInst key
	appInst := edgeproto.AppInst{
		Key: edgeproto.AppInstKey{
			AppKey:         app.Key,
			ClusterInstKey: rcinst.Key,
		},
	}

	// init first iter
	err := autoProvAggr.runIter(ctx, true)
	require.Nil(t, err)

	// non-trigger condition
	for ii := uint32(0); ii < policy.DeployIntervalCount; ii++ {
		count += uint64(1)
		err := autoProvAggr.runIter(ctx, false)
		require.Nil(t, err)
		cstats, found := appStats.cloudlets[cloudletKey]
		require.True(t, found)
		require.Equal(t, uint32(0), cstats.deployIntervalsMet)
	}

	// iterate to satisfy policy
	for ii := uint32(0); ii < policy.DeployIntervalCount; ii++ {
		count += uint64(policy.DeployClientCount)
		err := autoProvAggr.runIter(ctx, false)
		require.Nil(t, err)
	}

	cstats, found := appStats.cloudlets[cloudletKey]
	require.True(t, found, "found cloudlet stats")
	require.Equal(t, count, cstats.count)

	// check that auto-prov AppInst was created
	notify.WaitFor(&ds.AppInstCache, 1)
	found = ds.AppInstCache.Get(&appInst.Key, &edgeproto.AppInst{})
	require.True(t, found, "found auto-provisioned AppInst")

	// manually delete AppInst (auto-unprovision not supported yet)
	ds.AppInstCache.Delete(ctx, &appInst, 0)

	// update policy
	policy.DeployClientCount *= 2
	policy.DeployIntervalCount *= 2
	dn.AutoProvPolicyCache.Update(ctx, &policy, 0)
	// wait for changes to take effect
	for ii := 0; ii < 10; ii++ {
		if appStats.deployClientCount == policy.DeployClientCount && appStats.deployIntervalCount == policy.DeployIntervalCount {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	// verify changes
	appStats, found = autoProvAggr.allStats[app.Key]
	require.True(t, found)
	require.Equal(t, policy.DeployClientCount, appStats.deployClientCount)
	require.Equal(t, policy.DeployIntervalCount, appStats.deployIntervalCount)

	// remove policy from App
	app.AutoProvPolicy = ""
	dn.AppCache.Update(ctx, &app, 0)
	// wait for changes to take effect
	for ii := 0; ii < 10; ii++ {
		_, found = autoProvAggr.allStats[app.Key]
		if !found {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	// stats for app will be deleted if policy is removed from app
	_, found = autoProvAggr.allStats[app.Key]
	require.False(t, found)

	// clean up
	dn.AppCache.Delete(ctx, &app, 0)
	dn.AutoProvPolicyCache.Delete(ctx, &policy, 0)
	dn.ClusterInstCache.Delete(ctx, &rcinst, 0)
}
