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
	"flag"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	influxdb "github.com/influxdata/influxdb/client/v2"
	"github.com/influxdata/influxdb/models"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/notify"
	"github.com/edgexr/edge-cloud/testutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestAutoProv(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelNotify | log.DebugLevelApi | log.DebugLevelMetrics)
	log.InitTracer(nil)
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
	serverMgr.Start("ctrl", *notifyAddrs, nil)
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
	keys[edgeproto.ClusterInstKeyTagOrganization] = cinst.Key.Organization
	keys[edgeproto.CloudletKeyTagOrganization] = cinst.Key.CloudletKey.Organization
	keys[edgeproto.CloudletKeyTagName] = cinst.Key.CloudletKey.Name
	keys[edgeproto.ClusterKeyTagName] = cinst.Key.ClusterKey.Name

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
	require.Equal(t, 0, len(cacheData.frClusterInsts.InstsByCloudlet))
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

	// add policies
	policy := testutil.AutoProvPolicyData[0]
	policy.Cloudlets = []*edgeproto.AutoProvCloudlet{
		&edgeproto.AutoProvCloudlet{
			Key: rcinst.Key.CloudletKey,
		},
	}
	dn.AutoProvPolicyCache.Update(ctx, &policy, 0)

	policy2 := testutil.AutoProvPolicyData[3]
	policy2.Cloudlets = []*edgeproto.AutoProvCloudlet{
		&edgeproto.AutoProvCloudlet{
			Key: rcinst.Key.CloudletKey,
		},
	}
	dn.AutoProvPolicyCache.Update(ctx, &policy2, 0)

	// policy2 must have higher thresholds than policy1
	scale := uint32(2)
	require.True(t, policy2.DeployClientCount > scale*policy.DeployClientCount)
	require.True(t, policy2.DeployIntervalCount > scale*policy.DeployIntervalCount)

	// add app that uses above policy
	app := testutil.AppData[11]
	dn.AppCache.Update(ctx, &app, 0)

	notify.WaitFor(&cacheData.appCache, 1)
	notify.WaitFor(&cacheData.autoProvPolicyCache, 2)

	// check stats exist for app, check cached policy values
	appStats, found := autoProvAggr.allStats[app.Key]
	require.True(t, found)
	ap1, found := appStats.policies[policy.Key.Name]
	require.True(t, found)
	require.Equal(t, policy.DeployClientCount, ap1.deployClientCount)
	require.Equal(t, policy.DeployIntervalCount, ap1.deployIntervalCount)
	ap2, found := appStats.policies[policy2.Key.Name]
	require.True(t, found)
	require.Equal(t, policy2.DeployClientCount, ap2.deployClientCount)
	require.Equal(t, policy2.DeployIntervalCount, ap2.deployIntervalCount)
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
				"apporg",
				"cloudletorg",
				"ver",
			},
			Values: [][]interface{}{
				[]interface{}{
					time.Now().Format(time.RFC3339),
					app.Key.Name,
					cloudletKey.Name,
					count,
					app.Key.Organization,
					cloudletKey.Organization,
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
			ClusterInstKey: *rcinst.Key.Virtual(cloudcommon.AutoProvClusterName),
		},
	}

	// init first iter
	err := autoProvAggr.runIter(ctx, true)
	require.Nil(t, err)

	// non-trigger condition
	log.SpanLog(ctx, log.DebugLevelMetrics, "Non-trigger counting")
	for ii := uint32(0); ii < policy.DeployIntervalCount; ii++ {
		count += uint64(1)
		err := autoProvAggr.runIter(ctx, false)
		require.Nil(t, err)
		requireDeployIntervalsMet(t, appStats, &policy, &cloudletKey, 0)
		requireDeployIntervalsMet(t, appStats, &policy2, &cloudletKey, 0)
	}

	// iterate to satisfy first policy
	log.SpanLog(ctx, log.DebugLevelMetrics, "Trigger first policy")
	for ii := uint32(0); ii < policy.DeployIntervalCount; ii++ {
		count += uint64(policy.DeployClientCount)
		err := autoProvAggr.runIter(ctx, false)
		require.Nil(t, err)
		requireDeployIntervalsMet(t, appStats, &policy, &cloudletKey, ii+1)
		requireDeployIntervalsMet(t, appStats, &policy2, &cloudletKey, 0)
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
	policy.DeployClientCount *= scale
	policy.DeployIntervalCount *= scale
	policy.Cloudlets = []*edgeproto.AutoProvCloudlet{
		&edgeproto.AutoProvCloudlet{
			Key: rcinst.Key.CloudletKey,
		},
		&edgeproto.AutoProvCloudlet{
			Key: edgeproto.CloudletKey{
				Organization: "foo",
				Name:         "blah",
			},
		},
	}
	dn.AutoProvPolicyCache.Update(ctx, &policy, 0)
	// wait for changes to take effect
	for ii := 0; ii < 10; ii++ {
		if ap1.deployClientCount == policy.DeployClientCount && ap1.deployIntervalCount == policy.DeployIntervalCount {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	// verify changes
	require.Equal(t, policy.DeployClientCount, ap1.deployClientCount)
	require.Equal(t, policy.DeployIntervalCount, ap1.deployIntervalCount)
	require.Equal(t, 2, len(ap1.cloudletTrackers))

	// remove first policy from App
	app.AutoProvPolicies = []string{
		policy2.Key.Name,
	}
	dn.AppCache.Update(ctx, &app, 0)
	// wait for changes to take effect
	for ii := 0; ii < 10; ii++ {
		if len(appStats.policies) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	require.Equal(t, 1, len(appStats.policies))
	ap2, found = appStats.policies[policy2.Key.Name]
	require.True(t, found)

	// iterate to satisfy second policy
	log.SpanLog(ctx, log.DebugLevelMetrics, "Trigger second policy")
	for ii := uint32(0); ii < policy2.DeployIntervalCount; ii++ {
		count += uint64(policy2.DeployClientCount)
		err := autoProvAggr.runIter(ctx, false)
		require.Nil(t, err)
		requireDeployIntervalsMet(t, appStats, &policy2, &cloudletKey, ii+1)
	}

	// check that auto-prov AppInst was created
	notify.WaitFor(&ds.AppInstCache, 1)
	found = ds.AppInstCache.Get(&appInst.Key, &edgeproto.AppInst{})
	require.True(t, found, "found auto-provisioned AppInst")

	// manually delete AppInst (auto-unprovision not supported yet)
	ds.AppInstCache.Delete(ctx, &appInst, 0)

	// remove last policy from App
	app.AutoProvPolicies = []string{}
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

func requireDeployIntervalsMet(t *testing.T, appStats *apAppStats, policy *edgeproto.AutoProvPolicy, ckey *edgeproto.CloudletKey, expected uint32) {
	ap, found := appStats.policies[policy.Key.Name]
	require.True(t, found)
	tr, found := ap.cloudletTrackers[*ckey]
	require.True(t, found)
	require.Equal(t, expected, tr.deployIntervalsMet)
}
