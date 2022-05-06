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
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/edgexr/edge-cloud/cloudcommon"
	dme "github.com/edgexr/edge-cloud/d-match-engine/dme-proto"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/testutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// Test Choose order for create/delete
func TestChoose(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelNotify | log.DebugLevelApi | log.DebugLevelMetrics)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	// init with null nodeMgr
	cacheData.init(nil)
	autoProvAggr = NewAutoProvAggr(300, 0, &cacheData)
	autoProvAggr.allStats = make(map[edgeproto.AppKey]*apAppStats)

	// set up object data
	app := edgeproto.App{}
	app.Key.Name = "app"
	policy := testutil.AutoProvPolicyData[0]
	cloudlets := make([]edgeproto.Cloudlet, 3, 3)
	cloudlets[0].Key.Name = "A"
	cloudlets[1].Key.Name = "B"
	cloudlets[2].Key.Name = "C"
	potentialAppInsts := []edgeproto.AppInstKey{}
	potentialCreate := []*potentialCreateSite{}
	for _, cloudlet := range cloudlets {
		policy.Cloudlets = append(policy.Cloudlets,
			&edgeproto.AutoProvCloudlet{
				Key: cloudlet.Key,
				Loc: cloudlet.Location,
			})
		aiKey := edgeproto.AppInstKey{}
		aiKey.AppKey = app.Key
		aiKey.ClusterInstKey.CloudletKey = cloudlet.Key
		potentialAppInsts = append(potentialAppInsts, aiKey)
		pc := &potentialCreateSite{
			cloudletKey: cloudlet.Key,
			hasFree:     0,
		}
		potentialCreate = append(potentialCreate, pc)
	}

	app.AutoProvPolicies = []string{policy.Key.Name}
	// app stats
	appStats := apAppStats{}
	appStats.cloudlets = make(map[edgeproto.CloudletKey]*apCloudletStats)
	autoProvAggr.allStats[app.Key] = &appStats

	// the sortPotentialCreate and chooseDelete functions may modify the passed in
	// array so we need to clone it for testing.
	cloneA := func(in []edgeproto.AppInstKey) []edgeproto.AppInstKey {
		out := make([]edgeproto.AppInstKey, len(in), len(in))
		copy(out, in)
		return out
	}
	clone := func(in []*potentialCreateSite) []*potentialCreateSite {
		out := make([]*potentialCreateSite, len(in), len(in))
		copy(out, in)
		return out
	}

	// checker
	appChecker := newAppChecker(&cacheData, app.Key, nil)

	// sortPotentialCreate tests

	// no stats, should return same list
	results := appChecker.sortPotentialCreate(ctx, clone(potentialCreate))
	require.Equal(t, potentialCreate, results)

	// zero stats
	for _, cloudlet := range cloudlets {
		appStats.cloudlets[cloudlet.Key] = &apCloudletStats{}
	}
	results = appChecker.sortPotentialCreate(ctx, clone(potentialCreate))
	require.Equal(t, potentialCreate, results)

	// later cloudlets should be preferred
	appStats.cloudlets[cloudlets[0].Key].count = 2
	appStats.cloudlets[cloudlets[1].Key].count = 4
	appStats.cloudlets[cloudlets[2].Key].count = 6
	reverse := []*potentialCreateSite{
		potentialCreate[2],
		potentialCreate[1],
		potentialCreate[0],
	}
	results = appChecker.sortPotentialCreate(ctx, clone(potentialCreate))
	require.Equal(t, reverse, results)

	// change stats to change order
	appStats.cloudlets[cloudlets[0].Key].count = 2
	appStats.cloudlets[cloudlets[1].Key].count = 6
	appStats.cloudlets[cloudlets[2].Key].count = 5
	expected := []*potentialCreateSite{
		potentialCreate[1],
		potentialCreate[2],
		potentialCreate[0],
	}
	results = appChecker.sortPotentialCreate(ctx, clone(potentialCreate))
	require.Equal(t, expected, results)

	// check that cloudlets with free reservable ClusterInsts are preferred
	potentialCreate[2].hasFree = 1
	expected = []*potentialCreateSite{
		potentialCreate[2],
		potentialCreate[1],
		potentialCreate[0],
	}
	results = appChecker.sortPotentialCreate(ctx, clone(potentialCreate))
	require.Equal(t, expected, results)

	// chooseDelete tests

	// should get same list
	resultsA := appChecker.chooseDelete(ctx, cloneA(potentialAppInsts), 3)
	require.Equal(t, potentialAppInsts, resultsA)

	// should get truncated end of list
	resultsA = appChecker.chooseDelete(ctx, cloneA(potentialAppInsts), 2)
	require.Equal(t, potentialAppInsts[1:], resultsA)
}

func TestAppChecker(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelNotify | log.DebugLevelApi | log.DebugLevelMetrics)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	// init with null nodeMgr
	cacheData.init(nil)
	autoProvAggr = NewAutoProvAggr(300, 0, &cacheData)
	autoProvAggr.allStats = make(map[edgeproto.AppKey]*apAppStats)
	// forward AppInsts created by the test to cacheData
	dc := newDummyController(&cacheData.appInstCache, &cacheData.appInstRefsCache)
	dc.start()
	defer dc.stop()
	dialOpts = grpc.WithContextDialer(dc.getBufDialer())
	testDialOpt = grpc.WithInsecure()

	minmax := newMinMaxChecker(&cacheData)
	retryTracker = newRetryTracker()
	// run iterations manually, otherwise the cache update loop causes
	// checkApp to be run multiple times, and without the Controller code
	// to block invalid creates/deletes, we end up with incorrect states.
	// To track if app was scheduled for checking, replace the workers
	// work func with a dummy func.
	dummyCheckApp := newDummyCheckApp()
	minmax.workers.Init("autoprov-minmax-test", dummyCheckApp.CheckApp)

	// object data
	pt1Max := uint32(4)
	pt1 := makePolicyTest("policy1", pt1Max, &cacheData)
	pt1.updatePolicy(ctx)
	pt1.updateClusterInsts(ctx)

	pt2Max := uint32(6)
	pt2 := makePolicyTest("policy2", pt2Max, &cacheData)
	pt2.updatePolicy(ctx)
	pt2.updateClusterInsts(ctx)

	app := edgeproto.App{}
	app.Key.Name = "app"
	// add both policies to app
	app.AutoProvPolicy = pt1.policy.Key.Name
	app.AutoProvPolicies = append(app.AutoProvPolicies, pt2.policy.Key.Name)
	cacheData.appCache.Update(ctx, &app, 0)

	refs := edgeproto.AppInstRefs{}
	refs.Key = app.Key
	refs.Insts = make(map[string]uint32)
	cacheData.appInstRefsCache.Update(ctx, &refs, 0)

	var err error

	// no AppInsts to start
	require.Equal(t, 0, dc.appInstCache.GetCount())

	// set reasonable min/max and see that min is met
	pt1.policy.MinActiveInstances = 2
	pt1.policy.MaxInstances = 3
	pt1.updatePolicy(ctx)
	pt2.policy.MinActiveInstances = 3
	pt2.policy.MaxInstances = 5
	pt2.updatePolicy(ctx)
	minmax.CheckApp(ctx, app.Key)
	countMin := int(pt1.policy.MinActiveInstances + pt2.policy.MinActiveInstances)
	err = dc.waitForAppInsts(ctx, countMin)
	require.Nil(t, err)

	// set min equal to max
	pt1.policy.MinActiveInstances = pt1Max
	pt1.policy.MaxInstances = pt1Max
	pt1.updatePolicy(ctx)
	pt2.policy.MinActiveInstances = pt2Max
	pt2.policy.MaxInstances = pt2Max
	pt2.updatePolicy(ctx)
	// check that deployed min = max
	minmax.CheckApp(ctx, app.Key)
	err = dc.waitForAppInsts(ctx, int(pt1Max+pt2Max))
	require.Nil(t, err)

	// reduce max to see that AppInsts are removed
	pt1.policy.MinActiveInstances = 2
	pt1.policy.MaxInstances = 3
	pt1.updatePolicy(ctx)
	pt2.policy.MinActiveInstances = 3
	pt2.policy.MaxInstances = 5
	pt2.updatePolicy(ctx)
	minmax.CheckApp(ctx, app.Key)
	count := int(pt1.policy.MaxInstances + pt2.policy.MaxInstances)
	err = dc.waitForAppInsts(ctx, count)
	require.Nil(t, err)

	// bounds check - set min above available cloudlets count
	pt1.policy.MinActiveInstances = pt1Max + 2
	pt1.policy.MaxInstances = pt1Max + 2
	pt1.updatePolicy(ctx)
	pt2.policy.MinActiveInstances = pt2Max + 2
	pt2.policy.MaxInstances = pt2Max + 2
	pt2.updatePolicy(ctx)
	minmax.CheckApp(ctx, app.Key)
	count = pt1.count() + pt2.count()
	err = dc.waitForAppInsts(ctx, count)
	require.Nil(t, err)

	// set min/max to 0 to clean up everything
	pt1.policy.MinActiveInstances = 0
	pt1.policy.MaxInstances = 0
	pt1.updatePolicy(ctx)
	pt1.deleteAppInsts(ctx, dc, &app.Key)
	pt2.policy.MinActiveInstances = 0
	pt2.policy.MaxInstances = 0
	pt2.updatePolicy(ctx)
	pt2.deleteAppInsts(ctx, dc, &app.Key)

	minmax.CheckApp(ctx, app.Key)
	err = dc.waitForAppInsts(ctx, 0)
	require.Nil(t, err)

	// Check it works the same with MaxInstances=0
	pt1.policy.MinActiveInstances = 2
	pt1.policy.MaxInstances = 0
	pt1.updatePolicy(ctx)
	pt2.policy.MinActiveInstances = 3
	pt2.policy.MaxInstances = 0
	pt2.updatePolicy(ctx)
	minmax.CheckApp(ctx, app.Key)
	countMin = int(pt1.policy.MinActiveInstances + pt2.policy.MinActiveInstances)
	err = dc.waitForAppInsts(ctx, countMin)
	require.Nil(t, err)

	// set min/max to 0 to clean up everything
	pt1.policy.MinActiveInstances = 0
	pt1.policy.MaxInstances = 0
	pt1.updatePolicy(ctx)
	pt1.deleteAppInsts(ctx, dc, &app.Key)
	pt2.policy.MinActiveInstances = 0
	pt2.policy.MaxInstances = 0
	pt2.updatePolicy(ctx)
	pt2.deleteAppInsts(ctx, dc, &app.Key)
	minmax.CheckApp(ctx, app.Key)
	err = dc.waitForAppInsts(ctx, 0)
	require.Nil(t, err)

	// go back to reasonable settings (only using one policy from now)
	pt1.policy.MinActiveInstances = 2
	pt1.policy.MaxInstances = 3
	pt1.updatePolicy(ctx)
	minmax.CheckApp(ctx, app.Key)
	err = dc.waitForAppInsts(ctx, int(pt1.policy.MinActiveInstances))
	require.Nil(t, err)

	// simulate AppInst health check failure,
	// this should create another inst
	insts := pt1.getAppInsts(&app.Key)
	insts[0].HealthCheck = dme.HealthCheck_HEALTH_CHECK_SERVER_FAIL
	dc.updateAppInst(ctx, &insts[0])
	minmax.CheckApp(ctx, app.Key)
	err = dc.waitForAppInsts(ctx, int(pt1.policy.MinActiveInstances)+1)
	require.Nil(t, err)

	// simulate another AppInst health check failure,
	// this one should not trigger another create because
	// it would violate the max
	require.Equal(t, pt1.policy.MaxInstances, pt1.policy.MinActiveInstances+1)
	insts[1].HealthCheck = dme.HealthCheck_HEALTH_CHECK_SERVER_FAIL
	dc.updateAppInst(ctx, &insts[1])
	minmax.CheckApp(ctx, app.Key)
	err = dc.waitForAppInsts(ctx, int(pt1.policy.MinActiveInstances)+1)
	require.Nil(t, err)

	// delete both bad instances, this will get us down to 1
	// instance which is below min, so another one should get created.
	dc.deleteAppInst(ctx, &insts[0])
	dc.deleteAppInst(ctx, &insts[1])
	// verify count before checker
	err = dc.waitForAppInsts(ctx, 1)
	require.Nil(t, err)
	// run checker
	minmax.CheckApp(ctx, app.Key)
	err = dc.waitForAppInsts(ctx, int(pt1.policy.MinActiveInstances))
	require.Nil(t, err)

	// reset back to 0
	pt1.policy.MinActiveInstances = 0
	pt1.policy.MaxInstances = 0
	pt1.updatePolicy(ctx)
	pt1.deleteAppInsts(ctx, dc, &app.Key)
	minmax.CheckApp(ctx, app.Key)
	err = dc.waitForAppInsts(ctx, 0)
	require.Nil(t, err)

	// set to reasonable settings
	pt1.policy.MinActiveInstances = 2
	pt1.policy.MaxInstances = 3
	pt1.updatePolicy(ctx)
	minmax.CheckApp(ctx, app.Key)
	err = dc.waitForAppInsts(ctx, int(pt1.policy.MinActiveInstances))
	require.Nil(t, err)

	// simulate cloudlet offline, same as AppInst, will trigger
	// creating another AppInst.
	cloudletInfo0 := pt1.cloudletInfos[0]
	cloudletInfo0.State = dme.CloudletState_CLOUDLET_STATE_OFFLINE
	cacheData.cloudletInfoCache.Update(ctx, &cloudletInfo0, 0)
	minmax.CheckApp(ctx, app.Key)
	err = dc.waitForAppInsts(ctx, int(pt1.policy.MinActiveInstances)+1)
	require.Nil(t, err)

	// simulate second cloudlet offline, same as AppInst,
	// can't trigger another AppInst create because it would
	// exceed max.
	require.Equal(t, pt1.policy.MaxInstances, pt1.policy.MinActiveInstances+1)
	cloudletInfo1 := pt1.cloudletInfos[1]
	cloudletInfo1.State = dme.CloudletState_CLOUDLET_STATE_OFFLINE
	cacheData.cloudletInfoCache.Update(ctx, &cloudletInfo1, 0)
	minmax.CheckApp(ctx, app.Key)
	err = dc.waitForAppInsts(ctx, int(pt1.policy.MinActiveInstances)+1)
	require.Nil(t, err)

	// reset cloudlets back online
	cloudletInfo0.State = dme.CloudletState_CLOUDLET_STATE_READY
	cloudletInfo1.State = dme.CloudletState_CLOUDLET_STATE_READY
	cacheData.cloudletInfoCache.Update(ctx, &cloudletInfo0, 0)
	cacheData.cloudletInfoCache.Update(ctx, &cloudletInfo1, 0)

	// reset back to 0
	pt1.policy.MinActiveInstances = 0
	pt1.policy.MaxInstances = 0
	pt1.updatePolicy(ctx)
	pt1.deleteAppInsts(ctx, dc, &app.Key)
	minmax.CheckApp(ctx, app.Key)
	err = dc.waitForAppInsts(ctx, 0)
	require.Nil(t, err)

	// set to reasonable settings
	pt1.policy.MinActiveInstances = 2
	pt1.policy.MaxInstances = 4
	pt1.updatePolicy(ctx)
	minmax.CheckApp(ctx, app.Key)
	err = dc.waitForAppInsts(ctx, int(pt1.policy.MinActiveInstances))
	require.Nil(t, err)

	// Cloudlet maintenance tests - set up callback to detect
	// when AppInst creates are done.
	failovers := make(chan edgeproto.AutoProvInfo, 10)
	cacheData.autoProvInfoCache.SetUpdatedCb(func(ctx context.Context, old *edgeproto.AutoProvInfo, new *edgeproto.AutoProvInfo) {
		failovers <- *new
	})
	defer cacheData.autoProvInfoCache.SetUpdatedCb(nil)

	// set cloudlet0 to maintenance mode, will trigger
	// creating another AppInst.
	cloudlet0 := pt1.cloudlets[0]
	cloudlet0.MaintenanceState = dme.MaintenanceState_FAILOVER_REQUESTED
	cacheData.cloudletCache.Update(ctx, &cloudlet0, 0)

	minmax.CheckApp(ctx, app.Key)
	err = dc.waitForAppInsts(ctx, int(pt1.policy.MinActiveInstances)+1)
	require.Nil(t, err)
	select {
	case failover := <-failovers:
		require.Equal(t, cloudlet0.Key, failover.Key)
		require.Equal(t, dme.MaintenanceState_FAILOVER_DONE, failover.MaintenanceState)
		require.Equal(t, 0, len(failover.Errors))
		require.Equal(t, 1, len(failover.Completed))
		require.Contains(t, failover.Completed[0], "Created AppInst")
	case <-time.After(2 * time.Second):
		require.Fail(t, "timeout waiting for AutoProvInfo")
	}

	// set cloudlet1 to maintenance mode, and set dummy controller
	// to fail create, should capture failure.
	dc.failCreate = true
	cloudlet1 := pt1.cloudlets[1]
	cloudlet1.MaintenanceState = dme.MaintenanceState_FAILOVER_REQUESTED
	cacheData.cloudletCache.Update(ctx, &cloudlet1, 0)
	minmax.CheckApp(ctx, app.Key)
	select {
	case failover := <-failovers:
		require.Equal(t, cloudlet1.Key, failover.Key)
		require.Equal(t, dme.MaintenanceState_FAILOVER_ERROR, failover.MaintenanceState)
		require.Equal(t, 1, len(failover.Errors))
		require.Contains(t, failover.Errors[0], "Some error")
	case <-time.After(2 * time.Second):
		require.Fail(t, "timeout waiting for AutoProvInfo")
	}
	dc.failCreate = false

	// set cloudlet2 to maintenance mode, will trigger
	// failures because we can't meed min of 2 (3 of 4 cloudlets down)
	cloudlet2 := pt1.cloudlets[2]
	cloudlet2.MaintenanceState = dme.MaintenanceState_FAILOVER_REQUESTED
	cacheData.cloudletCache.Update(ctx, &cloudlet2, 0)

	minmax.CheckApp(ctx, app.Key)
	select {
	case failover := <-failovers:
		require.Equal(t, cloudlet2.Key, failover.Key)
		require.Equal(t, dme.MaintenanceState_FAILOVER_ERROR, failover.MaintenanceState)
		require.Equal(t, 1, len(failover.Errors))
		require.Contains(t, failover.Errors[0], "Not enough potential cloudlets to deploy to")
	case <-time.After(2 * time.Second):
		require.Fail(t, "timeout waiting for AutoProvInfo")
	}

	// move cloudlets out of maintenance
	cloudlet0.MaintenanceState = dme.MaintenanceState_NORMAL_OPERATION
	cloudlet1.MaintenanceState = dme.MaintenanceState_NORMAL_OPERATION
	cloudlet2.MaintenanceState = dme.MaintenanceState_NORMAL_OPERATION
	cacheData.cloudletCache.Update(ctx, &cloudlet0, 0)
	cacheData.cloudletCache.Update(ctx, &cloudlet1, 0)
	cacheData.cloudletCache.Update(ctx, &cloudlet2, 0)

	// reset back to 0
	pt1.policy.MinActiveInstances = 0
	pt1.policy.MaxInstances = 0
	pt1.updatePolicy(ctx)
	pt1.deleteAppInsts(ctx, dc, &app.Key)
	minmax.CheckApp(ctx, app.Key)
	err = dc.waitForAppInsts(ctx, 0)
	require.Nil(t, err)

	// create a manually create AppInst
	insts = pt1.getAppInsts(&app.Key)
	insts[0].Key.ClusterInstKey.ClusterKey.Name = "manual"
	dc.updateAppInst(ctx, &insts[0])

	// set to reasonable settings - this will only create
	// one AppInst to meet min
	pt1.policy.MinActiveInstances = 2
	pt1.policy.MaxInstances = 3
	pt1.updatePolicy(ctx)
	minmax.CheckApp(ctx, app.Key)
	err = dc.waitForAppInsts(ctx, int(pt1.policy.MinActiveInstances))
	require.Nil(t, err)

	// delete manually created AppInst - will then create another
	// to meet min
	dc.deleteAppInst(ctx, &insts[0])
	minmax.CheckApp(ctx, app.Key)
	err = dc.waitForAppInsts(ctx, int(pt1.policy.MinActiveInstances))
	require.Nil(t, err)

	// remove cloudlets from policy - will delete all
	// auto-provisioned AppInsts regardless of min because they are on
	// cloudlets not specified by any policy.
	cloudletsSave := pt1.policy.Cloudlets
	pt1.policy.Cloudlets = nil
	pt1.updatePolicy(ctx)
	minmax.CheckApp(ctx, app.Key)
	err = dc.waitForAppInsts(ctx, 0)
	require.Nil(t, err)

	// set cloudlets back
	pt1.policy.Cloudlets = cloudletsSave
	pt1.updatePolicy(ctx)
	minmax.CheckApp(ctx, app.Key)
	err = dc.waitForAppInsts(ctx, int(pt1.policy.MinActiveInstances))
	require.Nil(t, err)

	// set cloudlets offline (and fail delete because controller will
	// disallow changes to offline cloudlet).
	// Should still be same number of AppInsts.
	dc.failCreate = true
	dc.failDelete = true
	for _, cinfo := range pt1.cloudletInfos {
		// cinfo is a copy
		cinfo.State = dme.CloudletState_CLOUDLET_STATE_OFFLINE
		cacheData.cloudletInfoCache.Update(ctx, &cinfo, 0)
	}
	minmax.CheckApp(ctx, app.Key)
	err = dc.waitForAppInsts(ctx, int(pt1.policy.MinActiveInstances))
	require.Nil(t, err)

	// remove cloudlets (no change since controller still disallowing changes)
	pt1.policy.Cloudlets = nil
	pt1.updatePolicy(ctx)
	minmax.CheckApp(ctx, app.Key)
	err = dc.waitForAppInsts(ctx, int(pt1.policy.MinActiveInstances))
	require.Nil(t, err)
	minmax.workers.WaitIdle()
	dummyCheckApp.Clear()

	// bring cloudlets back online, should trigger delete of AppInsts
	// since they are no longer part of policy.
	dc.failCreate = false
	dc.failDelete = false
	for _, cinfo := range pt1.cloudletInfos {
		// cinfo is a copy
		cinfo.State = dme.CloudletState_CLOUDLET_STATE_READY
		cacheData.cloudletInfoCache.Update(ctx, &cinfo, 0)
	}
	// bug3506: App should be marked for checking
	minmax.workers.WaitIdle()
	require.True(t, dummyCheckApp.HasApp(app.Key))
	// run check
	minmax.CheckApp(ctx, app.Key)
	err = dc.waitForAppInsts(ctx, 0)
	require.Nil(t, err)

	// create App with MobiledgeX org, no policies
	// make sure they don't get deleted (edgecloud-3053)
	app2 := edgeproto.App{}
	app2.Key.Name = "app2"
	app2.Key.Organization = cloudcommon.OrganizationMobiledgeX
	cacheData.appCache.Update(ctx, &app2, 0)

	refs2 := edgeproto.AppInstRefs{}
	refs2.Key = app2.Key
	refs2.Insts = make(map[string]uint32)
	cacheData.appInstRefsCache.Update(ctx, &refs2, 0)

	insts = pt1.getAppInsts(&app2.Key)
	for _, inst := range insts {
		inst.Key.ClusterInstKey.Organization = cloudcommon.OrganizationMobiledgeX
		dc.updateAppInst(ctx, &inst)
	}
	minmax.CheckApp(ctx, app.Key)
	err = dc.waitForAppInsts(ctx, len(insts))
	require.Nil(t, err)

	// clean up
	for _, inst := range insts {
		dc.deleteAppInst(ctx, &inst)
	}

	// Bug3265 - make sure Cloudlet maintenance triggers failover reply
	// even if no Cloudlet not part of any AutoProv policy.
	log.SpanLog(ctx, log.DebugLevelMetrics, "test bug3265")
	pt1.cloudlets = nil
	pt2.cloudlets = nil
	pt1.updatePolicy(ctx)
	pt2.updatePolicy(ctx)
	for len(failovers) > 0 {
		<-failovers // drain the failovers chan
	}
	cloudlet0.MaintenanceState = dme.MaintenanceState_FAILOVER_REQUESTED
	cacheData.cloudletCache.Update(ctx, &cloudlet0, 0)
	select {
	case failover := <-failovers:
		require.Equal(t, cloudlet0.Key, failover.Key)
		require.Equal(t, dme.MaintenanceState_FAILOVER_DONE, failover.MaintenanceState)
		require.Equal(t, 0, len(failover.Errors))
		require.Equal(t, 0, len(failover.Completed))
	case <-time.After(2 * time.Second):
		require.Fail(t, "timeout waiting for AutoProvInfo")
	}
	// Also make sure reply is received even if state is already in maintenance
	cacheData.cloudletCache.Update(ctx, &cloudlet0, 0)
	select {
	case failover := <-failovers:
		require.Equal(t, cloudlet0.Key, failover.Key)
		require.Equal(t, dme.MaintenanceState_FAILOVER_DONE, failover.MaintenanceState)
		require.Equal(t, 0, len(failover.Errors))
		require.Equal(t, 0, len(failover.Completed))
	case <-time.After(2 * time.Second):
		require.Fail(t, "timeout waiting for AutoProvInfo")
	}

	// Bug4217: ETCD spike issue, autoprov service continuously
	//          creates & deletes app on CRM failure
	pt3Max := uint32(2)
	pt3 := makePolicyTest("policy3", pt3Max, &cacheData)
	pt3.updatePolicy(ctx)
	pt3.updateClusterInsts(ctx)
	appRetry := edgeproto.App{}
	appRetry.Key.Name = "appRetry"
	// add policy to app
	appRetry.AutoProvPolicies = append(appRetry.AutoProvPolicies, pt3.policy.Key.Name)
	cacheData.appCache.Update(ctx, &appRetry, 0)
	refs = edgeproto.AppInstRefs{}
	refs.Key = appRetry.Key
	refs.Insts = make(map[string]uint32)
	cacheData.appInstRefsCache.Update(ctx, &refs, 0)
	// no AppInsts to start
	require.Equal(t, 0, dc.appInstCache.GetCount())
	// test blacklisting by causing inst[0] create to fail
	insts = pt3.getAppInsts(&appRetry.Key)
	dc.failCreateInsts[insts[0].Key] = struct{}{}
	pt3.policy.MinActiveInstances = 1
	pt3.policy.MaxInstances = 1
	pt3.updatePolicy(ctx)
	minmax.CheckApp(ctx, appRetry.Key)
	// appinst create should fail on first cloudlet, and it should be marked,
	// but minmax will run create on next best potential cloudlet (inst[1])
	err = waitForRetryAppInsts(ctx, insts[0].Key, true)
	require.Nil(t, err)
	err = dc.waitForAppInsts(ctx, 1)
	require.Nil(t, err)
	require.True(t, dc.appInstCache.HasKey(&insts[1].Key))
	// delete all instances
	pt3.deleteAppInsts(ctx, dc, &appRetry.Key)
	err = dc.waitForAppInsts(ctx, 0)
	require.Nil(t, err)
	// clear artificial failure mode
	delete(dc.failCreateInsts, insts[0].Key)
	// re-run, cloudlet[0] is blacklisted so will not be used
	// even though we've removed the artificial failure.
	minmax.CheckApp(ctx, appRetry.Key)
	err = dc.waitForAppInsts(ctx, 1)
	require.Nil(t, err)
	require.True(t, dc.appInstCache.HasKey(&insts[1].Key))
	// delete all instances
	pt3.deleteAppInsts(ctx, dc, &appRetry.Key)
	err = dc.waitForAppInsts(ctx, 0)
	require.Nil(t, err)
	// clear out retry
	retryTracker.doRetry(ctx, minmax)
	err = waitForRetryAppInsts(ctx, insts[0].Key, false)
	require.Nil(t, err)
	// with retry cleared, minmax will attempt to create on inst[0] again
	minmax.CheckApp(ctx, appRetry.Key)
	err = dc.waitForAppInsts(ctx, 1)
	require.Nil(t, err)
	require.True(t, dc.appInstCache.HasKey(&insts[0].Key))

	// reset back to 0
	pt3.policy.MinActiveInstances = 0
	pt3.policy.MaxInstances = 0
	pt3.updatePolicy(ctx)
	pt3.deleteAppInsts(ctx, dc, &appRetry.Key)
	minmax.CheckApp(ctx, appRetry.Key)
	err = dc.waitForAppInsts(ctx, 0)
	require.Nil(t, err)
}

type policyTest struct {
	policy        edgeproto.AutoProvPolicy
	cloudlets     []edgeproto.Cloudlet
	cloudletInfos []edgeproto.CloudletInfo
	clusterInsts  []edgeproto.ClusterInst
	caches        *CacheData
}

func makePolicyTest(name string, count uint32, caches *CacheData) *policyTest {
	s := policyTest{}
	s.policy.Key.Name = name
	s.cloudlets = make([]edgeproto.Cloudlet, count, count)
	s.cloudletInfos = make([]edgeproto.CloudletInfo, count, count)
	s.clusterInsts = make([]edgeproto.ClusterInst, count, count)
	s.caches = caches
	for ii, _ := range s.cloudlets {
		s.cloudlets[ii].Key.Name = fmt.Sprintf("%s_%d", name, ii)
		s.cloudletInfos[ii].Key = s.cloudlets[ii].Key
		s.cloudletInfos[ii].State = dme.CloudletState_CLOUDLET_STATE_READY
		s.clusterInsts[ii].Key.CloudletKey = s.cloudlets[ii].Key
		s.clusterInsts[ii].Reservable = true
		s.clusterInsts[ii].Key.Organization = cloudcommon.OrganizationMobiledgeX
		s.policy.Cloudlets = append(s.policy.Cloudlets,
			&edgeproto.AutoProvCloudlet{Key: s.cloudlets[ii].Key})
	}
	return &s
}

func (s *policyTest) updateClusterInsts(ctx context.Context) {
	// objects must be copied before being put in the cache.
	for ii, _ := range s.cloudlets {
		obj := s.cloudlets[ii]
		s.caches.cloudletCache.Update(ctx, &obj, 0)
	}
	for ii, _ := range s.cloudletInfos {
		obj := s.cloudletInfos[ii]
		s.caches.cloudletInfoCache.Update(ctx, &obj, 0)
	}
	for ii, _ := range s.clusterInsts {
		obj := s.clusterInsts[ii]
		s.caches.frClusterInsts.Update(ctx, &obj, 0)
	}
}

func (s *policyTest) updatePolicy(ctx context.Context) {
	log.SpanLog(ctx, log.DebugLevelNotify, "policyTest update policy", "policy", s.policy.Key.Name)
	policy := s.policy
	s.caches.autoProvPolicyCache.Update(ctx, &policy, 0)
}

func (s *policyTest) count() int {
	return len(s.cloudlets)
}

func (s *policyTest) getAppInsts(key *edgeproto.AppKey) []edgeproto.AppInst {
	insts := []edgeproto.AppInst{}
	for ii, _ := range s.clusterInsts {
		inst := edgeproto.AppInst{}
		inst.Key.AppKey = *key
		inst.Key.ClusterInstKey = *s.clusterInsts[ii].Key.Virtual(cloudcommon.AutoProvClusterName)
		insts = append(insts, inst)
	}
	return insts
}

func (s *policyTest) deleteAppInsts(ctx context.Context, dc *DummyController, key *edgeproto.AppKey) {
	for _, inst := range s.getAppInsts(key) {
		dc.deleteAppInst(ctx, &inst)
	}
}

type DummyCheckApp struct {
	mux     sync.Mutex
	checked map[edgeproto.AppKey]struct{}
}

func newDummyCheckApp() *DummyCheckApp {
	s := &DummyCheckApp{}
	s.checked = make(map[edgeproto.AppKey]struct{})
	return s
}

func (s *DummyCheckApp) CheckApp(ctx context.Context, k interface{}) {
	s.mux.Lock()
	defer s.mux.Unlock()
	key, ok := k.(edgeproto.AppKey)
	if !ok {
		panic("not AppKey")
	}
	s.checked[key] = struct{}{}
}

func (s *DummyCheckApp) HasApp(key edgeproto.AppKey) bool {
	s.mux.Lock()
	defer s.mux.Unlock()
	_, found := s.checked[key]
	return found
}

func (s *DummyCheckApp) Clear() {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.checked = make(map[edgeproto.AppKey]struct{})
}
