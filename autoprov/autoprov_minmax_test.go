package main

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/testutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// Test Choose order for create/delete
func TestChoose(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelNotify | log.DebugLevelApi | log.DebugLevelMetrics)
	log.InitTracer("")
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	// init
	cacheData.init()
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

	}
	app.AutoProvPolicies = []string{policy.Key.Name}
	// app stats
	appStats := apAppStats{}
	appStats.cloudlets = make(map[edgeproto.CloudletKey]*apCloudletStats)
	autoProvAggr.allStats[app.Key] = &appStats

	// the chooseCreate and chooseDelete functions may modify the passed in
	// array so we need to clone it for testing.
	clone := func(in []edgeproto.AppInstKey) []edgeproto.AppInstKey {
		out := make([]edgeproto.AppInstKey, len(in), len(in))
		copy(out, in)
		return out
	}

	// checker
	appChecker := newAppChecker(&cacheData, &app.Key, nil, &sync.WaitGroup{})

	// chooseCreate tests

	// no stats, should return same list
	results := appChecker.chooseCreate(ctx, clone(potentialAppInsts), 3)
	require.Equal(t, potentialAppInsts, results)

	// no stats, should return same list (count greater than list)
	results = appChecker.chooseCreate(ctx, clone(potentialAppInsts), 100)
	require.Equal(t, potentialAppInsts, results)

	// no stats, should return same list (truncated)
	results = appChecker.chooseCreate(ctx, clone(potentialAppInsts), 1)
	require.Equal(t, potentialAppInsts[:1], results)

	// zero stats
	for _, cloudlet := range cloudlets {
		appStats.cloudlets[cloudlet.Key] = &apCloudletStats{}
	}
	results = appChecker.chooseCreate(ctx, clone(potentialAppInsts), 2)
	require.Equal(t, potentialAppInsts[:2], results)

	// later cloudlets should be preferred
	appStats.cloudlets[cloudlets[0].Key].count = 2
	appStats.cloudlets[cloudlets[1].Key].count = 4
	appStats.cloudlets[cloudlets[2].Key].count = 6
	reverse := []edgeproto.AppInstKey{
		potentialAppInsts[2],
		potentialAppInsts[1],
		potentialAppInsts[0],
	}
	results = appChecker.chooseCreate(ctx, clone(potentialAppInsts), 3)
	require.Equal(t, reverse, results)

	// change stats to change order
	appStats.cloudlets[cloudlets[0].Key].count = 2
	appStats.cloudlets[cloudlets[1].Key].count = 6
	appStats.cloudlets[cloudlets[2].Key].count = 5
	expected := []edgeproto.AppInstKey{
		potentialAppInsts[1],
		potentialAppInsts[2],
		potentialAppInsts[0],
	}
	results = appChecker.chooseCreate(ctx, clone(potentialAppInsts), 3)
	require.Equal(t, expected, results)

	// chooseDelete tests

	// should get same list
	results = appChecker.chooseDelete(ctx, clone(potentialAppInsts), 3)
	require.Equal(t, potentialAppInsts, results)

	// should get truncated end of list
	results = appChecker.chooseDelete(ctx, clone(potentialAppInsts), 2)
	require.Equal(t, potentialAppInsts[1:], results)
}

func TestAppChecker(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelNotify | log.DebugLevelApi | log.DebugLevelMetrics)
	log.InitTracer("")
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	// init
	cacheData.init()
	autoProvAggr = NewAutoProvAggr(300, 0, &cacheData)
	autoProvAggr.allStats = make(map[edgeproto.AppKey]*apAppStats)
	// forward AppInsts created by the test to cacheData
	dc := newDummyController(&cacheData.appInstCache, &cacheData.appInstRefsCache)
	dc.start()
	defer dc.stop()
	dialOpts = grpc.WithContextDialer(dc.getBufDialer())
	testDialOpt = grpc.WithInsecure()

	minmax := newMinMaxChecker(&cacheData)

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
	minmax.runIter(ctx)
	countMin := int(pt1.policy.MinActiveInstances + pt2.policy.MinActiveInstances)
	err = dc.waitForAppInsts(countMin)
	require.Nil(t, err)

	// set min equal to max
	pt1.policy.MinActiveInstances = pt1Max
	pt1.policy.MaxInstances = pt1Max
	pt1.updatePolicy(ctx)
	pt2.policy.MinActiveInstances = pt2Max
	pt2.policy.MaxInstances = pt2Max
	pt2.updatePolicy(ctx)
	// check that deployed min = max
	minmax.runIter(ctx)
	err = dc.waitForAppInsts(int(pt1Max + pt2Max))
	require.Nil(t, err)

	// reduce max to see that AppInsts are removed
	pt1.policy.MinActiveInstances = 2
	pt1.policy.MaxInstances = 3
	pt1.updatePolicy(ctx)
	pt2.policy.MinActiveInstances = 3
	pt2.policy.MaxInstances = 5
	pt2.updatePolicy(ctx)
	minmax.runIter(ctx)
	count := int(pt1.policy.MaxInstances + pt2.policy.MaxInstances)
	err = dc.waitForAppInsts(count)
	require.Nil(t, err)

	// bounds check - set min above available cloudlets count
	pt1.policy.MinActiveInstances = pt1Max + 2
	pt1.policy.MaxInstances = pt1Max + 2
	pt1.updatePolicy(ctx)
	pt2.policy.MinActiveInstances = pt2Max + 2
	pt2.policy.MaxInstances = pt2Max + 2
	pt2.updatePolicy(ctx)
	minmax.runIter(ctx)
	count = pt1.count() + pt2.count()
	err = dc.waitForAppInsts(count)
	require.Nil(t, err)

	// set min/max to 0 to clean up everything
	pt1.policy.MinActiveInstances = 0
	pt1.policy.MaxInstances = 0
	pt1.updatePolicy(ctx)
	pt2.policy.MinActiveInstances = 0
	pt2.policy.MaxInstances = 0
	pt2.updatePolicy(ctx)
	minmax.runIter(ctx)
	err = dc.waitForAppInsts(0)
	require.Nil(t, err)

	// go back to reasonable settings (only using one policy from now)
	pt1.policy.MinActiveInstances = 2
	pt1.policy.MaxInstances = 3
	pt1.updatePolicy(ctx)
	minmax.runIter(ctx)
	err = dc.waitForAppInsts(int(pt1.policy.MinActiveInstances))
	require.Nil(t, err)

	// simulate AppInst health check failure,
	// this should create another inst
	insts := pt1.getAppInsts(&app.Key)
	insts[0].HealthCheck = edgeproto.HealthCheck_HEALTH_CHECK_FAIL_SERVER_FAIL
	dc.updateAppInst(ctx, &insts[0])
	minmax.runIter(ctx)
	err = dc.waitForAppInsts(int(pt1.policy.MinActiveInstances) + 1)
	require.Nil(t, err)

	// simulate another AppInst health check failure,
	// this one should not trigger another create because
	// it would violate the max
	require.Equal(t, pt1.policy.MaxInstances, pt1.policy.MinActiveInstances+1)
	insts[1].HealthCheck = edgeproto.HealthCheck_HEALTH_CHECK_FAIL_SERVER_FAIL
	dc.updateAppInst(ctx, &insts[1])
	minmax.runIter(ctx)
	err = dc.waitForAppInsts(int(pt1.policy.MinActiveInstances) + 1)
	require.Nil(t, err)

	// delete both bad instances, this will get us down to 1
	// instance which is below min, so another one should get created.
	dc.deleteAppInst(ctx, &insts[0])
	dc.deleteAppInst(ctx, &insts[1])
	// verify count before checker
	err = dc.waitForAppInsts(1)
	require.Nil(t, err)
	// run checker
	minmax.runIter(ctx)
	err = dc.waitForAppInsts(int(pt1.policy.MinActiveInstances))
	require.Nil(t, err)

	// reset back to 0
	pt1.policy.MinActiveInstances = 0
	pt1.policy.MaxInstances = 0
	pt1.updatePolicy(ctx)
	minmax.runIter(ctx)
	err = dc.waitForAppInsts(0)
	require.Nil(t, err)

	// set to reasonable settings
	pt1.policy.MinActiveInstances = 2
	pt1.policy.MaxInstances = 3
	pt1.updatePolicy(ctx)
	minmax.runIter(ctx)
	err = dc.waitForAppInsts(int(pt1.policy.MinActiveInstances))
	require.Nil(t, err)

	// simulate cloudlet offline, same as AppInst, will trigger
	// creating another AppInst.
	cloudletInfo0 := pt1.cloudletInfos[0]
	cloudletInfo0.State = edgeproto.CloudletState_CLOUDLET_STATE_OFFLINE
	cacheData.cloudletInfoCache.Update(ctx, &cloudletInfo0, 0)
	minmax.runIter(ctx)
	err = dc.waitForAppInsts(int(pt1.policy.MinActiveInstances) + 1)
	require.Nil(t, err)

	// simulate second cloudlet offline, same as AppInst,
	// can't trigger another AppInst create because it would
	// exceed max.
	require.Equal(t, pt1.policy.MaxInstances, pt1.policy.MinActiveInstances+1)
	cloudletInfo1 := pt1.cloudletInfos[1]
	cloudletInfo1.State = edgeproto.CloudletState_CLOUDLET_STATE_OFFLINE
	cacheData.cloudletInfoCache.Update(ctx, &cloudletInfo1, 0)
	minmax.runIter(ctx)
	err = dc.waitForAppInsts(int(pt1.policy.MinActiveInstances) + 1)
	require.Nil(t, err)

	// reset cloudlets back online
	cloudletInfo0.State = edgeproto.CloudletState_CLOUDLET_STATE_READY
	cloudletInfo1.State = edgeproto.CloudletState_CLOUDLET_STATE_READY

	// reset back to 0
	pt1.policy.MinActiveInstances = 0
	pt1.policy.MaxInstances = 0
	pt1.updatePolicy(ctx)
	minmax.runIter(ctx)
	err = dc.waitForAppInsts(0)
	require.Nil(t, err)

	// set to reasonable settings
	pt1.policy.MinActiveInstances = 2
	pt1.policy.MaxInstances = 4
	pt1.updatePolicy(ctx)
	minmax.runIter(ctx)
	err = dc.waitForAppInsts(int(pt1.policy.MinActiveInstances))
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
	cloudlet0.MaintenanceState = edgeproto.MaintenanceState_FAILOVER_REQUESTED
	cacheData.cloudletCache.Update(ctx, &cloudlet0, 0)

	minmax.runIter(ctx)
	err = dc.waitForAppInsts(int(pt1.policy.MinActiveInstances) + 1)
	require.Nil(t, err)
	select {
	case failover := <-failovers:
		require.Equal(t, cloudlet0.Key, failover.Key)
		require.Equal(t, edgeproto.MaintenanceState_FAILOVER_DONE, failover.MaintenanceState)
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
	cloudlet1.MaintenanceState = edgeproto.MaintenanceState_FAILOVER_REQUESTED
	cacheData.cloudletCache.Update(ctx, &cloudlet1, 0)
	minmax.runIter(ctx)
	select {
	case failover := <-failovers:
		require.Equal(t, cloudlet1.Key, failover.Key)
		require.Equal(t, edgeproto.MaintenanceState_FAILOVER_ERROR, failover.MaintenanceState)
		require.Equal(t, 1, len(failover.Errors))
		require.Contains(t, failover.Errors[0], "Some error")
	case <-time.After(2 * time.Second):
		require.Fail(t, "timeout waiting for AutoProvInfo")
	}
	dc.failCreate = false

	// set cloudlet2 to maintenance mode, will trigger
	// failures because we can't meed min of 2 (3 of 4 cloudlets down)
	cloudlet2 := pt1.cloudlets[2]
	cloudlet2.MaintenanceState = edgeproto.MaintenanceState_FAILOVER_REQUESTED
	cacheData.cloudletCache.Update(ctx, &cloudlet2, 0)

	minmax.runIter(ctx)
	select {
	case failover := <-failovers:
		require.Equal(t, cloudlet2.Key, failover.Key)
		require.Equal(t, edgeproto.MaintenanceState_FAILOVER_ERROR, failover.MaintenanceState)
		require.Equal(t, 1, len(failover.Errors))
		require.Contains(t, failover.Errors[0], "Not enough potential cloudlets to deploy to")
	case <-time.After(2 * time.Second):
		require.Fail(t, "timeout waiting for AutoProvInfo")
	}

	// move cloudlets out of maintenance
	cloudlet0.MaintenanceState = edgeproto.MaintenanceState_NORMAL_OPERATION
	cloudlet1.MaintenanceState = edgeproto.MaintenanceState_NORMAL_OPERATION
	cloudlet2.MaintenanceState = edgeproto.MaintenanceState_NORMAL_OPERATION

	// reset back to 0
	pt1.policy.MinActiveInstances = 0
	pt1.policy.MaxInstances = 0
	pt1.updatePolicy(ctx)
	minmax.runIter(ctx)
	err = dc.waitForAppInsts(0)
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
	minmax.runIter(ctx)
	err = dc.waitForAppInsts(int(pt1.policy.MinActiveInstances))
	require.Nil(t, err)

	// delete manually created AppInst - will then create another
	// to meet min
	dc.deleteAppInst(ctx, &insts[0])
	minmax.runIter(ctx)
	err = dc.waitForAppInsts(int(pt1.policy.MinActiveInstances))
	require.Nil(t, err)

	// remove cloudlets from policy - will delete all
	// auto-provisioned AppInsts regardless of min because they are on
	// cloudlets not specified by any policy.
	pt1.policy.Cloudlets = nil
	pt1.updatePolicy(ctx)
	minmax.runIter(ctx)
	err = dc.waitForAppInsts(0)
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
		s.cloudletInfos[ii].State = edgeproto.CloudletState_CLOUDLET_STATE_READY
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
		inst.Key.ClusterInstKey = s.clusterInsts[ii].Key
		insts = append(insts, inst)
	}
	return insts
}
