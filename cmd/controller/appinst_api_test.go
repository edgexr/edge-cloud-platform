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
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/objstore"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	pfutils "github.com/edgexr/edge-cloud-platform/pkg/platform/utils"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
	"github.com/stretchr/testify/require"
	"go.etcd.io/etcd/client/v3/concurrency"
	"google.golang.org/grpc"
)

var (
	Pass bool = true
	Fail bool = false
)

type StreamoutMsg struct {
	Msgs []edgeproto.Result
	grpc.ServerStream
	Ctx context.Context
}

func (x *StreamoutMsg) Send(msg *edgeproto.Result) error {
	x.Msgs = append(x.Msgs, *msg)
	return nil
}

func (x *StreamoutMsg) Context() context.Context {
	return x.Ctx
}

func NewStreamoutMsg(ctx context.Context) *StreamoutMsg {
	return &StreamoutMsg{
		Ctx: ctx,
	}
}

func GetAppInstStreamMsgs(t *testing.T, ctx context.Context, key *edgeproto.AppInstKey, apis *AllApis, pass bool) []edgeproto.Result {
	// Verify stream appInst
	streamAppInst := NewStreamoutMsg(ctx)
	err := apis.streamObjApi.StreamAppInst(key, streamAppInst)
	if pass {
		require.Nil(t, err, "stream appinst")
		require.Greater(t, len(streamAppInst.Msgs), 0, "contains stream messages")
	} else {
		require.NotNil(t, err, "stream appinst should return error for key %s", *key)
	}
	return streamAppInst.Msgs
}

func GetClusterInstStreamMsgs(t *testing.T, ctx context.Context, key *edgeproto.ClusterInstKey, apis *AllApis, pass bool) []edgeproto.Result {
	// Verify stream clusterInst
	streamClusterInst := NewStreamoutMsg(ctx)
	err := apis.streamObjApi.StreamClusterInst(key, streamClusterInst)
	if pass {
		require.Nil(t, err, "stream clusterinst")
		require.Greater(t, len(streamClusterInst.Msgs), 0, "contains stream messages")
	} else {
		require.NotNil(t, err, "stream clusterinst should return error")
	}
	return streamClusterInst.Msgs
}

func GetCloudletStreamMsgs(t *testing.T, ctx context.Context, key *edgeproto.CloudletKey, apis *AllApis) []edgeproto.Result {
	// Verify stream cloudlet
	streamCloudlet := NewStreamoutMsg(ctx)
	err := apis.streamObjApi.StreamCloudlet(key, streamCloudlet)
	require.Nil(t, err, "stream cloudlet")
	require.Greater(t, len(streamCloudlet.Msgs), 0, "contains stream messages")
	return streamCloudlet.Msgs
}

func TestAppInstApi(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())
	appDnsRoot := "testappinstapi.net"
	*appDNSRoot = appDnsRoot
	testSvcs := testinit(ctx, t)
	defer testfinish(testSvcs)

	dummy := dummyEtcd{}
	dummy.Start()
	defer dummy.Stop()

	sync := InitSync(&dummy)
	apis := NewAllApis(sync)
	sync.Start()
	defer sync.Done()
	responder := DefaultDummyInfoResponder(apis)
	responder.InitDummyInfoResponder()

	reduceInfoTimeouts(t, ctx, apis)

	// cannote create instances without apps and cloudlets
	for _, data := range testutil.AppInstData() {
		obj := data
		err := apis.appInstApi.CreateAppInst(&obj, testutil.NewCudStreamoutAppInst(ctx))
		require.NotNil(t, err, "Create app inst without apps/cloudlets")
		// Verify stream AppInst fails
		GetAppInstStreamMsgs(t, ctx, &obj.Key, apis, Fail)
	}

	// create supporting data
	addTestPlatformFeatures(t, ctx, apis, testutil.PlatformFeaturesData())
	testutil.InternalFlavorCreate(t, apis.flavorApi, testutil.FlavorData())
	testutil.InternalGPUDriverCreate(t, apis.gpuDriverApi, testutil.GPUDriverData())
	testutil.InternalResTagTableCreate(t, apis.resTagTableApi, testutil.ResTagTableData())
	testutil.InternalCloudletCreate(t, apis.cloudletApi, testutil.CloudletData())
	insertCloudletInfo(ctx, apis, testutil.CloudletInfoData())
	testutil.InternalAutoProvPolicyCreate(t, apis.autoProvPolicyApi, testutil.AutoProvPolicyData())
	testutil.InternalAutoScalePolicyCreate(t, apis.autoScalePolicyApi, testutil.AutoScalePolicyData())
	testutil.InternalAppCreate(t, apis.appApi, testutil.AppData())
	testutil.InternalClusterInstCreate(t, apis.clusterInstApi, testutil.ClusterInstData())
	testutil.InternalCloudletRefsTest(t, "show", apis.cloudletRefsApi, testutil.CloudletRefsData())
	clusterInstCnt := len(apis.clusterInstApi.cache.Objs)
	require.Equal(t, len(testutil.ClusterInstData()), clusterInstCnt)

	// Set responder to fail. This should clean up the object after
	// the fake crm returns a failure. If it doesn't, the next test to
	// create all the app insts will fail.
	responder.SetSimulateAppCreateFailure(true)
	// clean up on failure may find ports inconsistent
	RequireAppInstPortConsistency = false
	for ii, data := range testutil.AppInstData() {
		obj := data // make new copy since range variable gets reused each iter
		if testutil.IsAutoClusterAutoDeleteApp(&obj) {
			continue
		}
		err := apis.appInstApi.CreateAppInst(&obj, testutil.NewCudStreamoutAppInst(ctx))
		require.NotNil(t, err, "Create app inst responder failures")
		// make sure error matches responder
		// if app-inst triggers auto-cluster, the error will be for a cluster
		if strings.Contains(err.Error(), "cluster inst") {
			require.Equal(t, "Encountered failures: crm create cluster inst failed", err.Error(), "AppInst[%d]: %v", ii, obj.Key)
		} else {
			require.Equal(t, "Encountered failures: crm create app inst failed", err.Error(), "AppInst[%d]: %v", ii, obj.Key)
		}
		// Verify that on error, undo deleted the appInst object from etcd
		show := testutil.ShowAppInst{}
		show.Init()
		err = apis.appInstApi.ShowAppInst(&obj, &show)
		require.Nil(t, err, "show app inst data")
		require.Equal(t, 0, len(show.Data))
		// Since appinst creation failed, object is deleted from etcd, stream obj should also be deleted
		GetAppInstStreamMsgs(t, ctx, &obj.Key, apis, Fail)
	}
	responder.SetSimulateAppCreateFailure(false)
	RequireAppInstPortConsistency = true
	require.Equal(t, 0, len(apis.appInstApi.cache.Objs))
	require.Equal(t, clusterInstCnt, len(apis.clusterInstApi.cache.Objs))
	testutil.InternalCloudletRefsTest(t, "show", apis.cloudletRefsApi, testutil.CloudletRefsData())

	testutil.InternalAppInstTest(t, "cud", apis.appInstApi, testutil.AppInstData(), testutil.WithCreatedAppInstTestData(testutil.CreatedAppInstData()))
	InternalAppInstCachedFieldsTest(t, ctx, apis)
	// check cluster insts created (includes explicit and auto)
	testutil.InternalClusterInstTest(t, "show", apis.clusterInstApi,
		append(testutil.ClusterInstData(), testutil.ClusterInstAutoData()...))
	require.Equal(t, len(testutil.ClusterInstData())+len(testutil.ClusterInstAutoData()), len(apis.clusterInstApi.cache.Objs))

	// after app insts create, check that cloudlet refs data is correct.
	// Note this refs data is a second set after app insts were created.
	testutil.InternalCloudletRefsTest(t, "show", apis.cloudletRefsApi, testutil.CloudletRefsWithAppInstsData())
	testutil.InternalAppInstRefsTest(t, "show", apis.appInstRefsApi, testutil.GetAppInstRefsData())

	// Test for being created and being deleted errors.
	testBeingErrors(t, ctx, responder, apis)

	commonApi := testutil.NewInternalAppInstApi(apis.appInstApi)

	// Set responder to fail delete.
	responder.SetSimulateAppDeleteFailure(true)
	obj := testutil.AppInstData()[0]
	err := apis.appInstApi.DeleteAppInst(&obj, testutil.NewCudStreamoutAppInst(ctx))
	require.NotNil(t, err, "Delete AppInst responder failure")
	responder.SetSimulateAppDeleteFailure(false)
	checkAppInstState(t, ctx, commonApi, &obj, edgeproto.TrackedState_READY)
	testutil.InternalAppInstRefsTest(t, "show", apis.appInstRefsApi, testutil.GetAppInstRefsData())
	// As there was some progress, there should be some messages in stream
	msgs := GetAppInstStreamMsgs(t, ctx, &obj.Key, apis, Fail)
	require.Greater(t, len(msgs), 0, "some progress messages before failure")

	obj = testutil.AppInstData()[0]
	// check override of error DELETE_ERROR
	err = forceAppInstState(ctx, &obj, edgeproto.TrackedState_DELETE_ERROR, responder, apis)
	require.Nil(t, err, "force state")
	checkAppInstState(t, ctx, commonApi, &obj, edgeproto.TrackedState_DELETE_ERROR)
	err = apis.appInstApi.CreateAppInst(&obj, testutil.NewCudStreamoutAppInst(ctx))
	require.Nil(t, err, "create overrides delete error")
	checkAppInstState(t, ctx, commonApi, &obj, edgeproto.TrackedState_READY)
	testutil.InternalAppInstRefsTest(t, "show", apis.appInstRefsApi, testutil.GetAppInstRefsData())
	// As there was progress, there should be some messages in stream
	msgs = GetAppInstStreamMsgs(t, ctx, &obj.Key, apis, Pass)
	require.Greater(t, len(msgs), 0, "progress messages")

	// check override of error CREATE_ERROR
	err = forceAppInstState(ctx, &obj, edgeproto.TrackedState_CREATE_ERROR, responder, apis)
	require.Nil(t, err, "force state")
	checkAppInstState(t, ctx, commonApi, &obj, edgeproto.TrackedState_CREATE_ERROR)
	err = apis.appInstApi.DeleteAppInst(&obj, testutil.NewCudStreamoutAppInst(ctx))
	require.Nil(t, err, "delete overrides create error")
	checkAppInstState(t, ctx, commonApi, &obj, edgeproto.TrackedState_NOT_PRESENT)
	// Verify that on error, undo deleted the appInst object from etcd
	show := testutil.ShowAppInst{}
	show.Init()
	err = apis.appInstApi.ShowAppInst(&obj, &show)
	require.Nil(t, err, "show app inst data")
	require.Equal(t, 0, len(show.Data))
	// Stream should be empty, as object is deleted from etcd
	GetAppInstStreamMsgs(t, ctx, &obj.Key, apis, Fail)
	// create copy of refs without the deleted AppInst
	appInstRefsDeleted := append([]edgeproto.AppInstRefs{}, testutil.GetAppInstRefsData()...)
	appInstRefsDeleted[0].Insts = make(map[string]uint32)
	for k, v := range testutil.GetAppInstRefsData()[0].Insts {
		if k == obj.Key.GetKeyString() {
			continue
		}
		appInstRefsDeleted[0].Insts[k] = v
	}
	testutil.InternalAppInstRefsTest(t, "show", apis.appInstRefsApi, appInstRefsDeleted)

	// check override of error UPDATE_ERROR
	err = apis.appInstApi.CreateAppInst(&obj, testutil.NewCudStreamoutAppInst(ctx))
	require.Nil(t, err, "create appinst")
	checkAppInstState(t, ctx, commonApi, &obj, edgeproto.TrackedState_READY)
	err = forceAppInstState(ctx, &obj, edgeproto.TrackedState_UPDATE_ERROR, responder, apis)
	require.Nil(t, err, "force state")
	checkAppInstState(t, ctx, commonApi, &obj, edgeproto.TrackedState_UPDATE_ERROR)
	err = apis.appInstApi.DeleteAppInst(&obj, testutil.NewCudStreamoutAppInst(ctx))
	require.Nil(t, err, "delete overrides create error")
	checkAppInstState(t, ctx, commonApi, &obj, edgeproto.TrackedState_NOT_PRESENT)
	testutil.InternalAppInstRefsTest(t, "show", apis.appInstRefsApi, appInstRefsDeleted)

	// override CRM error
	responder.SetSimulateAppCreateFailure(true)
	responder.SetSimulateAppDeleteFailure(true)
	obj = testutil.AppInstData()[0]
	obj.CrmOverride = edgeproto.CRMOverride_IGNORE_CRM_ERRORS
	err = apis.appInstApi.CreateAppInst(&obj, testutil.NewCudStreamoutAppInst(ctx))
	require.Nil(t, err, "override crm error")
	obj = testutil.AppInstData()[0]
	obj.CrmOverride = edgeproto.CRMOverride_IGNORE_CRM_ERRORS
	err = apis.appInstApi.DeleteAppInst(&obj, testutil.NewCudStreamoutAppInst(ctx))
	require.Nil(t, err, "override crm error")

	// ignore CRM
	obj = testutil.AppInstData()[0]
	obj.CrmOverride = edgeproto.CRMOverride_IGNORE_CRM
	err = apis.appInstApi.CreateAppInst(&obj, testutil.NewCudStreamoutAppInst(ctx))
	require.Nil(t, err, "ignore crm")
	obj = testutil.AppInstData()[0]
	obj.CrmOverride = edgeproto.CRMOverride_IGNORE_CRM
	err = apis.appInstApi.DeleteAppInst(&obj, testutil.NewCudStreamoutAppInst(ctx))
	require.Nil(t, err, "ignore crm")
	responder.SetSimulateAppCreateFailure(false)
	responder.SetSimulateAppDeleteFailure(false)

	// ignore CRM and transient state on delete of AppInst
	responder.SetSimulateAppDeleteFailure(true)
	for val, stateName := range edgeproto.TrackedState_name {
		state := edgeproto.TrackedState(val)
		if !edgeproto.IsTransientState(state) {
			continue
		}
		obj = testutil.AppInstData()[0]
		err = apis.appInstApi.CreateAppInst(&obj, testutil.NewCudStreamoutAppInst(ctx))
		require.Nil(t, err, "create AppInst")
		err = forceAppInstState(ctx, &obj, state, responder, apis)
		require.Nil(t, err, "force state")
		checkAppInstState(t, ctx, commonApi, &obj, state)
		obj = testutil.AppInstData()[0]
		obj.CrmOverride = edgeproto.CRMOverride_IGNORE_CRM_AND_TRANSIENT_STATE
		err = apis.appInstApi.DeleteAppInst(&obj, testutil.NewCudStreamoutAppInst(ctx))
		require.Nil(t, err, "override crm and transient state %s", stateName)
	}
	responder.SetSimulateAppDeleteFailure(false)

	testAppInstOverrideTransientDelete(t, ctx, commonApi, responder, apis)

	// Test Fqdn prefix
	for _, data := range apis.appInstApi.cache.Objs {
		obj := data.Obj
		app_name := util.K8SSanitize(obj.AppKey.Name + obj.AppKey.Version)
		if obj.AppKey.Name == "helmApp" || obj.AppKey.Name == "vm lb" {
			continue
		}
		cloudlet := edgeproto.Cloudlet{}
		found := apis.cloudletApi.cache.Get(&obj.Key.CloudletKey, &cloudlet)
		require.True(t, found)
		features := edgeproto.PlatformFeatures{}
		operator := obj.Key.CloudletKey.Organization

		for _, port := range obj.MappedPorts {
			lproto, err := edgeproto.LProtoStr(port.Proto)
			if err != nil {
				continue
			}
			if lproto == "http" {
				continue
			}
			test_prefix := ""
			if isIPAllocatedPerService(ctx, cloudlet.PlatformType, &features, operator) {
				test_prefix = fmt.Sprintf("%s-%s-", util.DNSSanitize(app_name), lproto)
			}
			require.Equal(t, test_prefix, port.FqdnPrefix, "check port fqdn prefix")
		}
	}

	// test appint create with overlapping ports
	obj = testutil.AppInstData()[0]
	obj.AppKey = testutil.AppData()[1].Key
	err = apis.appInstApi.CreateAppInst(&obj, testutil.NewCudStreamoutAppInst(ctx))
	require.NotNil(t, err, "Overlapping ports would trigger an app inst create failure")
	require.Contains(t, err.Error(), "port 80 is already in use")

	// delete all AppInsts and Apps and check that refs are empty
	for ii, data := range testutil.AppInstData() {
		obj := data
		if ii == 0 {
			// skip AppInst[0], it was deleted earlier in the test
			continue
		}
		if testutil.IsAutoClusterAutoDeleteApp(&obj) {
			continue
		}
		err := apis.appInstApi.DeleteAppInst(&obj, testutil.NewCudStreamoutAppInst(ctx))
		require.Nil(t, err, "Delete app inst %d failed", ii)
	}

	testAppInstId(t, ctx, apis)
	testAppFlavorRequest(t, ctx, commonApi, responder, apis)
	testSingleKubernetesCloudlet(t, ctx, apis, appDnsRoot)

	// cleanup unused reservable auto clusters
	apis.clusterInstApi.cleanupIdleReservableAutoClusters(ctx, time.Duration(0))
	apis.clusterInstApi.cleanupWorkers.WaitIdle()

	for ii, data := range testutil.AppData() {
		obj := data
		_, err := apis.appApi.DeleteApp(ctx, &obj)
		require.Nil(t, err, "Delete app %d: %s failed", ii, obj.Key.GetKeyString())
	}
	testutil.InternalAppInstRefsTest(t, "show", apis.appInstRefsApi, []edgeproto.AppInstRefs{})
	// ensure that no open channels exist and all stream channels were cleaned up
	chs, err := redisClient.PubSubChannels(ctx, "*").Result()
	require.Nil(t, err, "get pubsub channels")
	require.Equal(t, 0, len(chs), "all chans are cleaned up")
}

func appInstCachedFieldsTest(t *testing.T, ctx context.Context, cAppApi *testutil.AppCommonApi, cCloudletApi *testutil.CloudletCommonApi, cAppInstApi *testutil.AppInstCommonApi) {
	// test assumes test data has already been loaded

	// update app and check that app insts are updated
	updater := edgeproto.App{}
	updater.Key = testutil.AppData()[0].Key
	newPath := "resources: a new config"
	updater.AndroidPackageName = newPath
	updater.Fields = make([]string, 0)
	updater.Fields = append(updater.Fields, edgeproto.AppFieldAndroidPackageName)
	_, err := cAppApi.UpdateApp(ctx, &updater)
	require.Nil(t, err, "Update app")

	show := testutil.ShowAppInst{}
	show.Init()
	filter := edgeproto.AppInst{}
	filter.AppKey = testutil.AppData()[0].Key
	err = cAppInstApi.ShowAppInst(ctx, &filter, &show)
	require.Nil(t, err, "show app inst data")
	require.True(t, len(show.Data) > 0, "number of matching app insts")

	// update cloudlet and check that app insts are updated
	updater2 := edgeproto.Cloudlet{}
	updater2.Key = testutil.CloudletData()[0].Key
	newLat := 52.84583
	updater2.Location.Latitude = newLat
	updater2.Fields = make([]string, 0)
	updater2.Fields = append(updater2.Fields, edgeproto.CloudletFieldLocationLatitude)
	_, err = cCloudletApi.UpdateCloudlet(ctx, &updater2)
	require.Nil(t, err, "Update cloudlet")

	show.Init()
	filter = edgeproto.AppInst{}
	filter.Key.CloudletKey = testutil.CloudletData()[0].Key
	err = cAppInstApi.ShowAppInst(ctx, &filter, &show)
	require.Nil(t, err, "show app inst data")
	for _, inst := range show.Data {
		require.Equal(t, newLat, inst.CloudletLoc.Latitude, "check app inst latitude")
	}
	require.True(t, len(show.Data) > 0, "number of matching app insts")
}

func InternalAppInstCachedFieldsTest(t *testing.T, ctx context.Context, apis *AllApis) {
	cAppApi := testutil.NewInternalAppApi(apis.appApi)
	cCloudletApi := testutil.NewInternalCloudletApi(apis.cloudletApi)
	cAppInstApi := testutil.NewInternalAppInstApi(apis.appInstApi)
	appInstCachedFieldsTest(t, ctx, cAppApi, cCloudletApi, cAppInstApi)
}

func ClientAppInstCachedFieldsTest(t *testing.T, ctx context.Context, appApi edgeproto.AppApiClient, cloudletApi edgeproto.CloudletApiClient, appInstApi edgeproto.AppInstApiClient) {
	cAppApi := testutil.NewClientAppApi(appApi)
	cCloudletApi := testutil.NewClientCloudletApi(cloudletApi)
	cAppInstApi := testutil.NewClientAppInstApi(appInstApi)
	appInstCachedFieldsTest(t, ctx, cAppApi, cCloudletApi, cAppInstApi)
}

func TestAutoClusterInst(t *testing.T) {
	log.InitTracer(nil)
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())
	testSvcs := testinit(ctx, t)
	defer testfinish(testSvcs)

	dummy := dummyEtcd{}
	dummy.Start()

	sync := InitSync(&dummy)
	apis := NewAllApis(sync)
	sync.Start()
	defer sync.Done()
	dummyResponder := DefaultDummyInfoResponder(apis)
	dummyResponder.InitDummyInfoResponder()

	reduceInfoTimeouts(t, ctx, apis)

	// create supporting data
	addTestPlatformFeatures(t, ctx, apis, testutil.PlatformFeaturesData())
	testutil.InternalFlavorCreate(t, apis.flavorApi, testutil.FlavorData())
	testutil.InternalGPUDriverCreate(t, apis.gpuDriverApi, testutil.GPUDriverData())
	testutil.InternalResTagTableCreate(t, apis.resTagTableApi, testutil.ResTagTableData())
	testutil.InternalCloudletCreate(t, apis.cloudletApi, testutil.CloudletData())
	insertCloudletInfo(ctx, apis, testutil.CloudletInfoData())
	testutil.InternalAutoProvPolicyCreate(t, apis.autoProvPolicyApi, testutil.AutoProvPolicyData())
	testutil.InternalAppCreate(t, apis.appApi, testutil.AppData())
	// multi-tenant ClusterInst
	mt := testutil.ClusterInstData()[8]
	require.True(t, mt.MultiTenant)
	// negative tests
	// bad Organization
	mtBad := mt
	mtBad.Key.ClusterKey.Organization = "foo"
	err := apis.clusterInstApi.CreateClusterInst(&mtBad, testutil.NewCudStreamoutClusterInst(ctx))
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Only edgecloudorg ClusterInsts may be multi-tenant")
	// bad deployment type
	mtBad = mt
	mtBad.Deployment = cloudcommon.DeploymentTypeDocker
	err = apis.clusterInstApi.CreateClusterInst(&mtBad, testutil.NewCudStreamoutClusterInst(ctx))
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Multi-tenant clusters must be of deployment type Kubernetes")

	// Create multi-tenant ClusterInst before reservable tests.
	// Reservable tests should pass without using multi-tenant because
	// the App's SupportMultiTenant is false.
	err = apis.clusterInstApi.CreateClusterInst(&mt, testutil.NewCudStreamoutClusterInst(ctx))
	require.Nil(t, err)

	checkReserved := func(cloudletKey edgeproto.CloudletKey, found bool, id, reservedBy string) {
		key := &edgeproto.ClusterInstKey{}
		key.ClusterKey.Name = cloudcommon.ReservableClusterPrefix + id
		key.CloudletKey = cloudletKey
		key.ClusterKey.Organization = edgeproto.OrganizationEdgeCloud
		// look up reserved ClusterInst
		clusterInst := edgeproto.ClusterInst{}
		actualFound := apis.clusterInstApi.Get(key, &clusterInst)
		require.Equal(t, found, actualFound, "lookup %s", key.GetKeyString())
		if !found {
			return
		}
		require.True(t, clusterInst.Auto, "clusterinst is auto")
		require.True(t, clusterInst.Reservable, "clusterinst is reservable")
		require.Equal(t, reservedBy, clusterInst.ReservedBy, "reserved by matches")
		// Progress message should be there for cluster instance itself
		msgs := GetClusterInstStreamMsgs(t, ctx, key, apis, Pass)
		require.Greater(t, len(msgs), 0, "some progress messages")
	}
	createAutoClusterAppInst := func(copy edgeproto.AppInst, expectedId string) {
		copy.Key.Name += expectedId
		err := apis.appInstApi.CreateAppInst(&copy, testutil.NewCudStreamoutAppInst(ctx))
		require.Nil(t, err, "create app inst")
		// As there was some progress, there should be some messages in stream
		msgs := GetAppInstStreamMsgs(t, ctx, &copy.Key, apis, Pass)
		require.Greater(t, len(msgs), 0, "some progress messages")
		// Check that reserved ClusterInst was created
		checkReserved(copy.Key.CloudletKey, true, expectedId, copy.Key.Organization)
		// check for expected cluster name.
		require.Equal(t, cloudcommon.ReservableClusterPrefix+expectedId, copy.ClusterKey.Name)
	}
	deleteAutoClusterAppInst := func(copy edgeproto.AppInst, id string) {
		// delete appinst
		copy.Key.Name += id
		err := apis.appInstApi.DeleteAppInst(&copy, testutil.NewCudStreamoutAppInst(ctx))
		require.Nil(t, err, "delete app inst")
		checkReserved(copy.Key.CloudletKey, true, id, "")
	}
	checkReservedIds := func(key edgeproto.CloudletKey, expected uint64) {
		refs := edgeproto.CloudletRefs{}
		found := apis.cloudletRefsApi.cache.Get(&key, &refs)
		require.True(t, found)
		require.Equal(t, expected, refs.ReservedAutoClusterIds)
	}

	// create auto-cluster AppInsts
	appInst := testutil.AppInstData()[0]
	appInst.AppKey = testutil.AppData()[1].Key // does not support multi-tenant
	appInst.ClusterKey = edgeproto.ClusterKey{}
	cloudletKey := appInst.Key.CloudletKey
	createAutoClusterAppInst(appInst, "0")
	checkReservedIds(cloudletKey, 1)
	createAutoClusterAppInst(appInst, "1")
	checkReservedIds(cloudletKey, 3)
	createAutoClusterAppInst(appInst, "2")
	checkReservedIds(cloudletKey, 7)
	// delete one
	deleteAutoClusterAppInst(appInst, "1")
	checkReservedIds(cloudletKey, 7) // clusterinst doesn't get deleted
	// create again, should reuse existing free ClusterInst
	createAutoClusterAppInst(appInst, "1")
	checkReservedIds(cloudletKey, 7)
	// delete one again
	deleteAutoClusterAppInst(appInst, "1")
	checkReservedIds(cloudletKey, 7) // clusterinst doesn't get deleted
	// cleanup unused reservable auto clusters
	apis.clusterInstApi.cleanupIdleReservableAutoClusters(ctx, time.Duration(0))
	apis.clusterInstApi.cleanupWorkers.WaitIdle()
	checkReserved(cloudletKey, false, "1", "")
	checkReservedIds(cloudletKey, 5)
	// create again, should create new ClusterInst with next free id
	createAutoClusterAppInst(appInst, "1")
	checkReservedIds(cloudletKey, 7)
	// delete all of them
	deleteAutoClusterAppInst(appInst, "0")
	deleteAutoClusterAppInst(appInst, "1")
	deleteAutoClusterAppInst(appInst, "2")
	checkReservedIds(cloudletKey, 7)
	// cleanup unused reservable auto clusters
	apis.clusterInstApi.cleanupIdleReservableAutoClusters(ctx, time.Duration(0))
	apis.clusterInstApi.cleanupWorkers.WaitIdle()
	checkReserved(cloudletKey, false, "0", "")
	checkReserved(cloudletKey, false, "1", "")
	checkReserved(cloudletKey, false, "2", "")
	checkReservedIds(cloudletKey, 0)

	// Autocluster AppInst with AutoDelete delete option should fail
	autoDeleteAppInst := testutil.AppInstData()[10]
	autoDeleteAppInst.ClusterKey.Name = ""
	err = apis.appInstApi.CreateAppInst(&autoDeleteAppInst, testutil.NewCudStreamoutAppInst(ctx))
	require.NotNil(t, err, "create autodelete appInst")
	require.Contains(t, err.Error(), "Sidecar AppInst (AutoDelete App) must specify the Cluster name and organization to deploy to")
	// Verify that on error, undo deleted the appInst object from etcd
	show := testutil.ShowAppInst{}
	show.Init()
	err = apis.appInstApi.ShowAppInst(&autoDeleteAppInst, &show)
	require.Nil(t, err, "show app inst data")
	require.Equal(t, 0, len(show.Data))
	// Stream should not exist, as object deleted from etcd as part of undo
	GetAppInstStreamMsgs(t, ctx, &autoDeleteAppInst.Key, apis, Fail)

	err = apis.clusterInstApi.DeleteClusterInst(&mt, testutil.NewCudStreamoutClusterInst(ctx))
	require.Nil(t, err)

	dummy.Stop()
}

func checkAppInstState(t *testing.T, ctx context.Context, api *testutil.AppInstCommonApi, in *edgeproto.AppInst, state edgeproto.TrackedState) {
	out := edgeproto.AppInst{}
	found := testutil.GetAppInst(t, ctx, api, &in.Key, &out)
	if state == edgeproto.TrackedState_NOT_PRESENT {
		require.False(t, found, "get app inst")
	} else {
		require.True(t, found, "get app inst")
		require.Equal(t, state, out.State, "app inst state")
	}
}

func forceAppInstState(ctx context.Context, in *edgeproto.AppInst, state edgeproto.TrackedState, responder *DummyInfoResponder, apis *AllApis) error {
	if responder != nil {
		// disable responder, otherwise it will respond to certain states
		// and change the current state
		responder.enable = false
		defer func() {
			responder.enable = true
		}()
	}
	err := apis.appInstApi.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		obj := edgeproto.AppInst{}
		if !apis.appInstApi.store.STMGet(stm, &in.Key, &obj) {
			return in.Key.NotFoundError()
		}
		obj.State = state
		apis.appInstApi.store.STMPut(stm, &obj)
		return nil
	})
	return err
}

func testAppFlavorRequest(t *testing.T, ctx context.Context, api *testutil.AppInstCommonApi, responder *DummyInfoResponder, apis *AllApis) {
	// Non-nomial test, request an optional resource from a cloudlet that offers none.
	var testflavor = edgeproto.Flavor{
		Key: edgeproto.FlavorKey{
			Name: "x1.large-mex",
		},
		Ram:       8192,
		Vcpus:     8,
		Disk:      40,
		OptResMap: map[string]string{"gpu": "gpu:1"},
	}
	_, err := apis.flavorApi.CreateFlavor(ctx, &testflavor)
	require.Nil(t, err, "CreateFlavor")
	nonNomApp := testutil.AppInstData()[2]
	nonNomApp.Flavor = testflavor.Key
	err = apis.appInstApi.CreateAppInst(&nonNomApp, testutil.NewCudStreamoutAppInst(ctx))
	require.NotNil(t, err, "non-nom-app-create")
	require.Equal(t, "Cloudlet New York Site doesn't support GPU", err.Error())
}

// Test that Crm Override for Delete App overrides any failures
// on both side-car auto-apps and an underlying auto-cluster.
func testAppInstOverrideTransientDelete(t *testing.T, ctx context.Context, api *testutil.AppInstCommonApi, responder *DummyInfoResponder, apis *AllApis) {
	// autocluster app
	appKey := testutil.AppData()[0].Key
	ai := edgeproto.AppInst{
		Key: edgeproto.AppInstKey{
			Name:         "testApp",
			Organization: appKey.Organization,
			CloudletKey:  testutil.CloudletData()[1].Key,
		},
		AppKey: appKey,
	}
	// autoapp
	require.Equal(t, edgeproto.DeleteType_AUTO_DELETE, testutil.AppData()[9].DelOpt)
	aiautoAppKey := testutil.AppData()[9].Key // auto-delete app
	aiauto := edgeproto.AppInst{
		Key: edgeproto.AppInstKey{
			Name:         "autoDeleteInst",
			Organization: aiautoAppKey.Organization,
			CloudletKey:  ai.Key.CloudletKey,
		},
		AppKey: aiautoAppKey,
	}
	var err error
	var obj edgeproto.AppInst
	var clust edgeproto.ClusterInst
	clustApi := testutil.NewInternalClusterInstApi(apis.clusterInstApi)

	responder.SetSimulateAppDeleteFailure(true)
	responder.SetSimulateClusterDeleteFailure(true)
	for val, stateName := range edgeproto.TrackedState_name {
		state := edgeproto.TrackedState(val)
		if !edgeproto.IsTransientState(state) {
			continue
		}
		// create app (also creates clusterinst)
		obj = ai
		err = apis.appInstApi.CreateAppInst(&obj, testutil.NewCudStreamoutAppInst(ctx))
		require.Nil(t, err, "create AppInst")
		err = forceAppInstState(ctx, &obj, state, responder, apis)
		require.Nil(t, err, "force state")
		checkAppInstState(t, ctx, api, &obj, state)

		// set aiauto cluster name from real cluster name of create autocluster
		clKey := obj.ClusterInstKey()
		obj = aiauto
		obj.ClusterKey = clKey.ClusterKey
		// create auto app
		err = apis.appInstApi.CreateAppInst(&obj, testutil.NewCudStreamoutAppInst(ctx))
		require.Nil(t, err, "create AppInst on cluster %v", obj.ClusterKey)
		err = forceAppInstState(ctx, &obj, state, responder, apis)
		require.Nil(t, err, "force state")
		checkAppInstState(t, ctx, api, &obj, state)

		clust = edgeproto.ClusterInst{}
		clust.Key = *clKey
		err = forceClusterInstState(ctx, &clust, state, responder, apis)
		require.Nil(t, err, "force state")
		checkClusterInstState(t, ctx, clustApi, &clust, state)

		// delete app (to be able to delete reservable cluster)
		obj = ai
		obj.CrmOverride = edgeproto.CRMOverride_IGNORE_CRM_AND_TRANSIENT_STATE
		log.SpanLog(ctx, log.DebugLevelInfo, "test run appinst delete")
		err = apis.appInstApi.DeleteAppInst(&obj, testutil.NewCudStreamoutAppInst(ctx))
		require.Nil(t, err, "override crm and transient state %s", stateName)
		log.SpanLog(ctx, log.DebugLevelInfo, "test appinst deleted")

		// delete cluster (should also delete auto app)
		clust.CrmOverride = edgeproto.CRMOverride_IGNORE_CRM_AND_TRANSIENT_STATE
		log.SpanLog(ctx, log.DebugLevelInfo, "test run ClusterInst delete")
		err = apis.clusterInstApi.DeleteClusterInst(&clust, testutil.NewCudStreamoutClusterInst(ctx))
		require.Nil(t, err, "override crm and transient state %s", stateName)
		log.SpanLog(ctx, log.DebugLevelInfo, "test ClusterInst deleted")
		// make sure cluster got deleted (means apps also were deleted)
		found := testutil.GetClusterInst(t, ctx, clustApi, &clust.Key, &edgeproto.ClusterInst{})
		require.False(t, found)
	}

	responder.SetSimulateAppDeleteFailure(false)
	responder.SetSimulateClusterDeleteFailure(false)

}

func testSingleKubernetesCloudlet(t *testing.T, ctx context.Context, apis *AllApis, appDnsRoot string) {
	var err error
	var found bool
	// Single kubernetes cloudlets can be either multi-tenant,
	// or dedicated to a particular organization (which removes all
	// of the multi-tenant deployment restrictions on namespaces, etc).
	cloudletMT := edgeproto.Cloudlet{
		Key: edgeproto.CloudletKey{
			Organization: "unittest",
			Name:         "singlek8sMT",
		},
		IpSupport:     edgeproto.IpSupport_IP_SUPPORT_DYNAMIC,
		NumDynamicIps: 10,
		Location: dme.Loc{
			Latitude:  37.1231,
			Longitude: 94.123,
		},
		PlatformType: platform.PlatformTypeFakeSingleCluster,
		CrmOverride:  edgeproto.CRMOverride_IGNORE_CRM,
	}
	cloudletMTInfo := edgeproto.CloudletInfo{
		Key:                  cloudletMT.Key,
		State:                dme.CloudletState_CLOUDLET_STATE_READY,
		CompatibilityVersion: cloudcommon.GetCRMCompatibilityVersion(),
	}
	mtOrg := edgeproto.OrganizationEdgeCloud
	stOrg := testutil.AppInstData()[0].Key.Organization
	// Note: cloudcommon.DefaultMultiTenantCluster is for the MT cluster
	// on cloudlets with multiple k8s clusters and VMs.
	mtClust := cloudcommon.DefaultClust
	stClust := cloudcommon.DefaultClust

	cloudletST := cloudletMT
	cloudletST.Key.Name = "singlek8sST"
	cloudletST.SingleKubernetesClusterOwner = stOrg
	cloudletSTInfo := cloudletMTInfo
	cloudletSTInfo.Key = cloudletST.Key

	setupTests := []struct {
		desc         string
		cloudlet     *edgeproto.Cloudlet
		cloudletInfo *edgeproto.CloudletInfo
		ownerOrg     string
		mt           bool
	}{
		{"mt setup", &cloudletMT, &cloudletMTInfo, "", true},
		{"st setup", &cloudletST, &cloudletSTInfo, stOrg, false},
	}
	for _, test := range setupTests {
		clusterInstKey := getDefaultClustKey(test.cloudlet.Key, test.ownerOrg)
		// create cloudlet
		err = apis.cloudletApi.CreateCloudlet(test.cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
		require.Nil(t, err, test.desc)
		apis.cloudletInfoApi.Update(ctx, test.cloudletInfo, 0)
		// creating cloudlet also creates singleton cluster for cloudlet
		clusterInst := edgeproto.ClusterInst{}
		found = apis.clusterInstApi.Get(clusterInstKey, &clusterInst)
		require.True(t, found, test.desc)
		require.Equal(t, clusterInst.MultiTenant, test.mt)

		// trying to create clusterinst against cloudlets should fail
		tryClusterInst := edgeproto.ClusterInst{
			Key: edgeproto.ClusterInstKey{
				ClusterKey: edgeproto.ClusterKey{
					Name:         "someclust",
					Organization: "foo",
				},
			},
			Flavor:     testutil.FlavorData()[0].Key,
			NumMasters: 1,
			NumNodes:   2,
		}
		tryClusterInst.Key.CloudletKey = test.cloudlet.Key
		err = apis.clusterInstApi.CreateClusterInst(&tryClusterInst, testutil.NewCudStreamoutClusterInst(ctx))
		require.NotNil(t, err, test.desc)
		require.Contains(t, err.Error(), "only supports AppInst creates", test.desc)
	}

	// AppInst negative and positive tests
	// TODO: resource allocation failure...
	PASS := "PASS"
	dedicatedIp := true
	notDedicatedIp := false
	appInstCreateTests := []struct {
		desc        string
		aiIdx       int
		cloudlet    *edgeproto.Cloudlet
		clusterOrg  string
		clusterName string
		dedicatedIp bool
		uri         string
		errStr      string
	}{{
		"MT non-serverless app",
		3, &cloudletMT, mtOrg, "", notDedicatedIp, "",
		"Target cloudlet platform only supports serverless Apps",
	}, {
		"MT bad cluster org",
		0, &cloudletMT, "foo", "", notDedicatedIp, "",
		"Cluster organization must be set to " + mtOrg + " or left blank",
	}, {
		"MT bad cluster name",
		0, &cloudletMT, mtOrg, "foo", notDedicatedIp, "",
		"Cluster name for single kubernetes cluster cloudlet must be set to " + mtClust + " or left blank",
	}, {
		"ST bad cluster org", 0,
		&cloudletST, "foo", "", notDedicatedIp, "",
		"Cluster organization must be set to " + stOrg + " or left blank",
	}, {
		"ST bad cluster name", 0,
		&cloudletST, stOrg, "foo", notDedicatedIp, "",
		"Cluster name for single kubernetes cluster cloudlet must be set to " + stClust + " or left blank",
	}, {
		"MT specified correct cluster",
		0, &cloudletMT, mtOrg, mtClust, notDedicatedIp,
		"shared.singlek8smt-unittest.local." + appDnsRoot, PASS,
	}, {
		"MT any clust name blank org",
		0, &cloudletMT, "", "", notDedicatedIp,
		"shared.singlek8smt-unittest.local." + appDnsRoot, PASS,
	}, {
		"ST specified correct cluster",
		0, &cloudletST, stOrg, stClust, notDedicatedIp,
		"shared.singlek8sst-unittest.local." + appDnsRoot, PASS,
	}, {
		"ST blank clust name blank org",
		0, &cloudletST, "", "", notDedicatedIp,
		"shared.singlek8sst-unittest.local." + appDnsRoot, PASS,
	}, {
		"MT blank clust name dedicated",
		0, &cloudletMT, mtOrg, "", dedicatedIp,
		"pillimogo1-atlanticinc.singlek8smt-unittest.local." + appDnsRoot, PASS,
	}, {
		"ST blank clust name dedicated",
		0, &cloudletST, stOrg, "", dedicatedIp,
		"pillimogo1-atlanticinc.singlek8sst-unittest.local." + appDnsRoot, PASS,
	}, {
		"VM App",
		11, &cloudletST, "", "", notDedicatedIp, "",
		"Cannot deploy vm app to single kubernetes cloudlet",
	}, {
		"VM App",
		11, &cloudletMT, "", "", notDedicatedIp, "",
		"Cannot deploy vm app to single kubernetes cloudlet",
	}, {
		"Docker App",
		17, &cloudletST, "", "", notDedicatedIp, "",
		"Cannot deploy docker app to single kubernetes cloudlet",
	}, {
		"Docker App",
		17, &cloudletMT, "", "", notDedicatedIp, "",
		"Cannot deploy docker app to single kubernetes cloudlet",
	}}
	for _, test := range appInstCreateTests {
		ai := testutil.AppInstData()[test.aiIdx]
		ai.Key.CloudletKey = test.cloudlet.Key
		ai.ClusterKey.Name = test.clusterName
		ai.ClusterKey.Organization = test.clusterOrg
		ai.DedicatedIp = test.dedicatedIp
		err = apis.appInstApi.CreateAppInst(&ai, testutil.NewCudStreamoutAppInst(ctx))
		if test.errStr == PASS {
			require.Nil(t, err, test.desc)
			aiCheck := edgeproto.AppInst{}
			found := apis.appInstApi.cache.Get(&ai.Key, &aiCheck)
			require.True(t, found)
			require.Equal(t, test.uri, aiCheck.Uri, test.desc)
			// clean up
			err = apis.appInstApi.DeleteAppInst(&ai, testutil.NewCudStreamoutAppInst(ctx))
			require.Nil(t, err, test.desc)
		} else {
			require.NotNil(t, err, test.desc)
			require.Contains(t, err.Error(), test.errStr, test.desc)
		}
	}

	cleanupTests := []struct {
		desc     string
		cloudlet *edgeproto.Cloudlet
		ownerOrg string
	}{
		{"mt cleanup test", &cloudletMT, ""},
		{"st cleanup test", &cloudletST, stOrg},
	}
	for _, test := range cleanupTests {
		clusterInstKey := getDefaultClustKey(test.cloudlet.Key, test.ownerOrg)
		// Create AppInst
		ai := testutil.AppInstData()[0]
		ai.Key.Name = "blocker"
		ai.Key.CloudletKey = test.cloudlet.Key
		ai.ClusterKey.Name = ""
		ai.ClusterKey.Organization = ""
		err = apis.appInstApi.CreateAppInst(&ai, testutil.NewCudStreamoutAppInst(ctx))
		require.Nil(t, err, test.desc)

		// check refs
		refs := edgeproto.ClusterRefs{}
		found = apis.clusterRefsApi.cache.Get(clusterInstKey, &refs)
		require.True(t, found, test.desc)
		require.Equal(t, 1, len(refs.Apps), test.desc)
		refAiKey := ai.Key.GetRefKey()
		require.Equal(t, refAiKey, &refs.Apps[0], test.desc)

		// Test that delete cloudlet fails if AppInst exists
		test.cloudlet.CrmOverride = edgeproto.CRMOverride_IGNORE_CRM
		err = apis.cloudletApi.DeleteCloudlet(test.cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
		require.NotNil(t, err, test.desc)
		require.Contains(t, err.Error(), "Cloudlet in use by AppInst", test.desc)

		// delete AppInst
		err = apis.appInstApi.DeleteAppInst(&ai, testutil.NewCudStreamoutAppInst(ctx))
		require.Nil(t, err, test.desc)

		// now delete cloudlet should succeed
		test.cloudlet.CrmOverride = edgeproto.CRMOverride_IGNORE_CRM
		err = apis.cloudletApi.DeleteCloudlet(test.cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
		require.Nil(t, err, test.desc)

		// check that cluster and refs don't exist
		clusterInst := edgeproto.ClusterInst{}
		found = apis.clusterInstApi.Get(clusterInstKey, &clusterInst)
		require.False(t, found, test.desc)
		found = apis.clusterRefsApi.cache.Get(clusterInstKey, &refs)
		require.False(t, found, test.desc)
	}
}

func testAppInstId(t *testing.T, ctx context.Context, apis *AllApis) {
	var err error

	// Check that unique ids for AppInsts are unique.
	// In this case, we purposely name the Apps so that the generated
	// ids will conflict.
	// Both app Keys should dns sanitize to "ai1"
	app0 := testutil.AppData()[0]
	app0.Key.Name = "app"
	app0.Key.Version = "1.1.0"
	app0.AccessPorts = "tcp:81"

	app1 := app0
	app1.Key.Name = "app1"
	app1.Key.Version = "1.0"
	app0.AccessPorts = "tcp:82"

	appInst0 := testutil.AppInstData()[0]
	appInst0.Key.Name = "ai1"
	appInst0.AppKey = app0.Key

	appInst1 := appInst0
	appInst0.Key.Name = "ai.1"
	appInst1.AppKey = app1.Key

	// also create ClusterInsts because they share the same dns id
	// namespace as AppInsts
	cl0 := testutil.ClusterInstData()[0]
	cl0.Key.ClusterKey.Name = appInst0.Key.Name
	cl0.Key.ClusterKey.Organization = app0.Key.Organization

	cl1 := cl0
	cl1.Key.ClusterKey.Name = appInst1.Key.Name
	cl1.Key.ClusterKey.Organization = app1.Key.Organization

	expId0 := "atlanticinc-ai1-sanjosesite-ufgtinc"
	expId1 := "atlanticinc-ai1-sanjosesite-ufgtinc-1"

	dnsLabel0 := "ai1-atlanticinc"
	dnsLabel1 := "ai1-atlanticinc1"

	clDnsLabel0 := "ai1-atlanticinc2"
	clDnsLabel1 := "ai1-atlanticinc3"

	_, err = apis.appApi.CreateApp(ctx, &app0)
	require.Nil(t, err)
	_, err = apis.appApi.CreateApp(ctx, &app1)
	require.Nil(t, err)

	err = apis.appInstApi.CreateAppInst(&appInst0, testutil.NewCudStreamoutAppInst(ctx))
	require.Nil(t, err)
	err = apis.appInstApi.CreateAppInst(&appInst1, testutil.NewCudStreamoutAppInst(ctx))
	require.Nil(t, err)

	aiCheck0 := edgeproto.AppInst{}
	require.True(t, apis.appInstApi.cache.Get(&appInst0.Key, &aiCheck0))
	require.Equal(t, expId0, aiCheck0.UniqueId)
	require.Equal(t, dnsLabel0, aiCheck0.DnsLabel)

	aiCheck1 := edgeproto.AppInst{}
	require.True(t, apis.appInstApi.cache.Get(&appInst1.Key, &aiCheck1))
	require.Equal(t, expId1, aiCheck1.UniqueId)
	require.Equal(t, dnsLabel1, aiCheck1.DnsLabel)

	require.NotEqual(t, aiCheck0.UniqueId, aiCheck1.UniqueId)
	require.NotEqual(t, aiCheck0.DnsLabel, aiCheck1.DnsLabel)

	err = apis.clusterInstApi.CreateClusterInst(&cl0, testutil.NewCudStreamoutClusterInst(ctx))
	require.Nil(t, err)
	err = apis.clusterInstApi.CreateClusterInst(&cl1, testutil.NewCudStreamoutClusterInst(ctx))
	require.Nil(t, err)

	clCheck0 := edgeproto.ClusterInst{}
	require.True(t, apis.clusterInstApi.cache.Get(&cl0.Key, &clCheck0))
	require.Equal(t, clDnsLabel0, clCheck0.DnsLabel)

	clCheck1 := edgeproto.ClusterInst{}
	require.True(t, apis.clusterInstApi.cache.Get(&cl1.Key, &clCheck1))
	require.Equal(t, clDnsLabel1, clCheck1.DnsLabel)

	// func to check if ids are present in database
	hasIds := func(hasId0, hasId1 bool) {
		found0 := testHasAppInstId(apis.appInstApi.sync.store, expId0)
		require.Equal(t, hasId0, found0, "has id %s", expId0)
		found1 := testHasAppInstId(apis.appInstApi.sync.store, expId1)
		require.Equal(t, hasId1, found1, "has id %s", expId1)
	}
	hasDnsLabels := func(hasIds bool, ids ...string) {
		for _, id := range ids {
			// note that all objects are on the same cloudlet
			found := testHasAppInstDnsLabel(apis.appInstApi.sync.store, &appInst0.Key.CloudletKey, id)
			require.Equal(t, hasIds, found, "has id %s", id)
		}
	}
	// check that expected ids are there
	hasIds(true, true)
	hasDnsLabels(true, dnsLabel0, dnsLabel1, clDnsLabel0, clDnsLabel1)

	// make sure deleting AppInsts also removes ids
	err = apis.appInstApi.DeleteAppInst(&appInst0, testutil.NewCudStreamoutAppInst(ctx))
	require.Nil(t, err)
	hasIds(false, true)
	hasDnsLabels(false, dnsLabel0)
	hasDnsLabels(true, dnsLabel1, clDnsLabel0, clDnsLabel1)
	err = apis.appInstApi.DeleteAppInst(&appInst1, testutil.NewCudStreamoutAppInst(ctx))
	require.Nil(t, err)
	hasIds(false, false)
	hasDnsLabels(false, dnsLabel0, dnsLabel1)
	hasDnsLabels(true, clDnsLabel0, clDnsLabel1)

	// make sure deleting ClusterInsts also removes ids
	err = apis.clusterInstApi.DeleteClusterInst(&cl0, testutil.NewCudStreamoutClusterInst(ctx))
	require.Nil(t, err)
	hasDnsLabels(false, dnsLabel0, dnsLabel1, clDnsLabel0)
	hasDnsLabels(true, clDnsLabel1)
	err = apis.clusterInstApi.DeleteClusterInst(&cl1, testutil.NewCudStreamoutClusterInst(ctx))
	require.Nil(t, err)
	hasDnsLabels(false, dnsLabel0, dnsLabel1, clDnsLabel0, clDnsLabel1)

	// clean up
	_, err = apis.appApi.DeleteApp(ctx, &app0)
	require.Nil(t, err)
	_, err = apis.appApi.DeleteApp(ctx, &app1)
	require.Nil(t, err)
}

func testHasAppInstId(kvstore objstore.KVStore, id string) bool {
	return testKVStoreHasKey(kvstore, edgeproto.AppInstIdDbKey(id))
}

func testHasAppInstDnsLabel(kvstore objstore.KVStore, ckey *edgeproto.CloudletKey, id string) bool {
	return testKVStoreHasKey(kvstore, edgeproto.CloudletObjectDnsLabelDbKey(ckey, id))
}

func testKVStoreHasKey(kvstore objstore.KVStore, keystr string) bool {
	val, _, _, err := kvstore.Get(keystr)
	if err != nil {
		return false
	}
	if val == nil || len(val) == 0 {
		return false
	}
	return true
}

func TestAppInstIdDelimiter(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelApi)

	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())
	// The generated AppInstId must not have any '.'
	// in it. That will allow any platform-specific code
	// to append further strings to it, delimited by '.',
	// and maintain the uniqueness.
	for _, ai := range testutil.AppInstData() {
		// need the app definition as well
		for _, app := range testutil.AppData() {
			if app.Key.Matches(&ai.AppKey) {
				id, _ := pfutils.GetAppInstId(ctx, &ai, &app, "", platform.PlatformTypeFake)
				require.NotContains(t, id, ".", "id must not contain '.'")
			}
		}
	}
	app := testutil.AppData()[0]
	app.Key.Name += "."
	app.Key.Organization += "."
	app.Key.Version += "."
	appInst := testutil.AppInstData()[0]
	appInst.AppKey = app.Key
	appInst.ClusterKey.Name += "."
	appInst.ClusterKey.Organization += "."
	appInst.Key.CloudletKey.Name += "."
	appInst.Key.CloudletKey.Organization += "."
	id, _ := pfutils.GetAppInstId(ctx, &appInst, &app, ".", platform.PlatformTypeFake)
	require.NotContains(t, id, ".", "id must not contain '.'")

	// test name sanitization
	startWithNumReg := regexp.MustCompile("^\\d")
	appOrgStartWithNumber := edgeproto.App{
		Key: edgeproto.AppKey{
			Name:         "testapp",
			Organization: "5GTestOrg",
			Version:      "1.0",
		},
	}
	appInstOrgStartWithNumber := edgeproto.AppInst{
		Key: edgeproto.AppInstKey{
			Name:         "111",
			Organization: appOrgStartWithNumber.Key.Organization,
			CloudletKey: edgeproto.CloudletKey{
				Organization: "GDDT",
				Name:         "CloudletA",
			},
		},
	}

	id, _ = pfutils.GetAppInstId(ctx, &appInstOrgStartWithNumber, &appOrgStartWithNumber, ".", platform.PlatformTypeFake)
	require.Regexp(t, startWithNumReg, id, "fake id not sanitized")
	id, _ = pfutils.GetAppInstId(ctx, &appInstOrgStartWithNumber, &appOrgStartWithNumber, ".", platform.PlatformTypeOpenstack)
	require.NotRegexp(t, startWithNumReg, id, "openstack id must not start with number")
}

func waitForAppInstState(t *testing.T, ctx context.Context, apis *AllApis, key *edgeproto.AppInstKey, ii int, state edgeproto.TrackedState) {
	var ok bool
	for ii := 0; ii < 50; ii++ {
		apis.appInstApi.cache.Mux.Lock()
		inst, found := apis.appInstApi.cache.Objs[*key]
		ok = found && inst.Obj.State == state
		apis.appInstApi.cache.Mux.Unlock()
		if ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	require.True(t, ok, "Wait for state %s for AppInstData[%d]", state.String(), ii)
}

// Autoprov relies on being able to detect AppInst being created
// or AppInst being deleted errors.
func testBeingErrors(t *testing.T, ctx context.Context, responder *DummyInfoResponder, apis *AllApis) {
	var wg sync.WaitGroup

	testedAutoCluster := false
	// Error messages may vary based on autocluster/no-autocluster
	for ii := 0; ii < len(testutil.AppInstData()); ii++ {
		ai := testutil.AppInstData()[ii]
		if ai.ClusterKey.Name == "" {
			testedAutoCluster = true
		}

		// start delete of appinst
		wg.Add(1)
		responder.SetPause(true)
		go func() {
			err := apis.appInstApi.DeleteAppInst(&ai, testutil.NewCudStreamoutAppInst(ctx))
			require.Nil(t, err, "AppInstData[%d]", ii)
			wg.Done()
		}()
		// make sure appinst is in deleting state
		waitForAppInstState(t, ctx, apis, &ai.Key, ii, edgeproto.TrackedState_DELETING)
		// verify error
		checkErr := apis.appInstApi.DeleteAppInst(&ai, testutil.NewCudStreamoutAppInst(ctx))
		require.True(t, cloudcommon.IsAppInstBeingDeletedError(checkErr), "AppInstData[%d]: %s", ii, checkErr)
		// let delete finish
		responder.SetPause(false)
		wg.Wait()

		// start create of appinst
		ai = testutil.AppInstData()[ii]
		wg.Add(1)
		responder.SetPause(true)
		go func() {
			err := apis.appInstApi.CreateAppInst(&ai, testutil.NewCudStreamoutAppInst(ctx))
			require.Nil(t, err, "AppInstData[%d]", ii)
			wg.Done()
		}()
		// make sure appinst is in creating state
		waitForAppInstState(t, ctx, apis, &ai.Key, ii, edgeproto.TrackedState_CREATING)
		// verify error
		checkErr = apis.appInstApi.CreateAppInst(&ai, testutil.NewCudStreamoutAppInst(ctx))
		require.True(t, cloudcommon.IsAppInstBeingCreatedError(checkErr), "AppInstData[%d]: %s", ii, checkErr)
		// let delete finish
		responder.SetPause(false)
		wg.Wait()
	}
	require.True(t, testedAutoCluster, "tested autocluster")
}
