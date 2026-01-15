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

package controller

import (
	"context"
	fmt "fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/ccrmdummy"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	influxq "github.com/edgexr/edge-cloud-platform/pkg/influxq_client"
	"github.com/edgexr/edge-cloud-platform/pkg/influxq_client/influxq_testutil"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/fake"
	"github.com/edgexr/edge-cloud-platform/pkg/process"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
	"github.com/stretchr/testify/require"
	"go.etcd.io/etcd/client/v3/concurrency"
)

func TestClusterInstApi(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi | log.DebugLevelNotify | log.DebugLevelInfra)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())
	testSvcs := testinit(ctx, t)
	defer testfinish(testSvcs)

	dummy := regiondata.InMemoryStore{}
	dummy.Start()

	sync := regiondata.InitSync(&dummy)
	apis := NewAllApis(sync)
	sync.Start()
	defer sync.Done()

	responder := DefaultDummyInfoResponder(apis)
	responder.InitDummyInfoResponder()
	ccrm := ccrmdummy.StartDummyCCRM(ctx, testSvcs.DummyVault.Config, &dummy)
	registerDummyCCRMConn(t, ccrm)
	defer ccrm.Stop()

	reduceInfoTimeouts(t, ctx, apis)

	// cannot create insts without cluster/cloudlet
	for _, obj := range testutil.ClusterInstData() {
		err := apis.clusterInstApi.CreateClusterInst(&obj, testutil.NewCudStreamoutClusterInst(ctx))
		require.NotNil(t, err, "Create ClusterInst without cloudlet")
	}

	// create support data
	addTestPlatformFeatures(t, ctx, apis, testutil.PlatformFeaturesData())
	cloudletData := testutil.CloudletData()
	testutil.InternalFlavorCreate(t, apis.flavorApi, testutil.FlavorData())
	testutil.InternalGPUDriverCreate(t, apis.gpuDriverApi, testutil.GPUDriverData())
	testutil.InternalResTagTableCreate(t, apis.resTagTableApi, testutil.ResTagTableData())
	testutil.InternalZoneCreate(t, apis.zoneApi, testutil.ZoneData())
	testutil.InternalCloudletCreate(t, apis.cloudletApi, cloudletData)
	insertCloudletInfo(ctx, apis, testutil.CloudletInfoData())
	testutil.InternalAutoProvPolicyCreate(t, apis.autoProvPolicyApi, testutil.AutoProvPolicyData())
	testutil.InternalAutoScalePolicyCreate(t, apis.autoScalePolicyApi, testutil.AutoScalePolicyData())
	setTestMasterNodeFlavorSetting(t, ctx, apis)

	// Set responder to fail. This should clean up the object after
	// the fake crm returns a failure. If it doesn't, the next test to
	// create all the cluster insts will fail.
	responder.SetSimulateClusterCreateFailure(true)
	ccrm.SetSimulateClusterCreateFailure(true)
	for _, obj := range testutil.ClusterInstData() {
		err := apis.clusterInstApi.CreateClusterInst(&obj, testutil.NewCudStreamoutClusterInst(ctx))
		require.NotNil(t, err, "Create ClusterInst responder failures")
		// make sure error matches responder
		require.Contains(t, err.Error(), "create ClusterInst failed")
	}
	responder.SetSimulateClusterCreateFailure(false)
	ccrm.SetSimulateClusterCreateFailure(false)
	// 1 clusterInst is always present because of singlefakecloudlet, cloudletData[4]
	require.Equal(t, 1, len(apis.clusterInstApi.cache.Objs))

	testutil.InternalClusterInstTest(t, "cud", apis.clusterInstApi, testutil.ClusterInstData(), testutil.WithCreatedClusterInstTestData(testutil.CreatedClusterInstData()))
	// after cluster insts create, check that cloudlet refs data is correct.
	testutil.InternalCloudletRefsTest(t, "show", apis.cloudletRefsApi, testutil.CloudletRefsData())

	commonApi := testutil.NewInternalClusterInstApi(apis.clusterInstApi)

	// Set responder to fail delete.
	responder.SetSimulateClusterDeleteFailure(true)
	ccrm.SetSimulateClusterDeleteFailure(true)
	obj := testutil.ClusterInstData()[0]
	err := apis.clusterInstApi.DeleteClusterInst(&obj, testutil.NewCudStreamoutClusterInst(ctx))
	require.NotNil(t, err, "Delete ClusterInst responder failure")
	responder.SetSimulateClusterDeleteFailure(false)
	ccrm.SetSimulateClusterDeleteFailure(false)
	checkClusterInstState(t, ctx, commonApi, &obj, edgeproto.TrackedState_READY)

	// check override of error DELETE_ERROR
	err = forceClusterInstState(ctx, &obj, edgeproto.TrackedState_DELETE_ERROR, responder, apis)
	require.Nil(t, err, "force state")
	checkClusterInstState(t, ctx, commonApi, &obj, edgeproto.TrackedState_DELETE_ERROR)
	err = apis.clusterInstApi.CreateClusterInst(&obj, testutil.NewCudStreamoutClusterInst(ctx))
	require.Nil(t, err, "create overrides delete error")
	checkClusterInstState(t, ctx, commonApi, &obj, edgeproto.TrackedState_READY)
	// progress message should exist
	msgs := GetClusterInstStreamMsgs(t, ctx, &obj.Key, apis, Pass)
	require.Greater(t, len(msgs), 0, "some progress messages")

	// check override of error CREATE_ERROR
	err = forceClusterInstState(ctx, &obj, edgeproto.TrackedState_CREATE_ERROR, responder, apis)
	require.Nil(t, err, "force state")
	checkClusterInstState(t, ctx, commonApi, &obj, edgeproto.TrackedState_CREATE_ERROR)
	err = apis.clusterInstApi.DeleteClusterInst(&obj, testutil.NewCudStreamoutClusterInst(ctx))
	require.Nil(t, err, "delete overrides create error")
	checkClusterInstState(t, ctx, commonApi, &obj, edgeproto.TrackedState_NOT_PRESENT)
	// progress message should not exist as object is deleted from etcd
	GetClusterInstStreamMsgs(t, ctx, &obj.Key, apis, Fail)

	// test update of autoscale policy
	obj = testutil.ClusterInstData()[0]
	obj.Key.Organization = testutil.AutoScalePolicyData()[1].Key.Organization
	err = apis.clusterInstApi.CreateClusterInst(&obj, testutil.NewCudStreamoutClusterInst(ctx))
	require.Nil(t, err, "create ClusterInst")
	check := edgeproto.ClusterInst{}
	found := apis.clusterInstApi.cache.Get(&obj.Key, &check)
	require.True(t, found)
	require.Equal(t, 2, int(check.NumNodes))
	// progress message should exist
	msgs = GetClusterInstStreamMsgs(t, ctx, &obj.Key, apis, Pass)
	require.Greater(t, len(msgs), 0, "some progress messages")

	obj.AutoScalePolicy = testutil.AutoScalePolicyData()[1].Key.Name
	obj.Fields = []string{edgeproto.ClusterInstFieldAutoScalePolicy}
	err = apis.clusterInstApi.UpdateClusterInst(&obj, testutil.NewCudStreamoutClusterInst(ctx))
	require.Nil(t, err)
	check = edgeproto.ClusterInst{}
	found = apis.clusterInstApi.cache.Get(&obj.Key, &check)
	require.True(t, found)
	require.Equal(t, testutil.AutoScalePolicyData()[1].Key.Name, check.AutoScalePolicy)
	require.Equal(t, 4, int(check.NumNodes))
	// progress message should exist
	msgs = GetClusterInstStreamMsgs(t, ctx, &obj.Key, apis, Pass)
	require.Greater(t, len(msgs), 0, "some progress messages")

	obj = testutil.ClusterInstData()[0]
	checkClusterInstState(t, ctx, commonApi, &obj, edgeproto.TrackedState_NOT_PRESENT)
	// override CRM error
	responder.SetSimulateClusterCreateFailure(true)
	responder.SetSimulateClusterDeleteFailure(true)
	ccrm.SetSimulateClusterCreateFailure(true)
	ccrm.SetSimulateClusterDeleteFailure(true)
	obj = testutil.ClusterInstData()[0]
	obj.CrmOverride = edgeproto.CRMOverride_IGNORE_CRM_ERRORS
	err = apis.clusterInstApi.CreateClusterInst(&obj, testutil.NewCudStreamoutClusterInst(ctx))
	require.Nil(t, err, "override crm error")
	// progress message should exist
	msgs = GetClusterInstStreamMsgs(t, ctx, &obj.Key, apis, Pass)
	require.Greater(t, len(msgs), 0, "some progress messages")
	checkClusterInstState(t, ctx, commonApi, &obj, edgeproto.TrackedState_READY)
	obj = testutil.ClusterInstData()[0]
	obj.CrmOverride = edgeproto.CRMOverride_IGNORE_CRM_ERRORS
	err = apis.clusterInstApi.DeleteClusterInst(&obj, testutil.NewCudStreamoutClusterInst(ctx))
	require.Nil(t, err, "override crm error")
	// progress message should not exist
	GetClusterInstStreamMsgs(t, ctx, &obj.Key, apis, Fail)
	checkClusterInstState(t, ctx, commonApi, &obj, edgeproto.TrackedState_NOT_PRESENT)

	// ignore CRM
	obj = testutil.ClusterInstData()[0]
	obj.CrmOverride = edgeproto.CRMOverride_IGNORE_CRM
	err = apis.clusterInstApi.CreateClusterInst(&obj, testutil.NewCudStreamoutClusterInst(ctx))
	require.Nil(t, err, "ignore crm")
	checkClusterInstState(t, ctx, commonApi, &obj, edgeproto.TrackedState_READY)
	obj = testutil.ClusterInstData()[0]
	obj.CrmOverride = edgeproto.CRMOverride_IGNORE_CRM
	err = apis.clusterInstApi.DeleteClusterInst(&obj, testutil.NewCudStreamoutClusterInst(ctx))
	require.Nil(t, err, "ignore crm")
	checkClusterInstState(t, ctx, commonApi, &obj, edgeproto.TrackedState_NOT_PRESENT)

	// inavailability of matching node flavor
	obj = testutil.ClusterInstData()[0]
	obj.Flavor = testutil.FlavorData()[0].Key
	err = apis.clusterInstApi.CreateClusterInst(&obj, testutil.NewCudStreamoutClusterInst(ctx))
	require.NotNil(t, err, "flavor not available")

	// Create appInst with autocluster should fail as cluster create
	// responder is set to fail. But post failure, clusterInst object
	// created internally should be cleaned up
	targetCloudletKey := cloudletData[1].Key
	targetApp := testutil.AppData()[11]
	testReservableClusterInstExists := func(cloudletKey edgeproto.CloudletKey) {
		foundCluster := false
		for _, cCache := range apis.clusterInstApi.cache.Objs {
			if cCache.Obj.CloudletKey == cloudletKey &&
				cCache.Obj.Reservable {
				foundCluster = true
			}
		}
		require.False(t, foundCluster, "no reservable cluster exists on this cloudlet")
	}
	// 1. Ensure no reservable clusterinst is there on our target cloudlet
	testReservableClusterInstExists(targetCloudletKey)
	// 2. Create AppInst and ensure it fails
	_, err = apis.appApi.CreateApp(ctx, &targetApp)
	require.Nil(t, err, "create App")
	appinstTest := edgeproto.AppInst{}
	appinstTest.Key.Name = "testinst"
	appinstTest.Key.Organization = targetApp.Key.Organization
	appinstTest.AppKey = targetApp.Key
	appinstTest.CloudletKey = targetCloudletKey
	appinstTest.ClusterKey.Name = "autoclustertest"
	appinstTest.ClusterKey.Organization = edgeproto.OrganizationEdgeCloud
	err = apis.appInstApi.CreateAppInst(&appinstTest, testutil.NewCudStreamoutAppInst(ctx))
	require.NotNil(t, err)
	// 3. Ensure no reservable clusterinst exist on the target cloudlet
	testReservableClusterInstExists(targetCloudletKey)
	// 4. Clean up created app
	_, err = apis.appApi.DeleteApp(ctx, &targetApp)
	require.Nil(t, err, "delete App")

	responder.SetSimulateClusterCreateFailure(false)
	responder.SetSimulateClusterDeleteFailure(false)
	ccrm.SetSimulateClusterCreateFailure(false)
	ccrm.SetSimulateClusterDeleteFailure(false)

	testReservableClusterInst(t, ctx, commonApi, apis)
	testClusterInstOverrideTransientDelete(t, ctx, commonApi, responder, ccrm, apis)

	testClusterInstResourceUsage(t, ctx, apis, ccrm)
	testClusterInstGPUFlavor(t, ctx, apis)
	testClusterPotentialCloudlets(t, ctx, apis)
	testClusterResourceUsage(t, ctx, apis)
	testCloudletIPs(t, ctx, apis)
	testClusterInstFlavorResourceUsage(t, ctx, apis, ccrm)

	dummy.Stop()
}

func reduceInfoTimeouts(t *testing.T, ctx context.Context, apis *AllApis) {
	apis.settingsApi.initDefaults(ctx)

	settings, err := apis.settingsApi.ShowSettings(ctx, &edgeproto.Settings{})
	require.Nil(t, err)

	settings.CreateCloudletTimeout = edgeproto.Duration(3 * time.Second)
	settings.CreateClusterInstTimeout = edgeproto.Duration(3 * time.Second)
	settings.UpdateClusterInstTimeout = edgeproto.Duration(3 * time.Second)
	settings.DeleteClusterInstTimeout = edgeproto.Duration(3 * time.Second)
	settings.CreateAppInstTimeout = edgeproto.Duration(3 * time.Second)
	settings.UpdateAppInstTimeout = edgeproto.Duration(3 * time.Second)
	settings.DeleteAppInstTimeout = edgeproto.Duration(3 * time.Second)
	settings.CloudletMaintenanceTimeout = edgeproto.Duration(2 * time.Second)
	settings.UpdateVmPoolTimeout = edgeproto.Duration(1 * time.Second)
	settings.CcrmApiTimeout = edgeproto.Duration(3 * time.Second)

	settings.Fields = []string{
		edgeproto.SettingsFieldCreateCloudletTimeout,
		edgeproto.SettingsFieldCreateAppInstTimeout,
		edgeproto.SettingsFieldUpdateAppInstTimeout,
		edgeproto.SettingsFieldDeleteAppInstTimeout,
		edgeproto.SettingsFieldCreateClusterInstTimeout,
		edgeproto.SettingsFieldUpdateClusterInstTimeout,
		edgeproto.SettingsFieldDeleteClusterInstTimeout,
		edgeproto.SettingsFieldCloudletMaintenanceTimeout,
		edgeproto.SettingsFieldUpdateVmPoolTimeout,
		edgeproto.SettingsFieldCcrmApiTimeout,
	}
	_, err = apis.settingsApi.UpdateSettings(ctx, settings)
	require.Nil(t, err)

	updated, err := apis.settingsApi.ShowSettings(ctx, &edgeproto.Settings{})
	updated.Fields = []string{}
	settings.Fields = []string{}
	require.Equal(t, settings, updated)
}

func checkClusterInstState(t *testing.T, ctx context.Context, api *testutil.ClusterInstCommonApi, in *edgeproto.ClusterInst, state edgeproto.TrackedState) {
	out := edgeproto.ClusterInst{}
	found := testutil.GetClusterInst(t, ctx, api, &in.Key, &out)
	log.SpanLog(ctx, log.DebugLevelInfo, "check ClusterInst state", "state", state)
	if state == edgeproto.TrackedState_NOT_PRESENT {
		require.False(t, found, "get cluster inst")
	} else {
		require.True(t, found, "get cluster inst")
		require.Equal(t, state, out.State, "cluster inst state")
	}
}

func forceClusterInstState(ctx context.Context, in *edgeproto.ClusterInst, state edgeproto.TrackedState, responder *DummyInfoResponder, apis *AllApis) error {
	log.SpanLog(ctx, log.DebugLevelInfo, "force ClusterInst state", "state", state)
	if responder != nil {
		// disable responder, otherwise it will respond to certain states
		// and change the current state
		responder.enable = false
		defer func() {
			responder.enable = true
		}()
	}
	err := apis.clusterInstApi.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		obj := edgeproto.ClusterInst{}
		if !apis.clusterInstApi.store.STMGet(stm, &in.Key, &obj) {
			return in.Key.NotFoundError()
		}
		obj.State = state
		apis.clusterInstApi.store.STMPut(stm, &obj)
		return nil
	})
	return err
}

func testReservableClusterInst(t *testing.T, ctx context.Context, api *testutil.ClusterInstCommonApi, apis *AllApis) {
	cinst := testutil.ClusterInstData()[7]
	checkReservedBy(t, ctx, api, &cinst.Key, "")

	// create test app
	for _, app := range testutil.AppData() {
		_, err := apis.appApi.CreateApp(ctx, &app)
		require.Nil(t, err, "create App")
	}
	flavor := testutil.FlavorData()[0]

	// Should be able to create a developer AppInst on the ClusterInst
	streamOut := testutil.NewCudStreamoutAppInst(ctx)
	appKey := testutil.AppData()[0].Key
	appinst := edgeproto.AppInst{}
	appinst.Key.Name = "appinst1"
	appinst.Key.Organization = appKey.Organization
	appinst.CloudletKey = cinst.CloudletKey
	appinst.AppKey = appKey
	appinst.ClusterKey = cinst.Key
	appinst.Flavor = flavor.Key
	err := apis.appInstApi.CreateAppInst(&appinst, streamOut)
	require.Nil(t, err, "create AppInst")
	checkReservedBy(t, ctx, api, &cinst.Key, appinst.Key.Organization)

	// Cannot create another AppInst on it from different developer
	appKey2 := testutil.AppData()[10].Key
	appinst2 := edgeproto.AppInst{}
	appinst2.Key.Name = "appinst2"
	appinst2.Key.Organization = appKey2.Organization
	appinst2.CloudletKey = cinst.CloudletKey
	appinst2.AppKey = appKey2
	appinst2.ClusterKey = cinst.Key
	appinst2.KubernetesResources = &edgeproto.KubernetesResources{
		CpuPool: &edgeproto.NodePoolResources{
			TotalVcpus:  *edgeproto.NewUdec64(1, 0),
			TotalMemory: 100,
		},
	}
	require.NotEqual(t, appinst.Key.Organization, appinst2.Key.Organization)
	err = apis.appInstApi.CreateAppInst(&appinst2, streamOut)
	require.NotNil(t, err, "create AppInst on already reserved ClusterInst")
	// Can create another AppInst on it from the same developer
	appKey3 := testutil.AppData()[1].Key
	appinst3 := edgeproto.AppInst{}
	appinst3.Key.Name = "appinst3"
	appinst3.Key.Organization = appKey3.Organization
	appinst3.CloudletKey = cinst.CloudletKey
	appinst3.AppKey = appKey3
	appinst3.ClusterKey = cinst.Key
	appinst3.Flavor = flavor.Key
	require.Equal(t, appinst.Key.Organization, appinst3.Key.Organization)
	err = apis.appInstApi.CreateAppInst(&appinst3, streamOut)
	require.Nil(t, err)

	// Make sure above changes have not affected ReservedBy setting
	checkReservedBy(t, ctx, api, &cinst.Key, appinst.Key.Organization)

	// Delete second AppInst should not clear reservation
	err = apis.appInstApi.DeleteAppInst(&appinst3, streamOut)
	require.Nil(t, err, "delete AppInst on reservable ClusterInst")
	checkReservedBy(t, ctx, api, &cinst.Key, appinst.Key.Organization)

	// Deleting AppInst should removed ReservedBy
	err = apis.appInstApi.DeleteAppInst(&appinst, streamOut)
	require.Nil(t, err, "delete AppInst")
	checkReservedBy(t, ctx, api, &cinst.Key, "")

	// Can now create AppInst from different developer
	err = apis.appInstApi.CreateAppInst(&appinst2, streamOut)
	require.Nil(t, err, "create AppInst on reservable ClusterInst")
	checkReservedBy(t, ctx, api, &cinst.Key, appinst2.Key.Organization)

	// Delete AppInst
	err = apis.appInstApi.DeleteAppInst(&appinst2, streamOut)
	require.Nil(t, err, "delete AppInst on reservable ClusterInst")
	checkReservedBy(t, ctx, api, &cinst.Key, "")

	// Cannot create VM with cluster specified
	appBadKey := testutil.AppData()[12].Key
	appinstBad := edgeproto.AppInst{}
	appinstBad.Key.Name = "vmappinst"
	appinstBad.Key.Organization = appBadKey.Organization
	appinstBad.CloudletKey = testutil.CloudletData()[0].Key
	appinstBad.AppKey = appBadKey
	appinstBad.ClusterKey = cinst.Key
	err = apis.appInstApi.CreateAppInst(&appinstBad, streamOut)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Cluster name must be blank for App deployment type vm")

	// Delete App
	for _, app := range testutil.AppData() {
		_, err = apis.appApi.DeleteApp(ctx, &app)
		require.Nil(t, err, "delete App")
	}
	checkReservedBy(t, ctx, api, &cinst.Key, "")
}

func checkReservedBy(t *testing.T, ctx context.Context, api *testutil.ClusterInstCommonApi, key *edgeproto.ClusterKey, expected string) {
	cinst := edgeproto.ClusterInst{}
	found := testutil.GetClusterInst(t, ctx, api, key, &cinst)
	require.True(t, found, "get ClusterInst")
	require.True(t, cinst.Reservable)
	require.Equal(t, expected, cinst.ReservedBy)
	require.Equal(t, edgeproto.OrganizationEdgeCloud, cinst.Key.Organization)
}

// Test that Crm Override for Delete ClusterInst overrides any failures
// on side-car auto-apps.
func testClusterInstOverrideTransientDelete(t *testing.T, ctx context.Context, api *testutil.ClusterInstCommonApi, responder *DummyInfoResponder, ccrm *ccrmdummy.CCRMDummy, apis *AllApis) {
	clust := testutil.ClusterInstData()[0]
	clust.Key.Name = "crmoverride"

	// autoapp
	app := testutil.AppData()[9] // auto-delete app
	require.Equal(t, edgeproto.DeleteType_AUTO_DELETE, app.DelOpt)
	_, err := apis.appApi.CreateApp(ctx, &app)
	require.Nil(t, err, "create App")

	aiauto := edgeproto.AppInst{
		Key: edgeproto.AppInstKey{
			Name:         "aiauto",
			Organization: app.Key.Organization,
		},
		AppKey:      app.Key,
		ClusterKey:  clust.Key,
		CloudletKey: clust.CloudletKey,
	}

	var obj edgeproto.ClusterInst
	var ai edgeproto.AppInst
	appCommon := testutil.NewInternalAppInstApi(apis.appInstApi)

	responder.SetSimulateClusterDeleteFailure(true)
	responder.SetSimulateAppDeleteFailure(true)
	ccrm.SetSimulateClusterDeleteFailure(true)
	ccrm.SetSimulateAppDeleteFailure(true)
	for val, stateName := range edgeproto.TrackedState_name {
		state := edgeproto.TrackedState(val)
		if !edgeproto.IsTransientState(state) {
			continue
		}
		// create cluster
		obj = clust
		err = apis.clusterInstApi.CreateClusterInst(&obj, testutil.NewCudStreamoutClusterInst(ctx))
		require.Nil(t, err, "create ClusterInst")
		// create autoapp

		ai = aiauto
		err = apis.appInstApi.CreateAppInst(&ai, testutil.NewCudStreamoutAppInst(ctx))
		require.Nil(t, err, "create auto AppInst")
		// force bad states
		err = forceAppInstState(ctx, &ai, state, responder, apis)
		require.Nil(t, err, "force state")
		checkAppInstState(t, ctx, appCommon, &ai, state)
		err = forceClusterInstState(ctx, &obj, state, responder, apis)
		require.Nil(t, err, "force state")
		checkClusterInstState(t, ctx, api, &obj, state)
		// delete cluster
		obj = clust
		obj.CrmOverride = edgeproto.CRMOverride_IGNORE_CRM_AND_TRANSIENT_STATE
		err = apis.clusterInstApi.DeleteClusterInst(&obj, testutil.NewCudStreamoutClusterInst(ctx))
		require.Nil(t, err, "override crm and transient state %s", stateName)
	}
	responder.SetSimulateClusterDeleteFailure(false)
	responder.SetSimulateAppDeleteFailure(false)
	ccrm.SetSimulateClusterDeleteFailure(false)
	ccrm.SetSimulateAppDeleteFailure(false)

	_, err = apis.appApi.DeleteApp(ctx, &app)
	require.Nil(t, err, "delete App")

	// cleanup unused reservable auto clusters
	apis.clusterInstApi.cleanupIdleReservableAutoClusters(ctx, time.Duration(0))
	apis.clusterInstApi.cleanupWorkers.WaitIdle()
}

func getMetricCounts(t *testing.T, ctx context.Context, cloudlet *edgeproto.Cloudlet, apis *AllApis) *ResourceMetrics {
	var metrics []*edgeproto.Metric
	var err error
	err = apis.clusterInstApi.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		metrics, err = apis.clusterInstApi.getCloudletResourceMetric(ctx, stm, &cloudlet.Key)
		require.Nil(t, err, "get cloudlet resource metrics")
		require.Greater(t, len(metrics), 0, "metrics")
		return nil
	})
	require.Nil(t, err)
	pfType := cloudlet.PlatformType
	resMeasurement := cloudcommon.GetCloudletResourceUsageMeasurement(pfType)
	ramUsed := uint64(0)
	vcpusUsed := uint64(0)
	gpusUsed := uint64(0)
	externalIPsUsed := uint64(0)
	flavorCnt := make(map[string]uint64)
	for _, metric := range metrics {
		if metric.Name == resMeasurement {
			for _, val := range metric.Vals {
				switch val.Name {
				case cloudcommon.ResourceMetricRamMB:
					out := val.Value.(*edgeproto.MetricVal_Ival)
					ramUsed = out.Ival
				case cloudcommon.ResourceMetricVcpus:
					out := val.Value.(*edgeproto.MetricVal_Ival)
					vcpusUsed = out.Ival
				case cloudcommon.ResourceMetricGpus:
					out := val.Value.(*edgeproto.MetricVal_Ival)
					gpusUsed = out.Ival
				case cloudcommon.ResourceMetricExternalIPs:
					out := val.Value.(*edgeproto.MetricVal_Ival)
					externalIPsUsed = out.Ival
				}
			}
		} else if metric.Name == cloudcommon.CloudletFlavorUsageMeasurement {
			fName := ""
			for _, tag := range metric.Tags {
				if tag.Name != "flavor" {
					continue
				}
				fName = tag.Val
				if _, ok := flavorCnt[fName]; !ok {
					flavorCnt[fName] = uint64(0)
				}
				break
			}
			require.NotEmpty(t, fName, "flavor name found")
			for _, val := range metric.Vals {
				if val.Name != "count" {
					continue
				}
				out := val.Value.(*edgeproto.MetricVal_Ival)
				_, ok := flavorCnt[fName]
				require.True(t, ok, "flavor name found")
				flavorCnt[fName] += out.Ival
				break
			}
		}
	}
	return &ResourceMetrics{
		ramUsed:         ramUsed,
		vcpusUsed:       vcpusUsed,
		gpusUsed:        gpusUsed,
		externalIpsUsed: externalIPsUsed,
		flavorCnt:       flavorCnt,
	}
}

func getMetricsDiff(old *ResourceMetrics, new *ResourceMetrics) *ResourceMetrics {
	diffRam := new.ramUsed - old.ramUsed
	diffVcpus := new.vcpusUsed - old.vcpusUsed
	diffGpus := new.gpusUsed - old.gpusUsed
	diffExternalIps := new.externalIpsUsed - old.externalIpsUsed
	diffFlavorCnt := make(map[string]uint64)
	for fName, fCnt := range new.flavorCnt {
		if oldVal, ok := old.flavorCnt[fName]; ok {
			diffCnt := fCnt - oldVal
			if diffCnt > 0 {
				diffFlavorCnt[fName] = diffCnt
			}
		} else {
			diffFlavorCnt[fName] = fCnt
		}
	}
	return &ResourceMetrics{
		ramUsed:         diffRam,
		vcpusUsed:       diffVcpus,
		gpusUsed:        diffGpus,
		externalIpsUsed: diffExternalIps,
		flavorCnt:       diffFlavorCnt,
	}
}

func getClusterInstMetricCounts(t *testing.T, ctx context.Context, clusterInst *edgeproto.ClusterInst, apis *AllApis) *ResourceMetrics {
	var err error
	var nodeFlavor *edgeproto.FlavorInfo
	var masterNodeFlavor *edgeproto.FlavorInfo
	var lbFlavor *edgeproto.FlavorInfo
	gpusUsed := uint64(0)
	err = apis.clusterInstApi.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		existingCl := edgeproto.ClusterInst{}
		found := apis.clusterInstApi.store.STMGet(stm, &clusterInst.Key, &existingCl)
		require.True(t, found, "cluster inst exists")

		cloudletKey := existingCl.CloudletKey
		cloudlet := edgeproto.Cloudlet{}
		found = apis.cloudletApi.store.STMGet(stm, &cloudletKey, &cloudlet)
		require.True(t, found, "cloudlet exists")

		cloudletInfo := edgeproto.CloudletInfo{}
		found = apis.cloudletInfoApi.store.STMGet(stm, &cloudletKey, &cloudletInfo)
		require.True(t, found, "cloudlet info exists")

		for _, flavor := range cloudletInfo.Flavors {
			for _, pool := range existingCl.NodePools {
				if pool.NodeResources == nil {
					continue
				}
				if flavor.Name == pool.NodeResources.InfraNodeFlavor {
					nodeFlavor = flavor
					gpuCount := cloudcommon.NodeResourcesGPUCount(pool.NodeResources)
					gpusUsed += uint64(pool.NumNodes) * gpuCount
					break
				}
			}
			if existingCl.NodeResources != nil {
				if flavor.Name == existingCl.NodeResources.InfraNodeFlavor {
					nodeFlavor = flavor
					gpuCount := cloudcommon.NodeResourcesGPUCount(existingCl.NodeResources)
					gpusUsed += gpuCount
				}
			}
			if flavor.Name == existingCl.MasterNodeFlavor {
				masterNodeFlavor = flavor
			}
		}
		lbFlavor, err = apis.clusterInstApi.GetRootLBFlavorInfo(ctx, edgeproto.NewOptionalSTM(stm), &cloudlet, &cloudletInfo)
		require.Nil(t, err, "found rootlb flavor")
		return nil
	})
	log.SpanLog(ctx, log.DebugLevelApi, "cloudlet is", "cloudlet", clusterInst.CloudletKey)
	require.Nil(t, err)
	require.NotNil(t, nodeFlavor, "found node flavor")
	require.NotNil(t, masterNodeFlavor, "found master node flavor")
	require.NotNil(t, lbFlavor, "found rootlb flavor")
	ramUsed := uint64(clusterInst.NumNodes)*nodeFlavor.Ram +
		uint64(clusterInst.NumMasters)*masterNodeFlavor.Ram +
		lbFlavor.Ram
	vcpusUsed := uint64(clusterInst.NumNodes)*nodeFlavor.Vcpus +
		uint64(clusterInst.NumMasters)*masterNodeFlavor.Vcpus +
		lbFlavor.Vcpus
	externalIPsUsed := uint64(1) // 1 dedicated Flavor
	if nodeFlavor == masterNodeFlavor && gpusUsed > 0 {
		// master node also using gpus
		gpusUsed += uint64(clusterInst.NumMasters)
	}
	flavorCnt := make(map[string]uint64)
	if _, ok := flavorCnt[nodeFlavor.Name]; !ok {
		flavorCnt[nodeFlavor.Name] = uint64(0)
	}
	flavorCnt[nodeFlavor.Name] += uint64(clusterInst.NumNodes)
	if _, ok := flavorCnt[masterNodeFlavor.Name]; !ok {
		flavorCnt[masterNodeFlavor.Name] = uint64(0)
	}
	flavorCnt[masterNodeFlavor.Name] += uint64(clusterInst.NumMasters)
	if _, ok := flavorCnt[lbFlavor.Name]; !ok {
		flavorCnt[lbFlavor.Name] = uint64(0)
	}
	flavorCnt[lbFlavor.Name] += uint64(1)
	return &ResourceMetrics{
		ramUsed:         ramUsed,
		vcpusUsed:       vcpusUsed,
		gpusUsed:        gpusUsed,
		externalIpsUsed: externalIPsUsed,
		flavorCnt:       flavorCnt,
	}
}

type ResourceMetrics struct {
	ramUsed         uint64
	vcpusUsed       uint64
	gpusUsed        uint64
	externalIpsUsed uint64
	flavorCnt       map[string]uint64
}

func validateClusterInstMetrics(t *testing.T, ctx context.Context, cloudlet *edgeproto.Cloudlet, clusterInst *edgeproto.ClusterInst, oldResUsage *ResourceMetrics, apis *AllApis) {
	// get resource usage after clusterInst creation
	newResUsage := getMetricCounts(t, ctx, cloudlet, apis)
	// get resource usage of clusterInst
	actualResUsage := getMetricsDiff(oldResUsage, newResUsage)
	// validate that metrics output shows expected clusterinst resources
	expectedResUsage := getClusterInstMetricCounts(t, ctx, clusterInst, apis)
	require.Equal(t, actualResUsage.ramUsed, expectedResUsage.ramUsed, "ram metric matches")
	require.Equal(t, actualResUsage.vcpusUsed, expectedResUsage.vcpusUsed, "vcpus metric matches")
	require.Equal(t, actualResUsage.gpusUsed, expectedResUsage.gpusUsed, "gpus metric matches")
	require.Equal(t, actualResUsage.externalIpsUsed, expectedResUsage.externalIpsUsed, "externalips metric matches")
	for efName, efCnt := range expectedResUsage.flavorCnt {
		afCnt, found := actualResUsage.flavorCnt[efName]
		require.True(t, found, "expected flavor found")
		require.Equal(t, afCnt, efCnt, "flavor count matches")
	}
}

func testClusterInstResourceUsage(t *testing.T, ctx context.Context, apis *AllApis, ccrm *ccrmdummy.CCRMDummy) {
	// set the correct resource limits and flavors that these tests expect
	// for the target cloudlet, cloudlet[0]. Max Values come from the
	// resource snapshot of CloudletInfoData[0], which for some reason is
	// different than the OS max values.
	cloudletInfos := testutil.CloudletInfoData()
	ci := cloudletInfos[0]
	platformResources, ok := ccrm.GetFakePlatformResources(&ci.Key)
	require.True(t, ok)
	platformResources.Init()
	platformResources.SetMaxResources(102400, 109, 5000, 10, nil)
	for _, vm := range fake.GetPlatformVMs() {
		platformResources.AddPlatformVM(vm)
	}
	ccrm.SetFakePlatformFlavors(&ci.Key, ci.Flavors)
	log.SpanLog(ctx, log.DebugLevelApi, "platform resources are", "res", platformResources.GetSnapshot())

	obj := testutil.ClusterInstData()[0]
	obj.NumNodes = 10
	obj.Flavor = testutil.FlavorData()[3].Key
	err := apis.clusterInstApi.CreateClusterInst(&obj, testutil.NewCudStreamoutClusterInst(ctx))
	require.NotNil(t, err, "not enough resources available")
	require.Contains(t, err.Error(), "not enough resources available")

	// create appinst
	testutil.InternalAppCreate(t, apis.appApi, []edgeproto.App{
		testutil.AppData()[0], testutil.AppData()[12],
	})

	// get resource usage before clusterInst creation
	cloudletData := testutil.CloudletData()
	oldResUsage := getMetricCounts(t, ctx, &cloudletData[0], apis)

	// create clusterInst1
	clusterInstObj := testutil.ClusterInstData()[0]
	clusterInstObj.Key.Name = "GPUCluster"
	clusterInstObj.Flavor = testutil.FlavorData()[4].Key
	err = apis.clusterInstApi.CreateClusterInst(&clusterInstObj, testutil.NewCudStreamoutClusterInst(ctx))
	require.Nil(t, err, "create cluster inst with gpu flavor")
	// validate clusterinst resource metrics
	validateClusterInstMetrics(t, ctx, &cloudletData[0], &clusterInstObj, oldResUsage, apis)

	// get resource usage before clusterInst creation
	oldResUsage = getMetricCounts(t, ctx, &cloudletData[0], apis)

	// create clusterInst2
	clusterInstObj2 := testutil.ClusterInstData()[0]
	clusterInstObj2.Key.Name = "NonGPUCluster1"
	err = apis.clusterInstApi.CreateClusterInst(&clusterInstObj2, testutil.NewCudStreamoutClusterInst(ctx))
	require.Nil(t, err, "create cluster inst")
	// validate clusterinst resource metrics
	validateClusterInstMetrics(t, ctx, &cloudletData[0], &clusterInstObj2, oldResUsage, apis)

	// delete clusterInst2
	err = apis.clusterInstApi.DeleteClusterInst(&clusterInstObj2, testutil.NewCudStreamoutClusterInst(ctx))
	require.Nil(t, err, "delete cluster inst")
	// validate clusterinst resource metrics post deletion
	delResUsage := getMetricCounts(t, ctx, &cloudletData[0], apis)
	require.Equal(t, oldResUsage.ramUsed, delResUsage.ramUsed, "ram used is same as old value")
	require.Equal(t, oldResUsage.vcpusUsed, delResUsage.vcpusUsed, "vcpus used is same as old value")
	require.Equal(t, oldResUsage.gpusUsed, delResUsage.gpusUsed, "gpus used is same as old value")
	require.Equal(t, oldResUsage.externalIpsUsed, delResUsage.externalIpsUsed, "externalIpsUsed used is same as old value")
	for efName, efCnt := range delResUsage.flavorCnt {
		afCnt, found := oldResUsage.flavorCnt[efName]
		require.True(t, found, "expected flavor found")
		require.Equal(t, afCnt, efCnt, "flavor count matches")
	}

	// get resource usage before clusterInst creation
	oldResUsage = getMetricCounts(t, ctx, &cloudletData[0], apis)

	// create clusterInst2 again
	err = apis.clusterInstApi.CreateClusterInst(&clusterInstObj2, testutil.NewCudStreamoutClusterInst(ctx))
	require.Nil(t, err, "create cluster inst")
	// validate clusterinst resource metrics
	validateClusterInstMetrics(t, ctx, &cloudletData[0], &clusterInstObj2, oldResUsage, apis)

	appInstObj := testutil.AppInstData()[0]
	appInstObj.CloudletKey = clusterInstObj.CloudletKey
	appInstObj.ClusterKey = clusterInstObj.Key
	// must specify gpu in resource request to access gpu pool
	appInstObj.KubernetesResources = &edgeproto.KubernetesResources{
		GpuPool: &edgeproto.NodePoolResources{
			TotalVcpus:  *edgeproto.NewUdec64(0, 500*edgeproto.DecMillis),
			TotalMemory: 20,
			TotalGpus: []*edgeproto.GPUResource{{
				ModelId: "nvidia-t4", // matches cluster flavorData[4]
				Count:   1,
			}},
		},
	}
	testutil.InternalAppInstCreate(t, apis.appInstApi, []edgeproto.AppInst{
		appInstObj, testutil.AppInstData()[11],
	})

	err = apis.clusterInstApi.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		var found bool
		cloudletKey := obj.CloudletKey
		resCalc := NewCloudletResCalc(apis, edgeproto.NewOptionalSTM(stm), &cloudletKey)
		resCalc.InitDeps(ctx)
		cloudlet := resCalc.deps.cloudlet
		cloudletInfo := resCalc.deps.cloudletInfo
		cloudletRefs := resCalc.deps.cloudletRefs

		usedRes, err := resCalc.getCloudletUsedResources(ctx)
		require.Nil(t, err, "get all cloudlet resources")
		clusters := make(map[edgeproto.ClusterKey]struct{})
		resTypeVMAppCount := 0
		for ii, res := range usedRes.vms {
			if res.Key.Name == "" {
				if res.Type == cloudcommon.NodeTypeAppVM.String() {
					resTypeVMAppCount++
				}
				continue
			}
			existingCl := edgeproto.ClusterInst{}
			found = apis.clusterInstApi.store.STMGet(stm, &res.Key, &existingCl)
			require.True(t, found, "cluster inst %s from resources[%d] must exist", res.Key.GetKeyString(), ii)
			clusters[res.Key] = struct{}{}
		}
		require.Equal(t, 1, resTypeVMAppCount, "one vm appinst resource exists")
		for _, ciRefKey := range cloudletRefs.ClusterInsts {
			ciKey := ciRefKey
			existingCl := edgeproto.ClusterInst{}
			if apis.clusterInstApi.store.STMGet(stm, &ciKey, &existingCl) {
				_, found = clusters[ciKey]
				require.True(t, found, "refs clusterinst exists", ciKey)
			}
		}
		require.Equal(t, len(cloudletRefs.VmAppInsts), 1, "1 vm appinsts exists")

		// calculate total used resources
		infraResInfo := make(map[string]edgeproto.InfraResource)
		for _, resInfo := range cloudletInfo.ResourcesSnapshot.Info {
			infraResInfo[resInfo.Name] = resInfo
		}

		allResInfo, err := apis.cloudletApi.totalCloudletResources(ctx, resCalc.stm, cloudlet, cloudletInfo, usedRes, CloudletResCalcOptions{})
		require.Nil(t, err)
		// set quotas to what is currently being used
		// so creating anything should trigger both quota warnings and
		// available resource failures.
		quotas := []edgeproto.ResourceQuota{}
		for _, infraRes := range allResInfo {
			quotas = append(quotas, edgeproto.ResourceQuota{
				Name:           infraRes.Name,
				Value:          infraRes.Value.Whole,
				AlertThreshold: 30,
				ResourceType:   infraRes.ResourceType,
			})
		}
		log.SpanLog(ctx, log.DebugLevelApi, "set fake quotas", "quotas", quotas)
		cloudlet.ResourceQuotas = quotas
		// test cluster inst vm requirements
		quotaMap := make(map[string]edgeproto.ResourceQuota)
		for _, quota := range cloudlet.ResourceQuotas {
			quotaMap[quota.ResKey()] = quota
		}
		lbFlavor := resCalc.deps.lbFlavor
		clusterInst := testutil.ClusterInstData()[0]
		clusterInst.NumMasters = 2
		clusterInst.MasterNodeFlavor = "flavor.large"
		clusterInstFlavor := testutil.FlavorData()[4]
		clusterInst.EnsureDefaultNodePool()
		clusterInst.NodePools[0].SetFromFlavor(&clusterInstFlavor)
		clusterInst.NodePools[0].NumNodes = 2
		clusterInst.NodePools[0].NodeResources.InfraNodeFlavor = "flavor.large"
		clusterInst.IpAccess = edgeproto.IpAccess_IP_ACCESS_DEDICATED
		isManagedK8s := false // Master nodes & RootLB should be counted
		ciResources := NewCloudletResources()
		ciResources.AddClusterInstResources(ctx, &clusterInst, lbFlavor, isManagedK8s)
		// number of vm resources = num_nodes + num_masters + num_of_rootLBs
		require.Equal(t, 5, ciResources.numVms, "matches number of vm resources")
		numNodes := 0
		numMasters := 0
		numRootLB := 0
		for _, res := range ciResources.vms {
			if res.Type == cloudcommon.NodeTypeK8sClusterMaster.String() {
				numMasters += int(res.Count)
			} else if res.Type == cloudcommon.NodeTypeK8sClusterNode.String() {
				numNodes += int(res.Count)
			} else if res.Type == cloudcommon.NodeTypeDedicatedRootLB.String() {
				numRootLB += int(res.Count)
			} else {
				require.Fail(t, "invalid resource type", "type", res.Type)
			}
			require.Equal(t, res.Key, clusterInst.Key, "resource key matches cluster inst key")
		}
		require.Equal(t, numMasters, int(clusterInst.NumMasters), "resource type count matches")
		require.Equal(t, numNodes, int(clusterInst.GetNumNodes()), "resource type count matches")
		require.Equal(t, numRootLB, 1, "resource type count matches")

		isManagedK8s = true // Master nodes not allowed & RootLB should not be counted
		clusterInst.NumMasters = 0
		ciResources = NewCloudletResources()
		ciResources.AddClusterInstResources(ctx, &clusterInst, lbFlavor, isManagedK8s)
		// number of vm resources = num_nodes
		require.Equal(t, 2, ciResources.numVms, "matches number of vm resources")

		warnings, err := resCalc.CloudletFitsCluster(ctx, &clusterInst, nil)
		require.NotNil(t, err, "not enough resource available error")
		for _, resName := range []string{
			cloudcommon.ResourceRamMb,
			cloudcommon.ResourceVcpus,
			cloudcommon.ResourceDiskGb,
			"gpu/nvidia-t4",
			cloudcommon.ResourceInstances,
		} {
			rx := "required " + resName + " is .*? but only .*? is available"
			require.Regexp(t, regexp.MustCompile(rx), err.Error())
		}
		// Note that the clusterInst did not require an externalIP, but the
		// current usage is over the quota alert threshold, so it generates
		// a warning.
		allWarnings := strings.Join(warnings, ", ")
		for _, resName := range []string{
			cloudcommon.ResourceRamMb,
			cloudcommon.ResourceVcpus,
			cloudcommon.ResourceDiskGb,
			"gpu/nvidia-t4",
			cloudcommon.ResourceInstances,
		} {
			rx := "more than 30% of " + resName + " (.*?) is used by the cloudlet"
			require.Regexp(t, regexp.MustCompile(rx), allWarnings)
		}

		// test vm app inst resource requirements
		appInst := testutil.AppInstData()[11]
		//appInstFlavor := testutil.FlavorData()[4]
		appInst.NodeResources = &edgeproto.NodeResources{}
		//appInst.NodeResources.SetFromFlavor(&appInstFlavor)
		appInst.NodeResources.InfraNodeFlavor = "flavor.large"
		app := &testutil.AppData()[12]
		vmAppResources := NewCloudletResources()
		vmAppResources.AddVMAppInstResources(ctx, app, &appInst, lbFlavor)
		require.Equal(t, 2, len(vmAppResources.vms), "matches number of vm resources")
		foundVMRes := false
		foundVMRootLBRes := false
		for _, vmRes := range vmAppResources.vms {
			if vmRes.Type == cloudcommon.NodeTypeAppVM.String() {
				foundVMRes = true
			} else if vmRes.Type == cloudcommon.NodeTypeDedicatedRootLB.String() {
				foundVMRootLBRes = true
			}
			require.Equal(t, vmAppResources.vms[0].Key, *appInst.GetClusterKey(), "resource key matches appinst's clusterinst key")
		}
		require.True(t, foundVMRes, "resource type app vm found")
		require.True(t, foundVMRootLBRes, "resource type vm rootlb found")

		warnings, err = resCalc.CloudletFitsVMApp(ctx, app, &appInst)
		require.NotNil(t, err, "not enough resource available")
		for _, resName := range []string{
			cloudcommon.ResourceRamMb,
			cloudcommon.ResourceVcpus,
			cloudcommon.ResourceDiskGb,
			"gpu/nvidia-t4",
			cloudcommon.ResourceInstances,
		} {
			rx := "required " + resName + " is .*? but only .*? is available"
			require.Regexp(t, regexp.MustCompile(rx), err.Error())
		}
		allWarnings = strings.Join(warnings, ", ")
		for _, resName := range []string{
			cloudcommon.ResourceRamMb,
			cloudcommon.ResourceVcpus,
			cloudcommon.ResourceDiskGb,
			"gpu/nvidia-t4",
			cloudcommon.ResourceInstances,
			cloudcommon.ResourceExternalIPs,
		} {
			rx := "more than 30% of " + resName + " (.*?) is used by the cloudlet"
			require.Regexp(t, regexp.MustCompile(rx), allWarnings)
		}
		return nil
	})
	require.Nil(t, err)
}

var testInfluxProc *process.Influx

func influxUsageUnitTestSetup(t *testing.T) string {
	testInfluxProc = influxq_testutil.StartInfluxd(t)

	q := influxq.NewInfluxQ(cloudcommon.EventsDbName, "", "", InfluxClientTimeout)
	err := q.Start("http://" + testInfluxProc.HttpAddr)
	if err != nil {
		influxUsageUnitTestStop()
	}
	defer q.Stop()
	require.Nil(t, err, "new influx q")

	connected := q.WaitConnected()
	if !connected {
		influxUsageUnitTestStop()
	}
	require.True(t, connected)
	return "http://" + testInfluxProc.HttpAddr
}

func influxUsageUnitTestStop() {
	if testInfluxProc != nil {
		testInfluxProc.StopLocal()
		testInfluxProc = nil
	}
}

func TestDefaultMTCluster(t *testing.T) {
	log.InitTracer(nil)
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi | log.DebugLevelNotify)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())
	testSvcs := testinit(ctx, t)
	defer testfinish(testSvcs)

	dummy := regiondata.InMemoryStore{}
	dummy.Start()

	sync := regiondata.InitSync(&dummy)
	apis := NewAllApis(sync)
	sync.Start()
	defer sync.Done()

	dummyResponder := DefaultDummyInfoResponder(apis)
	dummyResponder.InitDummyInfoResponder()
	ccrm := ccrmdummy.StartDummyCCRM(ctx, testSvcs.DummyVault.Config, &dummy)
	registerDummyCCRMConn(t, ccrm)
	defer ccrm.Stop()
	reduceInfoTimeouts(t, ctx, apis)

	addTestPlatformFeatures(t, ctx, apis, testutil.PlatformFeaturesData())
	testutil.InternalFlavorTest(t, "cud", apis.flavorApi, testutil.FlavorData())
	setTestMasterNodeFlavorSetting(t, ctx, apis)

	cloudlet := testutil.CloudletData()[0]
	cloudlet.EnableDefaultServerlessCluster = true
	cloudlet.GpuConfig = edgeproto.GPUConfig{}
	cloudlet.ResTagMap = nil
	cloudlet.Zone = ""
	cloudletInfo := testutil.CloudletInfoData()[0]
	cloudletInfo.State = dme.CloudletState_CLOUDLET_STATE_INIT
	apis.cloudletInfoApi.Update(ctx, &cloudletInfo, 0)

	// create cloudlet, should create cluster
	err := apis.cloudletApi.CreateCloudlet(&cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err)
	// simulate ready state in info, which triggers cluster create
	cloudletInfo.State = dme.CloudletState_CLOUDLET_STATE_READY
	apis.cloudletInfoApi.Update(ctx, &cloudletInfo, 0)
	waitDefaultMTClust(t, cloudlet.Key, apis, true)

	// update to off, should delete cluster
	cloudlet.EnableDefaultServerlessCluster = false
	cloudlet.Fields = []string{edgeproto.CloudletFieldEnableDefaultServerlessCluster}
	err = apis.cloudletApi.UpdateCloudlet(&cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err)
	waitDefaultMTClust(t, cloudlet.Key, apis, false)

	// update to on, should create cluster
	cloudlet.EnableDefaultServerlessCluster = true
	err = apis.cloudletApi.UpdateCloudlet(&cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err)
	waitDefaultMTClust(t, cloudlet.Key, apis, true)

	// delete cloudlet, should auto-delete cluster
	err = apis.cloudletApi.DeleteCloudlet(&cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err)
	waitDefaultMTClust(t, cloudlet.Key, apis, false)
}

func waitDefaultMTClust(t *testing.T, cloudletKey edgeproto.CloudletKey, apis *AllApis, present bool) {
	key := cloudcommon.GetDefaultMTClustKey(cloudletKey)
	cinst := edgeproto.ClusterInst{}
	var found bool
	for ii := 0; ii < 40; ii++ {
		found = apis.clusterInstApi.Get(key, &cinst)
		if present == found {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	require.Equal(t, present, found, "DefaultMTCluster presence incorrect")
}

func testClusterInstGPUFlavor(t *testing.T, ctx context.Context, apis *AllApis) {
	cloudletData := testutil.CloudletData()
	vgpuCloudlet := cloudletData[0]
	vgpuCloudlet.Key.Name = "VGPUCloudlet"
	err := apis.cloudletApi.CreateCloudlet(&vgpuCloudlet, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err)
	cloudletInfo := testutil.CloudletInfoData()[0]
	cloudletInfo.Key = vgpuCloudlet.Key
	cloudletInfo.State = dme.CloudletState_CLOUDLET_STATE_READY
	apis.cloudletInfoApi.Update(ctx, &cloudletInfo, 0)

	obj := testutil.ClusterInstData()[0]
	obj.Flavor = edgeproto.FlavorKey{}
	obj.Key.Name = "GPUTestClusterFlavor"
	obj.NodePools[0].NodeResources.Gpus = []*edgeproto.GPUResource{{
		ModelId: "nvidia-t4",
		Count:   1,
	}}

	// Deploy GPU cluster on non-GPU cloudlet, should fail
	obj.CloudletKey = cloudletData[1].Key
	err = apis.clusterInstApi.CreateClusterInst(&obj, testutil.NewCudStreamoutClusterInst(ctx))
	require.NotNil(t, err, "create cluster inst with gpu flavor on vgpu cloudlet fails")
	require.Contains(t, err.Error(), "no suitable infra flavor found for requested node resources, 3 with not enough nvidia-t4")

	// Deploy GPU passthrough cluster on vGPU cloudlet, should fail
	cloudletInfo.Flavors = []*edgeproto.FlavorInfo{{
		Name:  "flavor.tiny2",
		Vcpus: uint64(1),
		Ram:   uint64(1024),
		Disk:  uint64(10),
	}, {
		Name:  "flavor.small",
		Vcpus: uint64(2),
		Ram:   uint64(1024),
		Disk:  uint64(20),
	}, {
		Name:  "flavor.large-nvidia",
		Vcpus: uint64(10),
		Ram:   uint64(8192),
		Disk:  uint64(40),
		Gpus: []*edgeproto.GPUResource{{
			ModelId: "nvidia-t4-q10",
			Vendor:  "nvidia",
			Memory:  2,
			Count:   1,
		}},
	}}
	apis.cloudletInfoApi.Update(ctx, &cloudletInfo, 0)
	obj.CloudletKey = vgpuCloudlet.Key
	err = apis.clusterInstApi.CreateClusterInst(&obj, testutil.NewCudStreamoutClusterInst(ctx))
	require.NotNil(t, err, "create cluster inst with gpu flavor on vgpu cloudlet fails")
	require.Contains(t, err.Error(), "failed to select infra flavor for pool gpupool, no suitable infra flavor found for requested node resources, 3 with not enough nvidia-t4")

	cloudletInfo.Flavors = append(cloudletInfo.Flavors, &edgeproto.FlavorInfo{
		Name:  "flavor.large-nvidia",
		Vcpus: uint64(10),
		Ram:   uint64(8192),
		Disk:  uint64(40),
		Gpus: []*edgeproto.GPUResource{{
			ModelId: "nvidia-t4",
			Vendor:  "nvidia",
			Memory:  2,
			Count:   1,
		}},
	})
	apis.cloudletInfoApi.Update(ctx, &cloudletInfo, 0)

	verbose = true
	err = apis.clusterInstApi.CreateClusterInst(&obj, testutil.NewCudStreamoutClusterInst(ctx))
	require.Nil(t, err, "create cluster inst with gpu flavor on gpu cloudlet")
}

func setTestMasterNodeFlavorSetting(t *testing.T, ctx context.Context, apis *AllApis) {
	// set default master node flavor
	// this is not required, but having at least one test do this
	// exercises that code path.
	flavors := testutil.FlavorData()
	settings := apis.settingsApi.Get()
	settings.MasterNodeFlavor = flavors[0].Key.Name
	settings.Fields = []string{edgeproto.SettingsFieldMasterNodeFlavor}
	_, err := apis.settingsApi.UpdateSettings(ctx, settings)
	require.Nil(t, err)
}

func testClusterPotentialCloudlets(t *testing.T, ctx context.Context, apis *AllApis) {
	// Test potential cloudlet algorithm based on available resources

	// Set up a test zone with 3 cloudlets. Expect ClusterCreate to
	// choose cloudlets based on available resources.
	zone, cloudlets, _, cleanup := testPotentialCloudletsCreateDeps(t, ctx, apis)
	defer cleanup()

	// Create six clusters. Resource usage in num nodes will be
	// 6, 5, 4, 3, 2, 1. For the first three clusters, it will
	// go in order based on name since all three cloudlets have
	// no resource usage. The second three clusters will start
	// from the last cloudlet because it has the most free resources,
	// and end on the first cloudlet. In the end, we should have:
	// cloudlet0: cluster0 (6 nodes) + cluster5 (1 node)
	// cloudlet1: cluster1 (5 nodes) + cluster4 (2 nodes)
	// cloudlet2: cluster2 (4 nodes) + cluster3 (3 nodes)
	clusters := []*edgeproto.ClusterInst{}
	for ii := 0; ii < 6; ii++ {
		ci := &edgeproto.ClusterInst{}
		ci.Key.Name = fmt.Sprintf("pcclust%d", ii)
		ci.Key.Organization = "pcdev"
		ci.ZoneKey = zone.Key
		ci.NodePools = []*edgeproto.NodePool{{
			Name:     "cpupool",
			NumNodes: uint32(6 - ii),
			NodeResources: &edgeproto.NodeResources{
				Vcpus: 1,
				Ram:   1024,
				Disk:  10,
			},
		}}
		err := apis.clusterInstApi.CreateClusterInst(ci, testutil.NewCudStreamoutClusterInst(ctx))
		require.Nil(t, err)
		outCi := &edgeproto.ClusterInst{}
		found := apis.clusterInstApi.cache.Get(&ci.Key, outCi)
		require.True(t, found)
		cloudletName := ""
		if ii < 3 {
			cloudletName = cloudlets[ii].Key.Name
		} else {
			cloudletName = cloudlets[5-ii].Key.Name
		}
		require.Equal(t, cloudletName, outCi.CloudletKey.Name)
		clusters = append(clusters, ci)
	}
	// cleanup
	for _, ci := range clusters {
		err := apis.clusterInstApi.DeleteClusterInst(ci, testutil.NewCudStreamoutClusterInst(ctx))
		require.Nil(t, err)
	}

	// test corner case, no cloudlets with enough resources
	ci := &edgeproto.ClusterInst{}
	ci.Key.Name = "toobig"
	ci.Key.Organization = "pcdev"
	ci.ZoneKey = zone.Key
	ci.NodePools = []*edgeproto.NodePool{{
		Name:     "cpupool",
		NumNodes: 20,
		NodeResources: &edgeproto.NodeResources{
			Vcpus: 4,
			Ram:   4096,
			Disk:  40,
		},
	}}
	err := apis.clusterInstApi.CreateClusterInst(ci, testutil.NewCudStreamoutClusterInst(ctx))
	require.NotNil(t, err)
	require.Equal(t, "not enough resources available to create the cluster", err.Error())
}

func testPotentialCloudletsCreateDeps(t *testing.T, ctx context.Context, apis *AllApis) (*edgeproto.Zone, []*edgeproto.Cloudlet, []*edgeproto.CloudletInfo, func()) {
	syncWait := apis.zoneApi.sync.SyncWait
	// create zone
	zone := &edgeproto.Zone{}
	zone.Key.Name = "pczone"
	zone.Key.Organization = "pcorg"
	_, err := apis.zoneApi.store.Put(ctx, zone, syncWait)
	require.Nil(t, err)

	// create cloudlets
	cloudletData := testutil.CloudletData()
	cloudletInfoData := testutil.CloudletInfoData()
	cloudlets := []*edgeproto.Cloudlet{}
	cloudletInfos := []*edgeproto.CloudletInfo{}
	for ii := 0; ii < 4; ii++ {
		cloudlet := cloudletData[0].Clone()
		cloudlet.Key.Name = fmt.Sprintf("c%d", ii)
		cloudlet.Key.Organization = zone.Key.Organization
		cloudlet.Zone = zone.Key.Name
		disk := 0 // no quota
		if ii == 3 {
			// add in a disk quota that prevents this cloudlet
			// from being used at all
			disk = 1
		}
		cloudlet.ResourceQuotas = []edgeproto.ResourceQuota{{
			Name:  cloudcommon.ResourceVcpus,
			Value: 20,
		}, {
			Name:  cloudcommon.ResourceRamMb,
			Value: 81920,
		}, {
			Name:  cloudcommon.ResourceDiskGb,
			Value: uint64(disk),
		}}
		_, err := apis.cloudletApi.store.Put(ctx, cloudlet, syncWait)
		require.Nil(t, err)
		info := cloudletInfoData[0].Clone()
		info.Key = cloudlet.Key
		info.ResourcesSnapshot.Info = nil
		_, err = apis.cloudletInfoApi.store.Put(ctx, info, syncWait)
		require.Nil(t, err)
		cloudlets = append(cloudlets, cloudlet)
		cloudletInfos = append(cloudletInfos, info)
	}

	cleanup := func() {
		for _, c := range cloudlets {
			apis.cloudletApi.store.Delete(ctx, c, syncWait)
		}
		for _, i := range cloudletInfos {
			apis.cloudletInfoApi.store.Delete(ctx, i, syncWait)
		}
		apis.zoneApi.store.Delete(ctx, zone, syncWait)
	}
	return zone, cloudlets, cloudletInfos, cleanup
}

type InfraRess []*edgeproto.InfraResource

func (s InfraRess) AddVcpus(val, max uint64) InfraRess {
	return append(s, &edgeproto.InfraResource{
		Name:          cloudcommon.ResourceVcpus,
		Value:         val,
		InfraMaxValue: max,
	})
}

func (s InfraRess) AddRam(val, max uint64) InfraRess {
	return append(s, &edgeproto.InfraResource{
		Name:          cloudcommon.ResourceRamMb,
		Value:         val,
		Units:         cloudcommon.ResourceRamUnits,
		InfraMaxValue: max,
	})
}

func (s InfraRess) AddDisk(val, max uint64) InfraRess {
	return append(s, &edgeproto.InfraResource{
		Name:          cloudcommon.ResourceDiskGb,
		Value:         val,
		Units:         cloudcommon.ResourceDiskUnits,
		InfraMaxValue: max,
	})
}

func (s InfraRess) AddGPU(product string, val, max uint64) InfraRess {
	return append(s, &edgeproto.InfraResource{
		Name:          product,
		Value:         val,
		InfraMaxValue: max,
		Type:          cloudcommon.ResourceTypeGPU,
	})
}

func (s InfraRess) AddOptRes(name string, val, max uint64) InfraRess {
	return append(s, &edgeproto.InfraResource{
		Name:          name,
		Value:         val,
		InfraMaxValue: max,
	})
}

func testClusterResourceUsage(t *testing.T, ctx context.Context, apis *AllApis) {
	// assumes testutil.CloudletData() cloudlets, cloudletInfos
	// are present
	cloudletData := testutil.CloudletData()

	// create app and appinst data for used calculations
	dockerApp := &edgeproto.App{
		Key: edgeproto.AppKey{
			Name:         "dockerApp",
			Organization: "dev",
			Version:      "1.0",
		},
		Deployment: cloudcommon.DeploymentTypeDocker,
	}
	k8sApp := &edgeproto.App{
		Key: edgeproto.AppKey{
			Name:         "k8sApp",
			Organization: "dev",
			Version:      "1.0",
		},
		Deployment: cloudcommon.DeploymentTypeKubernetes,
	}
	for _, app := range []*edgeproto.App{dockerApp, k8sApp} {
		_, err := apis.appApi.store.Put(ctx, app, apis.appApi.sync.SyncWait)
		require.Nil(t, err)
		defer apis.appApi.store.Delete(ctx, app, apis.appApi.sync.SyncWait)
	}
	// appinsts just need resources for used calculations
	aiK8sTiny := &edgeproto.AppInst{
		Key: edgeproto.AppInstKey{
			Name:         "aiK8sTiny",
			Organization: "dev",
		},
		AppKey: k8sApp.Key,
		KubernetesResources: &edgeproto.KubernetesResources{
			CpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(0, 500*edgeproto.DecMillis),
				TotalMemory: 100,
			},
		},
	}
	aiK8sMed := &edgeproto.AppInst{
		Key: edgeproto.AppInstKey{
			Name:         "aiK8sMed",
			Organization: "dev",
		},
		AppKey: k8sApp.Key,
		KubernetesResources: &edgeproto.KubernetesResources{
			CpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(2, 0),
				TotalMemory: 4096,
			},
		},
	}
	aiK8sGpu := &edgeproto.AppInst{
		Key: edgeproto.AppInstKey{
			Name:         "aiK8sGpu",
			Organization: "dev",
		},
		AppKey: k8sApp.Key,
		KubernetesResources: &edgeproto.KubernetesResources{
			GpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(2, 0),
				TotalMemory: 4096,
				TotalGpus: []*edgeproto.GPUResource{{
					ModelId: "nvidia-t4",
					Count:   1,
				}},
			},
		},
	}
	aiDocSmall := &edgeproto.AppInst{
		Key: edgeproto.AppInstKey{
			Name:         "aiDocSmall",
			Organization: "dev",
		},
		AppKey: dockerApp.Key,
		NodeResources: &edgeproto.NodeResources{
			Vcpus: 1,
			Ram:   2048,
			Disk:  10,
		},
	}
	aiDocMed := &edgeproto.AppInst{
		Key: edgeproto.AppInstKey{
			Name:         "aiDocMed",
			Organization: "dev",
		},
		AppKey: dockerApp.Key,
		NodeResources: &edgeproto.NodeResources{
			Vcpus: 3,
			Ram:   3072,
			Disk:  15,
		},
	}
	for _, ai := range []*edgeproto.AppInst{
		aiK8sTiny, aiK8sMed, aiK8sGpu, aiDocSmall, aiDocMed,
	} {
		_, err := apis.appInstApi.store.Put(ctx, ai, apis.appInstApi.sync.SyncWait)
		require.Nil(t, err)
		defer apis.appInstApi.store.Delete(ctx, ai, apis.appInstApi.sync.SyncWait)
	}

	// run tests
	var tests = []struct {
		desc   string
		ci     edgeproto.ClusterInst
		usage  edgeproto.ClusterResourceUsage
		refs   []edgeproto.AppInstKey
		expErr string
	}{{
		desc: "corner case: kubernetes no node pools",
		ci: edgeproto.ClusterInst{
			Deployment:  cloudcommon.DeploymentTypeKubernetes,
			CloudletKey: cloudletData[0].Key,
		},
		usage: edgeproto.ClusterResourceUsage{
			TotalResources:    []*edgeproto.InfraResource{},
			CpuPoolsResources: []*edgeproto.InfraResource{},
			GpuPoolsResources: []*edgeproto.InfraResource{},
		},
	}, {
		desc: "corner case: docker no node resources",
		ci: edgeproto.ClusterInst{
			Deployment:  cloudcommon.DeploymentTypeDocker,
			CloudletKey: cloudletData[0].Key,
		},
		usage: edgeproto.ClusterResourceUsage{
			TotalResources: []*edgeproto.InfraResource{},
		},
	}, {
		desc: "kubernetes cpu pool only, no used, flavor based",
		ci: edgeproto.ClusterInst{
			Deployment:  cloudcommon.DeploymentTypeKubernetes,
			CloudletKey: cloudletData[0].Key,
			NodePools: []*edgeproto.NodePool{{
				Name:     "cpu1",
				NumNodes: 2,
				NodeResources: &edgeproto.NodeResources{
					InfraNodeFlavor: "flavor.small",
				},
			}},
		},
		usage: edgeproto.ClusterResourceUsage{
			TotalResources:        InfraRess{}.AddDisk(0, 40).AddRam(0, 2048).AddVcpus(0, 4),
			CpuPoolsResources:     InfraRess{}.AddDisk(0, 40).AddRam(0, 2048).AddVcpus(0, 4),
			GpuPoolsResources:     InfraRess{},
			ResourceScore:         3024,
			CpuPoolsResourceScore: 3024,
		},
	}, {
		desc: "kubernetes cpu and gpu pools, no used, flavor and resource based",
		ci: edgeproto.ClusterInst{
			Deployment:  cloudcommon.DeploymentTypeKubernetes,
			CloudletKey: cloudletData[0].Key,
			NodePools: []*edgeproto.NodePool{{
				Name:     "cpu1",
				NumNodes: 2,
				NodeResources: &edgeproto.NodeResources{
					InfraNodeFlavor: "flavor.small",
				},
			}, {
				Name:     "gpu1",
				NumNodes: 3,
				NodeResources: &edgeproto.NodeResources{
					Vcpus: 2,
					Ram:   8192,
					Disk:  40,
					Gpus: []*edgeproto.GPUResource{{
						ModelId: "nvidia-t4",
						Count:   1,
					}},
				},
			}, {
				Name:     "cpu2",
				NumNodes: 1,
				NodeResources: &edgeproto.NodeResources{
					Vcpus: 4,
					Ram:   8192,
					Disk:  40,
				},
			}},
		},
		usage: edgeproto.ClusterResourceUsage{
			TotalResources:        InfraRess{}.AddDisk(0, 200).AddRam(0, 34816).AddGPU("nvidia-t4", 0, 3).AddVcpus(0, 14),
			CpuPoolsResources:     InfraRess{}.AddDisk(0, 80).AddRam(0, 10240).AddVcpus(0, 8),
			GpuPoolsResources:     InfraRess{}.AddDisk(0, 120).AddRam(0, 24576).AddGPU("nvidia-t4", 0, 3).AddVcpus(0, 6),
			ResourceScore:         24408,
			CpuPoolsResourceScore: 9120,
			GpuPoolsResourceScore: 15288,
		},
	}, {
		desc: "kubernetes cpu and gpu pools, used, resource based",
		ci: edgeproto.ClusterInst{
			Deployment:  cloudcommon.DeploymentTypeKubernetes,
			CloudletKey: cloudletData[0].Key,
			NodePools: []*edgeproto.NodePool{{
				Name:     "cpu1",
				NumNodes: 3,
				NodeResources: &edgeproto.NodeResources{
					Vcpus: 2,
					Ram:   8192,
					Disk:  40,
				}, // total: 6, 24576, 120
			}, {
				Name:     "gpu1",
				NumNodes: 3,
				NodeResources: &edgeproto.NodeResources{
					Vcpus: 2,
					Ram:   8192,
					Disk:  40,
					Gpus: []*edgeproto.GPUResource{{
						ModelId: "nvidia-t4",
						Count:   1,
					}},
				}, // total: 6, 24576, 120, 3
			}},
		},
		refs: []edgeproto.AppInstKey{
			aiK8sTiny.Key, aiK8sMed.Key, aiK8sGpu.Key,
			// cpu used: 2.5, 4196, 0
			// gpu used: 2, 4096, 0, 1
		},
		usage: edgeproto.ClusterResourceUsage{
			TotalResources:        InfraRess{}.AddDisk(0, 240).AddRam(8292, 49152).AddGPU("nvidia-t4", 1, 3).AddVcpus(4, 12),
			CpuPoolsResources:     InfraRess{}.AddDisk(0, 120).AddRam(4196, 24576).AddVcpus(2, 6),
			GpuPoolsResources:     InfraRess{}.AddDisk(0, 120).AddRam(4096, 24576).AddGPU("nvidia-t4", 1, 3).AddVcpus(2, 6),
			ResourceScore:         24180,
			CpuPoolsResourceScore: 11940,
			GpuPoolsResourceScore: 12240,
		},
	}, {
		desc: "kubernetes cpu and gpu pools, max used, resource based",
		ci: edgeproto.ClusterInst{
			Deployment:  cloudcommon.DeploymentTypeKubernetes,
			CloudletKey: cloudletData[0].Key,
			NodePools: []*edgeproto.NodePool{{
				Name:     "cpu1",
				NumNodes: 3,
				NodeResources: &edgeproto.NodeResources{
					Vcpus: 2,
					Ram:   8192,
					Disk:  40,
				}, // total: 6, 24576, 120
			}, {
				Name:     "gpu1",
				NumNodes: 3,
				NodeResources: &edgeproto.NodeResources{
					Vcpus: 2,
					Ram:   8192,
					Disk:  40,
					Gpus: []*edgeproto.GPUResource{{
						ModelId: "nvidia-t4",
						Count:   1,
					}},
				}, // total: 6, 24576, 120, 3
			}},
		},
		refs: []edgeproto.AppInstKey{
			aiK8sMed.Key, aiK8sMed.Key, aiK8sMed.Key,
			aiK8sGpu.Key, aiK8sGpu.Key, aiK8sGpu.Key,
			// cpu used: 6, 12288, 0
			// gpu used: 6, 12288, 0, 3
		},
		usage: edgeproto.ClusterResourceUsage{
			TotalResources:        InfraRess{}.AddDisk(0, 240).AddRam(24576, 49152).AddGPU("nvidia-t4", 3, 3).AddVcpus(12, 12),
			CpuPoolsResources:     InfraRess{}.AddDisk(0, 120).AddRam(12288, 24576).AddVcpus(6, 6),
			GpuPoolsResources:     InfraRess{}.AddDisk(0, 120).AddRam(12288, 24576).AddGPU("nvidia-t4", 3, 3).AddVcpus(6, 6),
			ResourceScore:         12288,
			CpuPoolsResourceScore: 6144,
			GpuPoolsResourceScore: 6144,
		},
	}, {
		desc: "docker used",
		ci: edgeproto.ClusterInst{
			Deployment:  cloudcommon.DeploymentTypeDocker,
			CloudletKey: cloudletData[0].Key,
			NodeResources: &edgeproto.NodeResources{
				InfraNodeFlavor: "flavor.large",
			}, // 10, 8192, 40
		},
		refs: []edgeproto.AppInstKey{
			aiDocSmall.Key, aiDocMed.Key,
		},
		usage: edgeproto.ClusterResourceUsage{
			TotalResources: InfraRess{}.AddDisk(25, 40).AddRam(5120, 8192).AddGPU("nvidia-t4", 0, 1).AddVcpus(4, 10),
			ResourceScore:  4536,
		},
	}}
	for _, test := range tests {
		info := &edgeproto.CloudletInfo{}
		found := apis.cloudletInfoApi.cache.Get(&test.ci.CloudletKey, info)
		require.True(t, found, test.desc)
		flavorLookup := info.GetFlavorLookup()
		// add in refs
		test.ci.Key.Name = test.desc
		refs := edgeproto.ClusterRefs{
			Key:  test.ci.Key,
			Apps: test.refs,
		}
		_, err := apis.clusterRefsApi.store.Put(ctx, &refs, apis.clusterRefsApi.sync.SyncWait)
		require.Nil(t, err)
		defer apis.clusterRefsApi.store.Delete(ctx, &refs, apis.clusterRefsApi.sync.SyncWait)
		// check usage
		usage, err := apis.clusterInstApi.getClusterResourceUsage(ctx, &test.ci, flavorLookup)
		if test.expErr != "" {
			require.NotNil(t, err, test.desc)
			require.Contains(t, err.Error(), test.expErr, test.desc)
		} else {
			test.usage.Key = test.ci.Key
			test.usage.CloudletKey = test.ci.CloudletKey
			test.usage.ZoneKey = test.ci.ZoneKey
			require.Nil(t, err, test.desc)
			require.Equal(t, &test.usage, usage, test.desc)
		}
	}
}

func testCloudletIPs(t *testing.T, ctx context.Context, apis *AllApis) {
	// This tests that the cluster is annotated correctly with
	// the allocated VIP.
	// Tests for IP allocation are in pkg/cloudletips
	cloudlet := testutil.CloudletData()[5]
	cloudlet.Key.Name = "testCloudletIPs"
	cloudlet.EnvVar = map[string]string{
		cloudcommon.FloatingVIPs: "10.10.10.150-10.10.10.154",
	}

	// create cloudlet
	err := apis.cloudletApi.CreateCloudlet(&cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err)

	// create cluster
	cluster := testutil.ClusterInstData()[0]
	cluster.CloudletKey = cloudlet.Key
	err = apis.clusterInstApi.CreateClusterInst(&cluster, testutil.NewCudStreamoutClusterInst(ctx))
	require.Nil(t, err)

	// check that cluster has control plane VIP annotation
	clusterObj := edgeproto.ClusterInst{}
	ok := apis.clusterInstApi.cache.Get(&cluster.Key, &clusterObj)
	require.True(t, ok)
	require.NotNil(t, clusterObj.Annotations)
	ip, ok := clusterObj.Annotations[cloudcommon.AnnotationControlVIP]
	require.True(t, ok)
	require.Equal(t, "10.10.10.150", ip)

	// check that cloudletIPs are set.
	// the "fakebaremetal" platform will allocate an IP for the
	// ingress-nginx load balancer.
	ips := edgeproto.CloudletIPs{}
	ok = apis.cloudletIPsApi.cache.Get(&cloudlet.Key, &ips)
	require.True(t, ok)
	require.Equal(t, 1, len(ips.ClusterIps), ips.ClusterIps)
	cips, ok := ips.ClusterIps[cluster.Key.GetKeyString()]
	require.True(t, ok, ips.ClusterIps)
	require.Equal(t, "10.10.10.150", cips.ControlPlaneIpv4)
	require.Equal(t, 1, len(cips.LoadBalancers), cips.LoadBalancers)
	lbKey := edgeproto.LoadBalancerKey{
		Namespace: k8smgmt.IngressNginxNamespace,
		Name:      k8smgmt.IngressNginxLoadBalancerName,
	}
	lb, ok := cips.LoadBalancers[lbKey.GetKeyString()]
	require.True(t, ok, cips.LoadBalancers)
	require.Equal(t, "10.10.10.151", lb.Ipv4)

	// delete cluster
	err = apis.clusterInstApi.DeleteClusterInst(&cluster, testutil.NewCudStreamoutClusterInst(ctx))
	require.Nil(t, err)

	// delete cloudlet
	err = apis.cloudletApi.DeleteCloudlet(&cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err)

	ok = apis.cloudletIPsApi.cache.Get(&cloudlet.Key, &ips)
	require.False(t, ok)
}

func testClusterInstFlavorResourceUsage(t *testing.T, ctx context.Context, apis *AllApis, ccrm *ccrmdummy.CCRMDummy) {
	// This tests bare metal cloudlet resource usage which tracks
	// resources in numbers of flavors (nodes) used.
	// Create test bare metal cloudlet
	cloudlet := testutil.CloudletData()[5]
	require.Equal(t, platform.PlatformTypeFakeBareMetal, cloudlet.PlatformType)
	cloudlet.Key.Name = "testFlavorCounts"
	cloudletInfo := &edgeproto.CloudletInfo{
		Key:   cloudlet.Key,
		State: dme.CloudletState_CLOUDLET_STATE_READY,
		Flavors: []*edgeproto.FlavorInfo{{
			Name:  "flavor.lg-master",
			Vcpus: uint64(4),
			Ram:   uint64(8192),
			Disk:  uint64(60),
		}, {
			Name:  "flavor.large-vgpu",
			Vcpus: uint64(4),
			Ram:   uint64(16384),
			Disk:  uint64(80),
			Gpus: []*edgeproto.GPUResource{{
				ModelId: "nvidia-v1",
				Vendor:  "nvidia",
				Memory:  12,
				Count:   1,
			}},
		}, {
			Name:  "flavor.large-gpu",
			Vcpus: uint64(12),
			Ram:   uint64(65536),
			Disk:  uint64(120),
			Gpus: []*edgeproto.GPUResource{{
				ModelId: "nvidia-t4",
				Vendor:  "nvidia",
				Memory:  80,
				Count:   1,
			}},
		}},
		ResourcesSnapshot: edgeproto.InfraResourcesSnapshot{
			Info: []edgeproto.InfraResource{{
				Name:          "flavor.lg-master",
				InfraMaxValue: uint64(8),
				Type:          "flavor",
			}, {
				Name:          "flavor.large-vgpu",
				InfraMaxValue: uint64(16),
				Type:          "flavor",
			}, {
				Name:          "flavor.large-gpu",
				InfraMaxValue: uint64(4),
				Type:          "flavor",
			}},
		},
		CompatibilityVersion: cloudcommon.GetCRMCompatibilityVersion(),
	}

	// ensure correct resource max values are returned in
	// resource snapshot as part of cloudletinfo.
	fake.FakeResourceSnapshots[cloudlet.Key] = &cloudletInfo.ResourcesSnapshot
	defer delete(fake.FakeResourceSnapshots, cloudlet.Key)

	// create cloudlet
	err := apis.cloudletApi.CreateCloudlet(&cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err)
	defer apis.cloudletApi.DeleteCloudlet(&cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
	// put cloudlet info
	apis.cloudletInfoApi.Update(ctx, cloudletInfo, 0)

	// For bare metal cloudlet, we do not allow workloads on
	// control plane.

	createClusterInst := func(name string, infraFlavor string, numNodes int) error {
		ci := &edgeproto.ClusterInst{
			Key: edgeproto.ClusterKey{
				Name:         name,
				Organization: "dev1",
			},
			CloudletKey: cloudlet.Key,
			NodePools: []*edgeproto.NodePool{{
				Name:     "pool1",
				NumNodes: uint32(numNodes),
				NodeResources: &edgeproto.NodeResources{
					InfraNodeFlavor: infraFlavor,
				},
			}},
		}
		return apis.clusterInstApi.CreateClusterInst(ci, testutil.NewCudStreamoutClusterInst(ctx))
	}
	deleteClusterInst := func(name string) {
		err := apis.clusterInstApi.DeleteClusterInst(&edgeproto.ClusterInst{
			Key: edgeproto.ClusterKey{
				Name:         name,
				Organization: "dev1",
			},
		}, testutil.NewCudStreamoutClusterInst(ctx))
		require.Nil(t, err)
	}

	verifyResourceUsage := func(filter string, expUsage map[string]int) {
		out, err := apis.cloudletApi.GetCloudletResourceUsage(ctx, &edgeproto.CloudletResourceUsage{
			Key: cloudlet.Key,
		})
		require.Nil(t, err)
		outUsage := map[string]int{}
		for _, info := range out.Info {
			if filter != "" && info.Type != filter {
				continue
			}
			outUsage[info.Name] = int(info.Value)
		}
		require.Equal(t, expUsage, outUsage)
	}

	// we're going to create cluster insts, check resource usage,
	// and verify that create fails if no resources are available.
	verifyResourceUsage("flavor", map[string]int{
		"flavor.lg-master":  0,
		"flavor.large-vgpu": 0,
		"flavor.large-gpu":  0,
	})

	err = createClusterInst("cpu", "flavor.lg-master", 3)
	require.Nil(t, err)
	verifyResourceUsage("flavor", map[string]int{
		"flavor.lg-master":  3,
		"flavor.large-vgpu": 0,
		"flavor.large-gpu":  0,
	})

	err = createClusterInst("gpu", "flavor.large-gpu", 3)
	require.Nil(t, err)
	verifyResourceUsage("flavor", map[string]int{
		"flavor.lg-master":  3,
		"flavor.large-vgpu": 0,
		"flavor.large-gpu":  3,
	})

	err = createClusterInst("gpu2", "flavor.large-gpu", 3)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "not enough resources available: required flavor/flavor.large-gpu is 3 but only 1 out of 4 is available")
	verifyResourceUsage("flavor", map[string]int{
		"flavor.lg-master":  3,
		"flavor.large-vgpu": 0,
		"flavor.large-gpu":  3,
	})

	// create clusterInst based on separate resources
	ci := &edgeproto.ClusterInst{
		Key: edgeproto.ClusterKey{
			Name:         "gpu3",
			Organization: "dev1",
		},
		CloudletKey: cloudlet.Key,
		NodePools: []*edgeproto.NodePool{{
			Name:     "pool1",
			NumNodes: uint32(5),
			NodeResources: &edgeproto.NodeResources{
				Vcpus: 4,
				Ram:   4096,
				Gpus: []*edgeproto.GPUResource{{
					ModelId: "nvidia-v1",
					Count:   1,
				}},
			},
		}},
	}
	err = apis.clusterInstApi.CreateClusterInst(ci, testutil.NewCudStreamoutClusterInst(ctx))
	require.Nil(t, err)
	verifyResourceUsage("flavor", map[string]int{
		"flavor.lg-master":  3,
		"flavor.large-vgpu": 5,
		"flavor.large-gpu":  3,
	})

	// verify ShowCloudletResourceUsage
	// this checks that content of flavors gets converted to
	// separate resources correctly for UI display.
	expUsage := []edgeproto.InfraResource{{
		Name:          cloudcommon.ResourceDiskGb,
		Value:         3*60 + 5*80 + 3*120,
		Units:         cloudcommon.ResourceDiskUnits,
		InfraMaxValue: 8*60 + 16*80 + 4*120,
	}, {
		Name:  cloudcommon.ResourceInstances,
		Value: 3 + 5 + 3,
	}, {
		Name:          cloudcommon.ResourceRamMb,
		Value:         3*8192 + 5*16384 + 3*65536,
		Units:         cloudcommon.ResourceRamUnits,
		InfraMaxValue: 8*8192 + 16*16384 + 4*65536,
	}, {
		Name:          "flavor.large-gpu",
		Value:         3,
		InfraMaxValue: 4,
		Type:          cloudcommon.ResourceTypeFlavor,
	}, {
		Name:          "flavor.large-vgpu",
		Value:         5,
		InfraMaxValue: 16,
		Type:          cloudcommon.ResourceTypeFlavor,
	}, {
		Name:          "flavor.lg-master",
		Value:         3,
		InfraMaxValue: 8,
		Type:          cloudcommon.ResourceTypeFlavor,
	}, {
		Name:          "nvidia-t4",
		Value:         3,
		InfraMaxValue: 4,
		Type:          cloudcommon.ResourceTypeGPU,
	}, {
		Name:          "nvidia-v1",
		Value:         5,
		InfraMaxValue: 16,
		Type:          cloudcommon.ResourceTypeGPU,
	}, {
		Name:          cloudcommon.ResourceVcpus,
		Value:         3*4 + 5*4 + 3*12,
		InfraMaxValue: 8*4 + 16*4 + 4*12,
	}}
	usage, err := apis.cloudletApi.GetCloudletResourceUsage(ctx, &edgeproto.CloudletResourceUsage{
		Key: cloudlet.Key,
	})
	require.Nil(t, err)
	require.Equal(t, expUsage, usage.Info)

	// verify ShowCloudletGPUUsage
	expGPUUsage := []*edgeproto.GPUUsage{{
		Gpu: &edgeproto.GPUResource{
			ModelId: "nvidia-t4",
			Vendor:  "nvidia",
			Memory:  80,
		},
		Usage: &edgeproto.InfraResource{
			Name:          "nvidia-t4",
			Value:         3,
			InfraMaxValue: 4,
			Type:          "gpu",
		},
	}, {
		Gpu: &edgeproto.GPUResource{
			ModelId: "nvidia-v1",
			Vendor:  "nvidia",
			Memory:  12,
		},
		Usage: &edgeproto.InfraResource{
			Name:          "nvidia-v1",
			Value:         5,
			InfraMaxValue: 16,
			Type:          "gpu",
		},
	}}
	gpuUsage := ShowCloudletGPUUsageData{
		ctx: ctx,
	}
	filter := &edgeproto.Cloudlet{
		Key: cloudlet.Key,
	}
	err = apis.cloudletApi.ShowCloudletGPUUsage(filter, &gpuUsage)
	require.Nil(t, err)
	require.Equal(t, 1, len(gpuUsage.data))
	require.Equal(t, expGPUUsage, gpuUsage.data[0].Gpus)

	deleteClusterInst("cpu")
	verifyResourceUsage("flavor", map[string]int{
		"flavor.lg-master":  0,
		"flavor.large-vgpu": 5,
		"flavor.large-gpu":  3,
	})

	deleteClusterInst("gpu")
	verifyResourceUsage("flavor", map[string]int{
		"flavor.lg-master":  0,
		"flavor.large-vgpu": 5,
		"flavor.large-gpu":  0,
	})

	deleteClusterInst("gpu3")
	verifyResourceUsage("flavor", map[string]int{
		"flavor.lg-master":  0,
		"flavor.large-vgpu": 0,
		"flavor.large-gpu":  0,
	})

	// test ShowFlavorsForZone
	show := testutil.ShowFlavorsForZone{}
	show.Init()
	show.Ctx = ctx
	err = apis.cloudletApi.ShowFlavorsForZone(cloudlet.GetZone(), &show)
	require.Nil(t, err)
}
