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
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/ccrmdummy"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/notify"
	"github.com/edgexr/edge-cloud-platform/pkg/process"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
	"github.com/edgexr/edge-cloud-platform/test/testutil/testservices"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func getGrpcClient(t *testing.T) (*grpc.ClientConn, error) {
	// grpc client
	return grpc.Dial("127.0.0.1:55001", grpc.WithInsecure(), grpc.WithDefaultCallOptions(grpc.ForceCodec(&cloudcommon.ProtoCodec{})))
}

func TestController(t *testing.T) {
	// for stress or leakage testing, bump up numTests
	numTests := 1
	for i := 0; i < numTests; i++ {
		testC(t)
	}
}

func testC(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelNotify | log.DebugLevelApi | log.DebugLevelUpgrade)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())
	flag.Parse() // set defaults

	// Using one or more clusters is primarily for stress testing.
	// It is recommended that a ramdisk be used to avoid etcd errors
	// slow disk response.
	useCluster := false
	useTwoClusters := false
	if useCluster || useTwoClusters {
		etcds, etcdAddrs, err := regiondata.StartLocalEtcdCluster("local", 3, 3100, process.WithCleanStartup())
		require.Nil(t, err)
		*etcdUrls = etcdAddrs
		defer func() {
			for _, e := range etcds {
				e.StopLocal()
			}
		}()
	} else if useTwoClusters {
		cluster2, _, err := regiondata.StartLocalEtcdCluster("local2", 3, 3300, process.WithCleanStartup())
		require.Nil(t, err)
		defer func() {
			for _, e := range cluster2 {
				e.StopLocal()
			}
		}()
	} else {
		// single etcd instance
		*localEtcd = true
		*initLocalEtcd = true
	}

	testSvcs := testinit(ctx, t)
	defer testfinish(testSvcs)

	redisCfg.SentinelAddrs = testSvcs.DummyRedisSrv.GetSentinelAddr()

	// avoid dummy influxQs created by testinit() since we're calling startServices
	services = Services{}
	// close redis client since it will get overwritten by startServices()
	redisClient.Close()

	leaseTimeoutSec = 3
	syncLeaseDataRetry = 0

	err := startServices()
	defer stopServices()
	require.Nil(t, err, "start")
	apis := services.allApis

	reduceInfoTimeouts(t, ctx, apis)

	testservices.CheckNotifySendOrder(t, notify.ServerMgrOne.GetSendOrder())

	conn, err := getGrpcClient(t)
	require.Nil(t, err, "grpc client")
	defer conn.Close()

	// test notify clients
	notifyAddrs := []string{*notifyAddr}
	crmNotify := notify.NewDummyHandler()
	crmClient := notify.NewClient("crm", notifyAddrs, nil)
	crmNotify.RegisterCRMClient(crmClient)
	dummyResponder := DummyInfoResponder{
		CloudletCache:       &crmNotify.CloudletCache,
		AppInstCache:        &crmNotify.AppInstCache,
		ClusterInstCache:    &crmNotify.ClusterInstCache,
		RecvAppInstInfo:     &crmNotify.AppInstInfoCache,
		RecvClusterInstInfo: &crmNotify.ClusterInstInfoCache,
	}
	dummyResponder.InitDummyInfoResponder()
	cloudletData := testutil.CloudletData()
	crmsOnEdge := map[edgeproto.CloudletKey]struct{}{}
	for ii, _ := range testutil.CloudletInfoData() {
		if cloudletData[ii].CrmOnEdge {
			crmNotify.CloudletInfoCache.Update(ctx, &testutil.CloudletInfoData()[ii], 0)
			crmsOnEdge[cloudletData[ii].Key] = struct{}{}
		}
	}
	etcdStore, err := regiondata.GetEtcdClientBasic(*etcdUrls)
	require.Nil(t, err)
	ccrm := ccrmdummy.StartDummyCCRM(ctx, testSvcs.DummyVault.Config, etcdStore)
	registerDummyCCRMConn(t, ccrm)
	defer ccrm.Stop()

	go crmClient.Start()
	defer crmClient.Stop()
	dmeNotify := notify.NewDummyHandler()
	dmeClient := notify.NewClient("dme", notifyAddrs, nil)
	dmeNotify.RegisterDMEClient(dmeClient)
	go dmeClient.Start()
	defer dmeClient.Stop()

	appClient := edgeproto.NewAppApiClient(conn)
	gpuDriverClient := edgeproto.NewGPUDriverApiClient(conn)
	resTagTableClient := edgeproto.NewResTagTableApiClient(conn)
	zoneClient := edgeproto.NewZoneApiClient(conn)
	cloudletClient := edgeproto.NewCloudletApiClient(conn)
	appInstClient := edgeproto.NewAppInstApiClient(conn)
	flavorClient := edgeproto.NewFlavorApiClient(conn)
	clusterInstClient := edgeproto.NewClusterInstApiClient(conn)
	cloudletInfoClient := edgeproto.NewCloudletInfoApiClient(conn)
	autoScalePolicyClient := edgeproto.NewAutoScalePolicyApiClient(conn)
	autoProvPolicyClient := edgeproto.NewAutoProvPolicyApiClient(conn)

	require.Nil(t, crmClient.WaitForConnect(1))
	require.Nil(t, dmeClient.WaitForConnect(1))
	for ii, _ := range testutil.CloudletInfoData() {
		if !cloudletData[ii].CrmOnEdge {
			continue
		}
		err := apis.cloudletInfoApi.cache.WaitForCloudletState(ctx, &testutil.CloudletInfoData()[ii].Key, dme.CloudletState_CLOUDLET_STATE_READY, time.Second)
		require.Nil(t, err, cloudletData[ii].Key)
	}
	addTestPlatformFeatures(t, ctx, apis, testutil.PlatformFeaturesData())

	testutil.ClientFlavorTest(t, "cud", flavorClient, testutil.FlavorData())
	testutil.ClientAutoProvPolicyTest(t, "cud", autoProvPolicyClient, testutil.AutoProvPolicyData())
	testutil.ClientAutoScalePolicyTest(t, "cud", autoScalePolicyClient, testutil.AutoScalePolicyData())
	testutil.ClientAppTest(t, "cud", appClient, testutil.CreatedAppData())
	testutil.ClientGPUDriverTest(t, "cud", gpuDriverClient, testutil.GPUDriverData())
	testutil.ClientResTagTableTest(t, "cud", resTagTableClient, testutil.ResTagTableData())
	testutil.ClientZoneTest(t, "cud", zoneClient, testutil.ZoneData())
	testutil.ClientCloudletTest(t, "cud", cloudletClient, cloudletData)
	testutil.ClientClusterInstTest(t, "cud", clusterInstClient, testutil.ClusterInstData(), testutil.WithCreatedClusterInstTestData(testutil.CreatedClusterInstData()))
	testutil.ClientAppInstTest(t, "cud", appInstClient, testutil.AppInstData(), testutil.WithCreatedAppInstTestData(testutil.CreatedAppInstData()))

	require.Nil(t, dmeNotify.WaitForAppInsts(len(testutil.AppInstData())))
	require.Nil(t, crmNotify.WaitForFlavors(len(testutil.FlavorData())))

	require.Equal(t, len(testutil.AppInstData()), len(dmeNotify.AppInstCache.Objs), "num appinsts")
	require.Equal(t, len(testutil.FlavorData()), len(crmNotify.FlavorCache.Objs), "num flavors")
	crmClusterInstCount := 0
	crmAppInstCount := 0
	for _, ci := range append(testutil.CreatedClusterInstData(), testutil.ClusterInstAutoData()...) {
		if _, found := crmsOnEdge[ci.CloudletKey]; found {
			crmClusterInstCount++
		}
	}
	for _, ai := range testutil.CreatedAppInstData() {
		if _, found := crmsOnEdge[ai.CloudletKey]; found {
			crmAppInstCount++
		}
	}
	require.Equal(t, crmClusterInstCount, len(crmNotify.ClusterInstInfoCache.Objs), "crm cluster inst infos")
	require.Equal(t, crmAppInstCount, len(crmNotify.AppInstInfoCache.Objs), "crm app inst infos")

	ClientAppInstCachedFieldsTest(t, ctx, appClient, cloudletClient, appInstClient)

	WaitForCloudletInfo(apis, len(testutil.CloudletInfoData()))
	require.Equal(t, len(testutil.CloudletInfoData()), len(apis.cloudletInfoApi.cache.Objs))
	require.Equal(t, len(crmsOnEdge), len(crmNotify.CloudletInfoCache.Objs))

	// test show api for info structs
	// XXX These checks won't work until we move notifyId out of struct
	// and into meta data in cache (TODO)
	if false {
		CheckCloudletInfo(t, cloudletInfoClient, testutil.CloudletInfoData())
	}
	testKeepAliveRecovery(t, ctx, apis)

	// test that delete checks disallow deletes of dependent objects
	stream, err := cloudletClient.DeleteCloudlet(ctx, &cloudletData[0])
	err = testutil.CloudletReadResultStream(stream, err)
	require.NotNil(t, err)
	_, err = appClient.DeleteApp(ctx, &testutil.AppData()[0])
	require.NotNil(t, err)
	_, err = autoScalePolicyClient.DeleteAutoScalePolicy(ctx, &testutil.AutoScalePolicyData()[0])
	require.NotNil(t, err)
	// test that delete works after removing dependencies
	for _, inst := range testutil.AppInstData() {
		if testutil.IsAutoClusterAutoDeleteApp(&inst) {
			continue
		}
		stream, err := appInstClient.DeleteAppInst(ctx, &inst)
		err = testutil.AppInstReadResultStream(stream, err)
		require.Nil(t, err)
	}
	for _, inst := range testutil.ClusterInstData() {
		stream, err := clusterInstClient.DeleteClusterInst(ctx, &inst)
		err = testutil.ClusterInstReadResultStream(stream, err)
		require.Nil(t, err)
	}
	// cleanup unused reservable auto clusters
	_, err = clusterInstClient.DeleteIdleReservableClusterInsts(ctx, &edgeproto.IdleReservableClusterInsts{})
	require.Nil(t, err)
	for _, obj := range testutil.AppData() {
		_, err = appClient.DeleteApp(ctx, &obj)
		require.Nil(t, err)
	}
	for _, obj := range testutil.AutoScalePolicyData() {
		_, err = autoScalePolicyClient.DeleteAutoScalePolicy(ctx, &obj)
		require.Nil(t, err)
	}
	for ii, _ := range testutil.CloudletInfoData() {
		obj := testutil.CloudletInfoData()[ii]
		obj.State = dme.CloudletState_CLOUDLET_STATE_OFFLINE
		crmNotify.CloudletInfoCache.Update(ctx, &obj, 0)
	}
	for _, obj := range testutil.CloudletData() {
		stream, err := cloudletClient.DeleteCloudlet(ctx, &obj)
		err = testutil.CloudletReadResultStream(stream, err)
		require.Nil(t, err)
	}

	// make sure dynamic app insts were deleted along with Apps
	require.Nil(t, dmeNotify.WaitForAppInsts(0))
	require.Equal(t, 0, len(dmeNotify.AppInstCache.Objs), "num appinsts")
	// deleting appinsts/cloudlets should also delete associated info
	require.Equal(t, 0, len(apis.cloudletInfoApi.cache.Objs))
	require.Equal(t, 0, len(apis.clusterInstApi.cache.Objs))
	require.Equal(t, 0, len(apis.appInstApi.cache.Objs))
}

func TestDataGen(t *testing.T) {
	out, err := os.Create("data_test.json")
	if err != nil {
		require.Nil(t, err, "open file")
		return
	}
	for _, obj := range testutil.DevData() {
		val, err := json.Marshal(&obj)
		require.Nil(t, err, "marshal %s", obj)
		out.Write(val)
		out.WriteString("\n")
	}
	out.Close()
}

func WaitForCloudletInfo(apis *AllApis, count int) {
	for i := 0; i < 10; i++ {
		if len(apis.cloudletInfoApi.cache.Objs) == count {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func CheckCloudletInfo(t *testing.T, client edgeproto.CloudletInfoApiClient, data []edgeproto.CloudletInfo) {
	api := testutil.NewClientCloudletInfoApi(client)
	ctx := context.TODO()

	show := testutil.ShowCloudletInfo{}
	show.Init()
	filterNone := edgeproto.CloudletInfo{}
	err := api.ShowCloudletInfo(ctx, &filterNone, &show)
	require.Nil(t, err, "show cloudlet info")
	for _, obj := range data {
		show.AssertFound(t, &obj)
	}
	require.Equal(t, len(data), len(show.Data), "show count")
}

func testKeepAliveRecovery(t *testing.T, ctx context.Context, apis *AllApis) {
	log.SpanLog(ctx, log.DebugLevelInfo, "testKeepAliveRecovery")
	// already some alerts from non-crm sources
	numPrevAlerts := len(apis.alertApi.cache.Objs)
	require.Equal(t, 0, len(apis.alertApi.sourceCache.Objs))

	// add some alerts from crm, will go into source cache
	for _, alert := range testutil.AlertData() {
		apis.alertApi.Update(ctx, &alert, 0)
	}
	numCrmAlerts := len(testutil.AlertData())
	totalAlerts := numPrevAlerts + numCrmAlerts
	WaitForAlerts(t, apis, totalAlerts)
	require.Equal(t, numCrmAlerts, len(apis.alertApi.sourceCache.Objs))
	leaseID := apis.syncLeaseData.ControllerAliveLease()

	log.SpanLog(ctx, log.DebugLevelInfo, "grab sync lease data lock")
	// grab syncLeaseData lock to prevent it restoring any
	// source data, so that we can verify data was flushed from etcd
	apis.syncLeaseData.mux.Lock()

	log.SpanLog(ctx, log.DebugLevelInfo, "revoke lease")
	// revoke lease to simulate timed out keepalives
	err := apis.syncLeaseData.sync.GetKVStore().Revoke(ctx, apis.syncLeaseData.leaseID)
	require.Nil(t, err)
	// wait for lease timeout (so etcd KeepAlive function returns)
	time.Sleep(time.Duration(leaseTimeoutSec) * time.Second)

	// data should have been flushed from etcd
	WaitForAlerts(t, apis, numPrevAlerts)
	// data should still be in source cache
	require.Equal(t, numCrmAlerts, len(apis.alertApi.sourceCache.Objs))

	log.SpanLog(ctx, log.DebugLevelInfo, "release sync lease data lock")
	// release sync lock
	apis.syncLeaseData.mux.Unlock()
	// alerts should be re-sync'd
	WaitForAlerts(t, apis, totalAlerts)
	// make sure there is a new lease ID
	require.NotEqual(t, leaseID, apis.syncLeaseData.leaseID)

	log.SpanLog(ctx, log.DebugLevelInfo, "delete alerts")
	// delete alerts
	for _, alert := range testutil.AlertData() {
		apis.alertApi.Delete(ctx, &alert, 0)
	}
	WaitForAlerts(t, apis, numPrevAlerts)
	require.Equal(t, 0, len(apis.alertApi.sourceCache.Objs))
}

func WaitForAlerts(t *testing.T, apis *AllApis, count int) {
	for i := 0; i < 10; i++ {
		if len(apis.alertApi.cache.Objs) == count {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.Equal(t, count, len(apis.alertApi.cache.Objs), "timed out waiting for alerts")
}

func TestControllerRace(t *testing.T) {
	t.Skip("Skip races test until we can fix too many operations in etcd transaction error for ClusterInst delete test")
	log.SetDebugLevel(log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())
	testSvcs := testinit(ctx, t)
	defer testfinish(testSvcs)

	etcdLocal, err := regiondata.StartLocalEtcdServer(process.WithCleanStartup())
	require.Nil(t, err)
	defer etcdLocal.StopLocal()

	// ctrl1
	objStore1, err := regiondata.GetEtcdClientBasic(etcdLocal.ClientAddrs)
	require.Nil(t, err)
	defer objStore1.Close()
	err = objStore1.CheckConnected(50, 20*time.Millisecond)
	require.Nil(t, err)
	sync1 := regiondata.InitSync(objStore1)
	apis1 := NewAllApis(sync1)
	sync1.Start()
	defer sync1.Done()
	dummyResponder1 := DummyInfoResponder{
		AppInstCache:        &apis1.appInstApi.cache,
		ClusterInstCache:    &apis1.clusterInstApi.cache,
		RecvAppInstInfo:     apis1.appInstInfoApi,
		RecvClusterInstInfo: apis1.clusterInstInfoApi,
	}
	dummyResponder1.InitDummyInfoResponder()
	reduceInfoTimeouts(t, ctx, apis1)

	// ctrl2
	objStore2, err := regiondata.GetEtcdClientBasic(etcdLocal.ClientAddrs)
	require.Nil(t, err)
	defer objStore2.Close()
	err = objStore2.CheckConnected(50, 20*time.Millisecond)
	require.Nil(t, err)
	sync2 := regiondata.InitSync(objStore2)
	apis2 := NewAllApis(sync2)
	sync2.Start()
	defer sync2.Done()
	dummyResponder2 := DummyInfoResponder{
		AppInstCache:        &apis2.appInstApi.cache,
		ClusterInstCache:    &apis2.clusterInstApi.cache,
		RecvAppInstInfo:     apis2.appInstInfoApi,
		RecvClusterInstInfo: apis2.clusterInstInfoApi,
	}
	dummyResponder2.InitDummyInfoResponder()
	reduceInfoTimeouts(t, ctx, apis2)

	// tests
	testClusterInstDeleteChecks(t, ctx, apis1, apis2)
	testFlavorDeleteChecks(t, ctx, apis1, apis2)
}

// Tests races between AppInst create and ClusterInst delete.
// Bad state is when AppInst gets created against ClusterInst that was deleted.
// Increase "numTries" to test thoroughly.
// deleteDelay may need to be adjusted on your machine to get the
// ClusterInst delete to fall in between the AppInst creates.
func testClusterInstDeleteChecks(t *testing.T, ctx context.Context, apis1, apis2 *AllApis) {
	var err error
	testutil.InternalFlavorCreate(t, apis1.flavorApi, testutil.FlavorData())
	testutil.InternalGPUDriverCreate(t, apis1.gpuDriverApi, testutil.GPUDriverData())
	testutil.InternalResTagTableCreate(t, apis1.resTagTableApi, testutil.ResTagTableData())

	numTries := 0
	deleteDelay := 700 * time.Millisecond
	numApps := 100
	for ii := 0; ii < numApps; ii++ {
		app := testutil.AppData()[9]
		app.Key.Name += fmt.Sprintf("%d", ii)
		_, err = apis1.appApi.CreateApp(ctx, &app)
		require.Nil(t, err)
	}
	cl := testutil.CloudletData()[0]
	err = apis1.cloudletApi.CreateCloudlet(&cl, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err)
	insertCloudletInfo(ctx, apis1, testutil.CloudletInfoData())
	insertCloudletInfo(ctx, apis2, testutil.CloudletInfoData())
	ci := testutil.ClusterInstData()[0]

	appKey := testutil.AppData()[9].Key // auto-delete app
	ai := edgeproto.AppInst{
		Key: edgeproto.AppInstKey{
			Name:         "autodel",
			Organization: appKey.Organization,
		},
		AppKey:      appKey,
		ClusterKey:  ci.Key,
		CloudletKey: ci.CloudletKey,
		Liveness:    edgeproto.Liveness_LIVENESS_DYNAMIC,
	}

	validTries := 0
	for try := 0; try < numTries; try++ {
		err = apis1.clusterInstApi.CreateClusterInst(&ci, testutil.NewCudStreamoutClusterInst(ctx))
		require.Nil(t, err)
		wg := sync.WaitGroup{}
		wg.Add(numApps + 1)
		// We want to see if there's ever a case where we're left
		// with an AppInst without a ClusterInst, by deleting
		// the ClusterInst while AppInst creates are happening.
		numOk := int32(0)
		numFail := int32(0)
		for ii := 0; ii < numApps; ii++ {
			go func(num int) {
				aiRun := ai
				aiRun.Key.Name = fmt.Sprintf("%d", num)
				aiRun.AppKey.Name += fmt.Sprintf("%d", num)
				err := apis2.appInstApi.CreateAppInst(&aiRun, testutil.NewCudStreamoutAppInst(ctx))
				if err == nil {
					atomic.AddInt32(&numOk, 1)
				} else {
					atomic.AddInt32(&numFail, 1)
					if strings.Contains(err.Error(), "DELETE") {
						err = nil
					}
				}
				assert.Nil(t, err)
				wg.Done()
			}(ii)
		}
		// sleep to try to get the ClusterInst delete to
		// fall inbetween the AppInst creates
		time.Sleep(deleteDelay)
		go func() {
			defer wg.Done()
			fmt.Printf("deleting ClusterInst\n")
			err := apis1.clusterInstApi.DeleteClusterInst(&ci, testutil.NewCudStreamoutClusterInst(ctx))
			require.Nil(t, err)
		}()
		wg.Wait()
		// delete needs to happen in the middle
		fmt.Printf("numOk is %d, numFail is %d\n", numOk, numFail)
		if numOk > 0 && numFail > 0 {
			validTries++
			require.Equal(t, 0, apis1.appInstApi.cache.GetCount())
		}
		for ii := 0; ii < numApps; ii++ {
			aiRun := ai
			aiRun.Key.Name = fmt.Sprintf("%d", ii)
			apis1.appInstApi.DeleteAppInst(&aiRun, testutil.NewCudStreamoutAppInst(ctx))
		}
	}
	fmt.Printf("valid tries: %d\n", validTries)

	// clean up
	err = apis1.cloudletApi.DeleteCloudlet(&cl, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err)
	evictCloudletInfo(ctx, apis1, testutil.CloudletInfoData())
	evictCloudletInfo(ctx, apis2, testutil.CloudletInfoData())
	for ii := 0; ii < numApps; ii++ {
		app := testutil.AppData()[9]
		app.Key.Name += fmt.Sprintf("%d", ii)
		_, err = apis1.appApi.DeleteApp(ctx, &app)
		require.Nil(t, err)
	}
	testutil.InternalResTagTableDelete(t, apis1.resTagTableApi, testutil.ResTagTableData())
	testutil.InternalGPUDriverDelete(t, apis1.gpuDriverApi, testutil.GPUDriverData())
	testutil.InternalFlavorDelete(t, apis1.flavorApi, testutil.FlavorData())
}

// Test race between App create (which depends on Flavor) and Flavor delete.
// Bad state is if App is created, but flavor it depends on is deleted.
// You may need to increase the 'numTries' to hit the error.
// In the current code, setting it to 100 should reliably hit the error.
func testFlavorDeleteChecks(t *testing.T, ctx context.Context, apis1, apis2 *AllApis) {
	numTries := 0 // for now disable the test since the race condition exists
	if numTries == 0 {
		return
	}
	flavor := testutil.FlavorData()[0]
	app := testutil.AppData()[0]
	app.DefaultFlavor = flavor.Key
	numBothCreated := 0
	numBothDeleted := 0
	for try := 0; try < numTries; try++ {
		// create flavor to be deleted
		_, err := apis1.flavorApi.CreateFlavor(ctx, &flavor)
		if err != nil && strings.Contains(err.Error(), "already exists") {
			err = nil
		}
		require.Nil(t, err)
		// spawn two threads in parallel that will race.
		// either the create App will go first, in which case
		// we'll end up with both the App and the Flavor because
		// flavor delete should fail.
		// Or the delete Flavor will go first, in which case
		// we'll end up with neither App nor Flavor.
		// We should never end up with the App but no Flavor.
		// Note that the create and delete happen from different
		// controllers.
		wg := sync.WaitGroup{}
		wg.Add(2)
		go func() {
			time.Sleep(time.Duration(rand.Int31n(100000000)))
			_, err := apis2.appApi.CreateApp(ctx, &app)
			fmt.Printf("app create err %v\n", err)
			wg.Done()
		}()
		go func() {
			time.Sleep(time.Duration(rand.Int31n(100000000)))
			_, err := apis1.flavorApi.DeleteFlavor(ctx, &flavor)
			fmt.Printf("flavor delete err %v\n", err)
			wg.Done()
		}()
		wg.Wait()
		numFlavors := apis1.flavorApi.cache.GetCount()
		numApps := apis2.appApi.cache.GetCount()
		if numFlavors == 0 && numApps == 0 {
			numBothDeleted++
		} else if numFlavors == 1 && numApps == 1 {
			numBothCreated++
		} else {
			fmt.Printf("numBothDeleted %d, numBothCreated %d\n", numBothDeleted, numBothCreated)
			require.True(t, false, "Bad state try %d, num flavors %d, num apps %d", try, numFlavors, numApps)
		}
		// clean up app if it got created
		_, err = apis2.appApi.DeleteApp(ctx, &app)
		if err != nil && strings.Contains(err.Error(), "not found") {
			err = nil
		}
		require.Nil(t, err)
	}
	// for this test to be valid, the random waits should be
	// enough to get both situations to occur, so that we have
	// a chance of hitting a race condition between the two.
	assert.Greater(t, 0, numBothCreated)
	assert.Greater(t, 0, numBothDeleted)
	fmt.Printf("numBothDeleted %d, numBothCreated %d\n", numBothDeleted, numBothCreated)

	// clean up flavor if it exists
	_, err := apis1.flavorApi.DeleteFlavor(ctx, &flavor)
	if err != nil && strings.Contains(err.Error(), "not found") {
		err = nil
	}
	require.Nil(t, err)
}
