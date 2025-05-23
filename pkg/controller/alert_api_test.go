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
	"os"
	"testing"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/ccrmdummy"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/svcnode"
	influxq "github.com/edgexr/edge-cloud-platform/pkg/influxq_client"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/process"
	"github.com/edgexr/edge-cloud-platform/pkg/rediscache"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
	"github.com/stretchr/testify/require"
)

func TestAlertApi(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi)
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

	testCloudletName := "testcloudlet"
	alertData := testutil.AlertData()
	cloudletData := testutil.CloudletData()
	testCloudlet := cloudletData[0]
	for _, alert := range alertData {
		if alert.Labels[edgeproto.CloudletKeyTagName] == testCloudlet.Key.Name && alert.Labels[edgeproto.CloudletKeyTagOrganization] == testCloudlet.Key.Organization {
			alert.Labels[edgeproto.CloudletKeyTagName] = testCloudletName
		}
		apis.alertApi.Update(ctx, &alert, 0)
	}
	testutil.InternalAlertTest(t, "show", apis.alertApi, alertData)

	addTestPlatformFeatures(t, ctx, apis, testutil.PlatformFeaturesData())
	testutil.InternalFlavorCreate(t, apis.flavorApi, testutil.FlavorData())
	testutil.InternalGPUDriverCreate(t, apis.gpuDriverApi, testutil.GPUDriverData())
	testutil.InternalResTagTableCreate(t, apis.resTagTableApi, testutil.ResTagTableData())
	testutil.InternalZoneCreate(t, apis.zoneApi, testutil.ZoneData())
	testutil.InternalCloudletCreate(t, apis.cloudletApi, cloudletData)
	testCloudlet.Key.Name = testCloudletName
	testutil.InternalCloudletCreate(t, apis.cloudletApi, []edgeproto.Cloudlet{testCloudlet})
	testCloudletInfo := testutil.CloudletInfoData()[0]
	testCloudletInfo.Key.Name = testCloudlet.Key.Name
	insertCloudletInfo(ctx, apis, []edgeproto.CloudletInfo{testCloudletInfo})
	getAlertsCount := func() (int, int) {
		count := 0
		totalCount := 0
		for _, data := range apis.alertApi.cache.Objs {
			val := data.Obj
			totalCount++
			if cloudletName, found := val.Labels[edgeproto.CloudletKeyTagName]; !found ||
				cloudletName != testCloudletName {
				continue
			}
			if cloudletOrg, found := val.Labels[edgeproto.CloudletKeyTagOrganization]; !found ||
				cloudletOrg != testCloudlet.Key.Organization {
				continue
			}
			count++
		}
		return count, totalCount
	}
	cloudletCount, totalCount := getAlertsCount()
	require.Greater(t, cloudletCount, 0, "cloudlet alerts exists")
	require.Greater(t, totalCount, 0, "alerts exists")
	err := apis.cloudletApi.DeleteCloudlet(&testCloudlet, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err, "delete cloudlet")
	expectedTotalCount := totalCount - cloudletCount
	cloudletCount, totalCount = getAlertsCount()
	require.Equal(t, cloudletCount, 0, "cloudlet alerts should not exist")
	require.Equal(t, totalCount, expectedTotalCount, "expected alerts should exist")

	dummy.Stop()
}

func TestAppInstDownAlert(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi)
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
	dummyResponder := DefaultDummyInfoResponder(apis)
	dummyResponder.InitDummyInfoResponder()
	ccrm := ccrmdummy.StartDummyCCRM(ctx, testSvcs.DummyVault.Config, &dummy)
	registerDummyCCRMConn(t, ccrm)
	defer ccrm.Stop()
	reduceInfoTimeouts(t, ctx, apis)

	// create supporting data
	addTestPlatformFeatures(t, ctx, apis, testutil.PlatformFeaturesData())
	testutil.InternalFlavorCreate(t, apis.flavorApi, testutil.FlavorData())
	testutil.InternalGPUDriverCreate(t, apis.gpuDriverApi, testutil.GPUDriverData())
	testutil.InternalResTagTableCreate(t, apis.resTagTableApi, testutil.ResTagTableData())
	testutil.InternalZoneCreate(t, apis.zoneApi, testutil.ZoneData())
	testutil.InternalCloudletCreate(t, apis.cloudletApi, testutil.CloudletData())
	insertCloudletInfo(ctx, apis, testutil.CloudletInfoData())
	testutil.InternalAutoProvPolicyCreate(t, apis.autoProvPolicyApi, testutil.AutoProvPolicyData())
	testutil.InternalAutoScalePolicyCreate(t, apis.autoScalePolicyApi, testutil.AutoScalePolicyData())
	testutil.InternalAppCreate(t, apis.appApi, testutil.AppData())
	testutil.InternalClusterInstCreate(t, apis.clusterInstApi, testutil.ClusterInstData())
	testutil.InternalAppInstCreate(t, apis.appInstApi, testutil.AppInstData())
	// Create a reservable clusterInst
	cinst := testutil.ClusterInstData()[7]
	streamOut := testutil.NewCudStreamoutAppInst(ctx)
	appinst := testutil.AppInstData()[0]
	appinst.Key.Name = testutil.AlertData()[3].Labels[edgeproto.AppInstKeyTagName]
	appinst.CloudletKey = cinst.CloudletKey
	appinst.ClusterKey = cinst.Key
	err := apis.appInstApi.CreateAppInst(&appinst, streamOut)
	require.Nil(t, err, "create AppInst")
	// Inject AppInst info check that all appInsts are Healthy
	for _, in := range testutil.AppInstInfoData() {
		apis.appInstInfoApi.Update(ctx, &in, 0)
	}
	for _, val := range apis.appInstApi.cache.Objs {
		require.Equal(t, dme.HealthCheck_HEALTH_CHECK_OK, val.Obj.HealthCheck)
	}
	// Trigger Alerts
	for _, alert := range testutil.AlertData() {
		apis.alertApi.Update(ctx, &alert, 0)
	}
	// Check reservable cluster

	found := apis.appInstApi.Get(&appinst.Key, &appinst)
	require.True(t, found)
	require.Equal(t, dme.HealthCheck_HEALTH_CHECK_ROOTLB_OFFLINE, appinst.HealthCheck)
	// check other appInstances
	for ii, testData := range testutil.CreatedAppInstData() {
		found = apis.appInstApi.Get(&testData.Key, &appinst)
		require.True(t, found)
		if ii == 0 {
			require.Equal(t, dme.HealthCheck_HEALTH_CHECK_SERVER_FAIL, appinst.HealthCheck)
		} else {
			require.Equal(t, dme.HealthCheck_HEALTH_CHECK_OK, appinst.HealthCheck)
		}
	}

	dummy.Stop()
}

type testServices struct {
	DummyRedisSrv *rediscache.DummyRedis
	RedisLocalSrv *process.RedisCache
	DummyVault    *vault.DummyServer
}

type TestOptions struct {
	// Start local redis server
	LocalRedis bool
}

type TestOp func(op *TestOptions)

func WithLocalRedis() TestOp {
	return func(op *TestOptions) { op.LocalRedis = true }
}

// Set up globals for API unit tests
func testinit(ctx context.Context, t *testing.T, opts ...TestOp) *testServices {
	options := TestOptions{}
	for _, op := range opts {
		op(&options)
	}
	svcs := &testServices{}
	tMode := true
	testMode = &tMode
	dockerRegistry := "docker.example.ut"
	registryFQDN = &dockerRegistry
	svcs.DummyVault = vault.NewDummyServer()
	vaultConfig = svcs.DummyVault.Config
	nodeMgr.VaultConfig = vaultConfig
	InfluxClientTimeout = time.Millisecond // no actual influx running
	services.regAuthMgr = cloudcommon.NewRegistryAuthMgr(vaultConfig, "example.ut")
	services.events = influxq.NewInfluxQ("events", "user", "pass", InfluxClientTimeout)
	services.cloudletResourcesInfluxQ = influxq.NewInfluxQ(cloudcommon.CloudletResourceUsageDbName, "user", "pass", InfluxClientTimeout)
	cleanupCloudletInfoTimeout = 100 * time.Millisecond
	RequireAppInstPortConsistency = true
	zplookup := &svcnode.ZonePoolCache{}
	zplookup.Init()
	nodeMgr.ZonePoolLookup = zplookup
	cloudletLookup := &svcnode.CloudletCache{}
	cloudletLookup.Init()
	nodeMgr.CloudletLookup = cloudletLookup
	os.Setenv("E2ETEST_SKIPREGISTRY", "true")
	if options.LocalRedis {
		// Since it is a single node, config file is not required
		procOpts := []process.StartOp{process.WithNoConfig(), process.WithCleanStartup()}
		redisLocal, err := StartLocalRedisServer(procOpts...)
		require.Nil(t, err, "start redis server")
		svcs.RedisLocalSrv = redisLocal
		redisCfg = rediscache.RedisConfig{
			StandaloneAddr: rediscache.DefaultRedisStandaloneAddr,
		}
		redisClient, err = rediscache.NewClient(ctx, &redisCfg)
		require.Nil(t, err, "setup redis client")
	} else {
		redisServer, err := rediscache.NewMockRedisServer()
		require.Nil(t, err, "start mock redis server")
		svcs.DummyRedisSrv = redisServer
		redisCfg = rediscache.RedisConfig{
			SentinelAddrs: redisServer.GetSentinelAddr(),
		}
		redisClient, err = rediscache.NewClient(ctx, &redisCfg)
		require.Nil(t, err, "setup redis client")
	}

	return svcs
}

func testfinish(s *testServices) {
	if redisClient != nil {
		redisClient.Close()
		redisClient = nil
	}
	if s.DummyRedisSrv != nil {
		s.DummyRedisSrv.Close()
		s.DummyRedisSrv = nil
	}
	if s.RedisLocalSrv != nil {
		s.RedisLocalSrv.StopLocal()
		s.RedisLocalSrv = nil
	}
	if s.DummyVault != nil {
		s.DummyVault.TestServer.Close()
		s.DummyVault = nil
	}
	services = Services{}
}

func registerDummyCCRMConn(t *testing.T, ccrm *ccrmdummy.CCRMDummy) {
	services.platformServiceConnCache = cloudcommon.NewGRPCConnCache(map[string]string{})
	conn, err := ccrm.GRPCClient()
	require.Nil(t, err)
	// all testutil platform features use node type "ccrm"
	services.platformServiceConnCache.SetConn("ccrm", conn)
}
