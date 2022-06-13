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
	"testing"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/dme-proto"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	influxq "github.com/edgexr/edge-cloud-platform/cmd/controller/influxq_client"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/objstore"
	"github.com/edgexr/edge-cloud-platform/pkg/process"
	"github.com/edgexr/edge-cloud-platform/pkg/rediscache"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
	"github.com/stretchr/testify/require"
)

func TestAlertApi(t *testing.T) {
	ctx, testSvcs, apis := testinit(t)
	defer testfinish(testSvcs)

	for _, alert := range testutil.AlertData {
		apis.alertApi.Update(ctx, &alert, 0)
	}
	testutil.InternalAlertTest(t, "show", apis.alertApi, testutil.AlertData)

	cloudletData := testutil.CloudletData()
	testutil.InternalFlavorCreate(t, apis.flavorApi, testutil.FlavorData)
	testutil.InternalGPUDriverCreate(t, apis.gpuDriverApi, testutil.GPUDriverData)
	testutil.InternalResTagTableCreate(t, apis.resTagTableApi, testutil.ResTagTableData)
	testutil.InternalCloudletCreate(t, apis.cloudletApi, cloudletData)
	testCloudlet := cloudletData[0]
	testCloudlet.Key.Name = "testcloudlet"
	testutil.InternalCloudletCreate(t, apis.cloudletApi, []edgeproto.Cloudlet{testCloudlet})
	testCloudletInfo := testutil.CloudletInfoData[0]
	testCloudletInfo.Key.Name = testCloudlet.Key.Name
	insertCloudletInfo(ctx, apis, []edgeproto.CloudletInfo{testCloudletInfo})
	getAlertsCount := func() (int, int) {
		count := 0
		totalCount := 0
		for _, data := range apis.alertApi.cache.Objs {
			val := data.Obj
			totalCount++
			if cloudletName, found := val.Labels[edgeproto.CloudletKeyTagName]; !found ||
				cloudletName != testCloudlet.Key.Name {
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
}

func TestAppInstDownAlert(t *testing.T) {
	ctx, testSvcs, apis := testinit(t)
	defer testfinish(testSvcs)

	dummyResponder := DummyInfoResponder{
		AppInstCache:        &apis.appInstApi.cache,
		ClusterInstCache:    &apis.clusterInstApi.cache,
		RecvAppInstInfo:     apis.appInstInfoApi,
		RecvClusterInstInfo: apis.clusterInstInfoApi,
	}
	dummyResponder.InitDummyInfoResponder()

	// create supporting data
	testutil.InternalFlavorCreate(t, apis.flavorApi, testutil.FlavorData)
	testutil.InternalGPUDriverCreate(t, apis.gpuDriverApi, testutil.GPUDriverData)
	testutil.InternalResTagTableCreate(t, apis.resTagTableApi, testutil.ResTagTableData)
	testutil.InternalCloudletCreate(t, apis.cloudletApi, testutil.CloudletData())
	insertCloudletInfo(ctx, apis, testutil.CloudletInfoData)
	testutil.InternalAutoProvPolicyCreate(t, apis.autoProvPolicyApi, testutil.AutoProvPolicyData)
	testutil.InternalAutoScalePolicyCreate(t, apis.autoScalePolicyApi, testutil.AutoScalePolicyData)
	testutil.InternalAppCreate(t, apis.appApi, testutil.AppData)
	testutil.InternalClusterInstCreate(t, apis.clusterInstApi, testutil.ClusterInstData)
	testutil.InternalAppInstCreate(t, apis.appInstApi, testutil.AppInstData)
	// Create a reservable clusterInst
	cinst := testutil.ClusterInstData[7]
	streamOut := testutil.NewCudStreamoutAppInst(ctx)
	appinst := edgeproto.AppInst{}
	appinst.Key.AppKey = testutil.AppData[0].Key
	appinst.Key.ClusterInstKey = *cinst.Key.Virtual("")
	err := apis.appInstApi.CreateAppInst(&appinst, streamOut)
	require.Nil(t, err, "create AppInst")
	// Inject AppInst info check that all appInsts are Healthy
	for ii, _ := range testutil.AppInstInfoData {
		in := &testutil.AppInstInfoData[ii]
		apis.appInstInfoApi.Update(ctx, in, 0)
	}
	for _, val := range apis.appInstApi.cache.Objs {
		require.Equal(t, dme.HealthCheck_HEALTH_CHECK_OK, val.Obj.HealthCheck)
	}
	// Trigger Alerts
	for _, alert := range testutil.AlertData {
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
}

type testServices struct {
	DummyRedisSrv *rediscache.DummyRedis
	RedisLocalSrv *process.RedisCache
	apis          *AllApis
	dummyEtcd     dummyEtcd
	sync          *Sync
}

type TestOptions struct {
	// Start local redis server
	LocalRedis bool
	NoApis     bool
}

type TestOp func(op *TestOptions)

func WithLocalRedis() TestOp {
	return func(op *TestOptions) { op.LocalRedis = true }
}

func WithNoApis() TestOp {
	return func(op *TestOptions) { op.NoApis = true }
}

// Set up globals for API unit tests
func testinit(t *testing.T, opts ...TestOp) (context.Context, *testServices, *AllApis) {
	options := TestOptions{}
	for _, op := range opts {
		op(&options)
	}
	log.SetTestDebugLevels(*debugLevels, log.DebugLevelEtcd|log.DebugLevelApi|log.DebugLevelEvents)
	log.InitTracer(nil)
	ctx := log.StartTestSpan(context.Background())

	svcs := &testServices{}
	objstore.InitRegion(1)
	tMode := true
	testMode = &tMode
	dockerRegistry := "docker.mobiledgex.net"
	registryFQDN = &dockerRegistry
	vaultConfig, _ = vault.BestConfig("")
	services.events = influxq.NewInfluxQ("events", "user", "pass")
	services.cloudletResourcesInfluxQ = influxq.NewInfluxQ(cloudcommon.CloudletResourceUsageDbName, "user", "pass")
	cleanupCloudletInfoTimeout = 100 * time.Millisecond
	RequireAppInstPortConsistency = true
	cplookup := &node.CloudletPoolCache{}
	cplookup.Init()
	nodeMgr.CloudletPoolLookup = cplookup
	cloudletLookup := &node.CloudletCache{}
	cloudletLookup.Init()
	nodeMgr.CloudletLookup = cloudletLookup
	if options.LocalRedis {
		// Since it is a single node, config file is not required
		procOpts := []process.StartOp{process.WithNoConfig()}
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
	if !options.NoApis {
		svcs.dummyEtcd.Start()
		svcs.sync = InitSync(&svcs.dummyEtcd)
		svcs.apis = NewAllApis(svcs.sync)
		svcs.sync.Start()
	}
	return ctx, svcs, svcs.apis
}

func testfinish(s *testServices) {
	if s.sync != nil {
		s.sync.Done()
		s.dummyEtcd.Stop()
	}
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
	log.FinishTracer()
	services = Services{}
}
