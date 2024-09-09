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
	"testing"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/ccrmdummy"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
	"github.com/stretchr/testify/require"
)

func TestZonePoolApi(t *testing.T) {
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

	// create supporting data
	addTestPlatformFeatures(t, ctx, apis, testutil.PlatformFeaturesData())
	testutil.InternalFlavorCreate(t, apis.flavorApi, testutil.FlavorData())
	testutil.InternalGPUDriverCreate(t, apis.gpuDriverApi, testutil.GPUDriverData())
	testutil.InternalResTagTableCreate(t, apis.resTagTableApi, testutil.ResTagTableData())
	testutil.InternalZoneCreate(t, apis.zoneApi, testutil.ZoneData())
	testutil.InternalCloudletCreate(t, apis.cloudletApi, testutil.CloudletData())

	testutil.InternalZonePoolTest(t, "cud", apis.zonePoolApi, testutil.ZonePoolData())

	// create test cloudlet
	testzone := edgeproto.Zone{
		Key: edgeproto.ZoneKey{
			Name:         "testzone",
			Organization: testutil.ZonePoolData()[0].Key.Organization,
		},
	}
	_, err := apis.zoneApi.CreateZone(ctx, &testzone)
	require.Nil(t, err)
	fedzone := edgeproto.Zone{
		Key: edgeproto.ZoneKey{
			Name:                  "testfedzone",
			Organization:          testutil.ZonePoolData()[0].Key.Organization,
			FederatedOrganization: "FedOrg",
		},
	}
	_, err = apis.zoneApi.CreateZone(ctx, &fedzone)
	require.Nil(t, err)

	testzones := []edgeproto.Zone{testzone, fedzone}

	count := 1
	for _, zone := range testzones {
		// set up test data
		poolKey := testutil.ZonePoolData()[0].Key
		member := edgeproto.ZonePoolMember{}
		member.Key = poolKey
		member.Zone = zone.Key
		pool := edgeproto.ZonePool{}

		// add member to pool
		_, err = apis.zonePoolApi.AddZonePoolMember(ctx, &member)
		require.Nil(t, err)
		count++
		found := apis.zonePoolApi.cache.Get(&poolKey, &pool)
		require.True(t, found, "get pool %v", poolKey)
		require.Equal(t, count, len(pool.Zones))

		// add duplicate should fail
		_, err = apis.zonePoolApi.AddZonePoolMember(ctx, &member)
		require.NotNil(t, err)

		// remove member from pool
		_, err = apis.zonePoolApi.RemoveZonePoolMember(ctx, &member)
		require.Nil(t, err)
		count--
		found = apis.zonePoolApi.cache.Get(&poolKey, &pool)
		require.True(t, found, "get pool %v", poolKey)
		require.Equal(t, count, len(pool.Zones))

		// use update to set members for next test
		poolUpdate := pool
		poolUpdate.Zones = append(poolUpdate.Zones, &member.Zone)
		poolUpdate.Fields = []string{edgeproto.ZonePoolFieldZones}
		_, err = apis.zonePoolApi.UpdateZonePool(ctx, &poolUpdate)
		require.Nil(t, err)
		count++
		found = apis.zonePoolApi.cache.Get(&poolKey, &pool)
		require.True(t, found, "get pool %v", poolKey)
		require.Equal(t, count, len(pool.Zones))

		// add cloudlet that doesn't exist, should fail
		_, err = apis.zonePoolApi.AddZonePoolMember(ctx, &member)
		require.NotNil(t, err)
	}
}
