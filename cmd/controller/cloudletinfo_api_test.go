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

	dme "github.com/edgexr/edge-cloud-platform/api/dme-proto"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/objstore"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
	"github.com/stretchr/testify/require"
)

func TestCloudletInfo(t *testing.T) {
	ctx, testSvcs, apis := testinit(t)
	defer testfinish(testSvcs)

	// create supporting data
	testutil.InternalFlavorCreate(t, apis.flavorApi, testutil.FlavorData)
	testutil.InternalGPUDriverCreate(t, apis.gpuDriverApi, testutil.GPUDriverData)
	testutil.InternalResTagTableCreate(t, apis.resTagTableApi, testutil.ResTagTableData)
	testutil.InternalCloudletCreate(t, apis.cloudletApi, testutil.CloudletData())
	insertCloudletInfo(ctx, apis, testutil.CloudletInfoData)

	testutil.InternalCloudletInfoTest(t, "show", apis.cloudletInfoApi, testutil.CloudletInfoData)
	evictCloudletInfo(ctx, apis, testutil.CloudletInfoData)

	// test revision changes to cloudletinfo object on update
	testCloudletInfoRevs(t, ctx, &testSvcs.dummyEtcd, apis, testutil.CloudletInfoData)
}

func insertCloudletInfo(ctx context.Context, apis *AllApis, data []edgeproto.CloudletInfo) {
	for ii := range data {
		in := &data[ii]
		in.State = dme.CloudletState_CLOUDLET_STATE_READY
		apis.cloudletInfoApi.Update(ctx, in, 0)
	}
}

func evictCloudletInfo(ctx context.Context, apis *AllApis, data []edgeproto.CloudletInfo) {
	for ii := range data {
		in := &data[ii]
		apis.cloudletInfoApi.Delete(ctx, in, 0)
	}
}

func testCloudletInfoRevs(t *testing.T, ctx context.Context, dummy *dummyEtcd, apis *AllApis, data []edgeproto.CloudletInfo) {
	testData := &data[0]
	apis.cloudletInfoApi.Update(ctx, testData, 0)
	keyStr := objstore.DbKeyString("CloudletInfo", testData.GetKey())
	_, _, rev0, err := dummy.Get(keyStr)
	require.Nil(t, err)

	// updating state should update the object in etcd, revs should change
	testData.State = dme.CloudletState_CLOUDLET_STATE_OFFLINE
	apis.cloudletInfoApi.Update(ctx, testData, 0)
	_, _, rev1, err := dummy.Get(keyStr)
	require.Nil(t, err)
	require.Greater(t, rev1, rev0)

	// updating the same object should not affect revs
	apis.cloudletInfoApi.Update(ctx, testData, 0)
	_, _, rev2, err := dummy.Get(keyStr)
	require.Nil(t, err)
	require.Equal(t, rev1, rev2)

	// updating redis only field should not affect revs
	testData.Status = edgeproto.StatusInfo{MsgCount: 1}
	apis.cloudletInfoApi.Update(ctx, testData, 0)
	_, _, rev3, err := dummy.Get(keyStr)
	require.Nil(t, err)
	require.Equal(t, rev2, rev3)

	// updating maintenance state should change revs
	testData.MaintenanceState = dme.MaintenanceState_MAINTENANCE_START
	apis.cloudletInfoApi.Update(ctx, testData, 0)
	_, _, rev4, err := dummy.Get(keyStr)
	require.Nil(t, err)
	require.Greater(t, rev4, rev3)
}
