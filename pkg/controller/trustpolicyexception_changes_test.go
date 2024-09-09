// Copyright 2024 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controller

import (
	"context"
	"sync"
	"testing"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
	"github.com/stretchr/testify/require"
)

// Tests for TPEInstanceState
// TODO: add test that checks that changes to dependent objects via API calls
// trigger calls to runTPEChange

func TestRunTPEChange(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	dummy := regiondata.InMemoryStore{}
	dummy.Start()

	cplookup := &node.ZonePoolCache{}
	cplookup.Init()
	nodeMgr.ZonePoolLookup = cplookup
	cloudletLookup := &node.CloudletCache{}
	cloudletLookup.Init()
	nodeMgr.CloudletLookup = cloudletLookup

	datasync := regiondata.InitSync(&dummy)
	apis := NewAllApis(datasync)
	datasync.Start()
	defer datasync.Done()

	// We're testing state changes that the normal APIs won't
	// let us do, so we're writing direct to the data store.

	// The initial state of all objects allows for enabling the TPE
	operOrg := "operOrg"
	// trust policy
	trustPolicy := testutil.TrustPolicyData()[0]
	trustPolicy.Key.Organization = operOrg
	// zone
	zone := testutil.ZoneData()[0]
	zone.Key.Organization = operOrg
	// cloudlet
	cloudlet := testutil.CloudletData()[0]
	cloudlet.CrmOnEdge = true
	cloudlet.Key.Organization = operOrg
	cloudlet.ResTagMap = nil
	cloudlet.GpuConfig = edgeproto.GPUConfig{}
	cloudlet.Zone = zone.Key.Name
	cloudlet.TrustPolicy = trustPolicy.Key.Name
	// cloudlet pool
	zonePool := edgeproto.ZonePool{
		Key: edgeproto.ZonePoolKey{
			Name:         "pool",
			Organization: operOrg,
		},
		Zones: []*edgeproto.ZoneKey{
			&zone.Key,
		},
	}
	// trusted app
	app := testutil.AppData()[0]
	app.Trusted = true
	// tpe
	tpe := testutil.TrustPolicyExceptionData()[0]
	tpe.Key.AppKey = app.Key
	tpe.Key.ZonePoolKey = zonePool.Key
	tpe.State = edgeproto.TrustPolicyExceptionState_TRUST_POLICY_EXCEPTION_STATE_ACTIVE
	// clusterInst
	ci := edgeproto.ClusterInst{}
	ci.CloudletKey = cloudlet.Key
	ci.Key.Name = "clust"
	ci.Key.Organization = app.Key.Organization
	ci.IpAccess = edgeproto.IpAccess_IP_ACCESS_DEDICATED
	// appInst
	ai := edgeproto.AppInst{}
	ai.Key.Name = "appInst"
	ai.Key.Organization = app.Key.Organization
	ai.CloudletKey = cloudlet.Key
	ai.AppKey = app.Key
	ai.ClusterKey = ci.Key
	ai.State = edgeproto.TrackedState_READY

	// write objects to store
	apis.trustPolicyApi.store.Put(ctx, &trustPolicy, datasync.SyncWait)
	apis.zoneApi.store.Put(ctx, &zone, datasync.SyncWait)
	apis.cloudletApi.store.Put(ctx, &cloudlet, datasync.SyncWait)
	apis.zonePoolApi.store.Put(ctx, &zonePool, datasync.SyncWait)
	apis.appApi.store.Put(ctx, &app, datasync.SyncWait)
	apis.trustPolicyExceptionApi.store.Put(ctx, &tpe, datasync.SyncWait)
	apis.clusterInstApi.store.Put(ctx, &ci, datasync.SyncWait)
	apis.appInstApi.store.Put(ctx, &ai, datasync.SyncWait)

	// target TPE instance
	tpeInstKey := edgeproto.TPEInstanceKey{
		TpeKey:      tpe.Key,
		AppInstKey:  ai.Key,
		ClusterKey:  ci.Key,
		CloudletKey: cloudlet.Key,
	}
	tpeInst := edgeproto.TPEInstanceState{}

	// helper funcs
	requireState := func(enable bool) {
		err := apis.trustPolicyExceptionApi.runTPEChange(ctx, tpe.Key, ai.Key, ci.Key, cloudlet.Key)
		require.Nil(t, err)
		found := apis.trustPolicyExceptionApi.instCache.Get(&tpeInstKey, &tpeInst)
		require.True(t, found)
		require.Equal(t, enable, tpeInst.TpeEnable)
		require.Equal(t, "", tpeInst.Owner)
		require.Equal(t, int32(0), tpeInst.RunCount)
		require.Equal(t, false, tpeInst.RunRequested)
	}
	requireDeleted := func() {
		err := apis.trustPolicyExceptionApi.runTPEChange(ctx, tpe.Key, ai.Key, ci.Key, cloudlet.Key)
		require.Nil(t, err)
		found := apis.trustPolicyExceptionApi.instCache.Get(&tpeInstKey, &tpeInst)
		require.False(t, found)
	}

	// initial state should allow for state to be enabled
	requireState(true)

	// ----------------------------------------------------------
	// There are two sets of tests for each dependent object.
	// Whether a state of the object affects the state of the TPE.
	// Whether a missing object deletes the TPE

	// test changing appInst state
	ai.State = edgeproto.TrackedState_CREATE_ERROR
	apis.appInstApi.store.Put(ctx, &ai, datasync.SyncWait)
	requireState(false)
	ai.State = edgeproto.TrackedState_READY
	apis.appInstApi.store.Put(ctx, &ai, datasync.SyncWait)
	requireState(true)
	// delete and recreate
	apis.appInstApi.store.Delete(ctx, &ai, datasync.SyncWait)
	requireDeleted()
	apis.appInstApi.store.Put(ctx, &ai, datasync.SyncWait)
	requireState(true)

	// test changing tpe state
	tpe.State = edgeproto.TrustPolicyExceptionState_TRUST_POLICY_EXCEPTION_STATE_REJECTED
	apis.trustPolicyExceptionApi.store.Put(ctx, &tpe, datasync.SyncWait)
	requireState(false)
	tpe.State = edgeproto.TrustPolicyExceptionState_TRUST_POLICY_EXCEPTION_STATE_ACTIVE
	apis.trustPolicyExceptionApi.store.Put(ctx, &tpe, datasync.SyncWait)
	requireState(true)
	// delete and recreate
	apis.trustPolicyExceptionApi.store.Delete(ctx, &tpe, datasync.SyncWait)
	requireDeleted()
	apis.trustPolicyExceptionApi.store.Put(ctx, &tpe, datasync.SyncWait)
	requireState(true)

	// test changing IP access
	ci.IpAccess = edgeproto.IpAccess_IP_ACCESS_SHARED
	apis.clusterInstApi.store.Put(ctx, &ci, datasync.SyncWait)
	requireState(false)
	ci.IpAccess = edgeproto.IpAccess_IP_ACCESS_DEDICATED
	apis.clusterInstApi.store.Put(ctx, &ci, datasync.SyncWait)
	requireState(true)
	// delete and recreate
	apis.clusterInstApi.store.Delete(ctx, &ci, datasync.SyncWait)
	requireDeleted()
	apis.clusterInstApi.store.Put(ctx, &ci, datasync.SyncWait)
	requireState(true)

	// test changing cloudlet trust policy
	cloudlet.TrustPolicy = ""
	apis.cloudletApi.store.Put(ctx, &cloudlet, datasync.SyncWait)
	requireState(false)
	cloudlet.TrustPolicy = trustPolicy.Key.Name
	apis.cloudletApi.store.Put(ctx, &cloudlet, datasync.SyncWait)
	requireState(true)
	// delete and recreate
	apis.cloudletApi.store.Delete(ctx, &cloudlet, datasync.SyncWait)
	requireDeleted()
	apis.cloudletApi.store.Put(ctx, &cloudlet, datasync.SyncWait)
	requireState(true)

	// test changing zonePool membership
	zonePool.Zones = nil
	apis.zonePoolApi.store.Put(ctx, &zonePool, datasync.SyncWait)
	requireState(false)
	zonePool.Zones = []*edgeproto.ZoneKey{&zone.Key}
	apis.zonePoolApi.store.Put(ctx, &zonePool, datasync.SyncWait)
	requireState(true)
	// delete and recreate
	apis.zonePoolApi.store.Delete(ctx, &zonePool, datasync.SyncWait)
	requireDeleted()
	apis.zonePoolApi.store.Put(ctx, &zonePool, datasync.SyncWait)
	requireState(true)

	// set all the object states to result in disabled TPE state
	ai.State = edgeproto.TrackedState_CREATE_ERROR
	apis.appInstApi.store.Put(ctx, &ai, datasync.SyncWait)
	tpe.State = edgeproto.TrustPolicyExceptionState_TRUST_POLICY_EXCEPTION_STATE_REJECTED
	apis.trustPolicyExceptionApi.store.Put(ctx, &tpe, datasync.SyncWait)
	ci.IpAccess = edgeproto.IpAccess_IP_ACCESS_SHARED
	apis.clusterInstApi.store.Put(ctx, &ci, datasync.SyncWait)
	cloudlet.TrustPolicy = ""
	apis.cloudletApi.store.Put(ctx, &cloudlet, datasync.SyncWait)
	zonePool.Zones = nil
	apis.zonePoolApi.store.Put(ctx, &zonePool, datasync.SyncWait)
	requireState(false)

	// Now test all enable changes in parallel.
	// We should not get stuck, and we should end up enabled.
	// In the log, we should see some "already running" messages as
	// some of the threads will trigger a rerun of the current running thread
	// instead of running themselves.
	wg := sync.WaitGroup{}
	wg.Add(5)
	go func() {
		defer wg.Done()
		ai.State = edgeproto.TrackedState_READY
		apis.appInstApi.store.Put(ctx, &ai, datasync.SyncWait)
		err := apis.trustPolicyExceptionApi.runTPEChange(ctx, tpe.Key, ai.Key, ci.Key, cloudlet.Key)
		require.Nil(t, err)
	}()
	go func() {
		defer wg.Done()
		tpe.State = edgeproto.TrustPolicyExceptionState_TRUST_POLICY_EXCEPTION_STATE_ACTIVE
		apis.trustPolicyExceptionApi.store.Put(ctx, &tpe, datasync.SyncWait)
		err := apis.trustPolicyExceptionApi.runTPEChange(ctx, tpe.Key, ai.Key, ci.Key, cloudlet.Key)
		require.Nil(t, err)
	}()
	go func() {
		defer wg.Done()
		ci.IpAccess = edgeproto.IpAccess_IP_ACCESS_DEDICATED
		apis.clusterInstApi.store.Put(ctx, &ci, datasync.SyncWait)
		err := apis.trustPolicyExceptionApi.runTPEChange(ctx, tpe.Key, ai.Key, ci.Key, cloudlet.Key)
		require.Nil(t, err)
	}()
	go func() {
		defer wg.Done()
		cloudlet.TrustPolicy = trustPolicy.Key.Name
		apis.cloudletApi.store.Put(ctx, &cloudlet, datasync.SyncWait)
		err := apis.trustPolicyExceptionApi.runTPEChange(ctx, tpe.Key, ai.Key, ci.Key, cloudlet.Key)
		require.Nil(t, err)
	}()
	go func() {
		defer wg.Done()
		zonePool.Zones = []*edgeproto.ZoneKey{&zone.Key}
		apis.zonePoolApi.store.Put(ctx, &zonePool, datasync.SyncWait)
		err := apis.trustPolicyExceptionApi.runTPEChange(ctx, tpe.Key, ai.Key, ci.Key, cloudlet.Key)
		require.Nil(t, err)
	}()
	wg.Wait()
	found := apis.trustPolicyExceptionApi.instCache.Get(&tpeInstKey, &tpeInst)
	require.True(t, found)
	require.Equal(t, true, tpeInst.TpeEnable)
	require.Equal(t, "", tpeInst.Owner)
	require.Equal(t, int32(0), tpeInst.RunCount)
	require.Equal(t, false, tpeInst.RunRequested)
}
