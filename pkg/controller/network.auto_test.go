// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: network.proto

package controller

import (
	"context"
	fmt "fmt"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/objstore"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
	_ "github.com/edgexr/edge-cloud-platform/tools/protogen"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	"github.com/stretchr/testify/require"
	"go.etcd.io/etcd/client/v3/concurrency"
	math "math"
	"testing"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

// NetworkStoreTracker wraps around the usual
// store to track the STM used for gets/puts.
type NetworkStoreTracker struct {
	edgeproto.NetworkStore
	getSTM concurrency.STM
	putSTM concurrency.STM
}

// Wrap the Api's store with a tracker store.
// Returns the tracker store, and the unwrap function to defer.
func wrapNetworkTrackerStore(api *NetworkApi) (*NetworkStoreTracker, func()) {
	orig := api.store
	tracker := &NetworkStoreTracker{
		NetworkStore: api.store,
	}
	api.store = tracker
	unwrap := func() {
		api.store = orig
	}
	return tracker, unwrap
}

func (s *NetworkStoreTracker) STMGet(stm concurrency.STM, key *edgeproto.NetworkKey, buf *edgeproto.Network) bool {
	found := s.NetworkStore.STMGet(stm, key, buf)
	if s.getSTM == nil {
		s.getSTM = stm
	}
	return found
}

func (s *NetworkStoreTracker) STMPut(stm concurrency.STM, obj *edgeproto.Network, ops ...objstore.KVOp) {
	s.NetworkStore.STMPut(stm, obj, ops...)
	if s.putSTM == nil {
		s.putSTM = stm
	}
}

// Caller must write by hand the test data generator.
// Each Ref object should only have a single reference to the key,
// in order to properly test each reference (i.e. don't have a single
// object that has multiple references).
type NetworkDeleteDataGen interface {
	GetNetworkTestObj() (*edgeproto.Network, *testSupportData)
	GetClusterInstNetworksRef(key *edgeproto.NetworkKey) (*edgeproto.ClusterInst, *testSupportData)
}

// NetworkDeleteStore wraps around the usual
// store to instrument checks and inject data while
// the delete api code is running.
type NetworkDeleteStore struct {
	edgeproto.NetworkStore
	t                   *testing.T
	allApis             *AllApis
	putDeletePrepare    bool
	putDeletePrepareCb  func()
	putDeletePrepareSTM concurrency.STM
}

func (s *NetworkDeleteStore) Put(ctx context.Context, m *edgeproto.Network, wait func(int64), ops ...objstore.KVOp) (*edgeproto.Result, error) {
	if wait != nil {
		s.putDeletePrepare = m.DeletePrepare
	}
	res, err := s.NetworkStore.Put(ctx, m, wait, ops...)
	if s.putDeletePrepare && s.putDeletePrepareCb != nil {
		s.putDeletePrepareCb()
	}
	return res, err
}

func (s *NetworkDeleteStore) STMPut(stm concurrency.STM, obj *edgeproto.Network, ops ...objstore.KVOp) {
	// there's an assumption that this is run within an ApplySTMWait,
	// where we wait for the caches to be updated with the transaction.
	if obj.DeletePrepare {
		s.putDeletePrepare = true
		s.putDeletePrepareSTM = stm
	} else {
		s.putDeletePrepare = false
		s.putDeletePrepareSTM = nil
	}
	s.NetworkStore.STMPut(stm, obj, ops...)
	if s.putDeletePrepare && s.putDeletePrepareCb != nil {
		s.putDeletePrepareCb()
	}
}

func (s *NetworkDeleteStore) Delete(ctx context.Context, m *edgeproto.Network, wait func(int64)) (*edgeproto.Result, error) {
	require.True(s.t, s.putDeletePrepare, "DeletePrepare must be comitted to database with a sync.Wait before deleting")
	return s.NetworkStore.Delete(ctx, m, wait)
}

func (s *NetworkDeleteStore) STMDel(stm concurrency.STM, key *edgeproto.NetworkKey) {
	require.True(s.t, s.putDeletePrepare, "DeletePrepare must be comitted to database with a sync.Wait before deleting")
	s.NetworkStore.STMDel(stm, key)
}

func (s *NetworkDeleteStore) requireUndoDeletePrepare(ctx context.Context, obj *edgeproto.Network) {
	deletePrepare := s.getDeletePrepare(ctx, obj)
	require.False(s.t, deletePrepare, "must undo delete prepare field on failure")
}

func (s *NetworkDeleteStore) getDeletePrepare(ctx context.Context, obj *edgeproto.Network) bool {
	buf := edgeproto.Network{}
	found := s.Get(ctx, obj.GetKey(), &buf)
	require.True(s.t, found, "expected test object to be found")
	return buf.DeletePrepare
}

func deleteNetworkChecks(t *testing.T, ctx context.Context, all *AllApis, dataGen NetworkDeleteDataGen) {
	var err error
	// override store so we can inject data and check data
	api := all.networkApi
	origStore := api.store
	deleteStore := &NetworkDeleteStore{
		NetworkStore: origStore,
		t:            t,
		allApis:      all,
	}
	api.store = deleteStore
	defer func() {
		api.store = origStore
	}()

	// inject testObj directly, bypassing create checks/deps
	testObj, supportData := dataGen.GetNetworkTestObj()
	supportData.put(t, ctx, all)
	defer supportData.delete(t, ctx, all)
	origStore.Put(ctx, testObj, api.sync.syncWait)

	// Positive test, delete should succeed without any references.
	// The overrided store checks that delete prepare was set on the
	// object in the database before actually doing the delete.
	testObj, _ = dataGen.GetNetworkTestObj()
	err = api.DeleteNetwork(testObj, testutil.NewCudStreamoutNetwork(ctx))
	require.Nil(t, err, "delete must succeed with no refs")

	// Negative test, inject testObj with delete prepare already set.
	testObj, _ = dataGen.GetNetworkTestObj()
	testObj.DeletePrepare = true
	origStore.Put(ctx, testObj, api.sync.syncWait)
	// delete should fail with already being deleted
	testObj, _ = dataGen.GetNetworkTestObj()
	err = api.DeleteNetwork(testObj, testutil.NewCudStreamoutNetwork(ctx))
	require.NotNil(t, err, "delete must fail if already being deleted")
	require.Equal(t, testObj.GetKey().BeingDeletedError().Error(), err.Error())
	// failed delete must not interfere with existing delete prepare state
	require.True(t, deleteStore.getDeletePrepare(ctx, testObj), "delete prepare must not be modified by failed delete")

	// inject testObj for ref tests
	testObj, _ = dataGen.GetNetworkTestObj()
	origStore.Put(ctx, testObj, api.sync.syncWait)

	{
		// Negative test, ClusterInst refers to Network.
		// The cb will inject refBy obj after delete prepare has been set.
		refBy, supportData := dataGen.GetClusterInstNetworksRef(testObj.GetKey())
		supportData.put(t, ctx, all)
		deleteStore.putDeletePrepareCb = func() {
			all.clusterInstApi.store.Put(ctx, refBy, all.clusterInstApi.sync.syncWait)
		}
		testObj, _ = dataGen.GetNetworkTestObj()
		err = api.DeleteNetwork(testObj, testutil.NewCudStreamoutNetwork(ctx))
		require.NotNil(t, err, "must fail delete with ref from ClusterInst")
		require.Contains(t, err.Error(), "in use")
		// check that delete prepare was reset
		deleteStore.requireUndoDeletePrepare(ctx, testObj)
		// remove ClusterInst obj
		_, err = all.clusterInstApi.store.Delete(ctx, refBy, all.clusterInstApi.sync.syncWait)
		require.Nil(t, err, "cleanup ref from ClusterInst must succeed")
		deleteStore.putDeletePrepareCb = nil
		supportData.delete(t, ctx, all)
	}

	// clean up testObj
	testObj, _ = dataGen.GetNetworkTestObj()
	err = api.DeleteNetwork(testObj, testutil.NewCudStreamoutNetwork(ctx))
	require.Nil(t, err, "cleanup must succeed")
}

func CreateNetworkAddRefsChecks(t *testing.T, ctx context.Context, all *AllApis, dataGen AllAddRefsDataGen) {
	var err error

	testObj, supportData := dataGen.GetCreateNetworkTestObj()
	supportData.put(t, ctx, all)
	{
		// set delete_prepare on referenced Cloudlet
		ref := supportData.getOneCloudlet()
		require.NotNil(t, ref, "support data must include one referenced Cloudlet")
		ref.DeletePrepare = true
		_, err = all.cloudletApi.store.Put(ctx, ref, all.cloudletApi.sync.syncWait)
		require.Nil(t, err)
		// api call must fail with object being deleted
		testObj, _ = dataGen.GetCreateNetworkTestObj()
		err = all.networkApi.CreateNetwork(testObj, testutil.NewCudStreamoutNetwork(ctx))
		require.NotNil(t, err, "CreateNetwork must fail with Cloudlet.DeletePrepare set")
		require.Equal(t, ref.GetKey().BeingDeletedError().Error(), err.Error())
		// reset delete_prepare on referenced Cloudlet
		ref.DeletePrepare = false
		_, err = all.cloudletApi.store.Put(ctx, ref, all.cloudletApi.sync.syncWait)
		require.Nil(t, err)
	}

	// wrap the stores so we can make sure all checks and changes
	// happen in the same STM.
	networkApiStore, networkApiUnwrap := wrapNetworkTrackerStore(all.networkApi)
	defer networkApiUnwrap()
	cloudletApiStore, cloudletApiUnwrap := wrapCloudletTrackerStore(all.cloudletApi)
	defer cloudletApiUnwrap()

	// CreateNetwork should succeed if no references are in delete_prepare
	testObj, _ = dataGen.GetCreateNetworkTestObj()
	err = all.networkApi.CreateNetwork(testObj, testutil.NewCudStreamoutNetwork(ctx))
	require.Nil(t, err, "CreateNetwork should succeed if no references are in delete prepare")
	// make sure everything ran in the same STM
	require.NotNil(t, networkApiStore.putSTM, "CreateNetwork put Network must be done in STM")
	require.NotNil(t, cloudletApiStore.getSTM, "CreateNetwork check Cloudlet ref must be done in STM")
	require.Equal(t, networkApiStore.putSTM, cloudletApiStore.getSTM, "CreateNetwork check Cloudlet ref must be done in same STM as Network put")

	// clean up
	// delete created test obj
	testObj, _ = dataGen.GetCreateNetworkTestObj()
	err = all.networkApi.DeleteNetwork(testObj, testutil.NewCudStreamoutNetwork(ctx))
	require.Nil(t, err)
	supportData.delete(t, ctx, all)
}
