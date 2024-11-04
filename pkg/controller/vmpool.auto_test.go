// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: vmpool.proto

package controller

import (
	"context"
	fmt "fmt"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/objstore"
	_ "github.com/edgexr/edge-cloud-platform/tools/protogen"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	_ "github.com/gogo/protobuf/types"
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

// VMPoolStoreTracker wraps around the usual
// store to track the STM used for gets/puts.
type VMPoolStoreTracker struct {
	edgeproto.VMPoolStore
	getSTM concurrency.STM
	putSTM concurrency.STM
}

// Wrap the Api's store with a tracker store.
// Returns the tracker store, and the unwrap function to defer.
func wrapVMPoolTrackerStore(api *VMPoolApi) (*VMPoolStoreTracker, func()) {
	orig := api.store
	tracker := &VMPoolStoreTracker{
		VMPoolStore: api.store,
	}
	api.store = tracker
	if api.cache.Store != nil {
		api.cache.Store = tracker
	}
	unwrap := func() {
		api.store = orig
		if api.cache.Store != nil {
			api.cache.Store = orig
		}
	}
	return tracker, unwrap
}

func (s *VMPoolStoreTracker) STMGet(stm concurrency.STM, key *edgeproto.VMPoolKey, buf *edgeproto.VMPool) bool {
	found := s.VMPoolStore.STMGet(stm, key, buf)
	if s.getSTM == nil {
		s.getSTM = stm
	}
	return found
}

func (s *VMPoolStoreTracker) STMPut(stm concurrency.STM, obj *edgeproto.VMPool, ops ...objstore.KVOp) {
	s.VMPoolStore.STMPut(stm, obj, ops...)
	if s.putSTM == nil {
		s.putSTM = stm
	}
}

// Caller must write by hand the test data generator.
// Each Ref object should only have a single reference to the key,
// in order to properly test each reference (i.e. don't have a single
// object that has multiple references).
type VMPoolDeleteDataGen interface {
	GetVMPoolTestObj() (*edgeproto.VMPool, *testSupportData)
	GetCloudletVmPoolRef(key *edgeproto.VMPoolKey) (*edgeproto.Cloudlet, *testSupportData)
}

// VMPoolDeleteStore wraps around the usual
// store to instrument checks and inject data while
// the delete api code is running.
type VMPoolDeleteStore struct {
	edgeproto.VMPoolStore
	t                   *testing.T
	allApis             *AllApis
	putDeletePrepare    bool
	putDeletePrepareCb  func()
	putDeletePrepareSTM concurrency.STM
}

func (s *VMPoolDeleteStore) Put(ctx context.Context, m *edgeproto.VMPool, wait func(int64), ops ...objstore.KVOp) (*edgeproto.Result, error) {
	if wait != nil {
		s.putDeletePrepare = m.DeletePrepare
	}
	res, err := s.VMPoolStore.Put(ctx, m, wait, ops...)
	if s.putDeletePrepare && s.putDeletePrepareCb != nil {
		s.putDeletePrepareCb()
	}
	return res, err
}

func (s *VMPoolDeleteStore) STMPut(stm concurrency.STM, obj *edgeproto.VMPool, ops ...objstore.KVOp) {
	// there's an assumption that this is run within an ApplySTMWait,
	// where we wait for the caches to be updated with the transaction.
	if obj.DeletePrepare {
		s.putDeletePrepare = true
		s.putDeletePrepareSTM = stm
	} else {
		s.putDeletePrepare = false
		s.putDeletePrepareSTM = nil
	}
	s.VMPoolStore.STMPut(stm, obj, ops...)
	if s.putDeletePrepare && s.putDeletePrepareCb != nil {
		s.putDeletePrepareCb()
	}
}

func (s *VMPoolDeleteStore) Delete(ctx context.Context, m *edgeproto.VMPool, wait func(int64)) (*edgeproto.Result, error) {
	require.True(s.t, s.putDeletePrepare, "DeletePrepare must be comitted to database with a sync.Wait before deleting")
	return s.VMPoolStore.Delete(ctx, m, wait)
}

func (s *VMPoolDeleteStore) STMDel(stm concurrency.STM, key *edgeproto.VMPoolKey) {
	require.True(s.t, s.putDeletePrepare, "DeletePrepare must be comitted to database with a sync.Wait before deleting")
	s.VMPoolStore.STMDel(stm, key)
}

func (s *VMPoolDeleteStore) requireUndoDeletePrepare(ctx context.Context, obj *edgeproto.VMPool) {
	deletePrepare := s.getDeletePrepare(ctx, obj)
	require.False(s.t, deletePrepare, "must undo delete prepare field on failure")
}

func (s *VMPoolDeleteStore) getDeletePrepare(ctx context.Context, obj *edgeproto.VMPool) bool {
	buf := edgeproto.VMPool{}
	found := s.Get(ctx, obj.GetKey(), &buf)
	require.True(s.t, found, "expected test object to be found")
	return buf.DeletePrepare
}

func deleteVMPoolChecks(t *testing.T, ctx context.Context, all *AllApis, dataGen VMPoolDeleteDataGen) {
	var err error
	// override store so we can inject data and check data
	api := all.vmPoolApi
	origStore := api.store
	deleteStore := &VMPoolDeleteStore{
		VMPoolStore: origStore,
		t:           t,
		allApis:     all,
	}
	api.store = deleteStore
	defer func() {
		api.store = origStore
	}()

	// inject testObj directly, bypassing create checks/deps
	testObj, supportData := dataGen.GetVMPoolTestObj()
	supportData.put(t, ctx, all)
	defer supportData.delete(t, ctx, all)
	origStore.Put(ctx, testObj, api.sync.SyncWait)

	// Positive test, delete should succeed without any references.
	// The overrided store checks that delete prepare was set on the
	// object in the database before actually doing the delete.
	testObj, _ = dataGen.GetVMPoolTestObj()
	_, err = api.DeleteVMPool(ctx, testObj)
	require.Nil(t, err, "delete must succeed with no refs")

	// Negative test, inject testObj with delete prepare already set.
	testObj, _ = dataGen.GetVMPoolTestObj()
	testObj.DeletePrepare = true
	origStore.Put(ctx, testObj, api.sync.SyncWait)
	// delete should fail with already being deleted
	testObj, _ = dataGen.GetVMPoolTestObj()
	_, err = api.DeleteVMPool(ctx, testObj)
	require.NotNil(t, err, "delete must fail if already being deleted")
	require.Equal(t, testObj.GetKey().BeingDeletedError().Error(), err.Error())
	// failed delete must not interfere with existing delete prepare state
	require.True(t, deleteStore.getDeletePrepare(ctx, testObj), "delete prepare must not be modified by failed delete")

	// inject testObj for ref tests
	testObj, _ = dataGen.GetVMPoolTestObj()
	origStore.Put(ctx, testObj, api.sync.SyncWait)

	{
		// Negative test, Cloudlet refers to VMPool.
		// The cb will inject refBy obj after delete prepare has been set.
		refBy, supportData := dataGen.GetCloudletVmPoolRef(testObj.GetKey())
		supportData.put(t, ctx, all)
		deleteStore.putDeletePrepareCb = func() {
			all.cloudletApi.store.Put(ctx, refBy, all.cloudletApi.sync.SyncWait)
		}
		testObj, _ = dataGen.GetVMPoolTestObj()
		_, err = api.DeleteVMPool(ctx, testObj)
		require.NotNil(t, err, "must fail delete with ref from Cloudlet")
		require.Contains(t, err.Error(), "in use")
		// check that delete prepare was reset
		deleteStore.requireUndoDeletePrepare(ctx, testObj)
		// remove Cloudlet obj
		_, err = all.cloudletApi.store.Delete(ctx, refBy, all.cloudletApi.sync.SyncWait)
		require.Nil(t, err, "cleanup ref from Cloudlet must succeed")
		deleteStore.putDeletePrepareCb = nil
		supportData.delete(t, ctx, all)
	}

	// clean up testObj
	testObj, _ = dataGen.GetVMPoolTestObj()
	_, err = api.DeleteVMPool(ctx, testObj)
	require.Nil(t, err, "cleanup must succeed")
}
