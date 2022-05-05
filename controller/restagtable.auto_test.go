// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: restagtable.proto

package main

import (
	"context"
	fmt "fmt"
	"github.com/coreos/etcd/clientv3/concurrency"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/objstore"
	_ "github.com/edgexr/edge-cloud/protogen"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	"github.com/stretchr/testify/require"
	math "math"
	"testing"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

// ResTagTableStoreTracker wraps around the usual
// store to track the STM used for gets/puts.
type ResTagTableStoreTracker struct {
	edgeproto.ResTagTableStore
	getSTM concurrency.STM
	putSTM concurrency.STM
}

// Wrap the Api's store with a tracker store.
// Returns the tracker store, and the unwrap function to defer.
func wrapResTagTableTrackerStore(api *ResTagTableApi) (*ResTagTableStoreTracker, func()) {
	orig := api.store
	tracker := &ResTagTableStoreTracker{
		ResTagTableStore: api.store,
	}
	api.store = tracker
	unwrap := func() {
		api.store = orig
	}
	return tracker, unwrap
}

func (s *ResTagTableStoreTracker) STMGet(stm concurrency.STM, key *edgeproto.ResTagTableKey, buf *edgeproto.ResTagTable) bool {
	found := s.ResTagTableStore.STMGet(stm, key, buf)
	if s.getSTM == nil {
		s.getSTM = stm
	}
	return found
}

func (s *ResTagTableStoreTracker) STMPut(stm concurrency.STM, obj *edgeproto.ResTagTable, ops ...objstore.KVOp) {
	s.ResTagTableStore.STMPut(stm, obj, ops...)
	if s.putSTM == nil {
		s.putSTM = stm
	}
}

// Caller must write by hand the test data generator.
// Each Ref object should only have a single reference to the key,
// in order to properly test each reference (i.e. don't have a single
// object that has multiple references).
type ResTagTableDeleteDataGen interface {
	GetResTagTableTestObj() (*edgeproto.ResTagTable, *testSupportData)
	GetCloudletResTagMapRef(key *edgeproto.ResTagTableKey) (*edgeproto.Cloudlet, *testSupportData)
}

// ResTagTableDeleteStore wraps around the usual
// store to instrument checks and inject data while
// the delete api code is running.
type ResTagTableDeleteStore struct {
	edgeproto.ResTagTableStore
	t                   *testing.T
	allApis             *AllApis
	putDeletePrepare    bool
	putDeletePrepareCb  func()
	putDeletePrepareSTM concurrency.STM
}

func (s *ResTagTableDeleteStore) Put(ctx context.Context, m *edgeproto.ResTagTable, wait func(int64), ops ...objstore.KVOp) (*edgeproto.Result, error) {
	if wait != nil {
		s.putDeletePrepare = m.DeletePrepare
	}
	res, err := s.ResTagTableStore.Put(ctx, m, wait, ops...)
	if s.putDeletePrepare && s.putDeletePrepareCb != nil {
		s.putDeletePrepareCb()
	}
	return res, err
}

func (s *ResTagTableDeleteStore) STMPut(stm concurrency.STM, obj *edgeproto.ResTagTable, ops ...objstore.KVOp) {
	// there's an assumption that this is run within an ApplySTMWait,
	// where we wait for the caches to be updated with the transaction.
	if obj.DeletePrepare {
		s.putDeletePrepare = true
		s.putDeletePrepareSTM = stm
	} else {
		s.putDeletePrepare = false
		s.putDeletePrepareSTM = nil
	}
	s.ResTagTableStore.STMPut(stm, obj, ops...)
	if s.putDeletePrepare && s.putDeletePrepareCb != nil {
		s.putDeletePrepareCb()
	}
}

func (s *ResTagTableDeleteStore) Delete(ctx context.Context, m *edgeproto.ResTagTable, wait func(int64)) (*edgeproto.Result, error) {
	require.True(s.t, s.putDeletePrepare, "DeletePrepare must be comitted to database with a sync.Wait before deleting")
	return s.ResTagTableStore.Delete(ctx, m, wait)
}

func (s *ResTagTableDeleteStore) STMDel(stm concurrency.STM, key *edgeproto.ResTagTableKey) {
	require.True(s.t, s.putDeletePrepare, "DeletePrepare must be comitted to database with a sync.Wait before deleting")
	s.ResTagTableStore.STMDel(stm, key)
}

func (s *ResTagTableDeleteStore) requireUndoDeletePrepare(ctx context.Context, obj *edgeproto.ResTagTable) {
	deletePrepare := s.getDeletePrepare(ctx, obj)
	require.False(s.t, deletePrepare, "must undo delete prepare field on failure")
}

func (s *ResTagTableDeleteStore) getDeletePrepare(ctx context.Context, obj *edgeproto.ResTagTable) bool {
	buf := edgeproto.ResTagTable{}
	found := s.Get(ctx, obj.GetKey(), &buf)
	require.True(s.t, found, "expected test object to be found")
	return buf.DeletePrepare
}

func deleteResTagTableChecks(t *testing.T, ctx context.Context, all *AllApis, dataGen ResTagTableDeleteDataGen) {
	var err error
	// override store so we can inject data and check data
	api := all.resTagTableApi
	origStore := api.store
	deleteStore := &ResTagTableDeleteStore{
		ResTagTableStore: origStore,
		t:                t,
		allApis:          all,
	}
	api.store = deleteStore
	defer func() {
		api.store = origStore
	}()

	// inject testObj directly, bypassing create checks/deps
	testObj, supportData := dataGen.GetResTagTableTestObj()
	supportData.put(t, ctx, all)
	defer supportData.delete(t, ctx, all)
	origStore.Put(ctx, testObj, api.sync.syncWait)

	// Positive test, delete should succeed without any references.
	// The overrided store checks that delete prepare was set on the
	// object in the database before actually doing the delete.
	testObj, _ = dataGen.GetResTagTableTestObj()
	_, err = api.DeleteResTagTable(ctx, testObj)
	require.Nil(t, err, "delete must succeed with no refs")

	// Negative test, inject testObj with delete prepare already set.
	testObj, _ = dataGen.GetResTagTableTestObj()
	testObj.DeletePrepare = true
	origStore.Put(ctx, testObj, api.sync.syncWait)
	// delete should fail with already being deleted
	testObj, _ = dataGen.GetResTagTableTestObj()
	_, err = api.DeleteResTagTable(ctx, testObj)
	require.NotNil(t, err, "delete must fail if already being deleted")
	require.Equal(t, testObj.GetKey().BeingDeletedError().Error(), err.Error())
	// failed delete must not interfere with existing delete prepare state
	require.True(t, deleteStore.getDeletePrepare(ctx, testObj), "delete prepare must not be modified by failed delete")

	// inject testObj for ref tests
	testObj, _ = dataGen.GetResTagTableTestObj()
	origStore.Put(ctx, testObj, api.sync.syncWait)

	{
		// Negative test, Cloudlet refers to ResTagTable.
		// The cb will inject refBy obj after delete prepare has been set.
		refBy, supportData := dataGen.GetCloudletResTagMapRef(testObj.GetKey())
		supportData.put(t, ctx, all)
		deleteStore.putDeletePrepareCb = func() {
			all.cloudletApi.store.Put(ctx, refBy, all.cloudletApi.sync.syncWait)
		}
		testObj, _ = dataGen.GetResTagTableTestObj()
		_, err = api.DeleteResTagTable(ctx, testObj)
		require.NotNil(t, err, "must fail delete with ref from Cloudlet")
		require.Contains(t, err.Error(), "in use")
		// check that delete prepare was reset
		deleteStore.requireUndoDeletePrepare(ctx, testObj)
		// remove Cloudlet obj
		_, err = all.cloudletApi.store.Delete(ctx, refBy, all.cloudletApi.sync.syncWait)
		require.Nil(t, err, "cleanup ref from Cloudlet must succeed")
		deleteStore.putDeletePrepareCb = nil
		supportData.delete(t, ctx, all)
	}

	// clean up testObj
	testObj, _ = dataGen.GetResTagTableTestObj()
	_, err = api.DeleteResTagTable(ctx, testObj)
	require.Nil(t, err, "cleanup must succeed")
}
