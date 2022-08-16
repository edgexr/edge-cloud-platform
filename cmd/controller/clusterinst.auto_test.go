// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: clusterinst.proto

package main

import (
	"context"
	fmt "fmt"
	_ "github.com/edgexr/edge-cloud-platform/api/dme-proto"
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

// ClusterInstStoreTracker wraps around the usual
// store to track the STM used for gets/puts.
type ClusterInstStoreTracker struct {
	edgeproto.ClusterInstStore
	getSTM concurrency.STM
	putSTM concurrency.STM
}

// Wrap the Api's store with a tracker store.
// Returns the tracker store, and the unwrap function to defer.
func wrapClusterInstTrackerStore(api *ClusterInstApi) (*ClusterInstStoreTracker, func()) {
	orig := api.store
	tracker := &ClusterInstStoreTracker{
		ClusterInstStore: api.store,
	}
	api.store = tracker
	unwrap := func() {
		api.store = orig
	}
	return tracker, unwrap
}

func (s *ClusterInstStoreTracker) STMGet(stm concurrency.STM, key *edgeproto.ClusterInstKey, buf *edgeproto.ClusterInst) bool {
	found := s.ClusterInstStore.STMGet(stm, key, buf)
	if s.getSTM == nil {
		s.getSTM = stm
	}
	return found
}

func (s *ClusterInstStoreTracker) STMPut(stm concurrency.STM, obj *edgeproto.ClusterInst, ops ...objstore.KVOp) {
	s.ClusterInstStore.STMPut(stm, obj, ops...)
	if s.putSTM == nil {
		s.putSTM = stm
	}
}

// Caller must write by hand the test data generator.
// Each Ref object should only have a single reference to the key,
// in order to properly test each reference (i.e. don't have a single
// object that has multiple references).
type ClusterInstDeleteDataGen interface {
	GetClusterInstTestObj() (*edgeproto.ClusterInst, *testSupportData)
	GetClusterInstAppInstAppsRef(key *edgeproto.ClusterInstKey) (*edgeproto.ClusterRefs, *testSupportData)
}

// ClusterInstDeleteStore wraps around the usual
// store to instrument checks and inject data while
// the delete api code is running.
type ClusterInstDeleteStore struct {
	edgeproto.ClusterInstStore
	t                   *testing.T
	allApis             *AllApis
	putDeletePrepare    bool
	putDeletePrepareCb  func()
	putDeletePrepareSTM concurrency.STM
}

func (s *ClusterInstDeleteStore) Put(ctx context.Context, m *edgeproto.ClusterInst, wait func(int64), ops ...objstore.KVOp) (*edgeproto.Result, error) {
	if wait != nil {
		s.putDeletePrepare = m.DeletePrepare
	}
	res, err := s.ClusterInstStore.Put(ctx, m, wait, ops...)
	if s.putDeletePrepare && s.putDeletePrepareCb != nil {
		s.putDeletePrepareCb()
	}
	return res, err
}

func (s *ClusterInstDeleteStore) STMPut(stm concurrency.STM, obj *edgeproto.ClusterInst, ops ...objstore.KVOp) {
	// there's an assumption that this is run within an ApplySTMWait,
	// where we wait for the caches to be updated with the transaction.
	if obj.DeletePrepare {
		s.putDeletePrepare = true
		s.putDeletePrepareSTM = stm
	} else {
		s.putDeletePrepare = false
		s.putDeletePrepareSTM = nil
	}
	s.ClusterInstStore.STMPut(stm, obj, ops...)
	if s.putDeletePrepare && s.putDeletePrepareCb != nil {
		s.putDeletePrepareCb()
	}
}

func (s *ClusterInstDeleteStore) Delete(ctx context.Context, m *edgeproto.ClusterInst, wait func(int64)) (*edgeproto.Result, error) {
	require.True(s.t, s.putDeletePrepare, "DeletePrepare must be comitted to database with a sync.Wait before deleting")
	return s.ClusterInstStore.Delete(ctx, m, wait)
}

func (s *ClusterInstDeleteStore) STMDel(stm concurrency.STM, key *edgeproto.ClusterInstKey) {
	require.True(s.t, s.putDeletePrepare, "DeletePrepare must be comitted to database with a sync.Wait before deleting")
	s.ClusterInstStore.STMDel(stm, key)
}

func (s *ClusterInstDeleteStore) requireUndoDeletePrepare(ctx context.Context, obj *edgeproto.ClusterInst) {
	deletePrepare := s.getDeletePrepare(ctx, obj)
	require.False(s.t, deletePrepare, "must undo delete prepare field on failure")
}

func (s *ClusterInstDeleteStore) getDeletePrepare(ctx context.Context, obj *edgeproto.ClusterInst) bool {
	buf := edgeproto.ClusterInst{}
	found := s.Get(ctx, obj.GetKey(), &buf)
	require.True(s.t, found, "expected test object to be found")
	return buf.DeletePrepare
}

func deleteClusterInstChecks(t *testing.T, ctx context.Context, all *AllApis, dataGen ClusterInstDeleteDataGen) {
	var err error
	// override store so we can inject data and check data
	api := all.clusterInstApi
	origStore := api.store
	deleteStore := &ClusterInstDeleteStore{
		ClusterInstStore: origStore,
		t:                t,
		allApis:          all,
	}
	api.store = deleteStore
	clusterRefsApiStore, clusterRefsApiUnwrap := wrapClusterRefsTrackerStore(all.clusterRefsApi)
	defer func() {
		api.store = origStore
		clusterRefsApiUnwrap()
	}()

	// inject testObj directly, bypassing create checks/deps
	testObj, supportData := dataGen.GetClusterInstTestObj()
	supportData.put(t, ctx, all)
	defer supportData.delete(t, ctx, all)
	origStore.Put(ctx, testObj, api.sync.syncWait)

	// Positive test, delete should succeed without any references.
	// The overrided store checks that delete prepare was set on the
	// object in the database before actually doing the delete.
	// This call back checks that any refs lookups are done in the
	// same stm as the delete prepare is set.
	deleteStore.putDeletePrepareCb = func() {
		// make sure ref objects reads happen in same stm
		// as delete prepare is set
		require.NotNil(t, deleteStore.putDeletePrepareSTM, "must set delete prepare in STM")
		require.NotNil(t, clusterRefsApiStore.getSTM, "must check for refs from ClusterRefs in STM")
		require.Equal(t, deleteStore.putDeletePrepareSTM, clusterRefsApiStore.getSTM, "delete prepare and ref check for ClusterRefs must be done in the same STM")
	}
	testObj, _ = dataGen.GetClusterInstTestObj()
	err = api.DeleteClusterInst(testObj, testutil.NewCudStreamoutClusterInst(ctx))
	require.Nil(t, err, "delete must succeed with no refs")
	deleteStore.putDeletePrepareCb = nil

	// Negative test, inject testObj with delete prepare already set.
	testObj, _ = dataGen.GetClusterInstTestObj()
	testObj.DeletePrepare = true
	origStore.Put(ctx, testObj, api.sync.syncWait)
	// delete should fail with already being deleted
	testObj, _ = dataGen.GetClusterInstTestObj()
	err = api.DeleteClusterInst(testObj, testutil.NewCudStreamoutClusterInst(ctx))
	require.NotNil(t, err, "delete must fail if already being deleted")
	require.Equal(t, testObj.GetKey().BeingDeletedError().Error(), err.Error())
	// failed delete must not interfere with existing delete prepare state
	require.True(t, deleteStore.getDeletePrepare(ctx, testObj), "delete prepare must not be modified by failed delete")

	// inject testObj for ref tests
	testObj, _ = dataGen.GetClusterInstTestObj()
	origStore.Put(ctx, testObj, api.sync.syncWait)

	{
		// Negative test, ClusterRefs refers to ClusterInst via refs object.
		// Inject the refs object to trigger an "in use" error.
		refBy, supportData := dataGen.GetClusterInstAppInstAppsRef(testObj.GetKey())
		supportData.put(t, ctx, all)
		_, err = all.clusterRefsApi.store.Put(ctx, refBy, all.clusterRefsApi.sync.syncWait)
		require.Nil(t, err)
		testObj, _ = dataGen.GetClusterInstTestObj()
		err = api.DeleteClusterInst(testObj, testutil.NewCudStreamoutClusterInst(ctx))
		require.NotNil(t, err, "delete with ref from ClusterRefs must fail")
		require.Contains(t, err.Error(), "in use")
		// check that delete prepare was reset
		deleteStore.requireUndoDeletePrepare(ctx, testObj)
		// remove ClusterRefs obj
		_, err = all.clusterRefsApi.store.Delete(ctx, refBy, all.clusterRefsApi.sync.syncWait)
		require.Nil(t, err, "cleanup ref from ClusterRefs must succeed")
		supportData.delete(t, ctx, all)
	}

	// clean up testObj
	testObj, _ = dataGen.GetClusterInstTestObj()
	err = api.DeleteClusterInst(testObj, testutil.NewCudStreamoutClusterInst(ctx))
	require.Nil(t, err, "cleanup must succeed")
}

func CreateClusterInstAddRefsChecks(t *testing.T, ctx context.Context, all *AllApis, dataGen AllAddRefsDataGen) {
	var err error

	testObj, supportData := dataGen.GetCreateClusterInstTestObj()
	supportData.put(t, ctx, all)
	{
		// set delete_prepare on referenced Cloudlet
		ref := supportData.getOneCloudlet()
		require.NotNil(t, ref, "support data must include one referenced Cloudlet")
		ref.DeletePrepare = true
		_, err = all.cloudletApi.store.Put(ctx, ref, all.cloudletApi.sync.syncWait)
		require.Nil(t, err)
		// api call must fail with object being deleted
		testObj, _ = dataGen.GetCreateClusterInstTestObj()
		err = all.clusterInstApi.CreateClusterInst(testObj, testutil.NewCudStreamoutClusterInst(ctx))
		require.NotNil(t, err, "CreateClusterInst must fail with Cloudlet.DeletePrepare set")
		require.Equal(t, ref.GetKey().BeingDeletedError().Error(), err.Error())
		// reset delete_prepare on referenced Cloudlet
		ref.DeletePrepare = false
		_, err = all.cloudletApi.store.Put(ctx, ref, all.cloudletApi.sync.syncWait)
		require.Nil(t, err)
	}
	{
		// set delete_prepare on referenced Flavor
		ref := supportData.getOneFlavor()
		require.NotNil(t, ref, "support data must include one referenced Flavor")
		ref.DeletePrepare = true
		_, err = all.flavorApi.store.Put(ctx, ref, all.flavorApi.sync.syncWait)
		require.Nil(t, err)
		// api call must fail with object being deleted
		testObj, _ = dataGen.GetCreateClusterInstTestObj()
		err = all.clusterInstApi.CreateClusterInst(testObj, testutil.NewCudStreamoutClusterInst(ctx))
		require.NotNil(t, err, "CreateClusterInst must fail with Flavor.DeletePrepare set")
		require.Equal(t, ref.GetKey().BeingDeletedError().Error(), err.Error())
		// reset delete_prepare on referenced Flavor
		ref.DeletePrepare = false
		_, err = all.flavorApi.store.Put(ctx, ref, all.flavorApi.sync.syncWait)
		require.Nil(t, err)
	}
	{
		// set delete_prepare on referenced AutoScalePolicy
		ref := supportData.getOneAutoScalePolicy()
		require.NotNil(t, ref, "support data must include one referenced AutoScalePolicy")
		ref.DeletePrepare = true
		_, err = all.autoScalePolicyApi.store.Put(ctx, ref, all.autoScalePolicyApi.sync.syncWait)
		require.Nil(t, err)
		// api call must fail with object being deleted
		testObj, _ = dataGen.GetCreateClusterInstTestObj()
		err = all.clusterInstApi.CreateClusterInst(testObj, testutil.NewCudStreamoutClusterInst(ctx))
		require.NotNil(t, err, "CreateClusterInst must fail with AutoScalePolicy.DeletePrepare set")
		require.Equal(t, ref.GetKey().BeingDeletedError().Error(), err.Error())
		// reset delete_prepare on referenced AutoScalePolicy
		ref.DeletePrepare = false
		_, err = all.autoScalePolicyApi.store.Put(ctx, ref, all.autoScalePolicyApi.sync.syncWait)
		require.Nil(t, err)
	}
	{
		// set delete_prepare on referenced Network
		ref := supportData.getOneNetwork()
		require.NotNil(t, ref, "support data must include one referenced Network")
		ref.DeletePrepare = true
		_, err = all.networkApi.store.Put(ctx, ref, all.networkApi.sync.syncWait)
		require.Nil(t, err)
		// api call must fail with object being deleted
		testObj, _ = dataGen.GetCreateClusterInstTestObj()
		err = all.clusterInstApi.CreateClusterInst(testObj, testutil.NewCudStreamoutClusterInst(ctx))
		require.NotNil(t, err, "CreateClusterInst must fail with Network.DeletePrepare set")
		require.Equal(t, ref.GetKey().BeingDeletedError().Error(), err.Error())
		// reset delete_prepare on referenced Network
		ref.DeletePrepare = false
		_, err = all.networkApi.store.Put(ctx, ref, all.networkApi.sync.syncWait)
		require.Nil(t, err)
	}

	// wrap the stores so we can make sure all checks and changes
	// happen in the same STM.
	clusterInstApiStore, clusterInstApiUnwrap := wrapClusterInstTrackerStore(all.clusterInstApi)
	defer clusterInstApiUnwrap()
	cloudletApiStore, cloudletApiUnwrap := wrapCloudletTrackerStore(all.cloudletApi)
	defer cloudletApiUnwrap()
	flavorApiStore, flavorApiUnwrap := wrapFlavorTrackerStore(all.flavorApi)
	defer flavorApiUnwrap()
	autoScalePolicyApiStore, autoScalePolicyApiUnwrap := wrapAutoScalePolicyTrackerStore(all.autoScalePolicyApi)
	defer autoScalePolicyApiUnwrap()
	networkApiStore, networkApiUnwrap := wrapNetworkTrackerStore(all.networkApi)
	defer networkApiUnwrap()

	// CreateClusterInst should succeed if no references are in delete_prepare
	testObj, _ = dataGen.GetCreateClusterInstTestObj()
	err = all.clusterInstApi.CreateClusterInst(testObj, testutil.NewCudStreamoutClusterInst(ctx))
	require.Nil(t, err, "CreateClusterInst should succeed if no references are in delete prepare")
	// make sure everything ran in the same STM
	require.NotNil(t, clusterInstApiStore.putSTM, "CreateClusterInst put ClusterInst must be done in STM")
	require.NotNil(t, cloudletApiStore.getSTM, "CreateClusterInst check Cloudlet ref must be done in STM")
	require.Equal(t, clusterInstApiStore.putSTM, cloudletApiStore.getSTM, "CreateClusterInst check Cloudlet ref must be done in same STM as ClusterInst put")
	require.NotNil(t, flavorApiStore.getSTM, "CreateClusterInst check Flavor ref must be done in STM")
	require.Equal(t, clusterInstApiStore.putSTM, flavorApiStore.getSTM, "CreateClusterInst check Flavor ref must be done in same STM as ClusterInst put")
	require.NotNil(t, autoScalePolicyApiStore.getSTM, "CreateClusterInst check AutoScalePolicy ref must be done in STM")
	require.Equal(t, clusterInstApiStore.putSTM, autoScalePolicyApiStore.getSTM, "CreateClusterInst check AutoScalePolicy ref must be done in same STM as ClusterInst put")
	require.NotNil(t, networkApiStore.getSTM, "CreateClusterInst check Network ref must be done in STM")
	require.Equal(t, clusterInstApiStore.putSTM, networkApiStore.getSTM, "CreateClusterInst check Network ref must be done in same STM as ClusterInst put")

	// clean up
	// delete created test obj
	testObj, _ = dataGen.GetCreateClusterInstTestObj()
	err = all.clusterInstApi.DeleteClusterInst(testObj, testutil.NewCudStreamoutClusterInst(ctx))
	require.Nil(t, err)
	supportData.delete(t, ctx, all)
}

func UpdateClusterInstAddRefsChecks(t *testing.T, ctx context.Context, all *AllApis, dataGen AllAddRefsDataGen) {
	var err error

	testObj, supportData := dataGen.GetUpdateClusterInstTestObj()
	supportData.put(t, ctx, all)
	{
		// set delete_prepare on referenced AutoScalePolicy
		ref := supportData.getOneAutoScalePolicy()
		require.NotNil(t, ref, "support data must include one referenced AutoScalePolicy")
		ref.DeletePrepare = true
		_, err = all.autoScalePolicyApi.store.Put(ctx, ref, all.autoScalePolicyApi.sync.syncWait)
		require.Nil(t, err)
		// api call must fail with object being deleted
		testObj, _ = dataGen.GetUpdateClusterInstTestObj()
		err = all.clusterInstApi.UpdateClusterInst(testObj, testutil.NewCudStreamoutClusterInst(ctx))
		require.NotNil(t, err, "UpdateClusterInst must fail with AutoScalePolicy.DeletePrepare set")
		require.Equal(t, ref.GetKey().BeingDeletedError().Error(), err.Error())
		// reset delete_prepare on referenced AutoScalePolicy
		ref.DeletePrepare = false
		_, err = all.autoScalePolicyApi.store.Put(ctx, ref, all.autoScalePolicyApi.sync.syncWait)
		require.Nil(t, err)
	}

	// wrap the stores so we can make sure all checks and changes
	// happen in the same STM.
	clusterInstApiStore, clusterInstApiUnwrap := wrapClusterInstTrackerStore(all.clusterInstApi)
	defer clusterInstApiUnwrap()
	autoScalePolicyApiStore, autoScalePolicyApiUnwrap := wrapAutoScalePolicyTrackerStore(all.autoScalePolicyApi)
	defer autoScalePolicyApiUnwrap()

	// UpdateClusterInst should succeed if no references are in delete_prepare
	testObj, _ = dataGen.GetUpdateClusterInstTestObj()
	err = all.clusterInstApi.UpdateClusterInst(testObj, testutil.NewCudStreamoutClusterInst(ctx))
	require.Nil(t, err, "UpdateClusterInst should succeed if no references are in delete prepare")
	// make sure everything ran in the same STM
	require.NotNil(t, clusterInstApiStore.putSTM, "UpdateClusterInst put ClusterInst must be done in STM")
	require.NotNil(t, autoScalePolicyApiStore.getSTM, "UpdateClusterInst check AutoScalePolicy ref must be done in STM")
	require.Equal(t, clusterInstApiStore.putSTM, autoScalePolicyApiStore.getSTM, "UpdateClusterInst check AutoScalePolicy ref must be done in same STM as ClusterInst put")

	// clean up
	supportData.delete(t, ctx, all)
}
