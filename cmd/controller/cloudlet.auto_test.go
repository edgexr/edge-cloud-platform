// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: cloudlet.proto

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

// GPUDriverStoreTracker wraps around the usual
// store to track the STM used for gets/puts.
type GPUDriverStoreTracker struct {
	edgeproto.GPUDriverStore
	getSTM concurrency.STM
	putSTM concurrency.STM
}

// Wrap the Api's store with a tracker store.
// Returns the tracker store, and the unwrap function to defer.
func wrapGPUDriverTrackerStore(api *GPUDriverApi) (*GPUDriverStoreTracker, func()) {
	orig := api.store
	tracker := &GPUDriverStoreTracker{
		GPUDriverStore: api.store,
	}
	api.store = tracker
	unwrap := func() {
		api.store = orig
	}
	return tracker, unwrap
}

func (s *GPUDriverStoreTracker) STMGet(stm concurrency.STM, key *edgeproto.GPUDriverKey, buf *edgeproto.GPUDriver) bool {
	found := s.GPUDriverStore.STMGet(stm, key, buf)
	if s.getSTM == nil {
		s.getSTM = stm
	}
	return found
}

func (s *GPUDriverStoreTracker) STMPut(stm concurrency.STM, obj *edgeproto.GPUDriver, ops ...objstore.KVOp) {
	s.GPUDriverStore.STMPut(stm, obj, ops...)
	if s.putSTM == nil {
		s.putSTM = stm
	}
}

// Caller must write by hand the test data generator.
// Each Ref object should only have a single reference to the key,
// in order to properly test each reference (i.e. don't have a single
// object that has multiple references).
type GPUDriverDeleteDataGen interface {
	GetGPUDriverTestObj() (*edgeproto.GPUDriver, *testSupportData)
	GetCloudletGpuConfigDriverRef(key *edgeproto.GPUDriverKey) (*edgeproto.Cloudlet, *testSupportData)
}

// GPUDriverDeleteStore wraps around the usual
// store to instrument checks and inject data while
// the delete api code is running.
type GPUDriverDeleteStore struct {
	edgeproto.GPUDriverStore
	t                   *testing.T
	allApis             *AllApis
	putDeletePrepare    bool
	putDeletePrepareCb  func()
	putDeletePrepareSTM concurrency.STM
}

func (s *GPUDriverDeleteStore) Put(ctx context.Context, m *edgeproto.GPUDriver, wait func(int64), ops ...objstore.KVOp) (*edgeproto.Result, error) {
	if wait != nil {
		s.putDeletePrepare = m.DeletePrepare
	}
	res, err := s.GPUDriverStore.Put(ctx, m, wait, ops...)
	if s.putDeletePrepare && s.putDeletePrepareCb != nil {
		s.putDeletePrepareCb()
	}
	return res, err
}

func (s *GPUDriverDeleteStore) STMPut(stm concurrency.STM, obj *edgeproto.GPUDriver, ops ...objstore.KVOp) {
	// there's an assumption that this is run within an ApplySTMWait,
	// where we wait for the caches to be updated with the transaction.
	if obj.DeletePrepare {
		s.putDeletePrepare = true
		s.putDeletePrepareSTM = stm
	} else {
		s.putDeletePrepare = false
		s.putDeletePrepareSTM = nil
	}
	s.GPUDriverStore.STMPut(stm, obj, ops...)
	if s.putDeletePrepare && s.putDeletePrepareCb != nil {
		s.putDeletePrepareCb()
	}
}

func (s *GPUDriverDeleteStore) Delete(ctx context.Context, m *edgeproto.GPUDriver, wait func(int64)) (*edgeproto.Result, error) {
	require.True(s.t, s.putDeletePrepare, "DeletePrepare must be comitted to database with a sync.Wait before deleting")
	return s.GPUDriverStore.Delete(ctx, m, wait)
}

func (s *GPUDriverDeleteStore) STMDel(stm concurrency.STM, key *edgeproto.GPUDriverKey) {
	require.True(s.t, s.putDeletePrepare, "DeletePrepare must be comitted to database with a sync.Wait before deleting")
	s.GPUDriverStore.STMDel(stm, key)
}

func (s *GPUDriverDeleteStore) requireUndoDeletePrepare(ctx context.Context, obj *edgeproto.GPUDriver) {
	deletePrepare := s.getDeletePrepare(ctx, obj)
	require.False(s.t, deletePrepare, "must undo delete prepare field on failure")
}

func (s *GPUDriverDeleteStore) getDeletePrepare(ctx context.Context, obj *edgeproto.GPUDriver) bool {
	buf := edgeproto.GPUDriver{}
	found := s.Get(ctx, obj.GetKey(), &buf)
	require.True(s.t, found, "expected test object to be found")
	return buf.DeletePrepare
}

func deleteGPUDriverChecks(t *testing.T, ctx context.Context, all *AllApis, dataGen GPUDriverDeleteDataGen) {
	var err error
	// override store so we can inject data and check data
	api := all.gpuDriverApi
	origStore := api.store
	deleteStore := &GPUDriverDeleteStore{
		GPUDriverStore: origStore,
		t:              t,
		allApis:        all,
	}
	api.store = deleteStore
	defer func() {
		api.store = origStore
	}()

	// inject testObj directly, bypassing create checks/deps
	testObj, supportData := dataGen.GetGPUDriverTestObj()
	supportData.put(t, ctx, all)
	defer supportData.delete(t, ctx, all)
	origStore.Put(ctx, testObj, api.sync.syncWait)

	// Positive test, delete should succeed without any references.
	// The overrided store checks that delete prepare was set on the
	// object in the database before actually doing the delete.
	testObj, _ = dataGen.GetGPUDriverTestObj()
	err = api.DeleteGPUDriver(testObj, testutil.NewCudStreamoutGPUDriver(ctx))
	require.Nil(t, err, "delete must succeed with no refs")

	// Negative test, inject testObj with delete prepare already set.
	testObj, _ = dataGen.GetGPUDriverTestObj()
	testObj.DeletePrepare = true
	origStore.Put(ctx, testObj, api.sync.syncWait)
	// delete should fail with already being deleted
	testObj, _ = dataGen.GetGPUDriverTestObj()
	err = api.DeleteGPUDriver(testObj, testutil.NewCudStreamoutGPUDriver(ctx))
	require.NotNil(t, err, "delete must fail if already being deleted")
	require.Equal(t, testObj.GetKey().BeingDeletedError().Error(), err.Error())
	// failed delete must not interfere with existing delete prepare state
	require.True(t, deleteStore.getDeletePrepare(ctx, testObj), "delete prepare must not be modified by failed delete")

	// inject testObj for ref tests
	testObj, _ = dataGen.GetGPUDriverTestObj()
	origStore.Put(ctx, testObj, api.sync.syncWait)

	{
		// Negative test, Cloudlet refers to GPUDriver.
		// The cb will inject refBy obj after delete prepare has been set.
		refBy, supportData := dataGen.GetCloudletGpuConfigDriverRef(testObj.GetKey())
		supportData.put(t, ctx, all)
		deleteStore.putDeletePrepareCb = func() {
			all.cloudletApi.store.Put(ctx, refBy, all.cloudletApi.sync.syncWait)
		}
		testObj, _ = dataGen.GetGPUDriverTestObj()
		err = api.DeleteGPUDriver(testObj, testutil.NewCudStreamoutGPUDriver(ctx))
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
	testObj, _ = dataGen.GetGPUDriverTestObj()
	err = api.DeleteGPUDriver(testObj, testutil.NewCudStreamoutGPUDriver(ctx))
	require.Nil(t, err, "cleanup must succeed")
}

// CloudletStoreTracker wraps around the usual
// store to track the STM used for gets/puts.
type CloudletStoreTracker struct {
	edgeproto.CloudletStore
	getSTM concurrency.STM
	putSTM concurrency.STM
}

// Wrap the Api's store with a tracker store.
// Returns the tracker store, and the unwrap function to defer.
func wrapCloudletTrackerStore(api *CloudletApi) (*CloudletStoreTracker, func()) {
	orig := api.store
	tracker := &CloudletStoreTracker{
		CloudletStore: api.store,
	}
	api.store = tracker
	unwrap := func() {
		api.store = orig
	}
	return tracker, unwrap
}

func (s *CloudletStoreTracker) STMGet(stm concurrency.STM, key *edgeproto.CloudletKey, buf *edgeproto.Cloudlet) bool {
	found := s.CloudletStore.STMGet(stm, key, buf)
	if s.getSTM == nil {
		s.getSTM = stm
	}
	return found
}

func (s *CloudletStoreTracker) STMPut(stm concurrency.STM, obj *edgeproto.Cloudlet, ops ...objstore.KVOp) {
	s.CloudletStore.STMPut(stm, obj, ops...)
	if s.putSTM == nil {
		s.putSTM = stm
	}
}

// Caller must write by hand the test data generator.
// Each Ref object should only have a single reference to the key,
// in order to properly test each reference (i.e. don't have a single
// object that has multiple references).
type CloudletDeleteDataGen interface {
	GetCloudletTestObj() (*edgeproto.Cloudlet, *testSupportData)
	GetAppInstKeyCloudletKeyRef(key *edgeproto.CloudletKey) (*edgeproto.AppInst, *testSupportData)
	GetAutoProvPolicyCloudletsRef(key *edgeproto.CloudletKey) (*edgeproto.AutoProvPolicy, *testSupportData)
	GetCloudletPoolCloudletsRef(key *edgeproto.CloudletKey) (*edgeproto.CloudletPool, *testSupportData)
	GetNetworkKeyCloudletKeyRef(key *edgeproto.CloudletKey) (*edgeproto.Network, *testSupportData)
	GetCloudletClusterInstClusterInstsRef(key *edgeproto.CloudletKey) (*edgeproto.CloudletRefs, *testSupportData)
}

// CloudletDeleteStore wraps around the usual
// store to instrument checks and inject data while
// the delete api code is running.
type CloudletDeleteStore struct {
	edgeproto.CloudletStore
	t                   *testing.T
	allApis             *AllApis
	putDeletePrepare    bool
	putDeletePrepareCb  func()
	putDeletePrepareSTM concurrency.STM
}

func (s *CloudletDeleteStore) Put(ctx context.Context, m *edgeproto.Cloudlet, wait func(int64), ops ...objstore.KVOp) (*edgeproto.Result, error) {
	if wait != nil {
		s.putDeletePrepare = m.DeletePrepare
	}
	res, err := s.CloudletStore.Put(ctx, m, wait, ops...)
	if s.putDeletePrepare && s.putDeletePrepareCb != nil {
		s.putDeletePrepareCb()
	}
	return res, err
}

func (s *CloudletDeleteStore) STMPut(stm concurrency.STM, obj *edgeproto.Cloudlet, ops ...objstore.KVOp) {
	// there's an assumption that this is run within an ApplySTMWait,
	// where we wait for the caches to be updated with the transaction.
	if obj.DeletePrepare {
		s.putDeletePrepare = true
		s.putDeletePrepareSTM = stm
	} else {
		s.putDeletePrepare = false
		s.putDeletePrepareSTM = nil
	}
	s.CloudletStore.STMPut(stm, obj, ops...)
	if s.putDeletePrepare && s.putDeletePrepareCb != nil {
		s.putDeletePrepareCb()
	}
}

func (s *CloudletDeleteStore) Delete(ctx context.Context, m *edgeproto.Cloudlet, wait func(int64)) (*edgeproto.Result, error) {
	require.True(s.t, s.putDeletePrepare, "DeletePrepare must be comitted to database with a sync.Wait before deleting")
	return s.CloudletStore.Delete(ctx, m, wait)
}

func (s *CloudletDeleteStore) STMDel(stm concurrency.STM, key *edgeproto.CloudletKey) {
	require.True(s.t, s.putDeletePrepare, "DeletePrepare must be comitted to database with a sync.Wait before deleting")
	s.CloudletStore.STMDel(stm, key)
}

func (s *CloudletDeleteStore) requireUndoDeletePrepare(ctx context.Context, obj *edgeproto.Cloudlet) {
	deletePrepare := s.getDeletePrepare(ctx, obj)
	require.False(s.t, deletePrepare, "must undo delete prepare field on failure")
}

func (s *CloudletDeleteStore) getDeletePrepare(ctx context.Context, obj *edgeproto.Cloudlet) bool {
	buf := edgeproto.Cloudlet{}
	found := s.Get(ctx, obj.GetKey(), &buf)
	require.True(s.t, found, "expected test object to be found")
	return buf.DeletePrepare
}

func deleteCloudletChecks(t *testing.T, ctx context.Context, all *AllApis, dataGen CloudletDeleteDataGen) {
	var err error
	// override store so we can inject data and check data
	api := all.cloudletApi
	origStore := api.store
	deleteStore := &CloudletDeleteStore{
		CloudletStore: origStore,
		t:             t,
		allApis:       all,
	}
	api.store = deleteStore
	cloudletRefsApiStore, cloudletRefsApiUnwrap := wrapCloudletRefsTrackerStore(all.cloudletRefsApi)
	defer func() {
		api.store = origStore
		cloudletRefsApiUnwrap()
	}()

	// inject testObj directly, bypassing create checks/deps
	testObj, supportData := dataGen.GetCloudletTestObj()
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
		require.NotNil(t, cloudletRefsApiStore.getSTM, "must check for refs from CloudletRefs in STM")
		require.Equal(t, deleteStore.putDeletePrepareSTM, cloudletRefsApiStore.getSTM, "delete prepare and ref check for CloudletRefs must be done in the same STM")
	}
	testObj, _ = dataGen.GetCloudletTestObj()
	err = api.DeleteCloudlet(testObj, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err, "delete must succeed with no refs")
	deleteStore.putDeletePrepareCb = nil

	// Negative test, inject testObj with delete prepare already set.
	testObj, _ = dataGen.GetCloudletTestObj()
	testObj.DeletePrepare = true
	origStore.Put(ctx, testObj, api.sync.syncWait)
	// delete should fail with already being deleted
	testObj, _ = dataGen.GetCloudletTestObj()
	err = api.DeleteCloudlet(testObj, testutil.NewCudStreamoutCloudlet(ctx))
	require.NotNil(t, err, "delete must fail if already being deleted")
	require.Equal(t, testObj.GetKey().BeingDeletedError().Error(), err.Error())
	// failed delete must not interfere with existing delete prepare state
	require.True(t, deleteStore.getDeletePrepare(ctx, testObj), "delete prepare must not be modified by failed delete")

	// inject testObj for ref tests
	testObj, _ = dataGen.GetCloudletTestObj()
	origStore.Put(ctx, testObj, api.sync.syncWait)

	{
		// Negative test, AppInst refers to Cloudlet.
		// The cb will inject refBy obj after delete prepare has been set.
		refBy, supportData := dataGen.GetAppInstKeyCloudletKeyRef(testObj.GetKey())
		supportData.put(t, ctx, all)
		deleteStore.putDeletePrepareCb = func() {
			all.appInstApi.store.Put(ctx, refBy, all.appInstApi.sync.syncWait)
		}
		testObj, _ = dataGen.GetCloudletTestObj()
		err = api.DeleteCloudlet(testObj, testutil.NewCudStreamoutCloudlet(ctx))
		require.NotNil(t, err, "must fail delete with ref from AppInst")
		require.Contains(t, err.Error(), "in use")
		// check that delete prepare was reset
		deleteStore.requireUndoDeletePrepare(ctx, testObj)
		// remove AppInst obj
		_, err = all.appInstApi.store.Delete(ctx, refBy, all.appInstApi.sync.syncWait)
		require.Nil(t, err, "cleanup ref from AppInst must succeed")
		deleteStore.putDeletePrepareCb = nil
		supportData.delete(t, ctx, all)
	}
	{
		// Negative test, AutoProvPolicy refers to Cloudlet.
		// The cb will inject refBy obj after delete prepare has been set.
		refBy, supportData := dataGen.GetAutoProvPolicyCloudletsRef(testObj.GetKey())
		supportData.put(t, ctx, all)
		deleteStore.putDeletePrepareCb = func() {
			all.autoProvPolicyApi.store.Put(ctx, refBy, all.autoProvPolicyApi.sync.syncWait)
		}
		testObj, _ = dataGen.GetCloudletTestObj()
		err = api.DeleteCloudlet(testObj, testutil.NewCudStreamoutCloudlet(ctx))
		require.NotNil(t, err, "must fail delete with ref from AutoProvPolicy")
		require.Contains(t, err.Error(), "in use")
		// check that delete prepare was reset
		deleteStore.requireUndoDeletePrepare(ctx, testObj)
		// remove AutoProvPolicy obj
		_, err = all.autoProvPolicyApi.store.Delete(ctx, refBy, all.autoProvPolicyApi.sync.syncWait)
		require.Nil(t, err, "cleanup ref from AutoProvPolicy must succeed")
		deleteStore.putDeletePrepareCb = nil
		supportData.delete(t, ctx, all)
	}
	{
		// Negative test, CloudletPool refers to Cloudlet.
		// The cb will inject refBy obj after delete prepare has been set.
		refBy, supportData := dataGen.GetCloudletPoolCloudletsRef(testObj.GetKey())
		supportData.put(t, ctx, all)
		deleteStore.putDeletePrepareCb = func() {
			all.cloudletPoolApi.store.Put(ctx, refBy, all.cloudletPoolApi.sync.syncWait)
		}
		testObj, _ = dataGen.GetCloudletTestObj()
		err = api.DeleteCloudlet(testObj, testutil.NewCudStreamoutCloudlet(ctx))
		require.NotNil(t, err, "must fail delete with ref from CloudletPool")
		require.Contains(t, err.Error(), "in use")
		// check that delete prepare was reset
		deleteStore.requireUndoDeletePrepare(ctx, testObj)
		// remove CloudletPool obj
		_, err = all.cloudletPoolApi.store.Delete(ctx, refBy, all.cloudletPoolApi.sync.syncWait)
		require.Nil(t, err, "cleanup ref from CloudletPool must succeed")
		deleteStore.putDeletePrepareCb = nil
		supportData.delete(t, ctx, all)
	}
	{
		// Negative test, Network refers to Cloudlet.
		// The cb will inject refBy obj after delete prepare has been set.
		refBy, supportData := dataGen.GetNetworkKeyCloudletKeyRef(testObj.GetKey())
		supportData.put(t, ctx, all)
		deleteStore.putDeletePrepareCb = func() {
			all.networkApi.store.Put(ctx, refBy, all.networkApi.sync.syncWait)
		}
		testObj, _ = dataGen.GetCloudletTestObj()
		err = api.DeleteCloudlet(testObj, testutil.NewCudStreamoutCloudlet(ctx))
		require.NotNil(t, err, "must fail delete with ref from Network")
		require.Contains(t, err.Error(), "in use")
		// check that delete prepare was reset
		deleteStore.requireUndoDeletePrepare(ctx, testObj)
		// remove Network obj
		_, err = all.networkApi.store.Delete(ctx, refBy, all.networkApi.sync.syncWait)
		require.Nil(t, err, "cleanup ref from Network must succeed")
		deleteStore.putDeletePrepareCb = nil
		supportData.delete(t, ctx, all)
	}
	{
		// Negative test, CloudletRefs refers to Cloudlet via refs object.
		// Inject the refs object to trigger an "in use" error.
		refBy, supportData := dataGen.GetCloudletClusterInstClusterInstsRef(testObj.GetKey())
		supportData.put(t, ctx, all)
		_, err = all.cloudletRefsApi.store.Put(ctx, refBy, all.cloudletRefsApi.sync.syncWait)
		require.Nil(t, err)
		testObj, _ = dataGen.GetCloudletTestObj()
		err = api.DeleteCloudlet(testObj, testutil.NewCudStreamoutCloudlet(ctx))
		require.NotNil(t, err, "delete with ref from CloudletRefs must fail")
		require.Contains(t, err.Error(), "in use")
		// check that delete prepare was reset
		deleteStore.requireUndoDeletePrepare(ctx, testObj)
		// remove CloudletRefs obj
		_, err = all.cloudletRefsApi.store.Delete(ctx, refBy, all.cloudletRefsApi.sync.syncWait)
		require.Nil(t, err, "cleanup ref from CloudletRefs must succeed")
		supportData.delete(t, ctx, all)
	}

	// clean up testObj
	testObj, _ = dataGen.GetCloudletTestObj()
	err = api.DeleteCloudlet(testObj, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err, "cleanup must succeed")
}

func CreateCloudletAddRefsChecks(t *testing.T, ctx context.Context, all *AllApis, dataGen AllAddRefsDataGen) {
	var err error

	testObj, supportData := dataGen.GetCreateCloudletTestObj()
	supportData.put(t, ctx, all)
	{
		// set delete_prepare on referenced Flavor
		ref := supportData.getOneFlavor()
		require.NotNil(t, ref, "support data must include one referenced Flavor")
		ref.DeletePrepare = true
		_, err = all.flavorApi.store.Put(ctx, ref, all.flavorApi.sync.syncWait)
		require.Nil(t, err)
		// api call must fail with object being deleted
		testObj, _ = dataGen.GetCreateCloudletTestObj()
		err = all.cloudletApi.CreateCloudlet(testObj, testutil.NewCudStreamoutCloudlet(ctx))
		require.NotNil(t, err, "CreateCloudlet must fail with Flavor.DeletePrepare set")
		require.Equal(t, ref.GetKey().BeingDeletedError().Error(), err.Error())
		// reset delete_prepare on referenced Flavor
		ref.DeletePrepare = false
		_, err = all.flavorApi.store.Put(ctx, ref, all.flavorApi.sync.syncWait)
		require.Nil(t, err)
	}
	{
		// set delete_prepare on referenced VMPool
		ref := supportData.getOneVMPool()
		require.NotNil(t, ref, "support data must include one referenced VMPool")
		ref.DeletePrepare = true
		_, err = all.vmPoolApi.store.Put(ctx, ref, all.vmPoolApi.sync.syncWait)
		require.Nil(t, err)
		// api call must fail with object being deleted
		testObj, _ = dataGen.GetCreateCloudletTestObj()
		err = all.cloudletApi.CreateCloudlet(testObj, testutil.NewCudStreamoutCloudlet(ctx))
		require.NotNil(t, err, "CreateCloudlet must fail with VMPool.DeletePrepare set")
		require.Equal(t, ref.GetKey().BeingDeletedError().Error(), err.Error())
		// reset delete_prepare on referenced VMPool
		ref.DeletePrepare = false
		_, err = all.vmPoolApi.store.Put(ctx, ref, all.vmPoolApi.sync.syncWait)
		require.Nil(t, err)
	}
	{
		// set delete_prepare on referenced TrustPolicy
		ref := supportData.getOneTrustPolicy()
		require.NotNil(t, ref, "support data must include one referenced TrustPolicy")
		ref.DeletePrepare = true
		_, err = all.trustPolicyApi.store.Put(ctx, ref, all.trustPolicyApi.sync.syncWait)
		require.Nil(t, err)
		// api call must fail with object being deleted
		testObj, _ = dataGen.GetCreateCloudletTestObj()
		err = all.cloudletApi.CreateCloudlet(testObj, testutil.NewCudStreamoutCloudlet(ctx))
		require.NotNil(t, err, "CreateCloudlet must fail with TrustPolicy.DeletePrepare set")
		require.Equal(t, ref.GetKey().BeingDeletedError().Error(), err.Error())
		// reset delete_prepare on referenced TrustPolicy
		ref.DeletePrepare = false
		_, err = all.trustPolicyApi.store.Put(ctx, ref, all.trustPolicyApi.sync.syncWait)
		require.Nil(t, err)
	}
	{
		// set delete_prepare on referenced GPUDriver
		ref := supportData.getOneGPUDriver()
		require.NotNil(t, ref, "support data must include one referenced GPUDriver")
		ref.DeletePrepare = true
		_, err = all.gpuDriverApi.store.Put(ctx, ref, all.gpuDriverApi.sync.syncWait)
		require.Nil(t, err)
		// api call must fail with object being deleted
		testObj, _ = dataGen.GetCreateCloudletTestObj()
		err = all.cloudletApi.CreateCloudlet(testObj, testutil.NewCudStreamoutCloudlet(ctx))
		require.NotNil(t, err, "CreateCloudlet must fail with GPUDriver.DeletePrepare set")
		require.Equal(t, ref.GetKey().BeingDeletedError().Error(), err.Error())
		// reset delete_prepare on referenced GPUDriver
		ref.DeletePrepare = false
		_, err = all.gpuDriverApi.store.Put(ctx, ref, all.gpuDriverApi.sync.syncWait)
		require.Nil(t, err)
	}

	// wrap the stores so we can make sure all checks and changes
	// happen in the same STM.
	cloudletApiStore, cloudletApiUnwrap := wrapCloudletTrackerStore(all.cloudletApi)
	defer cloudletApiUnwrap()
	flavorApiStore, flavorApiUnwrap := wrapFlavorTrackerStore(all.flavorApi)
	defer flavorApiUnwrap()
	vmPoolApiStore, vmPoolApiUnwrap := wrapVMPoolTrackerStore(all.vmPoolApi)
	defer vmPoolApiUnwrap()
	trustPolicyApiStore, trustPolicyApiUnwrap := wrapTrustPolicyTrackerStore(all.trustPolicyApi)
	defer trustPolicyApiUnwrap()
	gpuDriverApiStore, gpuDriverApiUnwrap := wrapGPUDriverTrackerStore(all.gpuDriverApi)
	defer gpuDriverApiUnwrap()

	// CreateCloudlet should succeed if no references are in delete_prepare
	testObj, _ = dataGen.GetCreateCloudletTestObj()
	err = all.cloudletApi.CreateCloudlet(testObj, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err, "CreateCloudlet should succeed if no references are in delete prepare")
	// make sure everything ran in the same STM
	require.NotNil(t, cloudletApiStore.putSTM, "CreateCloudlet put Cloudlet must be done in STM")
	require.NotNil(t, flavorApiStore.getSTM, "CreateCloudlet check Flavor ref must be done in STM")
	require.Equal(t, cloudletApiStore.putSTM, flavorApiStore.getSTM, "CreateCloudlet check Flavor ref must be done in same STM as Cloudlet put")
	require.NotNil(t, vmPoolApiStore.getSTM, "CreateCloudlet check VMPool ref must be done in STM")
	require.Equal(t, cloudletApiStore.putSTM, vmPoolApiStore.getSTM, "CreateCloudlet check VMPool ref must be done in same STM as Cloudlet put")
	require.NotNil(t, trustPolicyApiStore.getSTM, "CreateCloudlet check TrustPolicy ref must be done in STM")
	require.Equal(t, cloudletApiStore.putSTM, trustPolicyApiStore.getSTM, "CreateCloudlet check TrustPolicy ref must be done in same STM as Cloudlet put")
	require.NotNil(t, gpuDriverApiStore.getSTM, "CreateCloudlet check GPUDriver ref must be done in STM")
	require.Equal(t, cloudletApiStore.putSTM, gpuDriverApiStore.getSTM, "CreateCloudlet check GPUDriver ref must be done in same STM as Cloudlet put")

	// clean up
	// delete created test obj
	testObj, _ = dataGen.GetCreateCloudletTestObj()
	err = all.cloudletApi.DeleteCloudlet(testObj, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err)
	supportData.delete(t, ctx, all)
}

func UpdateCloudletAddRefsChecks(t *testing.T, ctx context.Context, all *AllApis, dataGen AllAddRefsDataGen) {
	var err error

	testObj, supportData := dataGen.GetUpdateCloudletTestObj()
	supportData.put(t, ctx, all)
	{
		// set delete_prepare on referenced TrustPolicy
		ref := supportData.getOneTrustPolicy()
		require.NotNil(t, ref, "support data must include one referenced TrustPolicy")
		ref.DeletePrepare = true
		_, err = all.trustPolicyApi.store.Put(ctx, ref, all.trustPolicyApi.sync.syncWait)
		require.Nil(t, err)
		// api call must fail with object being deleted
		testObj, _ = dataGen.GetUpdateCloudletTestObj()
		err = all.cloudletApi.UpdateCloudlet(testObj, testutil.NewCudStreamoutCloudlet(ctx))
		require.NotNil(t, err, "UpdateCloudlet must fail with TrustPolicy.DeletePrepare set")
		require.Equal(t, ref.GetKey().BeingDeletedError().Error(), err.Error())
		// reset delete_prepare on referenced TrustPolicy
		ref.DeletePrepare = false
		_, err = all.trustPolicyApi.store.Put(ctx, ref, all.trustPolicyApi.sync.syncWait)
		require.Nil(t, err)
	}
	{
		// set delete_prepare on referenced GPUDriver
		ref := supportData.getOneGPUDriver()
		require.NotNil(t, ref, "support data must include one referenced GPUDriver")
		ref.DeletePrepare = true
		_, err = all.gpuDriverApi.store.Put(ctx, ref, all.gpuDriverApi.sync.syncWait)
		require.Nil(t, err)
		// api call must fail with object being deleted
		testObj, _ = dataGen.GetUpdateCloudletTestObj()
		err = all.cloudletApi.UpdateCloudlet(testObj, testutil.NewCudStreamoutCloudlet(ctx))
		require.NotNil(t, err, "UpdateCloudlet must fail with GPUDriver.DeletePrepare set")
		require.Equal(t, ref.GetKey().BeingDeletedError().Error(), err.Error())
		// reset delete_prepare on referenced GPUDriver
		ref.DeletePrepare = false
		_, err = all.gpuDriverApi.store.Put(ctx, ref, all.gpuDriverApi.sync.syncWait)
		require.Nil(t, err)
	}

	// wrap the stores so we can make sure all checks and changes
	// happen in the same STM.
	cloudletApiStore, cloudletApiUnwrap := wrapCloudletTrackerStore(all.cloudletApi)
	defer cloudletApiUnwrap()
	trustPolicyApiStore, trustPolicyApiUnwrap := wrapTrustPolicyTrackerStore(all.trustPolicyApi)
	defer trustPolicyApiUnwrap()
	gpuDriverApiStore, gpuDriverApiUnwrap := wrapGPUDriverTrackerStore(all.gpuDriverApi)
	defer gpuDriverApiUnwrap()

	// UpdateCloudlet should succeed if no references are in delete_prepare
	testObj, _ = dataGen.GetUpdateCloudletTestObj()
	err = all.cloudletApi.UpdateCloudlet(testObj, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err, "UpdateCloudlet should succeed if no references are in delete prepare")
	// make sure everything ran in the same STM
	require.NotNil(t, cloudletApiStore.putSTM, "UpdateCloudlet put Cloudlet must be done in STM")
	require.NotNil(t, trustPolicyApiStore.getSTM, "UpdateCloudlet check TrustPolicy ref must be done in STM")
	require.Equal(t, cloudletApiStore.putSTM, trustPolicyApiStore.getSTM, "UpdateCloudlet check TrustPolicy ref must be done in same STM as Cloudlet put")
	require.NotNil(t, gpuDriverApiStore.getSTM, "UpdateCloudlet check GPUDriver ref must be done in STM")
	require.Equal(t, cloudletApiStore.putSTM, gpuDriverApiStore.getSTM, "UpdateCloudlet check GPUDriver ref must be done in same STM as Cloudlet put")

	// clean up
	supportData.delete(t, ctx, all)
}

func AddCloudletResMappingAddRefsChecks(t *testing.T, ctx context.Context, all *AllApis, dataGen AllAddRefsDataGen) {
	var err error

	testObj, supportData := dataGen.GetAddCloudletResMappingTestObj()
	supportData.put(t, ctx, all)
	{
		// set delete_prepare on referenced ResTagTable
		ref := supportData.getOneResTagTable()
		require.NotNil(t, ref, "support data must include one referenced ResTagTable")
		ref.DeletePrepare = true
		_, err = all.resTagTableApi.store.Put(ctx, ref, all.resTagTableApi.sync.syncWait)
		require.Nil(t, err)
		// api call must fail with object being deleted
		testObj, _ = dataGen.GetAddCloudletResMappingTestObj()
		_, err = all.cloudletApi.AddCloudletResMapping(ctx, testObj)
		require.NotNil(t, err, "AddCloudletResMapping must fail with ResTagTable.DeletePrepare set")
		require.Equal(t, ref.GetKey().BeingDeletedError().Error(), err.Error())
		// reset delete_prepare on referenced ResTagTable
		ref.DeletePrepare = false
		_, err = all.resTagTableApi.store.Put(ctx, ref, all.resTagTableApi.sync.syncWait)
		require.Nil(t, err)
	}

	// wrap the stores so we can make sure all checks and changes
	// happen in the same STM.
	cloudletApiStore, cloudletApiUnwrap := wrapCloudletTrackerStore(all.cloudletApi)
	defer cloudletApiUnwrap()
	resTagTableApiStore, resTagTableApiUnwrap := wrapResTagTableTrackerStore(all.resTagTableApi)
	defer resTagTableApiUnwrap()

	// AddCloudletResMapping should succeed if no references are in delete_prepare
	testObj, _ = dataGen.GetAddCloudletResMappingTestObj()
	_, err = all.cloudletApi.AddCloudletResMapping(ctx, testObj)
	require.Nil(t, err, "AddCloudletResMapping should succeed if no references are in delete prepare")
	// make sure everything ran in the same STM
	require.NotNil(t, cloudletApiStore.putSTM, "AddCloudletResMapping put Cloudlet must be done in STM")
	require.NotNil(t, resTagTableApiStore.getSTM, "AddCloudletResMapping check ResTagTable ref must be done in STM")
	require.Equal(t, cloudletApiStore.putSTM, resTagTableApiStore.getSTM, "AddCloudletResMapping check ResTagTable ref must be done in same STM as Cloudlet put")

	// clean up
	supportData.delete(t, ctx, all)
}
