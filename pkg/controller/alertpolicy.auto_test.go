// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: alertpolicy.proto

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

type AllDeleteDataGen interface {
	AlertPolicyDeleteDataGen
	AppDeleteDataGen
	AutoProvPolicyDeleteDataGen
	AutoScalePolicyDeleteDataGen
	CloudletDeleteDataGen
	CloudletPoolDeleteDataGen
	ClusterInstDeleteDataGen
	FlavorDeleteDataGen
	GPUDriverDeleteDataGen
	NetworkDeleteDataGen
	PlatformFeaturesDeleteDataGen
	ResTagTableDeleteDataGen
	TrustPolicyDeleteDataGen
	VMPoolDeleteDataGen
}

func allDeleteChecks(t *testing.T, ctx context.Context, all *AllApis, dataGen AllDeleteDataGen) {
	deleteAlertPolicyChecks(t, ctx, all, dataGen)
	deleteAppChecks(t, ctx, all, dataGen)
	deleteAutoProvPolicyChecks(t, ctx, all, dataGen)
	deleteAutoScalePolicyChecks(t, ctx, all, dataGen)
	deleteCloudletChecks(t, ctx, all, dataGen)
	deleteCloudletPoolChecks(t, ctx, all, dataGen)
	deleteClusterInstChecks(t, ctx, all, dataGen)
	deleteFlavorChecks(t, ctx, all, dataGen)
	deleteGPUDriverChecks(t, ctx, all, dataGen)
	deleteNetworkChecks(t, ctx, all, dataGen)
	deletePlatformFeaturesChecks(t, ctx, all, dataGen)
	deleteResTagTableChecks(t, ctx, all, dataGen)
	deleteTrustPolicyChecks(t, ctx, all, dataGen)
	deleteVMPoolChecks(t, ctx, all, dataGen)
}

type AllAddRefsDataGen interface {
	GetAddAppAlertPolicyTestObj() (*edgeproto.AppAlertPolicy, *testSupportData)
	GetAddAppAutoProvPolicyTestObj() (*edgeproto.AppAutoProvPolicy, *testSupportData)
	GetAddAutoProvPolicyCloudletTestObj() (*edgeproto.AutoProvPolicyCloudlet, *testSupportData)
	GetAddCloudletPoolMemberTestObj() (*edgeproto.CloudletPoolMember, *testSupportData)
	GetAddCloudletResMappingTestObj() (*edgeproto.CloudletResMap, *testSupportData)
	GetCreateAppTestObj() (*edgeproto.App, *testSupportData)
	GetCreateAppInstTestObj() (*edgeproto.AppInst, *testSupportData)
	GetCreateAutoProvPolicyTestObj() (*edgeproto.AutoProvPolicy, *testSupportData)
	GetCreateCloudletTestObj() (*edgeproto.Cloudlet, *testSupportData)
	GetCreateCloudletPoolTestObj() (*edgeproto.CloudletPool, *testSupportData)
	GetCreateClusterInstTestObj() (*edgeproto.ClusterInst, *testSupportData)
	GetCreateNetworkTestObj() (*edgeproto.Network, *testSupportData)
	GetCreateTrustPolicyExceptionTestObj() (*edgeproto.TrustPolicyException, *testSupportData)
	GetUpdateAppTestObj() (*edgeproto.App, *testSupportData)
	GetUpdateAutoProvPolicyTestObj() (*edgeproto.AutoProvPolicy, *testSupportData)
	GetUpdateCloudletTestObj() (*edgeproto.Cloudlet, *testSupportData)
	GetUpdateCloudletPoolTestObj() (*edgeproto.CloudletPool, *testSupportData)
	GetUpdateClusterInstTestObj() (*edgeproto.ClusterInst, *testSupportData)
}

func allAddRefsChecks(t *testing.T, ctx context.Context, all *AllApis, dataGen AllAddRefsDataGen) {
	AddAppAlertPolicyAddRefsChecks(t, ctx, all, dataGen)
	AddAppAutoProvPolicyAddRefsChecks(t, ctx, all, dataGen)
	AddAutoProvPolicyCloudletAddRefsChecks(t, ctx, all, dataGen)
	AddCloudletPoolMemberAddRefsChecks(t, ctx, all, dataGen)
	AddCloudletResMappingAddRefsChecks(t, ctx, all, dataGen)
	CreateAppAddRefsChecks(t, ctx, all, dataGen)
	CreateAppInstAddRefsChecks(t, ctx, all, dataGen)
	CreateAutoProvPolicyAddRefsChecks(t, ctx, all, dataGen)
	CreateCloudletAddRefsChecks(t, ctx, all, dataGen)
	CreateCloudletPoolAddRefsChecks(t, ctx, all, dataGen)
	CreateClusterInstAddRefsChecks(t, ctx, all, dataGen)
	CreateNetworkAddRefsChecks(t, ctx, all, dataGen)
	CreateTrustPolicyExceptionAddRefsChecks(t, ctx, all, dataGen)
	UpdateAppAddRefsChecks(t, ctx, all, dataGen)
	UpdateAutoProvPolicyAddRefsChecks(t, ctx, all, dataGen)
	UpdateCloudletAddRefsChecks(t, ctx, all, dataGen)
	UpdateCloudletPoolAddRefsChecks(t, ctx, all, dataGen)
	UpdateClusterInstAddRefsChecks(t, ctx, all, dataGen)
}

// AlertPolicyStoreTracker wraps around the usual
// store to track the STM used for gets/puts.
type AlertPolicyStoreTracker struct {
	edgeproto.AlertPolicyStore
	getSTM concurrency.STM
	putSTM concurrency.STM
}

// Wrap the Api's store with a tracker store.
// Returns the tracker store, and the unwrap function to defer.
func wrapAlertPolicyTrackerStore(api *AlertPolicyApi) (*AlertPolicyStoreTracker, func()) {
	orig := api.store
	tracker := &AlertPolicyStoreTracker{
		AlertPolicyStore: api.store,
	}
	api.store = tracker
	unwrap := func() {
		api.store = orig
	}
	return tracker, unwrap
}

func (s *AlertPolicyStoreTracker) STMGet(stm concurrency.STM, key *edgeproto.AlertPolicyKey, buf *edgeproto.AlertPolicy) bool {
	found := s.AlertPolicyStore.STMGet(stm, key, buf)
	if s.getSTM == nil {
		s.getSTM = stm
	}
	return found
}

func (s *AlertPolicyStoreTracker) STMPut(stm concurrency.STM, obj *edgeproto.AlertPolicy, ops ...objstore.KVOp) {
	s.AlertPolicyStore.STMPut(stm, obj, ops...)
	if s.putSTM == nil {
		s.putSTM = stm
	}
}

// Caller must write by hand the test data generator.
// Each Ref object should only have a single reference to the key,
// in order to properly test each reference (i.e. don't have a single
// object that has multiple references).
type AlertPolicyDeleteDataGen interface {
	GetAlertPolicyTestObj() (*edgeproto.AlertPolicy, *testSupportData)
	GetAppAlertPoliciesRef(key *edgeproto.AlertPolicyKey) (*edgeproto.App, *testSupportData)
}

// AlertPolicyDeleteStore wraps around the usual
// store to instrument checks and inject data while
// the delete api code is running.
type AlertPolicyDeleteStore struct {
	edgeproto.AlertPolicyStore
	t                   *testing.T
	allApis             *AllApis
	putDeletePrepare    bool
	putDeletePrepareCb  func()
	putDeletePrepareSTM concurrency.STM
}

func (s *AlertPolicyDeleteStore) Put(ctx context.Context, m *edgeproto.AlertPolicy, wait func(int64), ops ...objstore.KVOp) (*edgeproto.Result, error) {
	if wait != nil {
		s.putDeletePrepare = m.DeletePrepare
	}
	res, err := s.AlertPolicyStore.Put(ctx, m, wait, ops...)
	if s.putDeletePrepare && s.putDeletePrepareCb != nil {
		s.putDeletePrepareCb()
	}
	return res, err
}

func (s *AlertPolicyDeleteStore) STMPut(stm concurrency.STM, obj *edgeproto.AlertPolicy, ops ...objstore.KVOp) {
	// there's an assumption that this is run within an ApplySTMWait,
	// where we wait for the caches to be updated with the transaction.
	if obj.DeletePrepare {
		s.putDeletePrepare = true
		s.putDeletePrepareSTM = stm
	} else {
		s.putDeletePrepare = false
		s.putDeletePrepareSTM = nil
	}
	s.AlertPolicyStore.STMPut(stm, obj, ops...)
	if s.putDeletePrepare && s.putDeletePrepareCb != nil {
		s.putDeletePrepareCb()
	}
}

func (s *AlertPolicyDeleteStore) Delete(ctx context.Context, m *edgeproto.AlertPolicy, wait func(int64)) (*edgeproto.Result, error) {
	require.True(s.t, s.putDeletePrepare, "DeletePrepare must be comitted to database with a sync.Wait before deleting")
	return s.AlertPolicyStore.Delete(ctx, m, wait)
}

func (s *AlertPolicyDeleteStore) STMDel(stm concurrency.STM, key *edgeproto.AlertPolicyKey) {
	require.True(s.t, s.putDeletePrepare, "DeletePrepare must be comitted to database with a sync.Wait before deleting")
	s.AlertPolicyStore.STMDel(stm, key)
}

func (s *AlertPolicyDeleteStore) requireUndoDeletePrepare(ctx context.Context, obj *edgeproto.AlertPolicy) {
	deletePrepare := s.getDeletePrepare(ctx, obj)
	require.False(s.t, deletePrepare, "must undo delete prepare field on failure")
}

func (s *AlertPolicyDeleteStore) getDeletePrepare(ctx context.Context, obj *edgeproto.AlertPolicy) bool {
	buf := edgeproto.AlertPolicy{}
	found := s.Get(ctx, obj.GetKey(), &buf)
	require.True(s.t, found, "expected test object to be found")
	return buf.DeletePrepare
}

func deleteAlertPolicyChecks(t *testing.T, ctx context.Context, all *AllApis, dataGen AlertPolicyDeleteDataGen) {
	var err error
	// override store so we can inject data and check data
	api := all.alertPolicyApi
	origStore := api.store
	deleteStore := &AlertPolicyDeleteStore{
		AlertPolicyStore: origStore,
		t:                t,
		allApis:          all,
	}
	api.store = deleteStore
	defer func() {
		api.store = origStore
	}()

	// inject testObj directly, bypassing create checks/deps
	testObj, supportData := dataGen.GetAlertPolicyTestObj()
	supportData.put(t, ctx, all)
	defer supportData.delete(t, ctx, all)
	origStore.Put(ctx, testObj, api.sync.syncWait)

	// Positive test, delete should succeed without any references.
	// The overrided store checks that delete prepare was set on the
	// object in the database before actually doing the delete.
	testObj, _ = dataGen.GetAlertPolicyTestObj()
	_, err = api.DeleteAlertPolicy(ctx, testObj)
	require.Nil(t, err, "delete must succeed with no refs")

	// Negative test, inject testObj with delete prepare already set.
	testObj, _ = dataGen.GetAlertPolicyTestObj()
	testObj.DeletePrepare = true
	origStore.Put(ctx, testObj, api.sync.syncWait)
	// delete should fail with already being deleted
	testObj, _ = dataGen.GetAlertPolicyTestObj()
	_, err = api.DeleteAlertPolicy(ctx, testObj)
	require.NotNil(t, err, "delete must fail if already being deleted")
	require.Equal(t, testObj.GetKey().BeingDeletedError().Error(), err.Error())
	// failed delete must not interfere with existing delete prepare state
	require.True(t, deleteStore.getDeletePrepare(ctx, testObj), "delete prepare must not be modified by failed delete")

	// inject testObj for ref tests
	testObj, _ = dataGen.GetAlertPolicyTestObj()
	origStore.Put(ctx, testObj, api.sync.syncWait)

	{
		// Negative test, App refers to AlertPolicy.
		// The cb will inject refBy obj after delete prepare has been set.
		refBy, supportData := dataGen.GetAppAlertPoliciesRef(testObj.GetKey())
		supportData.put(t, ctx, all)
		deleteStore.putDeletePrepareCb = func() {
			all.appApi.store.Put(ctx, refBy, all.appApi.sync.syncWait)
		}
		testObj, _ = dataGen.GetAlertPolicyTestObj()
		_, err = api.DeleteAlertPolicy(ctx, testObj)
		require.NotNil(t, err, "must fail delete with ref from App")
		require.Contains(t, err.Error(), "in use")
		// check that delete prepare was reset
		deleteStore.requireUndoDeletePrepare(ctx, testObj)
		// remove App obj
		_, err = all.appApi.store.Delete(ctx, refBy, all.appApi.sync.syncWait)
		require.Nil(t, err, "cleanup ref from App must succeed")
		deleteStore.putDeletePrepareCb = nil
		supportData.delete(t, ctx, all)
	}

	// clean up testObj
	testObj, _ = dataGen.GetAlertPolicyTestObj()
	_, err = api.DeleteAlertPolicy(ctx, testObj)
	require.Nil(t, err, "cleanup must succeed")
}
