// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: trustpolicyexception.proto

package controller

import (
	"context"
	fmt "fmt"
	_ "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
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

// TrustPolicyExceptionStoreTracker wraps around the usual
// store to track the STM used for gets/puts.
type TrustPolicyExceptionStoreTracker struct {
	edgeproto.TrustPolicyExceptionStore
	getSTM concurrency.STM
	putSTM concurrency.STM
}

// Wrap the Api's store with a tracker store.
// Returns the tracker store, and the unwrap function to defer.
func wrapTrustPolicyExceptionTrackerStore(api *TrustPolicyExceptionApi) (*TrustPolicyExceptionStoreTracker, func()) {
	orig := api.store
	tracker := &TrustPolicyExceptionStoreTracker{
		TrustPolicyExceptionStore: api.store,
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

func (s *TrustPolicyExceptionStoreTracker) STMGet(stm concurrency.STM, key *edgeproto.TrustPolicyExceptionKey, buf *edgeproto.TrustPolicyException) bool {
	found := s.TrustPolicyExceptionStore.STMGet(stm, key, buf)
	if s.getSTM == nil {
		s.getSTM = stm
	}
	return found
}

func (s *TrustPolicyExceptionStoreTracker) STMPut(stm concurrency.STM, obj *edgeproto.TrustPolicyException, ops ...objstore.KVOp) {
	s.TrustPolicyExceptionStore.STMPut(stm, obj, ops...)
	if s.putSTM == nil {
		s.putSTM = stm
	}
}

func CreateTrustPolicyExceptionAddRefsChecks(t *testing.T, ctx context.Context, all *AllApis, dataGen AllAddRefsDataGen) {
	var err error

	testObj, supportData := dataGen.GetCreateTrustPolicyExceptionTestObj()
	supportData.put(t, ctx, all)
	{
		// set delete_prepare on referenced App
		ref := supportData.getOneApp()
		require.NotNil(t, ref, "support data must include one referenced App")
		ref.DeletePrepare = true
		_, err = all.appApi.store.Put(ctx, ref, all.appApi.sync.SyncWait)
		require.Nil(t, err)
		// api call must fail with object being deleted
		testObj, _ = dataGen.GetCreateTrustPolicyExceptionTestObj()
		_, err = all.trustPolicyExceptionApi.CreateTrustPolicyException(ctx, testObj)
		require.NotNil(t, err, "CreateTrustPolicyException must fail with App.DeletePrepare set")
		require.Equal(t, ref.GetKey().BeingDeletedError().Error(), err.Error())
		// reset delete_prepare on referenced App
		ref.DeletePrepare = false
		_, err = all.appApi.store.Put(ctx, ref, all.appApi.sync.SyncWait)
		require.Nil(t, err)
	}
	{
		// set delete_prepare on referenced ZonePool
		ref := supportData.getOneZonePool()
		require.NotNil(t, ref, "support data must include one referenced ZonePool")
		ref.DeletePrepare = true
		_, err = all.zonePoolApi.store.Put(ctx, ref, all.zonePoolApi.sync.SyncWait)
		require.Nil(t, err)
		// api call must fail with object being deleted
		testObj, _ = dataGen.GetCreateTrustPolicyExceptionTestObj()
		_, err = all.trustPolicyExceptionApi.CreateTrustPolicyException(ctx, testObj)
		require.NotNil(t, err, "CreateTrustPolicyException must fail with ZonePool.DeletePrepare set")
		require.Equal(t, ref.GetKey().BeingDeletedError().Error(), err.Error())
		// reset delete_prepare on referenced ZonePool
		ref.DeletePrepare = false
		_, err = all.zonePoolApi.store.Put(ctx, ref, all.zonePoolApi.sync.SyncWait)
		require.Nil(t, err)
	}

	// wrap the stores so we can make sure all checks and changes
	// happen in the same STM.
	trustPolicyExceptionApiStore, trustPolicyExceptionApiUnwrap := wrapTrustPolicyExceptionTrackerStore(all.trustPolicyExceptionApi)
	defer trustPolicyExceptionApiUnwrap()
	appApiStore, appApiUnwrap := wrapAppTrackerStore(all.appApi)
	defer appApiUnwrap()
	zonePoolApiStore, zonePoolApiUnwrap := wrapZonePoolTrackerStore(all.zonePoolApi)
	defer zonePoolApiUnwrap()

	// CreateTrustPolicyException should succeed if no references are in delete_prepare
	testObj, _ = dataGen.GetCreateTrustPolicyExceptionTestObj()
	_, err = all.trustPolicyExceptionApi.CreateTrustPolicyException(ctx, testObj)
	require.Nil(t, err, "CreateTrustPolicyException should succeed if no references are in delete prepare")
	// make sure everything ran in the same STM
	require.NotNil(t, trustPolicyExceptionApiStore.putSTM, "CreateTrustPolicyException put TrustPolicyException must be done in STM")
	require.NotNil(t, appApiStore.getSTM, "CreateTrustPolicyException check App ref must be done in STM")
	require.Equal(t, trustPolicyExceptionApiStore.putSTM, appApiStore.getSTM, "CreateTrustPolicyException check App ref must be done in same STM as TrustPolicyException put")
	require.NotNil(t, zonePoolApiStore.getSTM, "CreateTrustPolicyException check ZonePool ref must be done in STM")
	require.Equal(t, trustPolicyExceptionApiStore.putSTM, zonePoolApiStore.getSTM, "CreateTrustPolicyException check ZonePool ref must be done in same STM as TrustPolicyException put")

	// clean up
	// delete created test obj
	testObj, _ = dataGen.GetCreateTrustPolicyExceptionTestObj()
	_, err = all.trustPolicyExceptionApi.DeleteTrustPolicyException(ctx, testObj)
	require.Nil(t, err)
	supportData.delete(t, ctx, all)
}
