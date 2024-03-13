// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: appinst.proto

package controller

import (
	"context"
	fmt "fmt"
	_ "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
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

// AppInstStoreTracker wraps around the usual
// store to track the STM used for gets/puts.
type AppInstStoreTracker struct {
	edgeproto.AppInstStore
	getSTM concurrency.STM
	putSTM concurrency.STM
}

// Wrap the Api's store with a tracker store.
// Returns the tracker store, and the unwrap function to defer.
func wrapAppInstTrackerStore(api *AppInstApi) (*AppInstStoreTracker, func()) {
	orig := api.store
	tracker := &AppInstStoreTracker{
		AppInstStore: api.store,
	}
	api.store = tracker
	unwrap := func() {
		api.store = orig
	}
	return tracker, unwrap
}

func (s *AppInstStoreTracker) STMGet(stm concurrency.STM, key *edgeproto.AppInstKey, buf *edgeproto.AppInst) bool {
	found := s.AppInstStore.STMGet(stm, key, buf)
	if s.getSTM == nil {
		s.getSTM = stm
	}
	return found
}

func (s *AppInstStoreTracker) STMPut(stm concurrency.STM, obj *edgeproto.AppInst, ops ...objstore.KVOp) {
	s.AppInstStore.STMPut(stm, obj, ops...)
	if s.putSTM == nil {
		s.putSTM = stm
	}
}

func CreateAppInstAddRefsChecks(t *testing.T, ctx context.Context, all *AllApis, dataGen AllAddRefsDataGen) {
	var err error

	testObj, supportData := dataGen.GetCreateAppInstTestObj()
	supportData.put(t, ctx, all)
	{
		// set delete_prepare on referenced Cloudlet
		ref := supportData.getOneCloudlet()
		require.NotNil(t, ref, "support data must include one referenced Cloudlet")
		ref.DeletePrepare = true
		_, err = all.cloudletApi.store.Put(ctx, ref, all.cloudletApi.sync.syncWait)
		require.Nil(t, err)
		// api call must fail with object being deleted
		testObj, _ = dataGen.GetCreateAppInstTestObj()
		err = all.appInstApi.CreateAppInst(testObj, testutil.NewCudStreamoutAppInst(ctx))
		require.NotNil(t, err, "CreateAppInst must fail with Cloudlet.DeletePrepare set")
		require.Equal(t, ref.GetKey().BeingDeletedError().Error(), err.Error())
		// reset delete_prepare on referenced Cloudlet
		ref.DeletePrepare = false
		_, err = all.cloudletApi.store.Put(ctx, ref, all.cloudletApi.sync.syncWait)
		require.Nil(t, err)
	}
	{
		// set delete_prepare on referenced App
		ref := supportData.getOneApp()
		require.NotNil(t, ref, "support data must include one referenced App")
		ref.DeletePrepare = true
		_, err = all.appApi.store.Put(ctx, ref, all.appApi.sync.syncWait)
		require.Nil(t, err)
		// api call must fail with object being deleted
		testObj, _ = dataGen.GetCreateAppInstTestObj()
		err = all.appInstApi.CreateAppInst(testObj, testutil.NewCudStreamoutAppInst(ctx))
		require.NotNil(t, err, "CreateAppInst must fail with App.DeletePrepare set")
		require.Equal(t, ref.GetKey().BeingDeletedError().Error(), err.Error())
		// reset delete_prepare on referenced App
		ref.DeletePrepare = false
		_, err = all.appApi.store.Put(ctx, ref, all.appApi.sync.syncWait)
		require.Nil(t, err)
	}
	{
		// set delete_prepare on referenced ClusterInst
		ref := supportData.getOneClusterInst()
		require.NotNil(t, ref, "support data must include one referenced ClusterInst")
		ref.DeletePrepare = true
		_, err = all.clusterInstApi.store.Put(ctx, ref, all.clusterInstApi.sync.syncWait)
		require.Nil(t, err)
		// api call must fail with object being deleted
		testObj, _ = dataGen.GetCreateAppInstTestObj()
		err = all.appInstApi.CreateAppInst(testObj, testutil.NewCudStreamoutAppInst(ctx))
		require.NotNil(t, err, "CreateAppInst must fail with ClusterInst.DeletePrepare set")
		require.Equal(t, ref.GetKey().BeingDeletedError().Error(), err.Error())
		// reset delete_prepare on referenced ClusterInst
		ref.DeletePrepare = false
		_, err = all.clusterInstApi.store.Put(ctx, ref, all.clusterInstApi.sync.syncWait)
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
		testObj, _ = dataGen.GetCreateAppInstTestObj()
		err = all.appInstApi.CreateAppInst(testObj, testutil.NewCudStreamoutAppInst(ctx))
		require.NotNil(t, err, "CreateAppInst must fail with Flavor.DeletePrepare set")
		require.Equal(t, ref.GetKey().BeingDeletedError().Error(), err.Error())
		// reset delete_prepare on referenced Flavor
		ref.DeletePrepare = false
		_, err = all.flavorApi.store.Put(ctx, ref, all.flavorApi.sync.syncWait)
		require.Nil(t, err)
	}

	// wrap the stores so we can make sure all checks and changes
	// happen in the same STM.
	appInstApiStore, appInstApiUnwrap := wrapAppInstTrackerStore(all.appInstApi)
	defer appInstApiUnwrap()
	cloudletApiStore, cloudletApiUnwrap := wrapCloudletTrackerStore(all.cloudletApi)
	defer cloudletApiUnwrap()
	appApiStore, appApiUnwrap := wrapAppTrackerStore(all.appApi)
	defer appApiUnwrap()
	clusterInstApiStore, clusterInstApiUnwrap := wrapClusterInstTrackerStore(all.clusterInstApi)
	defer clusterInstApiUnwrap()
	flavorApiStore, flavorApiUnwrap := wrapFlavorTrackerStore(all.flavorApi)
	defer flavorApiUnwrap()

	// CreateAppInst should succeed if no references are in delete_prepare
	testObj, _ = dataGen.GetCreateAppInstTestObj()
	err = all.appInstApi.CreateAppInst(testObj, testutil.NewCudStreamoutAppInst(ctx))
	require.Nil(t, err, "CreateAppInst should succeed if no references are in delete prepare")
	// make sure everything ran in the same STM
	require.NotNil(t, appInstApiStore.putSTM, "CreateAppInst put AppInst must be done in STM")
	require.NotNil(t, cloudletApiStore.getSTM, "CreateAppInst check Cloudlet ref must be done in STM")
	require.Equal(t, appInstApiStore.putSTM, cloudletApiStore.getSTM, "CreateAppInst check Cloudlet ref must be done in same STM as AppInst put")
	require.NotNil(t, appApiStore.getSTM, "CreateAppInst check App ref must be done in STM")
	require.Equal(t, appInstApiStore.putSTM, appApiStore.getSTM, "CreateAppInst check App ref must be done in same STM as AppInst put")
	require.NotNil(t, clusterInstApiStore.getSTM, "CreateAppInst check ClusterInst ref must be done in STM")
	require.Equal(t, appInstApiStore.putSTM, clusterInstApiStore.getSTM, "CreateAppInst check ClusterInst ref must be done in same STM as AppInst put")
	require.NotNil(t, flavorApiStore.getSTM, "CreateAppInst check Flavor ref must be done in STM")
	require.Equal(t, appInstApiStore.putSTM, flavorApiStore.getSTM, "CreateAppInst check Flavor ref must be done in same STM as AppInst put")

	// clean up
	// delete created test obj
	testObj, _ = dataGen.GetCreateAppInstTestObj()
	err = all.appInstApi.DeleteAppInst(testObj, testutil.NewCudStreamoutAppInst(ctx))
	require.Nil(t, err)
	supportData.delete(t, ctx, all)
}
