// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: flavor.proto

package testutil

import "google.golang.org/grpc"
import "github.com/mobiledgex/edge-cloud/edgeproto"
import "io"
import "testing"
import "context"
import "time"
import "github.com/stretchr/testify/require"
import "github.com/mobiledgex/edge-cloud/log"
import "github.com/mobiledgex/edge-cloud/cli"
import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/googleapis/google/api"
import _ "github.com/mobiledgex/edge-cloud/protogen"
import _ "github.com/gogo/protobuf/gogoproto"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

type ShowFlavor struct {
	Data map[string]edgeproto.Flavor
	grpc.ServerStream
	Ctx context.Context
}

func (x *ShowFlavor) Init() {
	x.Data = make(map[string]edgeproto.Flavor)
}

func (x *ShowFlavor) Send(m *edgeproto.Flavor) error {
	x.Data[m.GetKey().GetKeyString()] = *m
	return nil
}

func (x *ShowFlavor) Context() context.Context {
	return x.Ctx
}

var FlavorShowExtraCount = 0

func (x *ShowFlavor) ReadStream(stream edgeproto.FlavorApi_ShowFlavorClient, err error) {
	x.Data = make(map[string]edgeproto.Flavor)
	if err != nil {
		return
	}
	for {
		obj, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		x.Data[obj.GetKey().GetKeyString()] = *obj
	}
}

func (x *ShowFlavor) CheckFound(obj *edgeproto.Flavor) bool {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	return found
}

func (x *ShowFlavor) AssertFound(t *testing.T, obj *edgeproto.Flavor) {
	check, found := x.Data[obj.GetKey().GetKeyString()]
	require.True(t, found, "find Flavor %s", obj.GetKey().GetKeyString())
	if found && !check.Matches(obj, edgeproto.MatchIgnoreBackend(), edgeproto.MatchSortArrayedKeys()) {
		require.Equal(t, *obj, check, "Flavor are equal")
	}
	if found {
		// remove in case there are dups in the list, so the
		// same object cannot be used again
		delete(x.Data, obj.GetKey().GetKeyString())
	}
}

func (x *ShowFlavor) AssertNotFound(t *testing.T, obj *edgeproto.Flavor) {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	require.False(t, found, "do not find Flavor %s", obj.GetKey().GetKeyString())
}

func WaitAssertFoundFlavor(t *testing.T, api edgeproto.FlavorApiClient, obj *edgeproto.Flavor, count int, retry time.Duration) {
	show := ShowFlavor{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowFlavor(ctx, obj)
		show.ReadStream(stream, err)
		cancel()
		if show.CheckFound(obj) {
			break
		}
		time.Sleep(retry)
	}
	show.AssertFound(t, obj)
}

func WaitAssertNotFoundFlavor(t *testing.T, api edgeproto.FlavorApiClient, obj *edgeproto.Flavor, count int, retry time.Duration) {
	show := ShowFlavor{}
	filterNone := edgeproto.Flavor{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowFlavor(ctx, &filterNone)
		show.ReadStream(stream, err)
		cancel()
		if !show.CheckFound(obj) {
			break
		}
		time.Sleep(retry)
	}
	show.AssertNotFound(t, obj)
}

// Wrap the api with a common interface
type FlavorCommonApi struct {
	internal_api edgeproto.FlavorApiServer
	client_api   edgeproto.FlavorApiClient
}

func (x *FlavorCommonApi) CreateFlavor(ctx context.Context, in *edgeproto.Flavor) (*edgeproto.Result, error) {
	copy := &edgeproto.Flavor{}
	*copy = *in
	if x.internal_api != nil {
		return x.internal_api.CreateFlavor(ctx, copy)
	} else {
		return x.client_api.CreateFlavor(ctx, copy)
	}
}

func (x *FlavorCommonApi) DeleteFlavor(ctx context.Context, in *edgeproto.Flavor) (*edgeproto.Result, error) {
	copy := &edgeproto.Flavor{}
	*copy = *in
	if x.internal_api != nil {
		return x.internal_api.DeleteFlavor(ctx, copy)
	} else {
		return x.client_api.DeleteFlavor(ctx, copy)
	}
}

func (x *FlavorCommonApi) UpdateFlavor(ctx context.Context, in *edgeproto.Flavor) (*edgeproto.Result, error) {
	copy := &edgeproto.Flavor{}
	*copy = *in
	if x.internal_api != nil {
		return x.internal_api.UpdateFlavor(ctx, copy)
	} else {
		return x.client_api.UpdateFlavor(ctx, copy)
	}
}

func (x *FlavorCommonApi) ShowFlavor(ctx context.Context, filter *edgeproto.Flavor, showData *ShowFlavor) error {
	if x.internal_api != nil {
		showData.Ctx = ctx
		return x.internal_api.ShowFlavor(filter, showData)
	} else {
		stream, err := x.client_api.ShowFlavor(ctx, filter)
		showData.ReadStream(stream, err)
		return err
	}
}

func NewInternalFlavorApi(api edgeproto.FlavorApiServer) *FlavorCommonApi {
	apiWrap := FlavorCommonApi{}
	apiWrap.internal_api = api
	return &apiWrap
}

func NewClientFlavorApi(api edgeproto.FlavorApiClient) *FlavorCommonApi {
	apiWrap := FlavorCommonApi{}
	apiWrap.client_api = api
	return &apiWrap
}

func InternalFlavorTest(t *testing.T, test string, api edgeproto.FlavorApiServer, testData []edgeproto.Flavor) {
	span := log.StartSpan(log.DebugLevelApi, "InternalFlavorTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "cud":
		basicFlavorCudTest(t, ctx, NewInternalFlavorApi(api), testData)
	case "show":
		basicFlavorShowTest(t, ctx, NewInternalFlavorApi(api), testData)
	}
}

func ClientFlavorTest(t *testing.T, test string, api edgeproto.FlavorApiClient, testData []edgeproto.Flavor) {
	span := log.StartSpan(log.DebugLevelApi, "ClientFlavorTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "cud":
		basicFlavorCudTest(t, ctx, NewClientFlavorApi(api), testData)
	case "show":
		basicFlavorShowTest(t, ctx, NewClientFlavorApi(api), testData)
	}
}

func basicFlavorShowTest(t *testing.T, ctx context.Context, api *FlavorCommonApi, testData []edgeproto.Flavor) {
	var err error

	show := ShowFlavor{}
	show.Init()
	filterNone := edgeproto.Flavor{}
	err = api.ShowFlavor(ctx, &filterNone, &show)
	require.Nil(t, err, "show data")
	require.Equal(t, len(testData)+FlavorShowExtraCount, len(show.Data), "Show count")
	for _, obj := range testData {
		show.AssertFound(t, &obj)
	}
}

func GetFlavor(t *testing.T, ctx context.Context, api *FlavorCommonApi, key *edgeproto.FlavorKey, out *edgeproto.Flavor) bool {
	var err error

	show := ShowFlavor{}
	show.Init()
	filter := edgeproto.Flavor{}
	filter.SetKey(key)
	err = api.ShowFlavor(ctx, &filter, &show)
	require.Nil(t, err, "show data")
	obj, found := show.Data[key.GetKeyString()]
	if found {
		*out = obj
	}
	return found
}

func basicFlavorCudTest(t *testing.T, ctx context.Context, api *FlavorCommonApi, testData []edgeproto.Flavor) {
	var err error

	if len(testData) < 3 {
		require.True(t, false, "Need at least 3 test data objects")
		return
	}

	// test create
	CreateFlavorData(t, ctx, api, testData)

	// test duplicate Create - should fail
	_, err = api.CreateFlavor(ctx, &testData[0])
	require.NotNil(t, err, "Create duplicate Flavor")

	// test show all items
	basicFlavorShowTest(t, ctx, api, testData)

	// test Delete
	_, err = api.DeleteFlavor(ctx, &testData[0])
	require.Nil(t, err, "Delete Flavor %s", testData[0].GetKey().GetKeyString())
	show := ShowFlavor{}
	show.Init()
	filterNone := edgeproto.Flavor{}
	err = api.ShowFlavor(ctx, &filterNone, &show)
	require.Nil(t, err, "show data")
	require.Equal(t, len(testData)-1+FlavorShowExtraCount, len(show.Data), "Show count")
	show.AssertNotFound(t, &testData[0])
	// test update of missing object
	_, err = api.UpdateFlavor(ctx, &testData[0])
	require.NotNil(t, err, "Update missing object")
	// Create it back
	_, err = api.CreateFlavor(ctx, &testData[0])
	require.Nil(t, err, "Create Flavor %s", testData[0].GetKey().GetKeyString())

	// test invalid keys
	bad := edgeproto.Flavor{}
	_, err = api.CreateFlavor(ctx, &bad)
	require.NotNil(t, err, "Create Flavor with no key info")

}

func InternalFlavorCreate(t *testing.T, api edgeproto.FlavorApiServer, testData []edgeproto.Flavor) {
	span := log.StartSpan(log.DebugLevelApi, "InternalFlavorCreate")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	CreateFlavorData(t, ctx, NewInternalFlavorApi(api), testData)
}

func ClientFlavorCreate(t *testing.T, api edgeproto.FlavorApiClient, testData []edgeproto.Flavor) {
	span := log.StartSpan(log.DebugLevelApi, "ClientFlavorCreate")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	CreateFlavorData(t, ctx, NewClientFlavorApi(api), testData)
}

func CreateFlavorData(t *testing.T, ctx context.Context, api *FlavorCommonApi, testData []edgeproto.Flavor) {
	var err error

	for _, obj := range testData {
		_, err = api.CreateFlavor(ctx, &obj)
		require.Nil(t, err, "Create Flavor %s", obj.GetKey().GetKeyString())
	}
}

func FindFlavorData(key *edgeproto.FlavorKey, testData []edgeproto.Flavor) (*edgeproto.Flavor, bool) {
	for ii, _ := range testData {
		if testData[ii].GetKey().Matches(key) {
			return &testData[ii], true
		}
	}
	return nil, false
}

func RunFlavorApi(conn *grpc.ClientConn, ctx context.Context, data *[]edgeproto.Flavor, dataMap interface{}, mode string) error {
	flavorApi := edgeproto.NewFlavorApiClient(conn)
	var err error
	for ii, objD := range *data {
		obj := &objD
		log.DebugLog(log.DebugLevelApi, "API %v for Flavor: %v", mode, obj.GetKey())
		switch mode {
		case "create":
			_, err = flavorApi.CreateFlavor(ctx, obj)
		case "delete":
			_, err = flavorApi.DeleteFlavor(ctx, obj)
		case "update":
			objMap, err := cli.GetGenericObjFromList(dataMap, ii)
			if err != nil {
				return fmt.Errorf("bad dataMap for Flavor: %v", err)
			}
			obj.Fields = cli.GetSpecifiedFields(objMap, obj, cli.YamlNamespace)
			_, err = flavorApi.UpdateFlavor(ctx, obj)
		case "add":
			_, err = flavorApi.AddFlavorRes(ctx, obj)
		case "remove":
			_, err = flavorApi.RemoveFlavorRes(ctx, obj)
		default:
			log.DebugLog(log.DebugLevelApi, "Unsupported API %v for Flavor: %v", mode, obj.GetKey())
			return nil
		}
		err = ignoreExpectedErrors(mode, obj.GetKey(), err)
		if err != nil {
			return fmt.Errorf("API %s failed for %v -- err %v", mode, obj.GetKey(), err)
		}
	}
	return nil
}

func (s *DummyServer) CreateFlavor(ctx context.Context, in *edgeproto.Flavor) (*edgeproto.Result, error) {
	if s.CudNoop {
		return &edgeproto.Result{}, nil
	}
	s.FlavorCache.Update(ctx, in, 0)
	return &edgeproto.Result{}, nil
}

func (s *DummyServer) DeleteFlavor(ctx context.Context, in *edgeproto.Flavor) (*edgeproto.Result, error) {
	if s.CudNoop {
		return &edgeproto.Result{}, nil
	}
	s.FlavorCache.Delete(ctx, in, 0)
	return &edgeproto.Result{}, nil
}

func (s *DummyServer) UpdateFlavor(ctx context.Context, in *edgeproto.Flavor) (*edgeproto.Result, error) {
	if s.CudNoop {
		return &edgeproto.Result{}, nil
	}
	s.FlavorCache.Update(ctx, in, 0)
	return &edgeproto.Result{}, nil
}

func (s *DummyServer) ShowFlavor(in *edgeproto.Flavor, server edgeproto.FlavorApi_ShowFlavorServer) error {
	var err error
	obj := &edgeproto.Flavor{}
	if obj.Matches(in, edgeproto.MatchFilter()) {
		for ii := 0; ii < s.ShowDummyCount; ii++ {
			server.Send(&edgeproto.Flavor{})
		}
	}
	err = s.FlavorCache.Show(in, func(obj *edgeproto.Flavor) error {
		err := server.Send(obj)
		return err
	})
	return err
}

func (s *DummyServer) AddFlavorRes(ctx context.Context, in *edgeproto.Flavor) (*edgeproto.Result, error) {
	if s.CudNoop {
		return &edgeproto.Result{}, nil
	}
	return &edgeproto.Result{}, nil
}

func (s *DummyServer) RemoveFlavorRes(ctx context.Context, in *edgeproto.Flavor) (*edgeproto.Result, error) {
	if s.CudNoop {
		return &edgeproto.Result{}, nil
	}
	return &edgeproto.Result{}, nil
}
