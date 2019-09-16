// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: operator.proto

package testutil

import "google.golang.org/grpc"
import "github.com/mobiledgex/edge-cloud/edgeproto"
import "io"
import "testing"
import "context"
import "time"
import "github.com/stretchr/testify/require"
import "github.com/mobiledgex/edge-cloud/log"
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

type ShowOperator struct {
	Data map[string]edgeproto.Operator
	grpc.ServerStream
}

func (x *ShowOperator) Init() {
	x.Data = make(map[string]edgeproto.Operator)
}

func (x *ShowOperator) Send(m *edgeproto.Operator) error {
	x.Data[m.Key.GetKeyString()] = *m
	return nil
}

func (x *ShowOperator) ReadStream(stream edgeproto.OperatorApi_ShowOperatorClient, err error) {
	x.Data = make(map[string]edgeproto.Operator)
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
		x.Data[obj.Key.GetKeyString()] = *obj
	}
}

func (x *ShowOperator) CheckFound(obj *edgeproto.Operator) bool {
	_, found := x.Data[obj.Key.GetKeyString()]
	return found
}

func (x *ShowOperator) AssertFound(t *testing.T, obj *edgeproto.Operator) {
	check, found := x.Data[obj.Key.GetKeyString()]
	require.True(t, found, "find Operator %s", obj.Key.GetKeyString())
	if found && !check.Matches(obj, edgeproto.MatchIgnoreBackend(), edgeproto.MatchSortArrayedKeys()) {
		require.Equal(t, *obj, check, "Operator are equal")
	}
	if found {
		// remove in case there are dups in the list, so the
		// same object cannot be used again
		delete(x.Data, obj.Key.GetKeyString())
	}
}

func (x *ShowOperator) AssertNotFound(t *testing.T, obj *edgeproto.Operator) {
	_, found := x.Data[obj.Key.GetKeyString()]
	require.False(t, found, "do not find Operator %s", obj.Key.GetKeyString())
}

func WaitAssertFoundOperator(t *testing.T, api edgeproto.OperatorApiClient, obj *edgeproto.Operator, count int, retry time.Duration) {
	show := ShowOperator{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowOperator(ctx, obj)
		show.ReadStream(stream, err)
		cancel()
		if show.CheckFound(obj) {
			break
		}
		time.Sleep(retry)
	}
	show.AssertFound(t, obj)
}

func WaitAssertNotFoundOperator(t *testing.T, api edgeproto.OperatorApiClient, obj *edgeproto.Operator, count int, retry time.Duration) {
	show := ShowOperator{}
	filterNone := edgeproto.Operator{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowOperator(ctx, &filterNone)
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
type OperatorCommonApi struct {
	internal_api edgeproto.OperatorApiServer
	client_api   edgeproto.OperatorApiClient
}

func (x *OperatorCommonApi) CreateOperator(ctx context.Context, in *edgeproto.Operator) (*edgeproto.Result, error) {
	copy := &edgeproto.Operator{}
	*copy = *in
	if x.internal_api != nil {
		return x.internal_api.CreateOperator(ctx, copy)
	} else {
		return x.client_api.CreateOperator(ctx, copy)
	}
}

func (x *OperatorCommonApi) UpdateOperator(ctx context.Context, in *edgeproto.Operator) (*edgeproto.Result, error) {
	copy := &edgeproto.Operator{}
	*copy = *in
	if x.internal_api != nil {
		return x.internal_api.UpdateOperator(ctx, copy)
	} else {
		return x.client_api.UpdateOperator(ctx, copy)
	}
}

func (x *OperatorCommonApi) DeleteOperator(ctx context.Context, in *edgeproto.Operator) (*edgeproto.Result, error) {
	copy := &edgeproto.Operator{}
	*copy = *in
	if x.internal_api != nil {
		return x.internal_api.DeleteOperator(ctx, copy)
	} else {
		return x.client_api.DeleteOperator(ctx, copy)
	}
}

func (x *OperatorCommonApi) ShowOperator(ctx context.Context, filter *edgeproto.Operator, showData *ShowOperator) error {
	if x.internal_api != nil {
		return x.internal_api.ShowOperator(filter, showData)
	} else {
		stream, err := x.client_api.ShowOperator(ctx, filter)
		showData.ReadStream(stream, err)
		return err
	}
}

func NewInternalOperatorApi(api edgeproto.OperatorApiServer) *OperatorCommonApi {
	apiWrap := OperatorCommonApi{}
	apiWrap.internal_api = api
	return &apiWrap
}

func NewClientOperatorApi(api edgeproto.OperatorApiClient) *OperatorCommonApi {
	apiWrap := OperatorCommonApi{}
	apiWrap.client_api = api
	return &apiWrap
}

func InternalOperatorTest(t *testing.T, test string, api edgeproto.OperatorApiServer, testData []edgeproto.Operator) {
	span := log.StartSpan(log.DebugLevelApi, "InternalOperatorTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "cud":
		basicOperatorCudTest(t, ctx, NewInternalOperatorApi(api), testData)
	case "show":
		basicOperatorShowTest(t, ctx, NewInternalOperatorApi(api), testData)
	}
}

func ClientOperatorTest(t *testing.T, test string, api edgeproto.OperatorApiClient, testData []edgeproto.Operator) {
	span := log.StartSpan(log.DebugLevelApi, "ClientOperatorTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "cud":
		basicOperatorCudTest(t, ctx, NewClientOperatorApi(api), testData)
	case "show":
		basicOperatorShowTest(t, ctx, NewClientOperatorApi(api), testData)
	}
}

func basicOperatorShowTest(t *testing.T, ctx context.Context, api *OperatorCommonApi, testData []edgeproto.Operator) {
	var err error

	show := ShowOperator{}
	show.Init()
	filterNone := edgeproto.Operator{}
	err = api.ShowOperator(ctx, &filterNone, &show)
	require.Nil(t, err, "show data")
	require.Equal(t, len(testData), len(show.Data), "Show count")
	for _, obj := range testData {
		show.AssertFound(t, &obj)
	}
}

func GetOperator(t *testing.T, ctx context.Context, api *OperatorCommonApi, key *edgeproto.OperatorKey, out *edgeproto.Operator) bool {
	var err error

	show := ShowOperator{}
	show.Init()
	filter := edgeproto.Operator{}
	filter.Key = *key
	err = api.ShowOperator(ctx, &filter, &show)
	require.Nil(t, err, "show data")
	obj, found := show.Data[key.GetKeyString()]
	if found {
		*out = obj
	}
	return found
}

func basicOperatorCudTest(t *testing.T, ctx context.Context, api *OperatorCommonApi, testData []edgeproto.Operator) {
	var err error

	if len(testData) < 3 {
		require.True(t, false, "Need at least 3 test data objects")
		return
	}

	// test create
	createOperatorData(t, ctx, api, testData)

	// test duplicate create - should fail
	_, err = api.CreateOperator(ctx, &testData[0])
	require.NotNil(t, err, "Create duplicate Operator")

	// test show all items
	basicOperatorShowTest(t, ctx, api, testData)

	// test delete
	_, err = api.DeleteOperator(ctx, &testData[0])
	require.Nil(t, err, "delete Operator %s", testData[0].Key.GetKeyString())
	show := ShowOperator{}
	show.Init()
	filterNone := edgeproto.Operator{}
	err = api.ShowOperator(ctx, &filterNone, &show)
	require.Nil(t, err, "show data")
	require.Equal(t, len(testData)-1, len(show.Data), "Show count")
	show.AssertNotFound(t, &testData[0])
	// test update of missing object
	_, err = api.UpdateOperator(ctx, &testData[0])
	require.NotNil(t, err, "Update missing object")
	// create it back
	_, err = api.CreateOperator(ctx, &testData[0])
	require.Nil(t, err, "Create Operator %s", testData[0].Key.GetKeyString())

	// test invalid keys
	bad := edgeproto.Operator{}
	_, err = api.CreateOperator(ctx, &bad)
	require.NotNil(t, err, "Create Operator with no key info")

}

func InternalOperatorCreate(t *testing.T, api edgeproto.OperatorApiServer, testData []edgeproto.Operator) {
	span := log.StartSpan(log.DebugLevelApi, "InternalOperatorCreate")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	createOperatorData(t, ctx, NewInternalOperatorApi(api), testData)
}

func ClientOperatorCreate(t *testing.T, api edgeproto.OperatorApiClient, testData []edgeproto.Operator) {
	span := log.StartSpan(log.DebugLevelApi, "ClientOperatorCreate")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	createOperatorData(t, ctx, NewClientOperatorApi(api), testData)
}

func createOperatorData(t *testing.T, ctx context.Context, api *OperatorCommonApi, testData []edgeproto.Operator) {
	var err error

	for _, obj := range testData {
		_, err = api.CreateOperator(ctx, &obj)
		require.Nil(t, err, "Create Operator %s", obj.Key.GetKeyString())
	}
}

func (s *DummyServer) CreateOperator(ctx context.Context, in *edgeproto.Operator) (*edgeproto.Result, error) {
	return &edgeproto.Result{}, nil
}

func (s *DummyServer) DeleteOperator(ctx context.Context, in *edgeproto.Operator) (*edgeproto.Result, error) {
	return &edgeproto.Result{}, nil
}

func (s *DummyServer) UpdateOperator(ctx context.Context, in *edgeproto.Operator) (*edgeproto.Result, error) {
	return &edgeproto.Result{}, nil
}

func (s *DummyServer) ShowOperator(in *edgeproto.Operator, server edgeproto.OperatorApi_ShowOperatorServer) error {
	obj := &edgeproto.Operator{}
	if obj.Matches(in, edgeproto.MatchFilter()) {
		server.Send(&edgeproto.Operator{})
		server.Send(&edgeproto.Operator{})
		server.Send(&edgeproto.Operator{})
	}
	for _, out := range s.Operators {
		if !out.Matches(in, edgeproto.MatchFilter()) {
			continue
		}
		server.Send(&out)
	}
	return nil
}
