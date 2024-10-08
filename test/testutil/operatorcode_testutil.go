// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: operatorcode.proto

package testutil

import (
	"context"
	fmt "fmt"
	edgeproto "github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/edgectl/wrapper"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	_ "github.com/edgexr/edge-cloud-platform/tools/protogen"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"io"
	math "math"
	"testing"
	"time"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

type ShowOperatorCode struct {
	Data map[string]edgeproto.OperatorCode
	grpc.ServerStream
	Ctx context.Context
}

func (x *ShowOperatorCode) Init() {
	x.Data = make(map[string]edgeproto.OperatorCode)
}

func (x *ShowOperatorCode) Send(m *edgeproto.OperatorCode) error {
	x.Data[m.GetKey().GetKeyString()] = *m
	return nil
}

func (x *ShowOperatorCode) Context() context.Context {
	return x.Ctx
}

var OperatorCodeShowExtraCount = 0

func (x *ShowOperatorCode) ReadStream(stream edgeproto.OperatorCodeApi_ShowOperatorCodeClient, err error) {
	x.Data = make(map[string]edgeproto.OperatorCode)
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

func (x *ShowOperatorCode) CheckFound(obj *edgeproto.OperatorCode) bool {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	return found
}

func (x *ShowOperatorCode) AssertFound(t *testing.T, obj *edgeproto.OperatorCode) {
	check, found := x.Data[obj.GetKey().GetKeyString()]
	require.True(t, found, "find OperatorCode %s", obj.GetKey().GetKeyString())
	if found && !check.Matches(obj, edgeproto.MatchIgnoreBackend(), edgeproto.MatchSortArrayedKeys()) {
		require.Equal(t, *obj, check, "OperatorCode are equal")
	}
	if found {
		// remove in case there are dups in the list, so the
		// same object cannot be used again
		delete(x.Data, obj.GetKey().GetKeyString())
	}
}

func (x *ShowOperatorCode) AssertNotFound(t *testing.T, obj *edgeproto.OperatorCode) {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	require.False(t, found, "do not find OperatorCode %s", obj.GetKey().GetKeyString())
}

func WaitAssertFoundOperatorCode(t *testing.T, api edgeproto.OperatorCodeApiClient, obj *edgeproto.OperatorCode, count int, retry time.Duration) {
	show := ShowOperatorCode{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowOperatorCode(ctx, obj)
		show.ReadStream(stream, err)
		cancel()
		if show.CheckFound(obj) {
			break
		}
		time.Sleep(retry)
	}
	show.AssertFound(t, obj)
}

func WaitAssertNotFoundOperatorCode(t *testing.T, api edgeproto.OperatorCodeApiClient, obj *edgeproto.OperatorCode, count int, retry time.Duration) {
	show := ShowOperatorCode{}
	filterNone := edgeproto.OperatorCode{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowOperatorCode(ctx, &filterNone)
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
type OperatorCodeCommonApi struct {
	internal_api edgeproto.OperatorCodeApiServer
	client_api   edgeproto.OperatorCodeApiClient
}

func (x *OperatorCodeCommonApi) CreateOperatorCode(ctx context.Context, in *edgeproto.OperatorCode) (*edgeproto.Result, error) {
	copy := &edgeproto.OperatorCode{}
	*copy = *in
	if x.internal_api != nil {
		return x.internal_api.CreateOperatorCode(ctx, copy)
	} else {
		res, err := x.client_api.CreateOperatorCode(ctx, copy)
		return res, unwrapGrpcError(err)
	}
}

func (x *OperatorCodeCommonApi) DeleteOperatorCode(ctx context.Context, in *edgeproto.OperatorCode) (*edgeproto.Result, error) {
	copy := &edgeproto.OperatorCode{}
	*copy = *in
	if x.internal_api != nil {
		return x.internal_api.DeleteOperatorCode(ctx, copy)
	} else {
		res, err := x.client_api.DeleteOperatorCode(ctx, copy)
		return res, unwrapGrpcError(err)
	}
}

func (x *OperatorCodeCommonApi) ShowOperatorCode(ctx context.Context, filter *edgeproto.OperatorCode, showData *ShowOperatorCode) error {
	if x.internal_api != nil {
		showData.Ctx = ctx
		return x.internal_api.ShowOperatorCode(filter, showData)
	} else {
		stream, err := x.client_api.ShowOperatorCode(ctx, filter)
		showData.ReadStream(stream, err)
		return unwrapGrpcError(err)
	}
}

func NewInternalOperatorCodeApi(api edgeproto.OperatorCodeApiServer) *OperatorCodeCommonApi {
	apiWrap := OperatorCodeCommonApi{}
	apiWrap.internal_api = api
	return &apiWrap
}

func NewClientOperatorCodeApi(api edgeproto.OperatorCodeApiClient) *OperatorCodeCommonApi {
	apiWrap := OperatorCodeCommonApi{}
	apiWrap.client_api = api
	return &apiWrap
}

type OperatorCodeTestOptions struct {
	createdData []edgeproto.OperatorCode
}

type OperatorCodeTestOp func(opts *OperatorCodeTestOptions)

func WithCreatedOperatorCodeTestData(createdData []edgeproto.OperatorCode) OperatorCodeTestOp {
	return func(opts *OperatorCodeTestOptions) { opts.createdData = createdData }
}

func InternalOperatorCodeTest(t *testing.T, test string, api edgeproto.OperatorCodeApiServer, testData []edgeproto.OperatorCode, ops ...OperatorCodeTestOp) {
	span := log.StartSpan(log.DebugLevelApi, "InternalOperatorCodeTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "cud":
		basicOperatorCodeCudTest(t, ctx, NewInternalOperatorCodeApi(api), testData, ops...)
	case "show":
		basicOperatorCodeShowTest(t, ctx, NewInternalOperatorCodeApi(api), testData)
	}
}

func ClientOperatorCodeTest(t *testing.T, test string, api edgeproto.OperatorCodeApiClient, testData []edgeproto.OperatorCode, ops ...OperatorCodeTestOp) {
	span := log.StartSpan(log.DebugLevelApi, "ClientOperatorCodeTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "cud":
		basicOperatorCodeCudTest(t, ctx, NewClientOperatorCodeApi(api), testData, ops...)
	case "show":
		basicOperatorCodeShowTest(t, ctx, NewClientOperatorCodeApi(api), testData)
	}
}

func basicOperatorCodeShowTest(t *testing.T, ctx context.Context, api *OperatorCodeCommonApi, testData []edgeproto.OperatorCode) {
	var err error

	show := ShowOperatorCode{}
	show.Init()
	filterNone := edgeproto.OperatorCode{}
	err = api.ShowOperatorCode(ctx, &filterNone, &show)
	require.Nil(t, err, "show data")
	require.Equal(t, len(testData)+OperatorCodeShowExtraCount, len(show.Data), "Show count")
	for _, obj := range testData {
		show.AssertFound(t, &obj)
	}
}

func GetOperatorCode(t *testing.T, ctx context.Context, api *OperatorCodeCommonApi, key *edgeproto.OperatorCodeKey, out *edgeproto.OperatorCode) bool {
	var err error

	show := ShowOperatorCode{}
	show.Init()
	filter := edgeproto.OperatorCode{}
	filter.SetKey(key)
	err = api.ShowOperatorCode(ctx, &filter, &show)
	require.Nil(t, err, "show data")
	obj, found := show.Data[key.GetKeyString()]
	if found {
		*out = obj
	}
	return found
}

func basicOperatorCodeCudTest(t *testing.T, ctx context.Context, api *OperatorCodeCommonApi, testData []edgeproto.OperatorCode, ops ...OperatorCodeTestOp) {
	var err error

	if len(testData) < 3 {
		require.True(t, false, "Need at least 3 test data objects")
		return
	}
	options := OperatorCodeTestOptions{}
	for _, op := range ops {
		op(&options)
	}
	createdData := testData
	if options.createdData != nil {
		createdData = options.createdData
	}

	// test create
	CreateOperatorCodeData(t, ctx, api, testData)

	// test duplicate Create - should fail
	_, err = api.CreateOperatorCode(ctx, &testData[0])
	require.NotNil(t, err, "Create duplicate OperatorCode")

	// test show all items
	basicOperatorCodeShowTest(t, ctx, api, createdData)

	// test Delete
	_, err = api.DeleteOperatorCode(ctx, &createdData[0])
	require.Nil(t, err, "Delete OperatorCode %s", testData[0].GetKey().GetKeyString())
	show := ShowOperatorCode{}
	show.Init()
	filterNone := edgeproto.OperatorCode{}
	err = api.ShowOperatorCode(ctx, &filterNone, &show)
	require.Nil(t, err, "show data")
	require.Equal(t, len(createdData)-1+OperatorCodeShowExtraCount, len(show.Data), "Show count")
	show.AssertNotFound(t, &createdData[0])
	// Create it back
	_, err = api.CreateOperatorCode(ctx, &testData[0])
	require.Nil(t, err, "Create OperatorCode %s", testData[0].GetKey().GetKeyString())

	// test invalid keys
	bad := edgeproto.OperatorCode{}
	_, err = api.CreateOperatorCode(ctx, &bad)
	require.NotNil(t, err, "Create OperatorCode with no key info")

}

func InternalOperatorCodeCreate(t *testing.T, api edgeproto.OperatorCodeApiServer, testData []edgeproto.OperatorCode) {
	span := log.StartSpan(log.DebugLevelApi, "InternalOperatorCodeCreate")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	CreateOperatorCodeData(t, ctx, NewInternalOperatorCodeApi(api), testData)
}

func ClientOperatorCodeCreate(t *testing.T, api edgeproto.OperatorCodeApiClient, testData []edgeproto.OperatorCode) {
	span := log.StartSpan(log.DebugLevelApi, "ClientOperatorCodeCreate")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	CreateOperatorCodeData(t, ctx, NewClientOperatorCodeApi(api), testData)
}

func CreateOperatorCodeData(t *testing.T, ctx context.Context, api *OperatorCodeCommonApi, testData []edgeproto.OperatorCode) {
	var err error

	for ii := range testData {
		obj := testData[ii]
		_, err = api.CreateOperatorCode(ctx, &obj)
		require.Nil(t, err, "Create OperatorCode %s", obj.GetKey().GetKeyString())
	}
}

func InternalOperatorCodeDelete(t *testing.T, api edgeproto.OperatorCodeApiServer, testData []edgeproto.OperatorCode) {
	span := log.StartSpan(log.DebugLevelApi, "InternalOperatorCodeDelete")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	DeleteOperatorCodeData(t, ctx, NewInternalOperatorCodeApi(api), testData)
}

func InternalOperatorCodeDeleteAll(t *testing.T, ctx context.Context, api edgeproto.OperatorCodeApiServer, data []edgeproto.OperatorCode) {
	intapi := NewInternalOperatorCodeApi(api)
	log.SpanLog(ctx, log.DebugLevelInfo, "deleting all OperatorCodes", "count", len(data))
	DeleteOperatorCodeData(t, ctx, intapi, data)
}

func ClientOperatorCodeDelete(t *testing.T, api edgeproto.OperatorCodeApiClient, testData []edgeproto.OperatorCode) {
	span := log.StartSpan(log.DebugLevelApi, "ClientOperatorCodeDelete")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	DeleteOperatorCodeData(t, ctx, NewClientOperatorCodeApi(api), testData)
}

func DeleteOperatorCodeData(t *testing.T, ctx context.Context, api *OperatorCodeCommonApi, testData []edgeproto.OperatorCode) {
	var err error

	for ii := range testData {
		obj := testData[ii]
		_, err = api.DeleteOperatorCode(ctx, &obj)
		require.Nil(t, err, "Delete OperatorCode %s", obj.GetKey().GetKeyString())
	}
}

func FindOperatorCodeData(key *edgeproto.OperatorCodeKey, testData []edgeproto.OperatorCode) (*edgeproto.OperatorCode, bool) {
	for ii, _ := range testData {
		if testData[ii].GetKey().Matches(key) {
			return &testData[ii], true
		}
	}
	return nil, false
}

func (r *Run) OperatorCodeApi(data *[]edgeproto.OperatorCode, dataMap interface{}, dataOut interface{}) {
	log.DebugLog(log.DebugLevelApi, "API for OperatorCode", "mode", r.Mode)
	if r.Mode == "show" {
		obj := &edgeproto.OperatorCode{}
		out, err := r.client.ShowOperatorCode(r.ctx, obj)
		if err != nil {
			r.logErr("OperatorCodeApi", err)
		} else {
			outp, ok := dataOut.(*[]edgeproto.OperatorCode)
			if !ok {
				panic(fmt.Sprintf("RunOperatorCodeApi expected dataOut type *[]edgeproto.OperatorCode, but was %T", dataOut))
			}
			*outp = append(*outp, out...)
		}
		return
	}
	for ii, objD := range *data {
		obj := &objD
		switch r.Mode {
		case "create":
			out, err := r.client.CreateOperatorCode(r.ctx, obj)
			if err != nil {
				r.logErr(fmt.Sprintf("OperatorCodeApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunOperatorCodeApi expected dataOut type *[]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		case "delete":
			out, err := r.client.DeleteOperatorCode(r.ctx, obj)
			if err != nil {
				r.logErr(fmt.Sprintf("OperatorCodeApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunOperatorCodeApi expected dataOut type *[]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		case "showfiltered":
			out, err := r.client.ShowOperatorCode(r.ctx, obj)
			if err != nil {
				r.logErr(fmt.Sprintf("OperatorCodeApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.OperatorCode)
				if !ok {
					panic(fmt.Sprintf("RunOperatorCodeApi expected dataOut type *[]edgeproto.OperatorCode, but was %T", dataOut))
				}
				*outp = append(*outp, out...)
			}
		}
	}
}

func (s *DummyServer) CreateOperatorCode(ctx context.Context, in *edgeproto.OperatorCode) (*edgeproto.Result, error) {
	if s.CudNoop {
		return &edgeproto.Result{}, nil
	}
	s.OperatorCodeCache.Update(ctx, in, 0)
	return &edgeproto.Result{}, nil
}

func (s *DummyServer) DeleteOperatorCode(ctx context.Context, in *edgeproto.OperatorCode) (*edgeproto.Result, error) {
	if s.CudNoop {
		return &edgeproto.Result{}, nil
	}
	s.OperatorCodeCache.Delete(ctx, in, 0)
	return &edgeproto.Result{}, nil
}

func (s *DummyServer) ShowOperatorCode(in *edgeproto.OperatorCode, server edgeproto.OperatorCodeApi_ShowOperatorCodeServer) error {
	var err error
	obj := &edgeproto.OperatorCode{}
	if obj.Matches(in, edgeproto.MatchFilter()) {
		for ii := 0; ii < s.ShowDummyCount; ii++ {
			server.Send(&edgeproto.OperatorCode{})
		}
		if ch, ok := s.MidstreamFailChs["ShowOperatorCode"]; ok {
			// Wait until client receives the SendMsg, since they
			// are buffered and dropped once we return err here.
			select {
			case <-ch:
			case <-time.After(5 * time.Second):
			}
			return fmt.Errorf("midstream failure!")
		}
	}
	err = s.OperatorCodeCache.Show(in, func(obj *edgeproto.OperatorCode) error {
		err := server.Send(obj)
		return err
	})
	return err
}

func (s *ApiClient) CreateOperatorCode(ctx context.Context, in *edgeproto.OperatorCode) (*edgeproto.Result, error) {
	api := edgeproto.NewOperatorCodeApiClient(s.Conn)
	return api.CreateOperatorCode(ctx, in)
}

func (s *CliClient) CreateOperatorCode(ctx context.Context, in *edgeproto.OperatorCode) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "CreateOperatorCode")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

func (s *ApiClient) DeleteOperatorCode(ctx context.Context, in *edgeproto.OperatorCode) (*edgeproto.Result, error) {
	api := edgeproto.NewOperatorCodeApiClient(s.Conn)
	return api.DeleteOperatorCode(ctx, in)
}

func (s *CliClient) DeleteOperatorCode(ctx context.Context, in *edgeproto.OperatorCode) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "DeleteOperatorCode")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

type OperatorCodeStream interface {
	Recv() (*edgeproto.OperatorCode, error)
}

func OperatorCodeReadStream(stream OperatorCodeStream) ([]edgeproto.OperatorCode, error) {
	output := []edgeproto.OperatorCode{}
	for {
		obj, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return output, fmt.Errorf("read OperatorCode stream failed, %v", err)
		}
		output = append(output, *obj)
	}
	return output, nil
}

func (s *ApiClient) ShowOperatorCode(ctx context.Context, in *edgeproto.OperatorCode) ([]edgeproto.OperatorCode, error) {
	api := edgeproto.NewOperatorCodeApiClient(s.Conn)
	stream, err := api.ShowOperatorCode(ctx, in)
	if err != nil {
		return nil, err
	}
	return OperatorCodeReadStream(stream)
}

func (s *CliClient) ShowOperatorCode(ctx context.Context, in *edgeproto.OperatorCode) ([]edgeproto.OperatorCode, error) {
	output := []edgeproto.OperatorCode{}
	args := append(s.BaseArgs, "controller", "ShowOperatorCode")
	err := wrapper.RunEdgectlObjs(args, in, &output, s.RunOps...)
	return output, err
}

type OperatorCodeApiClient interface {
	CreateOperatorCode(ctx context.Context, in *edgeproto.OperatorCode) (*edgeproto.Result, error)
	DeleteOperatorCode(ctx context.Context, in *edgeproto.OperatorCode) (*edgeproto.Result, error)
	ShowOperatorCode(ctx context.Context, in *edgeproto.OperatorCode) ([]edgeproto.OperatorCode, error)
}
