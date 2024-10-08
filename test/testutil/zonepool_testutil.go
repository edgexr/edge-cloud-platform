// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: zonepool.proto

package testutil

import (
	"context"
	fmt "fmt"
	_ "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	edgeproto "github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cli"
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

type ShowZonePool struct {
	Data map[string]edgeproto.ZonePool
	grpc.ServerStream
	Ctx context.Context
}

func (x *ShowZonePool) Init() {
	x.Data = make(map[string]edgeproto.ZonePool)
}

func (x *ShowZonePool) Send(m *edgeproto.ZonePool) error {
	x.Data[m.GetKey().GetKeyString()] = *m
	return nil
}

func (x *ShowZonePool) Context() context.Context {
	return x.Ctx
}

var ZonePoolShowExtraCount = 0

func (x *ShowZonePool) ReadStream(stream edgeproto.ZonePoolApi_ShowZonePoolClient, err error) {
	x.Data = make(map[string]edgeproto.ZonePool)
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

func (x *ShowZonePool) CheckFound(obj *edgeproto.ZonePool) bool {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	return found
}

func (x *ShowZonePool) AssertFound(t *testing.T, obj *edgeproto.ZonePool) {
	check, found := x.Data[obj.GetKey().GetKeyString()]
	require.True(t, found, "find ZonePool %s", obj.GetKey().GetKeyString())
	if found && !check.Matches(obj, edgeproto.MatchIgnoreBackend(), edgeproto.MatchSortArrayedKeys()) {
		require.Equal(t, *obj, check, "ZonePool are equal")
	}
	if found {
		// remove in case there are dups in the list, so the
		// same object cannot be used again
		delete(x.Data, obj.GetKey().GetKeyString())
	}
}

func (x *ShowZonePool) AssertNotFound(t *testing.T, obj *edgeproto.ZonePool) {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	require.False(t, found, "do not find ZonePool %s", obj.GetKey().GetKeyString())
}

func WaitAssertFoundZonePool(t *testing.T, api edgeproto.ZonePoolApiClient, obj *edgeproto.ZonePool, count int, retry time.Duration) {
	show := ShowZonePool{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowZonePool(ctx, obj)
		show.ReadStream(stream, err)
		cancel()
		if show.CheckFound(obj) {
			break
		}
		time.Sleep(retry)
	}
	show.AssertFound(t, obj)
}

func WaitAssertNotFoundZonePool(t *testing.T, api edgeproto.ZonePoolApiClient, obj *edgeproto.ZonePool, count int, retry time.Duration) {
	show := ShowZonePool{}
	filterNone := edgeproto.ZonePool{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowZonePool(ctx, &filterNone)
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
type ZonePoolCommonApi struct {
	internal_api edgeproto.ZonePoolApiServer
	client_api   edgeproto.ZonePoolApiClient
}

func (x *ZonePoolCommonApi) CreateZonePool(ctx context.Context, in *edgeproto.ZonePool) (*edgeproto.Result, error) {
	copy := &edgeproto.ZonePool{}
	*copy = *in
	if x.internal_api != nil {
		return x.internal_api.CreateZonePool(ctx, copy)
	} else {
		res, err := x.client_api.CreateZonePool(ctx, copy)
		return res, unwrapGrpcError(err)
	}
}

func (x *ZonePoolCommonApi) DeleteZonePool(ctx context.Context, in *edgeproto.ZonePool) (*edgeproto.Result, error) {
	copy := &edgeproto.ZonePool{}
	*copy = *in
	if x.internal_api != nil {
		return x.internal_api.DeleteZonePool(ctx, copy)
	} else {
		res, err := x.client_api.DeleteZonePool(ctx, copy)
		return res, unwrapGrpcError(err)
	}
}

func (x *ZonePoolCommonApi) ShowZonePool(ctx context.Context, filter *edgeproto.ZonePool, showData *ShowZonePool) error {
	if x.internal_api != nil {
		showData.Ctx = ctx
		return x.internal_api.ShowZonePool(filter, showData)
	} else {
		stream, err := x.client_api.ShowZonePool(ctx, filter)
		showData.ReadStream(stream, err)
		return unwrapGrpcError(err)
	}
}

func NewInternalZonePoolApi(api edgeproto.ZonePoolApiServer) *ZonePoolCommonApi {
	apiWrap := ZonePoolCommonApi{}
	apiWrap.internal_api = api
	return &apiWrap
}

func NewClientZonePoolApi(api edgeproto.ZonePoolApiClient) *ZonePoolCommonApi {
	apiWrap := ZonePoolCommonApi{}
	apiWrap.client_api = api
	return &apiWrap
}

type ZonePoolTestOptions struct {
	createdData []edgeproto.ZonePool
}

type ZonePoolTestOp func(opts *ZonePoolTestOptions)

func WithCreatedZonePoolTestData(createdData []edgeproto.ZonePool) ZonePoolTestOp {
	return func(opts *ZonePoolTestOptions) { opts.createdData = createdData }
}

func InternalZonePoolTest(t *testing.T, test string, api edgeproto.ZonePoolApiServer, testData []edgeproto.ZonePool, ops ...ZonePoolTestOp) {
	span := log.StartSpan(log.DebugLevelApi, "InternalZonePoolTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "cud":
		basicZonePoolCudTest(t, ctx, NewInternalZonePoolApi(api), testData, ops...)
	case "show":
		basicZonePoolShowTest(t, ctx, NewInternalZonePoolApi(api), testData)
	}
}

func ClientZonePoolTest(t *testing.T, test string, api edgeproto.ZonePoolApiClient, testData []edgeproto.ZonePool, ops ...ZonePoolTestOp) {
	span := log.StartSpan(log.DebugLevelApi, "ClientZonePoolTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "cud":
		basicZonePoolCudTest(t, ctx, NewClientZonePoolApi(api), testData, ops...)
	case "show":
		basicZonePoolShowTest(t, ctx, NewClientZonePoolApi(api), testData)
	}
}

func basicZonePoolShowTest(t *testing.T, ctx context.Context, api *ZonePoolCommonApi, testData []edgeproto.ZonePool) {
	var err error

	show := ShowZonePool{}
	show.Init()
	filterNone := edgeproto.ZonePool{}
	err = api.ShowZonePool(ctx, &filterNone, &show)
	require.Nil(t, err, "show data")
	require.Equal(t, len(testData)+ZonePoolShowExtraCount, len(show.Data), "Show count")
	for _, obj := range testData {
		show.AssertFound(t, &obj)
	}
}

func GetZonePool(t *testing.T, ctx context.Context, api *ZonePoolCommonApi, key *edgeproto.ZonePoolKey, out *edgeproto.ZonePool) bool {
	var err error

	show := ShowZonePool{}
	show.Init()
	filter := edgeproto.ZonePool{}
	filter.SetKey(key)
	err = api.ShowZonePool(ctx, &filter, &show)
	require.Nil(t, err, "show data")
	obj, found := show.Data[key.GetKeyString()]
	if found {
		*out = obj
	}
	return found
}

func basicZonePoolCudTest(t *testing.T, ctx context.Context, api *ZonePoolCommonApi, testData []edgeproto.ZonePool, ops ...ZonePoolTestOp) {
	var err error

	if len(testData) < 3 {
		require.True(t, false, "Need at least 3 test data objects")
		return
	}
	options := ZonePoolTestOptions{}
	for _, op := range ops {
		op(&options)
	}
	createdData := testData
	if options.createdData != nil {
		createdData = options.createdData
	}

	// test create
	CreateZonePoolData(t, ctx, api, testData)

	// test duplicate Create - should fail
	_, err = api.CreateZonePool(ctx, &testData[0])
	require.NotNil(t, err, "Create duplicate ZonePool")

	// test show all items
	basicZonePoolShowTest(t, ctx, api, createdData)

	// test Delete
	_, err = api.DeleteZonePool(ctx, &createdData[0])
	require.Nil(t, err, "Delete ZonePool %s", testData[0].GetKey().GetKeyString())
	show := ShowZonePool{}
	show.Init()
	filterNone := edgeproto.ZonePool{}
	err = api.ShowZonePool(ctx, &filterNone, &show)
	require.Nil(t, err, "show data")
	require.Equal(t, len(createdData)-1+ZonePoolShowExtraCount, len(show.Data), "Show count")
	show.AssertNotFound(t, &createdData[0])
	// Create it back
	_, err = api.CreateZonePool(ctx, &testData[0])
	require.Nil(t, err, "Create ZonePool %s", testData[0].GetKey().GetKeyString())

	// test invalid keys
	bad := edgeproto.ZonePool{}
	_, err = api.CreateZonePool(ctx, &bad)
	require.NotNil(t, err, "Create ZonePool with no key info")

}

func InternalZonePoolCreate(t *testing.T, api edgeproto.ZonePoolApiServer, testData []edgeproto.ZonePool) {
	span := log.StartSpan(log.DebugLevelApi, "InternalZonePoolCreate")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	CreateZonePoolData(t, ctx, NewInternalZonePoolApi(api), testData)
}

func ClientZonePoolCreate(t *testing.T, api edgeproto.ZonePoolApiClient, testData []edgeproto.ZonePool) {
	span := log.StartSpan(log.DebugLevelApi, "ClientZonePoolCreate")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	CreateZonePoolData(t, ctx, NewClientZonePoolApi(api), testData)
}

func CreateZonePoolData(t *testing.T, ctx context.Context, api *ZonePoolCommonApi, testData []edgeproto.ZonePool) {
	var err error

	for ii := range testData {
		obj := testData[ii]
		_, err = api.CreateZonePool(ctx, &obj)
		require.Nil(t, err, "Create ZonePool %s", obj.GetKey().GetKeyString())
	}
}

func InternalZonePoolDelete(t *testing.T, api edgeproto.ZonePoolApiServer, testData []edgeproto.ZonePool) {
	span := log.StartSpan(log.DebugLevelApi, "InternalZonePoolDelete")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	DeleteZonePoolData(t, ctx, NewInternalZonePoolApi(api), testData)
}

func InternalZonePoolDeleteAll(t *testing.T, ctx context.Context, api edgeproto.ZonePoolApiServer, data []edgeproto.ZonePool) {
	intapi := NewInternalZonePoolApi(api)
	log.SpanLog(ctx, log.DebugLevelInfo, "deleting all ZonePools", "count", len(data))
	DeleteZonePoolData(t, ctx, intapi, data)
}

func ClientZonePoolDelete(t *testing.T, api edgeproto.ZonePoolApiClient, testData []edgeproto.ZonePool) {
	span := log.StartSpan(log.DebugLevelApi, "ClientZonePoolDelete")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	DeleteZonePoolData(t, ctx, NewClientZonePoolApi(api), testData)
}

func DeleteZonePoolData(t *testing.T, ctx context.Context, api *ZonePoolCommonApi, testData []edgeproto.ZonePool) {
	var err error

	for ii := range testData {
		obj := testData[ii]
		_, err = api.DeleteZonePool(ctx, &obj)
		require.Nil(t, err, "Delete ZonePool %s", obj.GetKey().GetKeyString())
	}
}

func FindZonePoolData(key *edgeproto.ZonePoolKey, testData []edgeproto.ZonePool) (*edgeproto.ZonePool, bool) {
	for ii, _ := range testData {
		if testData[ii].GetKey().Matches(key) {
			return &testData[ii], true
		}
	}
	return nil, false
}

func (r *Run) ZonePoolApi(data *[]edgeproto.ZonePool, dataMap interface{}, dataOut interface{}) {
	log.DebugLog(log.DebugLevelApi, "API for ZonePool", "mode", r.Mode)
	if r.Mode == "show" {
		obj := &edgeproto.ZonePool{}
		out, err := r.client.ShowZonePool(r.ctx, obj)
		if err != nil {
			r.logErr("ZonePoolApi", err)
		} else {
			outp, ok := dataOut.(*[]edgeproto.ZonePool)
			if !ok {
				panic(fmt.Sprintf("RunZonePoolApi expected dataOut type *[]edgeproto.ZonePool, but was %T", dataOut))
			}
			*outp = append(*outp, out...)
		}
		return
	}
	for ii, objD := range *data {
		obj := &objD
		switch r.Mode {
		case "create":
			out, err := r.client.CreateZonePool(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("ZonePoolApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunZonePoolApi expected dataOut type *[]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		case "delete":
			out, err := r.client.DeleteZonePool(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("ZonePoolApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunZonePoolApi expected dataOut type *[]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		case "update":
			// set specified fields
			objMap, err := cli.GetGenericObjFromList(dataMap, ii)
			if err != nil {
				log.DebugLog(log.DebugLevelApi, "bad dataMap for ZonePool", "err", err)
				*r.Rc = false
				return
			}
			yamlData := cli.MapData{
				Namespace: cli.YamlNamespace,
				Data:      objMap,
			}
			obj.Fields = cli.GetSpecifiedFields(&yamlData, obj)

			out, err := r.client.UpdateZonePool(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("ZonePoolApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunZonePoolApi expected dataOut type *[]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		case "showfiltered":
			out, err := r.client.ShowZonePool(r.ctx, obj)
			if err != nil {
				r.logErr(fmt.Sprintf("ZonePoolApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.ZonePool)
				if !ok {
					panic(fmt.Sprintf("RunZonePoolApi expected dataOut type *[]edgeproto.ZonePool, but was %T", dataOut))
				}
				*outp = append(*outp, out...)
			}
		}
	}
}

func (r *Run) ZonePoolApi_ZonePoolMember(data *[]edgeproto.ZonePoolMember, dataMap interface{}, dataOut interface{}) {
	log.DebugLog(log.DebugLevelApi, "API for ZonePoolMember", "mode", r.Mode)
	for ii, objD := range *data {
		obj := &objD
		switch r.Mode {
		case "add":
			out, err := r.client.AddZonePoolMember(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("ZonePoolApi_ZonePoolMember[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunZonePoolApi_ZonePoolMember expected dataOut type *[]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		case "remove":
			out, err := r.client.RemoveZonePoolMember(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("ZonePoolApi_ZonePoolMember[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunZonePoolApi_ZonePoolMember expected dataOut type *[]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		}
	}
}

func (s *DummyServer) CreateZonePool(ctx context.Context, in *edgeproto.ZonePool) (*edgeproto.Result, error) {
	if s.CudNoop {
		return &edgeproto.Result{}, nil
	}
	s.ZonePoolCache.Update(ctx, in, 0)
	return &edgeproto.Result{}, nil
}

func (s *DummyServer) DeleteZonePool(ctx context.Context, in *edgeproto.ZonePool) (*edgeproto.Result, error) {
	if s.CudNoop {
		return &edgeproto.Result{}, nil
	}
	s.ZonePoolCache.Delete(ctx, in, 0)
	return &edgeproto.Result{}, nil
}

func (s *DummyServer) UpdateZonePool(ctx context.Context, in *edgeproto.ZonePool) (*edgeproto.Result, error) {
	if s.CudNoop {
		return &edgeproto.Result{}, nil
	}
	s.ZonePoolCache.Update(ctx, in, 0)
	return &edgeproto.Result{}, nil
}

func (s *DummyServer) ShowZonePool(in *edgeproto.ZonePool, server edgeproto.ZonePoolApi_ShowZonePoolServer) error {
	var err error
	obj := &edgeproto.ZonePool{}
	if obj.Matches(in, edgeproto.MatchFilter()) {
		for ii := 0; ii < s.ShowDummyCount; ii++ {
			server.Send(&edgeproto.ZonePool{})
		}
		if ch, ok := s.MidstreamFailChs["ShowZonePool"]; ok {
			// Wait until client receives the SendMsg, since they
			// are buffered and dropped once we return err here.
			select {
			case <-ch:
			case <-time.After(5 * time.Second):
			}
			return fmt.Errorf("midstream failure!")
		}
	}
	err = s.ZonePoolCache.Show(in, func(obj *edgeproto.ZonePool) error {
		err := server.Send(obj)
		return err
	})
	return err
}

func (s *ApiClient) CreateZonePool(ctx context.Context, in *edgeproto.ZonePool) (*edgeproto.Result, error) {
	api := edgeproto.NewZonePoolApiClient(s.Conn)
	return api.CreateZonePool(ctx, in)
}

func (s *CliClient) CreateZonePool(ctx context.Context, in *edgeproto.ZonePool) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "CreateZonePool")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

func (s *ApiClient) DeleteZonePool(ctx context.Context, in *edgeproto.ZonePool) (*edgeproto.Result, error) {
	api := edgeproto.NewZonePoolApiClient(s.Conn)
	return api.DeleteZonePool(ctx, in)
}

func (s *CliClient) DeleteZonePool(ctx context.Context, in *edgeproto.ZonePool) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "DeleteZonePool")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

func (s *ApiClient) UpdateZonePool(ctx context.Context, in *edgeproto.ZonePool) (*edgeproto.Result, error) {
	api := edgeproto.NewZonePoolApiClient(s.Conn)
	return api.UpdateZonePool(ctx, in)
}

func (s *CliClient) UpdateZonePool(ctx context.Context, in *edgeproto.ZonePool) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "UpdateZonePool")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

type ZonePoolStream interface {
	Recv() (*edgeproto.ZonePool, error)
}

func ZonePoolReadStream(stream ZonePoolStream) ([]edgeproto.ZonePool, error) {
	output := []edgeproto.ZonePool{}
	for {
		obj, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return output, fmt.Errorf("read ZonePool stream failed, %v", err)
		}
		output = append(output, *obj)
	}
	return output, nil
}

func (s *ApiClient) ShowZonePool(ctx context.Context, in *edgeproto.ZonePool) ([]edgeproto.ZonePool, error) {
	api := edgeproto.NewZonePoolApiClient(s.Conn)
	stream, err := api.ShowZonePool(ctx, in)
	if err != nil {
		return nil, err
	}
	return ZonePoolReadStream(stream)
}

func (s *CliClient) ShowZonePool(ctx context.Context, in *edgeproto.ZonePool) ([]edgeproto.ZonePool, error) {
	output := []edgeproto.ZonePool{}
	args := append(s.BaseArgs, "controller", "ShowZonePool")
	err := wrapper.RunEdgectlObjs(args, in, &output, s.RunOps...)
	return output, err
}

func (s *ApiClient) AddZonePoolMember(ctx context.Context, in *edgeproto.ZonePoolMember) (*edgeproto.Result, error) {
	api := edgeproto.NewZonePoolApiClient(s.Conn)
	return api.AddZonePoolMember(ctx, in)
}

func (s *CliClient) AddZonePoolMember(ctx context.Context, in *edgeproto.ZonePoolMember) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "AddZonePoolMember")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

func (s *ApiClient) RemoveZonePoolMember(ctx context.Context, in *edgeproto.ZonePoolMember) (*edgeproto.Result, error) {
	api := edgeproto.NewZonePoolApiClient(s.Conn)
	return api.RemoveZonePoolMember(ctx, in)
}

func (s *CliClient) RemoveZonePoolMember(ctx context.Context, in *edgeproto.ZonePoolMember) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "RemoveZonePoolMember")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

type ZonePoolApiClient interface {
	CreateZonePool(ctx context.Context, in *edgeproto.ZonePool) (*edgeproto.Result, error)
	DeleteZonePool(ctx context.Context, in *edgeproto.ZonePool) (*edgeproto.Result, error)
	UpdateZonePool(ctx context.Context, in *edgeproto.ZonePool) (*edgeproto.Result, error)
	ShowZonePool(ctx context.Context, in *edgeproto.ZonePool) ([]edgeproto.ZonePool, error)
	AddZonePoolMember(ctx context.Context, in *edgeproto.ZonePoolMember) (*edgeproto.Result, error)
	RemoveZonePoolMember(ctx context.Context, in *edgeproto.ZonePoolMember) (*edgeproto.Result, error)
}
