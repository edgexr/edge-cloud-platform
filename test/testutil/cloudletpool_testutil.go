// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: cloudletpool.proto

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

type ShowCloudletPool struct {
	Data map[string]edgeproto.CloudletPool
	grpc.ServerStream
	Ctx context.Context
}

func (x *ShowCloudletPool) Init() {
	x.Data = make(map[string]edgeproto.CloudletPool)
}

func (x *ShowCloudletPool) Send(m *edgeproto.CloudletPool) error {
	x.Data[m.GetKey().GetKeyString()] = *m
	return nil
}

func (x *ShowCloudletPool) Context() context.Context {
	return x.Ctx
}

var CloudletPoolShowExtraCount = 0

func (x *ShowCloudletPool) ReadStream(stream edgeproto.CloudletPoolApi_ShowCloudletPoolClient, err error) {
	x.Data = make(map[string]edgeproto.CloudletPool)
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

func (x *ShowCloudletPool) CheckFound(obj *edgeproto.CloudletPool) bool {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	return found
}

func (x *ShowCloudletPool) AssertFound(t *testing.T, obj *edgeproto.CloudletPool) {
	check, found := x.Data[obj.GetKey().GetKeyString()]
	require.True(t, found, "find CloudletPool %s", obj.GetKey().GetKeyString())
	if found && !check.Matches(obj, edgeproto.MatchIgnoreBackend(), edgeproto.MatchSortArrayedKeys()) {
		require.Equal(t, *obj, check, "CloudletPool are equal")
	}
	if found {
		// remove in case there are dups in the list, so the
		// same object cannot be used again
		delete(x.Data, obj.GetKey().GetKeyString())
	}
}

func (x *ShowCloudletPool) AssertNotFound(t *testing.T, obj *edgeproto.CloudletPool) {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	require.False(t, found, "do not find CloudletPool %s", obj.GetKey().GetKeyString())
}

func WaitAssertFoundCloudletPool(t *testing.T, api edgeproto.CloudletPoolApiClient, obj *edgeproto.CloudletPool, count int, retry time.Duration) {
	show := ShowCloudletPool{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowCloudletPool(ctx, obj)
		show.ReadStream(stream, err)
		cancel()
		if show.CheckFound(obj) {
			break
		}
		time.Sleep(retry)
	}
	show.AssertFound(t, obj)
}

func WaitAssertNotFoundCloudletPool(t *testing.T, api edgeproto.CloudletPoolApiClient, obj *edgeproto.CloudletPool, count int, retry time.Duration) {
	show := ShowCloudletPool{}
	filterNone := edgeproto.CloudletPool{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowCloudletPool(ctx, &filterNone)
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
type CloudletPoolCommonApi struct {
	internal_api edgeproto.CloudletPoolApiServer
	client_api   edgeproto.CloudletPoolApiClient
}

func (x *CloudletPoolCommonApi) CreateCloudletPool(ctx context.Context, in *edgeproto.CloudletPool) (*edgeproto.Result, error) {
	copy := &edgeproto.CloudletPool{}
	*copy = *in
	if x.internal_api != nil {
		return x.internal_api.CreateCloudletPool(ctx, copy)
	} else {
		res, err := x.client_api.CreateCloudletPool(ctx, copy)
		return res, unwrapGrpcError(err)
	}
}

func (x *CloudletPoolCommonApi) DeleteCloudletPool(ctx context.Context, in *edgeproto.CloudletPool) (*edgeproto.Result, error) {
	copy := &edgeproto.CloudletPool{}
	*copy = *in
	if x.internal_api != nil {
		return x.internal_api.DeleteCloudletPool(ctx, copy)
	} else {
		res, err := x.client_api.DeleteCloudletPool(ctx, copy)
		return res, unwrapGrpcError(err)
	}
}

func (x *CloudletPoolCommonApi) ShowCloudletPool(ctx context.Context, filter *edgeproto.CloudletPool, showData *ShowCloudletPool) error {
	if x.internal_api != nil {
		showData.Ctx = ctx
		return x.internal_api.ShowCloudletPool(filter, showData)
	} else {
		stream, err := x.client_api.ShowCloudletPool(ctx, filter)
		showData.ReadStream(stream, err)
		return unwrapGrpcError(err)
	}
}

func NewInternalCloudletPoolApi(api edgeproto.CloudletPoolApiServer) *CloudletPoolCommonApi {
	apiWrap := CloudletPoolCommonApi{}
	apiWrap.internal_api = api
	return &apiWrap
}

func NewClientCloudletPoolApi(api edgeproto.CloudletPoolApiClient) *CloudletPoolCommonApi {
	apiWrap := CloudletPoolCommonApi{}
	apiWrap.client_api = api
	return &apiWrap
}

type CloudletPoolTestOptions struct {
	createdData []edgeproto.CloudletPool
}

type CloudletPoolTestOp func(opts *CloudletPoolTestOptions)

func WithCreatedCloudletPoolTestData(createdData []edgeproto.CloudletPool) CloudletPoolTestOp {
	return func(opts *CloudletPoolTestOptions) { opts.createdData = createdData }
}

func InternalCloudletPoolTest(t *testing.T, test string, api edgeproto.CloudletPoolApiServer, testData []edgeproto.CloudletPool, ops ...CloudletPoolTestOp) {
	span := log.StartSpan(log.DebugLevelApi, "InternalCloudletPoolTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "cud":
		basicCloudletPoolCudTest(t, ctx, NewInternalCloudletPoolApi(api), testData, ops...)
	case "show":
		basicCloudletPoolShowTest(t, ctx, NewInternalCloudletPoolApi(api), testData)
	}
}

func ClientCloudletPoolTest(t *testing.T, test string, api edgeproto.CloudletPoolApiClient, testData []edgeproto.CloudletPool, ops ...CloudletPoolTestOp) {
	span := log.StartSpan(log.DebugLevelApi, "ClientCloudletPoolTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "cud":
		basicCloudletPoolCudTest(t, ctx, NewClientCloudletPoolApi(api), testData, ops...)
	case "show":
		basicCloudletPoolShowTest(t, ctx, NewClientCloudletPoolApi(api), testData)
	}
}

func basicCloudletPoolShowTest(t *testing.T, ctx context.Context, api *CloudletPoolCommonApi, testData []edgeproto.CloudletPool) {
	var err error

	show := ShowCloudletPool{}
	show.Init()
	filterNone := edgeproto.CloudletPool{}
	err = api.ShowCloudletPool(ctx, &filterNone, &show)
	require.Nil(t, err, "show data")
	require.Equal(t, len(testData)+CloudletPoolShowExtraCount, len(show.Data), "Show count")
	for _, obj := range testData {
		show.AssertFound(t, &obj)
	}
}

func GetCloudletPool(t *testing.T, ctx context.Context, api *CloudletPoolCommonApi, key *edgeproto.CloudletPoolKey, out *edgeproto.CloudletPool) bool {
	var err error

	show := ShowCloudletPool{}
	show.Init()
	filter := edgeproto.CloudletPool{}
	filter.SetKey(key)
	err = api.ShowCloudletPool(ctx, &filter, &show)
	require.Nil(t, err, "show data")
	obj, found := show.Data[key.GetKeyString()]
	if found {
		*out = obj
	}
	return found
}

func basicCloudletPoolCudTest(t *testing.T, ctx context.Context, api *CloudletPoolCommonApi, testData []edgeproto.CloudletPool, ops ...CloudletPoolTestOp) {
	var err error

	if len(testData) < 3 {
		require.True(t, false, "Need at least 3 test data objects")
		return
	}
	options := CloudletPoolTestOptions{}
	for _, op := range ops {
		op(&options)
	}
	createdData := testData
	if options.createdData != nil {
		createdData = options.createdData
	}

	// test create
	CreateCloudletPoolData(t, ctx, api, testData)

	// test duplicate Create - should fail
	_, err = api.CreateCloudletPool(ctx, &testData[0])
	require.NotNil(t, err, "Create duplicate CloudletPool")

	// test show all items
	basicCloudletPoolShowTest(t, ctx, api, createdData)

	// test Delete
	_, err = api.DeleteCloudletPool(ctx, &createdData[0])
	require.Nil(t, err, "Delete CloudletPool %s", testData[0].GetKey().GetKeyString())
	show := ShowCloudletPool{}
	show.Init()
	filterNone := edgeproto.CloudletPool{}
	err = api.ShowCloudletPool(ctx, &filterNone, &show)
	require.Nil(t, err, "show data")
	require.Equal(t, len(createdData)-1+CloudletPoolShowExtraCount, len(show.Data), "Show count")
	show.AssertNotFound(t, &createdData[0])
	// Create it back
	_, err = api.CreateCloudletPool(ctx, &testData[0])
	require.Nil(t, err, "Create CloudletPool %s", testData[0].GetKey().GetKeyString())

	// test invalid keys
	bad := edgeproto.CloudletPool{}
	_, err = api.CreateCloudletPool(ctx, &bad)
	require.NotNil(t, err, "Create CloudletPool with no key info")

}

func InternalCloudletPoolCreate(t *testing.T, api edgeproto.CloudletPoolApiServer, testData []edgeproto.CloudletPool) {
	span := log.StartSpan(log.DebugLevelApi, "InternalCloudletPoolCreate")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	CreateCloudletPoolData(t, ctx, NewInternalCloudletPoolApi(api), testData)
}

func ClientCloudletPoolCreate(t *testing.T, api edgeproto.CloudletPoolApiClient, testData []edgeproto.CloudletPool) {
	span := log.StartSpan(log.DebugLevelApi, "ClientCloudletPoolCreate")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	CreateCloudletPoolData(t, ctx, NewClientCloudletPoolApi(api), testData)
}

func CreateCloudletPoolData(t *testing.T, ctx context.Context, api *CloudletPoolCommonApi, testData []edgeproto.CloudletPool) {
	var err error

	for ii := range testData {
		obj := testData[ii]
		_, err = api.CreateCloudletPool(ctx, &obj)
		require.Nil(t, err, "Create CloudletPool %s", obj.GetKey().GetKeyString())
	}
}

func InternalCloudletPoolDelete(t *testing.T, api edgeproto.CloudletPoolApiServer, testData []edgeproto.CloudletPool) {
	span := log.StartSpan(log.DebugLevelApi, "InternalCloudletPoolDelete")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	DeleteCloudletPoolData(t, ctx, NewInternalCloudletPoolApi(api), testData)
}

func ClientCloudletPoolDelete(t *testing.T, api edgeproto.CloudletPoolApiClient, testData []edgeproto.CloudletPool) {
	span := log.StartSpan(log.DebugLevelApi, "ClientCloudletPoolDelete")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	DeleteCloudletPoolData(t, ctx, NewClientCloudletPoolApi(api), testData)
}

func DeleteCloudletPoolData(t *testing.T, ctx context.Context, api *CloudletPoolCommonApi, testData []edgeproto.CloudletPool) {
	var err error

	for ii := range testData {
		obj := testData[ii]
		_, err = api.DeleteCloudletPool(ctx, &obj)
		require.Nil(t, err, "Delete CloudletPool %s", obj.GetKey().GetKeyString())
	}
}

func FindCloudletPoolData(key *edgeproto.CloudletPoolKey, testData []edgeproto.CloudletPool) (*edgeproto.CloudletPool, bool) {
	for ii, _ := range testData {
		if testData[ii].GetKey().Matches(key) {
			return &testData[ii], true
		}
	}
	return nil, false
}

func (r *Run) CloudletPoolApi(data *[]edgeproto.CloudletPool, dataMap interface{}, dataOut interface{}) {
	log.DebugLog(log.DebugLevelApi, "API for CloudletPool", "mode", r.Mode)
	if r.Mode == "show" {
		obj := &edgeproto.CloudletPool{}
		out, err := r.client.ShowCloudletPool(r.ctx, obj)
		if err != nil {
			r.logErr("CloudletPoolApi", err)
		} else {
			outp, ok := dataOut.(*[]edgeproto.CloudletPool)
			if !ok {
				panic(fmt.Sprintf("RunCloudletPoolApi expected dataOut type *[]edgeproto.CloudletPool, but was %T", dataOut))
			}
			*outp = append(*outp, out...)
		}
		return
	}
	for ii, objD := range *data {
		obj := &objD
		switch r.Mode {
		case "create":
			out, err := r.client.CreateCloudletPool(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("CloudletPoolApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunCloudletPoolApi expected dataOut type *[]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		case "delete":
			out, err := r.client.DeleteCloudletPool(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("CloudletPoolApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunCloudletPoolApi expected dataOut type *[]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		case "update":
			// set specified fields
			objMap, err := cli.GetGenericObjFromList(dataMap, ii)
			if err != nil {
				log.DebugLog(log.DebugLevelApi, "bad dataMap for CloudletPool", "err", err)
				*r.Rc = false
				return
			}
			yamlData := cli.MapData{
				Namespace: cli.YamlNamespace,
				Data:      objMap,
			}
			obj.Fields = cli.GetSpecifiedFields(&yamlData, obj)

			out, err := r.client.UpdateCloudletPool(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("CloudletPoolApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunCloudletPoolApi expected dataOut type *[]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		case "showfiltered":
			out, err := r.client.ShowCloudletPool(r.ctx, obj)
			if err != nil {
				r.logErr(fmt.Sprintf("CloudletPoolApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.CloudletPool)
				if !ok {
					panic(fmt.Sprintf("RunCloudletPoolApi expected dataOut type *[]edgeproto.CloudletPool, but was %T", dataOut))
				}
				*outp = append(*outp, out...)
			}
		}
	}
}

func (r *Run) CloudletPoolApi_CloudletPoolMember(data *[]edgeproto.CloudletPoolMember, dataMap interface{}, dataOut interface{}) {
	log.DebugLog(log.DebugLevelApi, "API for CloudletPoolMember", "mode", r.Mode)
	for ii, objD := range *data {
		obj := &objD
		switch r.Mode {
		case "add":
			out, err := r.client.AddCloudletPoolMember(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("CloudletPoolApi_CloudletPoolMember[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunCloudletPoolApi_CloudletPoolMember expected dataOut type *[]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		case "remove":
			out, err := r.client.RemoveCloudletPoolMember(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("CloudletPoolApi_CloudletPoolMember[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunCloudletPoolApi_CloudletPoolMember expected dataOut type *[]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		}
	}
}

func (s *DummyServer) CreateCloudletPool(ctx context.Context, in *edgeproto.CloudletPool) (*edgeproto.Result, error) {
	if s.CudNoop {
		return &edgeproto.Result{}, nil
	}
	s.CloudletPoolCache.Update(ctx, in, 0)
	return &edgeproto.Result{}, nil
}

func (s *DummyServer) DeleteCloudletPool(ctx context.Context, in *edgeproto.CloudletPool) (*edgeproto.Result, error) {
	if s.CudNoop {
		return &edgeproto.Result{}, nil
	}
	s.CloudletPoolCache.Delete(ctx, in, 0)
	return &edgeproto.Result{}, nil
}

func (s *DummyServer) UpdateCloudletPool(ctx context.Context, in *edgeproto.CloudletPool) (*edgeproto.Result, error) {
	if s.CudNoop {
		return &edgeproto.Result{}, nil
	}
	s.CloudletPoolCache.Update(ctx, in, 0)
	return &edgeproto.Result{}, nil
}

func (s *DummyServer) ShowCloudletPool(in *edgeproto.CloudletPool, server edgeproto.CloudletPoolApi_ShowCloudletPoolServer) error {
	var err error
	obj := &edgeproto.CloudletPool{}
	if obj.Matches(in, edgeproto.MatchFilter()) {
		for ii := 0; ii < s.ShowDummyCount; ii++ {
			server.Send(&edgeproto.CloudletPool{})
		}
		if ch, ok := s.MidstreamFailChs["ShowCloudletPool"]; ok {
			// Wait until client receives the SendMsg, since they
			// are buffered and dropped once we return err here.
			select {
			case <-ch:
			case <-time.After(5 * time.Second):
			}
			return fmt.Errorf("midstream failure!")
		}
	}
	err = s.CloudletPoolCache.Show(in, func(obj *edgeproto.CloudletPool) error {
		err := server.Send(obj)
		return err
	})
	return err
}

func (s *ApiClient) CreateCloudletPool(ctx context.Context, in *edgeproto.CloudletPool) (*edgeproto.Result, error) {
	api := edgeproto.NewCloudletPoolApiClient(s.Conn)
	return api.CreateCloudletPool(ctx, in)
}

func (s *CliClient) CreateCloudletPool(ctx context.Context, in *edgeproto.CloudletPool) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "CreateCloudletPool")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

func (s *ApiClient) DeleteCloudletPool(ctx context.Context, in *edgeproto.CloudletPool) (*edgeproto.Result, error) {
	api := edgeproto.NewCloudletPoolApiClient(s.Conn)
	return api.DeleteCloudletPool(ctx, in)
}

func (s *CliClient) DeleteCloudletPool(ctx context.Context, in *edgeproto.CloudletPool) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "DeleteCloudletPool")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

func (s *ApiClient) UpdateCloudletPool(ctx context.Context, in *edgeproto.CloudletPool) (*edgeproto.Result, error) {
	api := edgeproto.NewCloudletPoolApiClient(s.Conn)
	return api.UpdateCloudletPool(ctx, in)
}

func (s *CliClient) UpdateCloudletPool(ctx context.Context, in *edgeproto.CloudletPool) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "UpdateCloudletPool")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

type CloudletPoolStream interface {
	Recv() (*edgeproto.CloudletPool, error)
}

func CloudletPoolReadStream(stream CloudletPoolStream) ([]edgeproto.CloudletPool, error) {
	output := []edgeproto.CloudletPool{}
	for {
		obj, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return output, fmt.Errorf("read CloudletPool stream failed, %v", err)
		}
		output = append(output, *obj)
	}
	return output, nil
}

func (s *ApiClient) ShowCloudletPool(ctx context.Context, in *edgeproto.CloudletPool) ([]edgeproto.CloudletPool, error) {
	api := edgeproto.NewCloudletPoolApiClient(s.Conn)
	stream, err := api.ShowCloudletPool(ctx, in)
	if err != nil {
		return nil, err
	}
	return CloudletPoolReadStream(stream)
}

func (s *CliClient) ShowCloudletPool(ctx context.Context, in *edgeproto.CloudletPool) ([]edgeproto.CloudletPool, error) {
	output := []edgeproto.CloudletPool{}
	args := append(s.BaseArgs, "controller", "ShowCloudletPool")
	err := wrapper.RunEdgectlObjs(args, in, &output, s.RunOps...)
	return output, err
}

func (s *ApiClient) AddCloudletPoolMember(ctx context.Context, in *edgeproto.CloudletPoolMember) (*edgeproto.Result, error) {
	api := edgeproto.NewCloudletPoolApiClient(s.Conn)
	return api.AddCloudletPoolMember(ctx, in)
}

func (s *CliClient) AddCloudletPoolMember(ctx context.Context, in *edgeproto.CloudletPoolMember) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "AddCloudletPoolMember")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

func (s *ApiClient) RemoveCloudletPoolMember(ctx context.Context, in *edgeproto.CloudletPoolMember) (*edgeproto.Result, error) {
	api := edgeproto.NewCloudletPoolApiClient(s.Conn)
	return api.RemoveCloudletPoolMember(ctx, in)
}

func (s *CliClient) RemoveCloudletPoolMember(ctx context.Context, in *edgeproto.CloudletPoolMember) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "RemoveCloudletPoolMember")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

type CloudletPoolApiClient interface {
	CreateCloudletPool(ctx context.Context, in *edgeproto.CloudletPool) (*edgeproto.Result, error)
	DeleteCloudletPool(ctx context.Context, in *edgeproto.CloudletPool) (*edgeproto.Result, error)
	UpdateCloudletPool(ctx context.Context, in *edgeproto.CloudletPool) (*edgeproto.Result, error)
	ShowCloudletPool(ctx context.Context, in *edgeproto.CloudletPool) ([]edgeproto.CloudletPool, error)
	AddCloudletPoolMember(ctx context.Context, in *edgeproto.CloudletPoolMember) (*edgeproto.Result, error)
	RemoveCloudletPoolMember(ctx context.Context, in *edgeproto.CloudletPoolMember) (*edgeproto.Result, error)
}
