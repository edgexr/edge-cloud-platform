// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: flavor.proto

package testutil

import (
	"context"
	fmt "fmt"
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
		res, err := x.client_api.CreateFlavor(ctx, copy)
		return res, unwrapGrpcError(err)
	}
}

func (x *FlavorCommonApi) DeleteFlavor(ctx context.Context, in *edgeproto.Flavor) (*edgeproto.Result, error) {
	copy := &edgeproto.Flavor{}
	*copy = *in
	if x.internal_api != nil {
		return x.internal_api.DeleteFlavor(ctx, copy)
	} else {
		res, err := x.client_api.DeleteFlavor(ctx, copy)
		return res, unwrapGrpcError(err)
	}
}

func (x *FlavorCommonApi) UpdateFlavor(ctx context.Context, in *edgeproto.Flavor) (*edgeproto.Result, error) {
	copy := &edgeproto.Flavor{}
	*copy = *in
	if x.internal_api != nil {
		return x.internal_api.UpdateFlavor(ctx, copy)
	} else {
		res, err := x.client_api.UpdateFlavor(ctx, copy)
		return res, unwrapGrpcError(err)
	}
}

func (x *FlavorCommonApi) ShowFlavor(ctx context.Context, filter *edgeproto.Flavor, showData *ShowFlavor) error {
	if x.internal_api != nil {
		showData.Ctx = ctx
		return x.internal_api.ShowFlavor(filter, showData)
	} else {
		stream, err := x.client_api.ShowFlavor(ctx, filter)
		showData.ReadStream(stream, err)
		return unwrapGrpcError(err)
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

type FlavorTestOptions struct {
	createdData []edgeproto.Flavor
}

type FlavorTestOp func(opts *FlavorTestOptions)

func WithCreatedFlavorTestData(createdData []edgeproto.Flavor) FlavorTestOp {
	return func(opts *FlavorTestOptions) { opts.createdData = createdData }
}

func InternalFlavorTest(t *testing.T, test string, api edgeproto.FlavorApiServer, testData []edgeproto.Flavor, ops ...FlavorTestOp) {
	span := log.StartSpan(log.DebugLevelApi, "InternalFlavorTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "cud":
		basicFlavorCudTest(t, ctx, NewInternalFlavorApi(api), testData, ops...)
	case "show":
		basicFlavorShowTest(t, ctx, NewInternalFlavorApi(api), testData)
	}
}

func ClientFlavorTest(t *testing.T, test string, api edgeproto.FlavorApiClient, testData []edgeproto.Flavor, ops ...FlavorTestOp) {
	span := log.StartSpan(log.DebugLevelApi, "ClientFlavorTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "cud":
		basicFlavorCudTest(t, ctx, NewClientFlavorApi(api), testData, ops...)
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

func basicFlavorCudTest(t *testing.T, ctx context.Context, api *FlavorCommonApi, testData []edgeproto.Flavor, ops ...FlavorTestOp) {
	var err error

	if len(testData) < 3 {
		require.True(t, false, "Need at least 3 test data objects")
		return
	}
	options := FlavorTestOptions{}
	for _, op := range ops {
		op(&options)
	}
	createdData := testData
	if options.createdData != nil {
		createdData = options.createdData
	}

	// test create
	CreateFlavorData(t, ctx, api, testData)

	// test duplicate Create - should fail
	_, err = api.CreateFlavor(ctx, &testData[0])
	require.NotNil(t, err, "Create duplicate Flavor")

	// test show all items
	basicFlavorShowTest(t, ctx, api, createdData)

	// test Delete
	_, err = api.DeleteFlavor(ctx, &createdData[0])
	require.Nil(t, err, "Delete Flavor %s", testData[0].GetKey().GetKeyString())
	show := ShowFlavor{}
	show.Init()
	filterNone := edgeproto.Flavor{}
	err = api.ShowFlavor(ctx, &filterNone, &show)
	require.Nil(t, err, "show data")
	require.Equal(t, len(createdData)-1+FlavorShowExtraCount, len(show.Data), "Show count")
	show.AssertNotFound(t, &createdData[0])
	// test update of missing object
	_, err = api.UpdateFlavor(ctx, &createdData[0])
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

	for ii := range testData {
		obj := testData[ii]
		_, err = api.CreateFlavor(ctx, &obj)
		require.Nil(t, err, "Create Flavor %s", obj.GetKey().GetKeyString())
	}
}

func InternalFlavorDelete(t *testing.T, api edgeproto.FlavorApiServer, testData []edgeproto.Flavor) {
	span := log.StartSpan(log.DebugLevelApi, "InternalFlavorDelete")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	DeleteFlavorData(t, ctx, NewInternalFlavorApi(api), testData)
}

func ClientFlavorDelete(t *testing.T, api edgeproto.FlavorApiClient, testData []edgeproto.Flavor) {
	span := log.StartSpan(log.DebugLevelApi, "ClientFlavorDelete")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	DeleteFlavorData(t, ctx, NewClientFlavorApi(api), testData)
}

func DeleteFlavorData(t *testing.T, ctx context.Context, api *FlavorCommonApi, testData []edgeproto.Flavor) {
	var err error

	for ii := range testData {
		obj := testData[ii]
		_, err = api.DeleteFlavor(ctx, &obj)
		require.Nil(t, err, "Delete Flavor %s", obj.GetKey().GetKeyString())
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

func (r *Run) FlavorApi(data *[]edgeproto.Flavor, dataMap interface{}, dataOut interface{}) {
	log.DebugLog(log.DebugLevelApi, "API for Flavor", "mode", r.Mode)
	if r.Mode == "show" {
		obj := &edgeproto.Flavor{}
		out, err := r.client.ShowFlavor(r.ctx, obj)
		if err != nil {
			r.logErr("FlavorApi", err)
		} else {
			outp, ok := dataOut.(*[]edgeproto.Flavor)
			if !ok {
				panic(fmt.Sprintf("RunFlavorApi expected dataOut type *[]edgeproto.Flavor, but was %T", dataOut))
			}
			*outp = append(*outp, out...)
		}
		return
	}
	for ii, objD := range *data {
		obj := &objD
		switch r.Mode {
		case "create":
			out, err := r.client.CreateFlavor(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("FlavorApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunFlavorApi expected dataOut type *[]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		case "delete":
			out, err := r.client.DeleteFlavor(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("FlavorApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunFlavorApi expected dataOut type *[]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		case "update":
			// set specified fields
			objMap, err := cli.GetGenericObjFromList(dataMap, ii)
			if err != nil {
				log.DebugLog(log.DebugLevelApi, "bad dataMap for Flavor", "err", err)
				*r.Rc = false
				return
			}
			yamlData := cli.MapData{
				Namespace: cli.YamlNamespace,
				Data:      objMap,
			}
			obj.Fields = cli.GetSpecifiedFields(&yamlData, obj)

			out, err := r.client.UpdateFlavor(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("FlavorApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunFlavorApi expected dataOut type *[]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		case "showfiltered":
			out, err := r.client.ShowFlavor(r.ctx, obj)
			if err != nil {
				r.logErr(fmt.Sprintf("FlavorApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Flavor)
				if !ok {
					panic(fmt.Sprintf("RunFlavorApi expected dataOut type *[]edgeproto.Flavor, but was %T", dataOut))
				}
				*outp = append(*outp, out...)
			}
		case "addflavorres":
			out, err := r.client.AddFlavorRes(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("FlavorApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunFlavorApi expected dataOut type *[]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		case "removeflavorres":
			out, err := r.client.RemoveFlavorRes(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("FlavorApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunFlavorApi expected dataOut type *[]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		}
	}
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
		if ch, ok := s.MidstreamFailChs["ShowFlavor"]; ok {
			// Wait until client receives the SendMsg, since they
			// are buffered and dropped once we return err here.
			select {
			case <-ch:
			case <-time.After(5 * time.Second):
			}
			return fmt.Errorf("midstream failure!")
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

func (s *ApiClient) CreateFlavor(ctx context.Context, in *edgeproto.Flavor) (*edgeproto.Result, error) {
	api := edgeproto.NewFlavorApiClient(s.Conn)
	return api.CreateFlavor(ctx, in)
}

func (s *CliClient) CreateFlavor(ctx context.Context, in *edgeproto.Flavor) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "CreateFlavor")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

func (s *ApiClient) DeleteFlavor(ctx context.Context, in *edgeproto.Flavor) (*edgeproto.Result, error) {
	api := edgeproto.NewFlavorApiClient(s.Conn)
	return api.DeleteFlavor(ctx, in)
}

func (s *CliClient) DeleteFlavor(ctx context.Context, in *edgeproto.Flavor) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "DeleteFlavor")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

func (s *ApiClient) UpdateFlavor(ctx context.Context, in *edgeproto.Flavor) (*edgeproto.Result, error) {
	api := edgeproto.NewFlavorApiClient(s.Conn)
	return api.UpdateFlavor(ctx, in)
}

func (s *CliClient) UpdateFlavor(ctx context.Context, in *edgeproto.Flavor) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "UpdateFlavor")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

type FlavorStream interface {
	Recv() (*edgeproto.Flavor, error)
}

func FlavorReadStream(stream FlavorStream) ([]edgeproto.Flavor, error) {
	output := []edgeproto.Flavor{}
	for {
		obj, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return output, fmt.Errorf("read Flavor stream failed, %v", err)
		}
		output = append(output, *obj)
	}
	return output, nil
}

func (s *ApiClient) ShowFlavor(ctx context.Context, in *edgeproto.Flavor) ([]edgeproto.Flavor, error) {
	api := edgeproto.NewFlavorApiClient(s.Conn)
	stream, err := api.ShowFlavor(ctx, in)
	if err != nil {
		return nil, err
	}
	return FlavorReadStream(stream)
}

func (s *CliClient) ShowFlavor(ctx context.Context, in *edgeproto.Flavor) ([]edgeproto.Flavor, error) {
	output := []edgeproto.Flavor{}
	args := append(s.BaseArgs, "controller", "ShowFlavor")
	err := wrapper.RunEdgectlObjs(args, in, &output, s.RunOps...)
	return output, err
}

func (s *ApiClient) AddFlavorRes(ctx context.Context, in *edgeproto.Flavor) (*edgeproto.Result, error) {
	api := edgeproto.NewFlavorApiClient(s.Conn)
	return api.AddFlavorRes(ctx, in)
}

func (s *CliClient) AddFlavorRes(ctx context.Context, in *edgeproto.Flavor) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "AddFlavorRes")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

func (s *ApiClient) RemoveFlavorRes(ctx context.Context, in *edgeproto.Flavor) (*edgeproto.Result, error) {
	api := edgeproto.NewFlavorApiClient(s.Conn)
	return api.RemoveFlavorRes(ctx, in)
}

func (s *CliClient) RemoveFlavorRes(ctx context.Context, in *edgeproto.Flavor) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "RemoveFlavorRes")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

type FlavorApiClient interface {
	CreateFlavor(ctx context.Context, in *edgeproto.Flavor) (*edgeproto.Result, error)
	DeleteFlavor(ctx context.Context, in *edgeproto.Flavor) (*edgeproto.Result, error)
	UpdateFlavor(ctx context.Context, in *edgeproto.Flavor) (*edgeproto.Result, error)
	ShowFlavor(ctx context.Context, in *edgeproto.Flavor) ([]edgeproto.Flavor, error)
	AddFlavorRes(ctx context.Context, in *edgeproto.Flavor) (*edgeproto.Result, error)
	RemoveFlavorRes(ctx context.Context, in *edgeproto.Flavor) (*edgeproto.Result, error)
}
