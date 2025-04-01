// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: zone.proto

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

type ShowZone struct {
	Data map[string]edgeproto.Zone
	grpc.ServerStream
	Ctx context.Context
}

func (x *ShowZone) Init() {
	x.Data = make(map[string]edgeproto.Zone)
}

func (x *ShowZone) Send(m *edgeproto.Zone) error {
	x.Data[m.GetKey().GetKeyString()] = *m
	return nil
}

func (x *ShowZone) Context() context.Context {
	return x.Ctx
}

var ZoneShowExtraCount = 0

func (x *ShowZone) ReadStream(stream edgeproto.ZoneApi_ShowZoneClient, err error) {
	x.Data = make(map[string]edgeproto.Zone)
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

func (x *ShowZone) CheckFound(obj *edgeproto.Zone) bool {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	return found
}

func (x *ShowZone) AssertFound(t *testing.T, obj *edgeproto.Zone) {
	check, found := x.Data[obj.GetKey().GetKeyString()]
	require.True(t, found, "find Zone %s", obj.GetKey().GetKeyString())
	if found && !check.Matches(obj, edgeproto.MatchIgnoreBackend(), edgeproto.MatchSortArrayedKeys()) {
		require.Equal(t, *obj, check, "Zone are equal")
	}
	if found {
		// remove in case there are dups in the list, so the
		// same object cannot be used again
		delete(x.Data, obj.GetKey().GetKeyString())
	}
}

func (x *ShowZone) AssertNotFound(t *testing.T, obj *edgeproto.Zone) {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	require.False(t, found, "do not find Zone %s", obj.GetKey().GetKeyString())
}

func WaitAssertFoundZone(t *testing.T, api edgeproto.ZoneApiClient, obj *edgeproto.Zone, count int, retry time.Duration) {
	show := ShowZone{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowZone(ctx, obj)
		show.ReadStream(stream, err)
		cancel()
		if show.CheckFound(obj) {
			break
		}
		time.Sleep(retry)
	}
	show.AssertFound(t, obj)
}

func WaitAssertNotFoundZone(t *testing.T, api edgeproto.ZoneApiClient, obj *edgeproto.Zone, count int, retry time.Duration) {
	show := ShowZone{}
	filterNone := edgeproto.Zone{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowZone(ctx, &filterNone)
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
type ZoneCommonApi struct {
	internal_api edgeproto.ZoneApiServer
	client_api   edgeproto.ZoneApiClient
}

func (x *ZoneCommonApi) CreateZone(ctx context.Context, in *edgeproto.Zone) (*edgeproto.Result, error) {
	copy := &edgeproto.Zone{}
	*copy = *in
	if x.internal_api != nil {
		return x.internal_api.CreateZone(ctx, copy)
	} else {
		res, err := x.client_api.CreateZone(ctx, copy)
		return res, unwrapGrpcError(err)
	}
}

func (x *ZoneCommonApi) DeleteZone(ctx context.Context, in *edgeproto.Zone) (*edgeproto.Result, error) {
	copy := &edgeproto.Zone{}
	*copy = *in
	if x.internal_api != nil {
		return x.internal_api.DeleteZone(ctx, copy)
	} else {
		res, err := x.client_api.DeleteZone(ctx, copy)
		return res, unwrapGrpcError(err)
	}
}

func (x *ZoneCommonApi) ShowZone(ctx context.Context, filter *edgeproto.Zone, showData *ShowZone) error {
	if x.internal_api != nil {
		showData.Ctx = ctx
		return x.internal_api.ShowZone(filter, showData)
	} else {
		stream, err := x.client_api.ShowZone(ctx, filter)
		showData.ReadStream(stream, err)
		return unwrapGrpcError(err)
	}
}

func NewInternalZoneApi(api edgeproto.ZoneApiServer) *ZoneCommonApi {
	apiWrap := ZoneCommonApi{}
	apiWrap.internal_api = api
	return &apiWrap
}

func NewClientZoneApi(api edgeproto.ZoneApiClient) *ZoneCommonApi {
	apiWrap := ZoneCommonApi{}
	apiWrap.client_api = api
	return &apiWrap
}

type ZoneTestOptions struct {
	createdData []edgeproto.Zone
}

type ZoneTestOp func(opts *ZoneTestOptions)

func WithCreatedZoneTestData(createdData []edgeproto.Zone) ZoneTestOp {
	return func(opts *ZoneTestOptions) { opts.createdData = createdData }
}

func InternalZoneTest(t *testing.T, test string, api edgeproto.ZoneApiServer, testData []edgeproto.Zone, ops ...ZoneTestOp) {
	span := log.StartSpan(log.DebugLevelApi, "InternalZoneTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "cud":
		basicZoneCudTest(t, ctx, NewInternalZoneApi(api), testData, ops...)
	case "show":
		basicZoneShowTest(t, ctx, NewInternalZoneApi(api), testData)
	}
}

func ClientZoneTest(t *testing.T, test string, api edgeproto.ZoneApiClient, testData []edgeproto.Zone, ops ...ZoneTestOp) {
	span := log.StartSpan(log.DebugLevelApi, "ClientZoneTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "cud":
		basicZoneCudTest(t, ctx, NewClientZoneApi(api), testData, ops...)
	case "show":
		basicZoneShowTest(t, ctx, NewClientZoneApi(api), testData)
	}
}

func basicZoneShowTest(t *testing.T, ctx context.Context, api *ZoneCommonApi, testData []edgeproto.Zone) {
	var err error

	show := ShowZone{}
	show.Init()
	filterNone := edgeproto.Zone{}
	err = api.ShowZone(ctx, &filterNone, &show)
	require.Nil(t, err, "show data")
	require.Equal(t, len(testData)+ZoneShowExtraCount, len(show.Data), "Show count")
	for _, obj := range testData {
		show.AssertFound(t, &obj)
	}
}

func GetZone(t *testing.T, ctx context.Context, api *ZoneCommonApi, key *edgeproto.ZoneKey, out *edgeproto.Zone) bool {
	var err error

	show := ShowZone{}
	show.Init()
	filter := edgeproto.Zone{}
	filter.SetKey(key)
	err = api.ShowZone(ctx, &filter, &show)
	require.Nil(t, err, "show data")
	obj, found := show.Data[key.GetKeyString()]
	if found {
		*out = obj
	}
	return found
}

func basicZoneCudTest(t *testing.T, ctx context.Context, api *ZoneCommonApi, testData []edgeproto.Zone, ops ...ZoneTestOp) {
	var err error

	if len(testData) < 3 {
		require.True(t, false, "Need at least 3 test data objects")
		return
	}
	options := ZoneTestOptions{}
	for _, op := range ops {
		op(&options)
	}
	createdData := testData
	if options.createdData != nil {
		createdData = options.createdData
	}

	// test create
	CreateZoneData(t, ctx, api, testData)

	// test duplicate Create - should fail
	_, err = api.CreateZone(ctx, &testData[0])
	require.NotNil(t, err, "Create duplicate Zone")

	// test show all items
	basicZoneShowTest(t, ctx, api, createdData)

	// test Delete
	_, err = api.DeleteZone(ctx, &createdData[0])
	require.Nil(t, err, "Delete Zone %s", testData[0].GetKey().GetKeyString())
	show := ShowZone{}
	show.Init()
	filterNone := edgeproto.Zone{}
	err = api.ShowZone(ctx, &filterNone, &show)
	require.Nil(t, err, "show data")
	require.Equal(t, len(createdData)-1+ZoneShowExtraCount, len(show.Data), "Show count")
	show.AssertNotFound(t, &createdData[0])
	// Create it back
	_, err = api.CreateZone(ctx, &testData[0])
	require.Nil(t, err, "Create Zone %s", testData[0].GetKey().GetKeyString())

	// test invalid keys
	bad := edgeproto.Zone{}
	_, err = api.CreateZone(ctx, &bad)
	require.NotNil(t, err, "Create Zone with no key info")

}

func InternalZoneCreate(t *testing.T, api edgeproto.ZoneApiServer, testData []edgeproto.Zone) {
	span := log.StartSpan(log.DebugLevelApi, "InternalZoneCreate")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	CreateZoneData(t, ctx, NewInternalZoneApi(api), testData)
}

func ClientZoneCreate(t *testing.T, api edgeproto.ZoneApiClient, testData []edgeproto.Zone) {
	span := log.StartSpan(log.DebugLevelApi, "ClientZoneCreate")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	CreateZoneData(t, ctx, NewClientZoneApi(api), testData)
}

func CreateZoneData(t *testing.T, ctx context.Context, api *ZoneCommonApi, testData []edgeproto.Zone) {
	var err error

	for ii := range testData {
		obj := testData[ii]
		_, err = api.CreateZone(ctx, &obj)
		require.Nil(t, err, "Create Zone %s", obj.GetKey().GetKeyString())
	}
}

func InternalZoneDelete(t *testing.T, api edgeproto.ZoneApiServer, testData []edgeproto.Zone) {
	span := log.StartSpan(log.DebugLevelApi, "InternalZoneDelete")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	DeleteZoneData(t, ctx, NewInternalZoneApi(api), testData)
}

func InternalZoneDeleteAll(t *testing.T, ctx context.Context, api edgeproto.ZoneApiServer, data []edgeproto.Zone) {
	intapi := NewInternalZoneApi(api)
	log.SpanLog(ctx, log.DebugLevelInfo, "deleting all Zones", "count", len(data))
	DeleteZoneData(t, ctx, intapi, data)
}

func ClientZoneDelete(t *testing.T, api edgeproto.ZoneApiClient, testData []edgeproto.Zone) {
	span := log.StartSpan(log.DebugLevelApi, "ClientZoneDelete")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	DeleteZoneData(t, ctx, NewClientZoneApi(api), testData)
}

func DeleteZoneData(t *testing.T, ctx context.Context, api *ZoneCommonApi, testData []edgeproto.Zone) {
	var err error

	for ii := range testData {
		obj := testData[ii]
		_, err = api.DeleteZone(ctx, &obj)
		require.Nil(t, err, "Delete Zone %s", obj.GetKey().GetKeyString())
	}
}

func FindZoneData(key *edgeproto.ZoneKey, testData []edgeproto.Zone) (*edgeproto.Zone, bool) {
	for ii, _ := range testData {
		if testData[ii].GetKey().Matches(key) {
			return &testData[ii], true
		}
	}
	return nil, false
}

func (r *Run) ZoneApi(data *[]edgeproto.Zone, dataMap interface{}, dataOut interface{}) {
	log.DebugLog(log.DebugLevelApi, "API for Zone", "mode", r.Mode)
	if r.Mode == "show" {
		obj := &edgeproto.Zone{}
		out, err := r.client.ShowZone(r.ctx, obj)
		if err != nil {
			r.logErr("ZoneApi", err)
		} else {
			outp, ok := dataOut.(*[]edgeproto.Zone)
			if !ok {
				panic(fmt.Sprintf("RunZoneApi expected dataOut type *[]edgeproto.Zone, but was %T", dataOut))
			}
			*outp = append(*outp, out...)
		}
		return
	}
	for ii, objD := range *data {
		obj := &objD
		switch r.Mode {
		case "create":
			out, err := r.client.CreateZone(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("ZoneApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunZoneApi expected dataOut type *[]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		case "delete":
			out, err := r.client.DeleteZone(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("ZoneApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunZoneApi expected dataOut type *[]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		case "update":
			// set specified fields
			objMap, err := cli.GetGenericObjFromList(dataMap, ii)
			if err != nil {
				log.DebugLog(log.DebugLevelApi, "bad dataMap for Zone", "err", err)
				*r.Rc = false
				return
			}
			yamlData := cli.MapData{
				Namespace: cli.YamlNamespace,
				Data:      objMap,
			}
			obj.Fields = cli.GetSpecifiedFields(&yamlData, obj)

			out, err := r.client.UpdateZone(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("ZoneApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunZoneApi expected dataOut type *[]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		case "showfiltered":
			out, err := r.client.ShowZone(r.ctx, obj)
			if err != nil {
				r.logErr(fmt.Sprintf("ZoneApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Zone)
				if !ok {
					panic(fmt.Sprintf("RunZoneApi expected dataOut type *[]edgeproto.Zone, but was %T", dataOut))
				}
				*outp = append(*outp, out...)
			}
		case "showzonegpus":
			out, err := r.client.ShowZoneGPUs(r.ctx, obj)
			if err != nil {
				r.logErr(fmt.Sprintf("ZoneApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.ZoneGPUs)
				if !ok {
					panic(fmt.Sprintf("RunZoneApi expected dataOut type *[]edgeproto.ZoneGPUs, but was %T", dataOut))
				}
				*outp = append(*outp, out...)
			}
		}
	}
}

func (s *DummyServer) CreateZone(ctx context.Context, in *edgeproto.Zone) (*edgeproto.Result, error) {
	if s.CudNoop {
		return &edgeproto.Result{}, nil
	}
	s.ZoneCache.Update(ctx, in, 0)
	return &edgeproto.Result{}, nil
}

func (s *DummyServer) DeleteZone(ctx context.Context, in *edgeproto.Zone) (*edgeproto.Result, error) {
	if s.CudNoop {
		return &edgeproto.Result{}, nil
	}
	s.ZoneCache.Delete(ctx, in, 0)
	return &edgeproto.Result{}, nil
}

func (s *DummyServer) UpdateZone(ctx context.Context, in *edgeproto.Zone) (*edgeproto.Result, error) {
	if s.CudNoop {
		return &edgeproto.Result{}, nil
	}
	s.ZoneCache.Update(ctx, in, 0)
	return &edgeproto.Result{}, nil
}

func (s *DummyServer) ShowZone(in *edgeproto.Zone, server edgeproto.ZoneApi_ShowZoneServer) error {
	var err error
	obj := &edgeproto.Zone{}
	if obj.Matches(in, edgeproto.MatchFilter()) {
		for ii := 0; ii < s.ShowDummyCount; ii++ {
			server.Send(&edgeproto.Zone{})
		}
		if ch, ok := s.MidstreamFailChs["ShowZone"]; ok {
			// Wait until client receives the SendMsg, since they
			// are buffered and dropped once we return err here.
			select {
			case <-ch:
			case <-time.After(5 * time.Second):
			}
			return fmt.Errorf("midstream failure!")
		}
	}
	err = s.ZoneCache.Show(in, func(obj *edgeproto.Zone) error {
		err := server.Send(obj)
		return err
	})
	return err
}

func (s *DummyServer) ShowZoneGPUs(in *edgeproto.Zone, server edgeproto.ZoneApi_ShowZoneGPUsServer) error {
	var err error
	if true {
		for ii := 0; ii < s.ShowDummyCount; ii++ {
			server.Send(&edgeproto.ZoneGPUs{})
		}
		if ch, ok := s.MidstreamFailChs["ShowZoneGPUs"]; ok {
			// Wait until client receives the SendMsg, since they
			// are buffered and dropped once we return err here.
			select {
			case <-ch:
			case <-time.After(5 * time.Second):
			}
			return fmt.Errorf("midstream failure!")
		}
	}
	return err
}

func (s *ApiClient) CreateZone(ctx context.Context, in *edgeproto.Zone) (*edgeproto.Result, error) {
	api := edgeproto.NewZoneApiClient(s.Conn)
	return api.CreateZone(ctx, in)
}

func (s *CliClient) CreateZone(ctx context.Context, in *edgeproto.Zone) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "CreateZone")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

func (s *ApiClient) DeleteZone(ctx context.Context, in *edgeproto.Zone) (*edgeproto.Result, error) {
	api := edgeproto.NewZoneApiClient(s.Conn)
	return api.DeleteZone(ctx, in)
}

func (s *CliClient) DeleteZone(ctx context.Context, in *edgeproto.Zone) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "DeleteZone")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

func (s *ApiClient) UpdateZone(ctx context.Context, in *edgeproto.Zone) (*edgeproto.Result, error) {
	api := edgeproto.NewZoneApiClient(s.Conn)
	return api.UpdateZone(ctx, in)
}

func (s *CliClient) UpdateZone(ctx context.Context, in *edgeproto.Zone) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "UpdateZone")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

type ZoneStream interface {
	Recv() (*edgeproto.Zone, error)
}

func ZoneReadStream(stream ZoneStream) ([]edgeproto.Zone, error) {
	output := []edgeproto.Zone{}
	for {
		obj, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return output, fmt.Errorf("read Zone stream failed, %v", err)
		}
		output = append(output, *obj)
	}
	return output, nil
}

func (s *ApiClient) ShowZone(ctx context.Context, in *edgeproto.Zone) ([]edgeproto.Zone, error) {
	api := edgeproto.NewZoneApiClient(s.Conn)
	stream, err := api.ShowZone(ctx, in)
	if err != nil {
		return nil, err
	}
	return ZoneReadStream(stream)
}

func (s *CliClient) ShowZone(ctx context.Context, in *edgeproto.Zone) ([]edgeproto.Zone, error) {
	output := []edgeproto.Zone{}
	args := append(s.BaseArgs, "controller", "ShowZone")
	err := wrapper.RunEdgectlObjs(args, in, &output, s.RunOps...)
	return output, err
}

type ZoneGPUsStream interface {
	Recv() (*edgeproto.ZoneGPUs, error)
}

func ZoneGPUsReadStream(stream ZoneGPUsStream) ([]edgeproto.ZoneGPUs, error) {
	output := []edgeproto.ZoneGPUs{}
	for {
		obj, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return output, fmt.Errorf("read ZoneGPUs stream failed, %v", err)
		}
		output = append(output, *obj)
	}
	return output, nil
}

func (s *ApiClient) ShowZoneGPUs(ctx context.Context, in *edgeproto.Zone) ([]edgeproto.ZoneGPUs, error) {
	api := edgeproto.NewZoneApiClient(s.Conn)
	stream, err := api.ShowZoneGPUs(ctx, in)
	if err != nil {
		return nil, err
	}
	return ZoneGPUsReadStream(stream)
}

func (s *CliClient) ShowZoneGPUs(ctx context.Context, in *edgeproto.Zone) ([]edgeproto.ZoneGPUs, error) {
	output := []edgeproto.ZoneGPUs{}
	args := append(s.BaseArgs, "controller", "ShowZoneGPUs")
	err := wrapper.RunEdgectlObjs(args, in, &output, s.RunOps...)
	return output, err
}

type ZoneApiClient interface {
	CreateZone(ctx context.Context, in *edgeproto.Zone) (*edgeproto.Result, error)
	DeleteZone(ctx context.Context, in *edgeproto.Zone) (*edgeproto.Result, error)
	UpdateZone(ctx context.Context, in *edgeproto.Zone) (*edgeproto.Result, error)
	ShowZone(ctx context.Context, in *edgeproto.Zone) ([]edgeproto.Zone, error)
	ShowZoneGPUs(ctx context.Context, in *edgeproto.Zone) ([]edgeproto.ZoneGPUs, error)
}
