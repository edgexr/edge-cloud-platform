// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: device.proto

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
	_ "github.com/gogo/protobuf/types"
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

type ShowDevice struct {
	Data map[string]edgeproto.Device
	grpc.ServerStream
	Ctx context.Context
}

func (x *ShowDevice) Init() {
	x.Data = make(map[string]edgeproto.Device)
}

func (x *ShowDevice) Send(m *edgeproto.Device) error {
	x.Data[m.GetKey().GetKeyString()] = *m
	return nil
}

func (x *ShowDevice) Context() context.Context {
	return x.Ctx
}

var DeviceShowExtraCount = 0

func (x *ShowDevice) ReadStream(stream edgeproto.DeviceApi_ShowDeviceClient, err error) {
	x.Data = make(map[string]edgeproto.Device)
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

func (x *ShowDevice) CheckFound(obj *edgeproto.Device) bool {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	return found
}

func (x *ShowDevice) AssertFound(t *testing.T, obj *edgeproto.Device) {
	check, found := x.Data[obj.GetKey().GetKeyString()]
	require.True(t, found, "find Device %s", obj.GetKey().GetKeyString())
	if found && !check.Matches(obj, edgeproto.MatchIgnoreBackend(), edgeproto.MatchSortArrayedKeys()) {
		require.Equal(t, *obj, check, "Device are equal")
	}
	if found {
		// remove in case there are dups in the list, so the
		// same object cannot be used again
		delete(x.Data, obj.GetKey().GetKeyString())
	}
}

func (x *ShowDevice) AssertNotFound(t *testing.T, obj *edgeproto.Device) {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	require.False(t, found, "do not find Device %s", obj.GetKey().GetKeyString())
}

func WaitAssertFoundDevice(t *testing.T, api edgeproto.DeviceApiClient, obj *edgeproto.Device, count int, retry time.Duration) {
	show := ShowDevice{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowDevice(ctx, obj)
		show.ReadStream(stream, err)
		cancel()
		if show.CheckFound(obj) {
			break
		}
		time.Sleep(retry)
	}
	show.AssertFound(t, obj)
}

func WaitAssertNotFoundDevice(t *testing.T, api edgeproto.DeviceApiClient, obj *edgeproto.Device, count int, retry time.Duration) {
	show := ShowDevice{}
	filterNone := edgeproto.Device{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowDevice(ctx, &filterNone)
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
type DeviceCommonApi struct {
	internal_api edgeproto.DeviceApiServer
	client_api   edgeproto.DeviceApiClient
}

func (x *DeviceCommonApi) ShowDevice(ctx context.Context, filter *edgeproto.Device, showData *ShowDevice) error {
	if x.internal_api != nil {
		showData.Ctx = ctx
		return x.internal_api.ShowDevice(filter, showData)
	} else {
		stream, err := x.client_api.ShowDevice(ctx, filter)
		showData.ReadStream(stream, err)
		return unwrapGrpcError(err)
	}
}

func NewInternalDeviceApi(api edgeproto.DeviceApiServer) *DeviceCommonApi {
	apiWrap := DeviceCommonApi{}
	apiWrap.internal_api = api
	return &apiWrap
}

func NewClientDeviceApi(api edgeproto.DeviceApiClient) *DeviceCommonApi {
	apiWrap := DeviceCommonApi{}
	apiWrap.client_api = api
	return &apiWrap
}

type DeviceTestOptions struct {
	createdData []edgeproto.Device
}

type DeviceTestOp func(opts *DeviceTestOptions)

func WithCreatedDeviceTestData(createdData []edgeproto.Device) DeviceTestOp {
	return func(opts *DeviceTestOptions) { opts.createdData = createdData }
}

func InternalDeviceTest(t *testing.T, test string, api edgeproto.DeviceApiServer, testData []edgeproto.Device, ops ...DeviceTestOp) {
	span := log.StartSpan(log.DebugLevelApi, "InternalDeviceTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "show":
		basicDeviceShowTest(t, ctx, NewInternalDeviceApi(api), testData)
	}
}

func ClientDeviceTest(t *testing.T, test string, api edgeproto.DeviceApiClient, testData []edgeproto.Device, ops ...DeviceTestOp) {
	span := log.StartSpan(log.DebugLevelApi, "ClientDeviceTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "show":
		basicDeviceShowTest(t, ctx, NewClientDeviceApi(api), testData)
	}
}

func basicDeviceShowTest(t *testing.T, ctx context.Context, api *DeviceCommonApi, testData []edgeproto.Device) {
	var err error

	show := ShowDevice{}
	show.Init()
	filterNone := edgeproto.Device{}
	err = api.ShowDevice(ctx, &filterNone, &show)
	require.Nil(t, err, "show data")
	require.Equal(t, len(testData)+DeviceShowExtraCount, len(show.Data), "Show count")
	for _, obj := range testData {
		show.AssertFound(t, &obj)
	}
}

func GetDevice(t *testing.T, ctx context.Context, api *DeviceCommonApi, key *edgeproto.DeviceKey, out *edgeproto.Device) bool {
	var err error

	show := ShowDevice{}
	show.Init()
	filter := edgeproto.Device{}
	filter.SetKey(key)
	err = api.ShowDevice(ctx, &filter, &show)
	require.Nil(t, err, "show data")
	obj, found := show.Data[key.GetKeyString()]
	if found {
		*out = obj
	}
	return found
}

func FindDeviceData(key *edgeproto.DeviceKey, testData []edgeproto.Device) (*edgeproto.Device, bool) {
	for ii, _ := range testData {
		if testData[ii].GetKey().Matches(key) {
			return &testData[ii], true
		}
	}
	return nil, false
}

type DeviceDataOut struct {
	Devices []edgeproto.Result
	Errors  []Err
}

// used to intersperse other creates/deletes/checks
// note the objs value is the previous one for create,
// but the next one for delete
type RunDeviceDataApiCallback func(objs string)

func RunDeviceDataApis(run *Run, in *edgeproto.DeviceData, inMap map[string]interface{}, out *DeviceDataOut, apicb RunDeviceDataApiCallback) {
	apicb("")
	run.DeviceApi(&in.Devices, inMap["devices"], &out.Devices)
	apicb("devices")
	out.Errors = run.Errs
}

func RunDeviceDataReverseApis(run *Run, in *edgeproto.DeviceData, inMap map[string]interface{}, out *DeviceDataOut, apicb RunDeviceDataApiCallback) {
	apicb("devices")
	run.DeviceApi(&in.Devices, inMap["devices"], &out.Devices)
	apicb("")
	out.Errors = run.Errs
}

func RunDeviceDataShowApis(run *Run, in *edgeproto.DeviceData, selector edgeproto.AllSelector, out *edgeproto.DeviceData) {
	if selector.Has("devices") {
		run.DeviceApi(&in.Devices, nil, &out.Devices)
	}
}

func DeleteAllDeviceDataInternal(t *testing.T, ctx context.Context, apis InternalCUDAPIs, in *edgeproto.DeviceData) {
}

func (r *Run) DeviceApi(data *[]edgeproto.Device, dataMap interface{}, dataOut interface{}) {
	log.DebugLog(log.DebugLevelApi, "API for Device", "mode", r.Mode)
	if r.Mode == "show" {
		obj := &edgeproto.Device{}
		out, err := r.client.ShowDevice(r.ctx, obj)
		if err != nil {
			r.logErr("DeviceApi", err)
		} else {
			outp, ok := dataOut.(*[]edgeproto.Device)
			if !ok {
				panic(fmt.Sprintf("RunDeviceApi expected dataOut type *[]edgeproto.Device, but was %T", dataOut))
			}
			*outp = append(*outp, out...)
		}
		return
	}
	for ii, objD := range *data {
		obj := &objD
		switch r.Mode {
		case "inject":
			out, err := r.client.InjectDevice(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("DeviceApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunDeviceApi expected dataOut type *[]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		case "showfiltered":
			out, err := r.client.ShowDevice(r.ctx, obj)
			if err != nil {
				r.logErr(fmt.Sprintf("DeviceApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Device)
				if !ok {
					panic(fmt.Sprintf("RunDeviceApi expected dataOut type *[]edgeproto.Device, but was %T", dataOut))
				}
				*outp = append(*outp, out...)
			}
		case "evict":
			out, err := r.client.EvictDevice(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("DeviceApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunDeviceApi expected dataOut type *[]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		}
	}
}

func (r *Run) DeviceApi_DeviceReport(data *[]edgeproto.DeviceReport, dataMap interface{}, dataOut interface{}) {
	log.DebugLog(log.DebugLevelApi, "API for DeviceReport", "mode", r.Mode)
	if r.Mode == "show" {
		obj := &edgeproto.DeviceReport{}
		out, err := r.client.ShowDeviceReport(r.ctx, obj)
		if err != nil {
			r.logErr("DeviceApi_DeviceReport", err)
		} else {
			outp, ok := dataOut.(*[]edgeproto.Device)
			if !ok {
				panic(fmt.Sprintf("RunDeviceApi_DeviceReport expected dataOut type *[]edgeproto.Device, but was %T", dataOut))
			}
			*outp = append(*outp, out...)
		}
		return
	}
	for ii, objD := range *data {
		obj := &objD
		switch r.Mode {
		case "showfiltered":
			out, err := r.client.ShowDeviceReport(r.ctx, obj)
			if err != nil {
				r.logErr(fmt.Sprintf("DeviceApi_DeviceReport[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Device)
				if !ok {
					panic(fmt.Sprintf("RunDeviceApi_DeviceReport expected dataOut type *[]edgeproto.Device, but was %T", dataOut))
				}
				*outp = append(*outp, out...)
			}
		}
	}
}

func (s *DummyServer) InjectDevice(ctx context.Context, in *edgeproto.Device) (*edgeproto.Result, error) {
	if s.CudNoop {
		return &edgeproto.Result{}, nil
	}
	s.DeviceCache.Update(ctx, in, 0)
	return &edgeproto.Result{}, nil
}

func (s *DummyServer) ShowDevice(in *edgeproto.Device, server edgeproto.DeviceApi_ShowDeviceServer) error {
	var err error
	obj := &edgeproto.Device{}
	if obj.Matches(in, edgeproto.MatchFilter()) {
		for ii := 0; ii < s.ShowDummyCount; ii++ {
			server.Send(&edgeproto.Device{})
		}
		if ch, ok := s.MidstreamFailChs["ShowDevice"]; ok {
			// Wait until client receives the SendMsg, since they
			// are buffered and dropped once we return err here.
			select {
			case <-ch:
			case <-time.After(5 * time.Second):
			}
			return fmt.Errorf("midstream failure!")
		}
	}
	err = s.DeviceCache.Show(in, func(obj *edgeproto.Device) error {
		err := server.Send(obj)
		return err
	})
	return err
}

func (s *DummyServer) EvictDevice(ctx context.Context, in *edgeproto.Device) (*edgeproto.Result, error) {
	if s.CudNoop {
		return &edgeproto.Result{}, nil
	}
	s.DeviceCache.Delete(ctx, in, 0)
	return &edgeproto.Result{}, nil
}

func (s *DummyServer) ShowDeviceReport(in *edgeproto.DeviceReport, server edgeproto.DeviceApi_ShowDeviceReportServer) error {
	var err error
	if true {
		for ii := 0; ii < s.ShowDummyCount; ii++ {
			server.Send(&edgeproto.Device{})
		}
		if ch, ok := s.MidstreamFailChs["ShowDeviceReport"]; ok {
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

func (s *ApiClient) InjectDevice(ctx context.Context, in *edgeproto.Device) (*edgeproto.Result, error) {
	api := edgeproto.NewDeviceApiClient(s.Conn)
	return api.InjectDevice(ctx, in)
}

func (s *CliClient) InjectDevice(ctx context.Context, in *edgeproto.Device) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "InjectDevice")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

type DeviceStream interface {
	Recv() (*edgeproto.Device, error)
}

func DeviceReadStream(stream DeviceStream) ([]edgeproto.Device, error) {
	output := []edgeproto.Device{}
	for {
		obj, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return output, fmt.Errorf("read Device stream failed, %v", err)
		}
		output = append(output, *obj)
	}
	return output, nil
}

func (s *ApiClient) ShowDevice(ctx context.Context, in *edgeproto.Device) ([]edgeproto.Device, error) {
	api := edgeproto.NewDeviceApiClient(s.Conn)
	stream, err := api.ShowDevice(ctx, in)
	if err != nil {
		return nil, err
	}
	return DeviceReadStream(stream)
}

func (s *CliClient) ShowDevice(ctx context.Context, in *edgeproto.Device) ([]edgeproto.Device, error) {
	output := []edgeproto.Device{}
	args := append(s.BaseArgs, "controller", "ShowDevice")
	err := wrapper.RunEdgectlObjs(args, in, &output, s.RunOps...)
	return output, err
}

func (s *ApiClient) EvictDevice(ctx context.Context, in *edgeproto.Device) (*edgeproto.Result, error) {
	api := edgeproto.NewDeviceApiClient(s.Conn)
	return api.EvictDevice(ctx, in)
}

func (s *CliClient) EvictDevice(ctx context.Context, in *edgeproto.Device) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "EvictDevice")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

func (s *ApiClient) ShowDeviceReport(ctx context.Context, in *edgeproto.DeviceReport) ([]edgeproto.Device, error) {
	api := edgeproto.NewDeviceApiClient(s.Conn)
	stream, err := api.ShowDeviceReport(ctx, in)
	if err != nil {
		return nil, err
	}
	return DeviceReadStream(stream)
}

func (s *CliClient) ShowDeviceReport(ctx context.Context, in *edgeproto.DeviceReport) ([]edgeproto.Device, error) {
	output := []edgeproto.Device{}
	args := append(s.BaseArgs, "controller", "ShowDeviceReport")
	err := wrapper.RunEdgectlObjs(args, in, &output, s.RunOps...)
	return output, err
}

type DeviceApiClient interface {
	InjectDevice(ctx context.Context, in *edgeproto.Device) (*edgeproto.Result, error)
	ShowDevice(ctx context.Context, in *edgeproto.Device) ([]edgeproto.Device, error)
	EvictDevice(ctx context.Context, in *edgeproto.Device) (*edgeproto.Result, error)
	ShowDeviceReport(ctx context.Context, in *edgeproto.DeviceReport) ([]edgeproto.Device, error)
}
