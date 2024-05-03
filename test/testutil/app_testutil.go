// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: app.proto

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

type ShowApp struct {
	Data map[string]edgeproto.App
	grpc.ServerStream
	Ctx context.Context
}

func (x *ShowApp) Init() {
	x.Data = make(map[string]edgeproto.App)
}

func (x *ShowApp) Send(m *edgeproto.App) error {
	x.Data[m.GetKey().GetKeyString()] = *m
	return nil
}

func (x *ShowApp) Context() context.Context {
	return x.Ctx
}

var AppShowExtraCount = 0

func (x *ShowApp) ReadStream(stream edgeproto.AppApi_ShowAppClient, err error) {
	x.Data = make(map[string]edgeproto.App)
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

func (x *ShowApp) CheckFound(obj *edgeproto.App) bool {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	return found
}

func (x *ShowApp) AssertFound(t *testing.T, obj *edgeproto.App) {
	check, found := x.Data[obj.GetKey().GetKeyString()]
	require.True(t, found, "find App %s", obj.GetKey().GetKeyString())
	if found && !check.Matches(obj, edgeproto.MatchIgnoreBackend(), edgeproto.MatchSortArrayedKeys()) {
		require.Equal(t, *obj, check, "App are equal")
	}
	if found {
		// remove in case there are dups in the list, so the
		// same object cannot be used again
		delete(x.Data, obj.GetKey().GetKeyString())
	}
}

func (x *ShowApp) AssertNotFound(t *testing.T, obj *edgeproto.App) {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	require.False(t, found, "do not find App %s", obj.GetKey().GetKeyString())
}

func WaitAssertFoundApp(t *testing.T, api edgeproto.AppApiClient, obj *edgeproto.App, count int, retry time.Duration) {
	show := ShowApp{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowApp(ctx, obj)
		show.ReadStream(stream, err)
		cancel()
		if show.CheckFound(obj) {
			break
		}
		time.Sleep(retry)
	}
	show.AssertFound(t, obj)
}

func WaitAssertNotFoundApp(t *testing.T, api edgeproto.AppApiClient, obj *edgeproto.App, count int, retry time.Duration) {
	show := ShowApp{}
	filterNone := edgeproto.App{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowApp(ctx, &filterNone)
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
type AppCommonApi struct {
	internal_api edgeproto.AppApiServer
	client_api   edgeproto.AppApiClient
}

func (x *AppCommonApi) CreateApp(ctx context.Context, in *edgeproto.App) (*edgeproto.Result, error) {
	copy := &edgeproto.App{}
	*copy = *in
	if x.internal_api != nil {
		return x.internal_api.CreateApp(ctx, copy)
	} else {
		res, err := x.client_api.CreateApp(ctx, copy)
		return res, unwrapGrpcError(err)
	}
}

func (x *AppCommonApi) DeleteApp(ctx context.Context, in *edgeproto.App) (*edgeproto.Result, error) {
	copy := &edgeproto.App{}
	*copy = *in
	if x.internal_api != nil {
		return x.internal_api.DeleteApp(ctx, copy)
	} else {
		res, err := x.client_api.DeleteApp(ctx, copy)
		return res, unwrapGrpcError(err)
	}
}

func (x *AppCommonApi) UpdateApp(ctx context.Context, in *edgeproto.App) (*edgeproto.Result, error) {
	copy := &edgeproto.App{}
	*copy = *in
	if x.internal_api != nil {
		return x.internal_api.UpdateApp(ctx, copy)
	} else {
		res, err := x.client_api.UpdateApp(ctx, copy)
		return res, unwrapGrpcError(err)
	}
}

func (x *AppCommonApi) ShowApp(ctx context.Context, filter *edgeproto.App, showData *ShowApp) error {
	if x.internal_api != nil {
		showData.Ctx = ctx
		return x.internal_api.ShowApp(filter, showData)
	} else {
		stream, err := x.client_api.ShowApp(ctx, filter)
		showData.ReadStream(stream, err)
		return unwrapGrpcError(err)
	}
}

func NewInternalAppApi(api edgeproto.AppApiServer) *AppCommonApi {
	apiWrap := AppCommonApi{}
	apiWrap.internal_api = api
	return &apiWrap
}

func NewClientAppApi(api edgeproto.AppApiClient) *AppCommonApi {
	apiWrap := AppCommonApi{}
	apiWrap.client_api = api
	return &apiWrap
}

type AppTestOptions struct {
	createdData []edgeproto.App
}

type AppTestOp func(opts *AppTestOptions)

func WithCreatedAppTestData(createdData []edgeproto.App) AppTestOp {
	return func(opts *AppTestOptions) { opts.createdData = createdData }
}

func InternalAppTest(t *testing.T, test string, api edgeproto.AppApiServer, testData []edgeproto.App, ops ...AppTestOp) {
	span := log.StartSpan(log.DebugLevelApi, "InternalAppTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "cud":
		basicAppCudTest(t, ctx, NewInternalAppApi(api), testData, ops...)
	case "show":
		basicAppShowTest(t, ctx, NewInternalAppApi(api), testData)
	}
}

func ClientAppTest(t *testing.T, test string, api edgeproto.AppApiClient, testData []edgeproto.App, ops ...AppTestOp) {
	span := log.StartSpan(log.DebugLevelApi, "ClientAppTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "cud":
		basicAppCudTest(t, ctx, NewClientAppApi(api), testData, ops...)
	case "show":
		basicAppShowTest(t, ctx, NewClientAppApi(api), testData)
	}
}

func basicAppShowTest(t *testing.T, ctx context.Context, api *AppCommonApi, testData []edgeproto.App) {
	var err error

	show := ShowApp{}
	show.Init()
	filterNone := edgeproto.App{}
	err = api.ShowApp(ctx, &filterNone, &show)
	require.Nil(t, err, "show data")
	require.Equal(t, len(testData)+AppShowExtraCount, len(show.Data), "Show count")
	for _, obj := range testData {
		show.AssertFound(t, &obj)
	}
}

func GetApp(t *testing.T, ctx context.Context, api *AppCommonApi, key *edgeproto.AppKey, out *edgeproto.App) bool {
	var err error

	show := ShowApp{}
	show.Init()
	filter := edgeproto.App{}
	filter.SetKey(key)
	err = api.ShowApp(ctx, &filter, &show)
	require.Nil(t, err, "show data")
	obj, found := show.Data[key.GetKeyString()]
	if found {
		*out = obj
	}
	return found
}

func basicAppCudTest(t *testing.T, ctx context.Context, api *AppCommonApi, testData []edgeproto.App, ops ...AppTestOp) {
	var err error

	if len(testData) < 3 {
		require.True(t, false, "Need at least 3 test data objects")
		return
	}
	options := AppTestOptions{}
	for _, op := range ops {
		op(&options)
	}
	createdData := testData
	if options.createdData != nil {
		createdData = options.createdData
	}

	// test create
	CreateAppData(t, ctx, api, testData)

	// test duplicate Create - should fail
	_, err = api.CreateApp(ctx, &testData[0])
	require.NotNil(t, err, "Create duplicate App")

	// test show all items
	basicAppShowTest(t, ctx, api, createdData)

	// test Delete
	_, err = api.DeleteApp(ctx, &createdData[0])
	require.Nil(t, err, "Delete App %s", testData[0].GetKey().GetKeyString())
	show := ShowApp{}
	show.Init()
	filterNone := edgeproto.App{}
	err = api.ShowApp(ctx, &filterNone, &show)
	require.Nil(t, err, "show data")
	require.Equal(t, len(createdData)-1+AppShowExtraCount, len(show.Data), "Show count")
	show.AssertNotFound(t, &createdData[0])
	// test update of missing object
	_, err = api.UpdateApp(ctx, &createdData[0])
	require.NotNil(t, err, "Update missing object")
	// Create it back
	_, err = api.CreateApp(ctx, &testData[0])
	require.Nil(t, err, "Create App %s", testData[0].GetKey().GetKeyString())

	// test invalid keys
	bad := edgeproto.App{}
	_, err = api.CreateApp(ctx, &bad)
	require.NotNil(t, err, "Create App with no key info")

}

func InternalAppCreate(t *testing.T, api edgeproto.AppApiServer, testData []edgeproto.App) {
	span := log.StartSpan(log.DebugLevelApi, "InternalAppCreate")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	CreateAppData(t, ctx, NewInternalAppApi(api), testData)
}

func ClientAppCreate(t *testing.T, api edgeproto.AppApiClient, testData []edgeproto.App) {
	span := log.StartSpan(log.DebugLevelApi, "ClientAppCreate")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	CreateAppData(t, ctx, NewClientAppApi(api), testData)
}

func CreateAppData(t *testing.T, ctx context.Context, api *AppCommonApi, testData []edgeproto.App) {
	var err error

	for ii := range testData {
		obj := testData[ii]
		_, err = api.CreateApp(ctx, &obj)
		require.Nil(t, err, "Create App %s", obj.GetKey().GetKeyString())
	}
}

func InternalAppDelete(t *testing.T, api edgeproto.AppApiServer, testData []edgeproto.App) {
	span := log.StartSpan(log.DebugLevelApi, "InternalAppDelete")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	DeleteAppData(t, ctx, NewInternalAppApi(api), testData)
}

func ClientAppDelete(t *testing.T, api edgeproto.AppApiClient, testData []edgeproto.App) {
	span := log.StartSpan(log.DebugLevelApi, "ClientAppDelete")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	DeleteAppData(t, ctx, NewClientAppApi(api), testData)
}

func DeleteAppData(t *testing.T, ctx context.Context, api *AppCommonApi, testData []edgeproto.App) {
	var err error

	for ii := range testData {
		obj := testData[ii]
		_, err = api.DeleteApp(ctx, &obj)
		require.Nil(t, err, "Delete App %s", obj.GetKey().GetKeyString())
	}
}

func FindAppData(key *edgeproto.AppKey, testData []edgeproto.App) (*edgeproto.App, bool) {
	for ii, _ := range testData {
		if testData[ii].GetKey().Matches(key) {
			return &testData[ii], true
		}
	}
	return nil, false
}

func (r *Run) AppApi(data *[]edgeproto.App, dataMap interface{}, dataOut interface{}) {
	log.DebugLog(log.DebugLevelApi, "API for App", "mode", r.Mode)
	if r.Mode == "show" {
		obj := &edgeproto.App{}
		out, err := r.client.ShowApp(r.ctx, obj)
		if err != nil {
			r.logErr("AppApi", err)
		} else {
			outp, ok := dataOut.(*[]edgeproto.App)
			if !ok {
				panic(fmt.Sprintf("RunAppApi expected dataOut type *[]edgeproto.App, but was %T", dataOut))
			}
			*outp = append(*outp, out...)
		}
		return
	}
	for ii, objD := range *data {
		obj := &objD
		switch r.Mode {
		case "create":
			out, err := r.client.CreateApp(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("AppApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunAppApi expected dataOut type *[]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		case "delete":
			out, err := r.client.DeleteApp(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("AppApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunAppApi expected dataOut type *[]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		case "update":
			// set specified fields
			objMap, err := cli.GetGenericObjFromList(dataMap, ii)
			if err != nil {
				log.DebugLog(log.DebugLevelApi, "bad dataMap for App", "err", err)
				*r.Rc = false
				return
			}
			yamlData := cli.MapData{
				Namespace: cli.YamlNamespace,
				Data:      objMap,
			}
			obj.Fields = cli.GetSpecifiedFields(&yamlData, obj)

			out, err := r.client.UpdateApp(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("AppApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunAppApi expected dataOut type *[]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		case "showfiltered":
			out, err := r.client.ShowApp(r.ctx, obj)
			if err != nil {
				r.logErr(fmt.Sprintf("AppApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.App)
				if !ok {
					panic(fmt.Sprintf("RunAppApi expected dataOut type *[]edgeproto.App, but was %T", dataOut))
				}
				*outp = append(*outp, out...)
			}
		}
	}
}

func (r *Run) AppApi_AppAlertPolicy(data *[]edgeproto.AppAlertPolicy, dataMap interface{}, dataOut interface{}) {
	log.DebugLog(log.DebugLevelApi, "API for AppAlertPolicy", "mode", r.Mode)
	for ii, objD := range *data {
		obj := &objD
		switch r.Mode {
		case "add":
			out, err := r.client.AddAppAlertPolicy(r.ctx, obj)
			if err != nil {
				r.logErr(fmt.Sprintf("AppApi_AppAlertPolicy[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunAppApi_AppAlertPolicy expected dataOut type *[]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		case "remove":
			out, err := r.client.RemoveAppAlertPolicy(r.ctx, obj)
			if err != nil {
				r.logErr(fmt.Sprintf("AppApi_AppAlertPolicy[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunAppApi_AppAlertPolicy expected dataOut type *[]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		}
	}
}

func (r *Run) AppApi_AppAutoProvPolicy(data *[]edgeproto.AppAutoProvPolicy, dataMap interface{}, dataOut interface{}) {
	log.DebugLog(log.DebugLevelApi, "API for AppAutoProvPolicy", "mode", r.Mode)
	for ii, objD := range *data {
		obj := &objD
		switch r.Mode {
		case "add":
			out, err := r.client.AddAppAutoProvPolicy(r.ctx, obj)
			if err != nil {
				r.logErr(fmt.Sprintf("AppApi_AppAutoProvPolicy[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunAppApi_AppAutoProvPolicy expected dataOut type *[]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		case "remove":
			out, err := r.client.RemoveAppAutoProvPolicy(r.ctx, obj)
			if err != nil {
				r.logErr(fmt.Sprintf("AppApi_AppAutoProvPolicy[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunAppApi_AppAutoProvPolicy expected dataOut type *[]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		}
	}
}

func (r *Run) AppApi_DeploymentCloudletRequest(data *[]edgeproto.DeploymentCloudletRequest, dataMap interface{}, dataOut interface{}) {
	log.DebugLog(log.DebugLevelApi, "API for DeploymentCloudletRequest", "mode", r.Mode)
	if r.Mode == "show" {
		obj := &edgeproto.DeploymentCloudletRequest{}
		out, err := r.client.ShowCloudletsForAppDeployment(r.ctx, obj)
		if err != nil {
			r.logErr("AppApi_DeploymentCloudletRequest", err)
		} else {
			outp, ok := dataOut.(*[]edgeproto.CloudletKey)
			if !ok {
				panic(fmt.Sprintf("RunAppApi_DeploymentCloudletRequest expected dataOut type *[]edgeproto.CloudletKey, but was %T", dataOut))
			}
			*outp = append(*outp, out...)
		}
		return
	}
	for ii, objD := range *data {
		obj := &objD
		switch r.Mode {
		case "showfiltered":
			out, err := r.client.ShowCloudletsForAppDeployment(r.ctx, obj)
			if err != nil {
				r.logErr(fmt.Sprintf("AppApi_DeploymentCloudletRequest[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.CloudletKey)
				if !ok {
					panic(fmt.Sprintf("RunAppApi_DeploymentCloudletRequest expected dataOut type *[]edgeproto.CloudletKey, but was %T", dataOut))
				}
				*outp = append(*outp, out...)
			}
		}
	}
}

func (s *DummyServer) CreateApp(ctx context.Context, in *edgeproto.App) (*edgeproto.Result, error) {
	if s.CudNoop {
		return &edgeproto.Result{}, nil
	}
	s.AppCache.Update(ctx, in, 0)
	return &edgeproto.Result{}, nil
}

func (s *DummyServer) DeleteApp(ctx context.Context, in *edgeproto.App) (*edgeproto.Result, error) {
	if s.CudNoop {
		return &edgeproto.Result{}, nil
	}
	s.AppCache.Delete(ctx, in, 0)
	return &edgeproto.Result{}, nil
}

func (s *DummyServer) UpdateApp(ctx context.Context, in *edgeproto.App) (*edgeproto.Result, error) {
	if s.CudNoop {
		return &edgeproto.Result{}, nil
	}
	s.AppCache.Update(ctx, in, 0)
	return &edgeproto.Result{}, nil
}

func (s *DummyServer) ShowApp(in *edgeproto.App, server edgeproto.AppApi_ShowAppServer) error {
	var err error
	obj := &edgeproto.App{}
	if obj.Matches(in, edgeproto.MatchFilter()) {
		for ii := 0; ii < s.ShowDummyCount; ii++ {
			server.Send(&edgeproto.App{})
		}
		if ch, ok := s.MidstreamFailChs["ShowApp"]; ok {
			// Wait until client receives the SendMsg, since they
			// are buffered and dropped once we return err here.
			select {
			case <-ch:
			case <-time.After(5 * time.Second):
			}
			return fmt.Errorf("midstream failure!")
		}
	}
	err = s.AppCache.Show(in, func(obj *edgeproto.App) error {
		err := server.Send(obj)
		return err
	})
	return err
}

func (s *ApiClient) CreateApp(ctx context.Context, in *edgeproto.App) (*edgeproto.Result, error) {
	api := edgeproto.NewAppApiClient(s.Conn)
	return api.CreateApp(ctx, in)
}

func (s *CliClient) CreateApp(ctx context.Context, in *edgeproto.App) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "CreateApp")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

func (s *ApiClient) DeleteApp(ctx context.Context, in *edgeproto.App) (*edgeproto.Result, error) {
	api := edgeproto.NewAppApiClient(s.Conn)
	return api.DeleteApp(ctx, in)
}

func (s *CliClient) DeleteApp(ctx context.Context, in *edgeproto.App) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "DeleteApp")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

func (s *ApiClient) UpdateApp(ctx context.Context, in *edgeproto.App) (*edgeproto.Result, error) {
	api := edgeproto.NewAppApiClient(s.Conn)
	return api.UpdateApp(ctx, in)
}

func (s *CliClient) UpdateApp(ctx context.Context, in *edgeproto.App) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "UpdateApp")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

type AppStream interface {
	Recv() (*edgeproto.App, error)
}

func AppReadStream(stream AppStream) ([]edgeproto.App, error) {
	output := []edgeproto.App{}
	for {
		obj, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return output, fmt.Errorf("read App stream failed, %v", err)
		}
		output = append(output, *obj)
	}
	return output, nil
}

func (s *ApiClient) ShowApp(ctx context.Context, in *edgeproto.App) ([]edgeproto.App, error) {
	api := edgeproto.NewAppApiClient(s.Conn)
	stream, err := api.ShowApp(ctx, in)
	if err != nil {
		return nil, err
	}
	return AppReadStream(stream)
}

func (s *CliClient) ShowApp(ctx context.Context, in *edgeproto.App) ([]edgeproto.App, error) {
	output := []edgeproto.App{}
	args := append(s.BaseArgs, "controller", "ShowApp")
	err := wrapper.RunEdgectlObjs(args, in, &output, s.RunOps...)
	return output, err
}

func (s *ApiClient) AddAppAutoProvPolicy(ctx context.Context, in *edgeproto.AppAutoProvPolicy) (*edgeproto.Result, error) {
	api := edgeproto.NewAppApiClient(s.Conn)
	return api.AddAppAutoProvPolicy(ctx, in)
}

func (s *CliClient) AddAppAutoProvPolicy(ctx context.Context, in *edgeproto.AppAutoProvPolicy) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "AddAppAutoProvPolicy")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

func (s *ApiClient) RemoveAppAutoProvPolicy(ctx context.Context, in *edgeproto.AppAutoProvPolicy) (*edgeproto.Result, error) {
	api := edgeproto.NewAppApiClient(s.Conn)
	return api.RemoveAppAutoProvPolicy(ctx, in)
}

func (s *CliClient) RemoveAppAutoProvPolicy(ctx context.Context, in *edgeproto.AppAutoProvPolicy) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "RemoveAppAutoProvPolicy")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

func (s *ApiClient) AddAppAlertPolicy(ctx context.Context, in *edgeproto.AppAlertPolicy) (*edgeproto.Result, error) {
	api := edgeproto.NewAppApiClient(s.Conn)
	return api.AddAppAlertPolicy(ctx, in)
}

func (s *CliClient) AddAppAlertPolicy(ctx context.Context, in *edgeproto.AppAlertPolicy) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "AddAppAlertPolicy")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

func (s *ApiClient) RemoveAppAlertPolicy(ctx context.Context, in *edgeproto.AppAlertPolicy) (*edgeproto.Result, error) {
	api := edgeproto.NewAppApiClient(s.Conn)
	return api.RemoveAppAlertPolicy(ctx, in)
}

func (s *CliClient) RemoveAppAlertPolicy(ctx context.Context, in *edgeproto.AppAlertPolicy) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "RemoveAppAlertPolicy")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

type CloudletKeyStream interface {
	Recv() (*edgeproto.CloudletKey, error)
}

func CloudletKeyReadStream(stream CloudletKeyStream) ([]edgeproto.CloudletKey, error) {
	output := []edgeproto.CloudletKey{}
	for {
		obj, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return output, fmt.Errorf("read CloudletKey stream failed, %v", err)
		}
		output = append(output, *obj)
	}
	return output, nil
}

func (s *ApiClient) ShowCloudletsForAppDeployment(ctx context.Context, in *edgeproto.DeploymentCloudletRequest) ([]edgeproto.CloudletKey, error) {
	api := edgeproto.NewAppApiClient(s.Conn)
	stream, err := api.ShowCloudletsForAppDeployment(ctx, in)
	if err != nil {
		return nil, err
	}
	return CloudletKeyReadStream(stream)
}

func (s *CliClient) ShowCloudletsForAppDeployment(ctx context.Context, in *edgeproto.DeploymentCloudletRequest) ([]edgeproto.CloudletKey, error) {
	output := []edgeproto.CloudletKey{}
	args := append(s.BaseArgs, "controller", "ShowCloudletsForAppDeployment")
	err := wrapper.RunEdgectlObjs(args, in, &output, s.RunOps...)
	return output, err
}

type AppApiClient interface {
	CreateApp(ctx context.Context, in *edgeproto.App) (*edgeproto.Result, error)
	DeleteApp(ctx context.Context, in *edgeproto.App) (*edgeproto.Result, error)
	UpdateApp(ctx context.Context, in *edgeproto.App) (*edgeproto.Result, error)
	ShowApp(ctx context.Context, in *edgeproto.App) ([]edgeproto.App, error)
	AddAppAutoProvPolicy(ctx context.Context, in *edgeproto.AppAutoProvPolicy) (*edgeproto.Result, error)
	RemoveAppAutoProvPolicy(ctx context.Context, in *edgeproto.AppAutoProvPolicy) (*edgeproto.Result, error)
	AddAppAlertPolicy(ctx context.Context, in *edgeproto.AppAlertPolicy) (*edgeproto.Result, error)
	RemoveAppAlertPolicy(ctx context.Context, in *edgeproto.AppAlertPolicy) (*edgeproto.Result, error)
	ShowCloudletsForAppDeployment(ctx context.Context, in *edgeproto.DeploymentCloudletRequest) ([]edgeproto.CloudletKey, error)
}
