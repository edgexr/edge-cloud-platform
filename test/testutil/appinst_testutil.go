// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: appinst.proto

package testutil

import (
	"context"
	fmt "fmt"
	_ "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
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

type ShowAppInst struct {
	Data map[string]edgeproto.AppInst
	grpc.ServerStream
	Ctx context.Context
}

func (x *ShowAppInst) Init() {
	x.Data = make(map[string]edgeproto.AppInst)
}

func (x *ShowAppInst) Send(m *edgeproto.AppInst) error {
	x.Data[m.GetKey().GetKeyString()] = *m
	return nil
}

func (x *ShowAppInst) Context() context.Context {
	return x.Ctx
}

var AppInstShowExtraCount = 0

type CudStreamoutAppInst struct {
	grpc.ServerStream
	Ctx context.Context
}

func (x *CudStreamoutAppInst) Send(res *edgeproto.Result) error {
	fmt.Println(res)
	return nil
}

func (x *CudStreamoutAppInst) Context() context.Context {
	return x.Ctx
}

func NewCudStreamoutAppInst(ctx context.Context) *CudStreamoutAppInst {
	return &CudStreamoutAppInst{
		Ctx: ctx,
	}
}

func AppInstReadResultStream(stream ResultStream, err error) error {
	if err != nil {
		return err
	}
	for {
		res, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		fmt.Println(res)
	}
}

func (x *ShowAppInst) ReadStream(stream edgeproto.AppInstApi_ShowAppInstClient, err error) {
	x.Data = make(map[string]edgeproto.AppInst)
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

func (x *ShowAppInst) CheckFound(obj *edgeproto.AppInst) bool {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	return found
}

func (x *ShowAppInst) AssertFound(t *testing.T, obj *edgeproto.AppInst) {
	check, found := x.Data[obj.GetKey().GetKeyString()]
	require.True(t, found, "find AppInst %s", obj.GetKey().GetKeyString())
	if found && !check.Matches(obj, edgeproto.MatchIgnoreBackend(), edgeproto.MatchSortArrayedKeys()) {
		require.Equal(t, *obj, check, "AppInst are equal")
	}
	if found {
		// remove in case there are dups in the list, so the
		// same object cannot be used again
		delete(x.Data, obj.GetKey().GetKeyString())
	}
}

func (x *ShowAppInst) AssertNotFound(t *testing.T, obj *edgeproto.AppInst) {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	require.False(t, found, "do not find AppInst %s", obj.GetKey().GetKeyString())
}

func WaitAssertFoundAppInst(t *testing.T, api edgeproto.AppInstApiClient, obj *edgeproto.AppInst, count int, retry time.Duration) {
	show := ShowAppInst{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowAppInst(ctx, obj)
		show.ReadStream(stream, err)
		cancel()
		if show.CheckFound(obj) {
			break
		}
		time.Sleep(retry)
	}
	show.AssertFound(t, obj)
}

func WaitAssertNotFoundAppInst(t *testing.T, api edgeproto.AppInstApiClient, obj *edgeproto.AppInst, count int, retry time.Duration) {
	show := ShowAppInst{}
	filterNone := edgeproto.AppInst{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowAppInst(ctx, &filterNone)
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
type AppInstCommonApi struct {
	internal_api edgeproto.AppInstApiServer
	client_api   edgeproto.AppInstApiClient
}

func (x *AppInstCommonApi) CreateAppInst(ctx context.Context, in *edgeproto.AppInst) (*edgeproto.Result, error) {
	copy := &edgeproto.AppInst{}
	*copy = *in
	if x.internal_api != nil {
		err := x.internal_api.CreateAppInst(copy, NewCudStreamoutAppInst(ctx))
		return &edgeproto.Result{}, err
	} else {
		stream, err := x.client_api.CreateAppInst(ctx, copy)
		err = AppInstReadResultStream(stream, err)
		return &edgeproto.Result{}, unwrapGrpcError(err)
	}
}

func (x *AppInstCommonApi) DeleteAppInst(ctx context.Context, in *edgeproto.AppInst) (*edgeproto.Result, error) {
	copy := &edgeproto.AppInst{}
	*copy = *in
	if x.internal_api != nil {
		err := x.internal_api.DeleteAppInst(copy, NewCudStreamoutAppInst(ctx))
		return &edgeproto.Result{}, err
	} else {
		stream, err := x.client_api.DeleteAppInst(ctx, copy)
		err = AppInstReadResultStream(stream, err)
		return &edgeproto.Result{}, unwrapGrpcError(err)
	}
}

func (x *AppInstCommonApi) UpdateAppInst(ctx context.Context, in *edgeproto.AppInst) (*edgeproto.Result, error) {
	copy := &edgeproto.AppInst{}
	*copy = *in
	if x.internal_api != nil {
		err := x.internal_api.UpdateAppInst(copy, NewCudStreamoutAppInst(ctx))
		return &edgeproto.Result{}, err
	} else {
		stream, err := x.client_api.UpdateAppInst(ctx, copy)
		err = AppInstReadResultStream(stream, err)
		return &edgeproto.Result{}, unwrapGrpcError(err)
	}
}

func (x *AppInstCommonApi) ShowAppInst(ctx context.Context, filter *edgeproto.AppInst, showData *ShowAppInst) error {
	if x.internal_api != nil {
		showData.Ctx = ctx
		return x.internal_api.ShowAppInst(filter, showData)
	} else {
		stream, err := x.client_api.ShowAppInst(ctx, filter)
		showData.ReadStream(stream, err)
		return unwrapGrpcError(err)
	}
}

func NewInternalAppInstApi(api edgeproto.AppInstApiServer) *AppInstCommonApi {
	apiWrap := AppInstCommonApi{}
	apiWrap.internal_api = api
	return &apiWrap
}

func NewClientAppInstApi(api edgeproto.AppInstApiClient) *AppInstCommonApi {
	apiWrap := AppInstCommonApi{}
	apiWrap.client_api = api
	return &apiWrap
}

type AppInstTestOptions struct {
	createdData []edgeproto.AppInst
}

type AppInstTestOp func(opts *AppInstTestOptions)

func WithCreatedAppInstTestData(createdData []edgeproto.AppInst) AppInstTestOp {
	return func(opts *AppInstTestOptions) { opts.createdData = createdData }
}

func InternalAppInstTest(t *testing.T, test string, api edgeproto.AppInstApiServer, testData []edgeproto.AppInst, ops ...AppInstTestOp) {
	span := log.StartSpan(log.DebugLevelApi, "InternalAppInstTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "cud":
		basicAppInstCudTest(t, ctx, NewInternalAppInstApi(api), testData, ops...)
	case "show":
		basicAppInstShowTest(t, ctx, NewInternalAppInstApi(api), testData)
	}
}

func ClientAppInstTest(t *testing.T, test string, api edgeproto.AppInstApiClient, testData []edgeproto.AppInst, ops ...AppInstTestOp) {
	span := log.StartSpan(log.DebugLevelApi, "ClientAppInstTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "cud":
		basicAppInstCudTest(t, ctx, NewClientAppInstApi(api), testData, ops...)
	case "show":
		basicAppInstShowTest(t, ctx, NewClientAppInstApi(api), testData)
	}
}

func basicAppInstShowTest(t *testing.T, ctx context.Context, api *AppInstCommonApi, testData []edgeproto.AppInst) {
	var err error

	show := ShowAppInst{}
	show.Init()
	filterNone := edgeproto.AppInst{}
	err = api.ShowAppInst(ctx, &filterNone, &show)
	require.Nil(t, err, "show data")
	require.Equal(t, len(testData)+AppInstShowExtraCount, len(show.Data), "Show count")
	for _, obj := range testData {
		show.AssertFound(t, &obj)
	}
}

func GetAppInst(t *testing.T, ctx context.Context, api *AppInstCommonApi, key *edgeproto.AppInstKey, out *edgeproto.AppInst) bool {
	var err error

	show := ShowAppInst{}
	show.Init()
	filter := edgeproto.AppInst{}
	filter.SetKey(key)
	err = api.ShowAppInst(ctx, &filter, &show)
	require.Nil(t, err, "show data")
	obj, found := show.Data[key.GetKeyString()]
	if found {
		*out = obj
	}
	return found
}

func basicAppInstCudTest(t *testing.T, ctx context.Context, api *AppInstCommonApi, testData []edgeproto.AppInst, ops ...AppInstTestOp) {
	var err error

	if len(testData) < 3 {
		require.True(t, false, "Need at least 3 test data objects")
		return
	}
	options := AppInstTestOptions{}
	for _, op := range ops {
		op(&options)
	}
	createdData := testData
	if options.createdData != nil {
		createdData = options.createdData
	}

	// test create
	CreateAppInstData(t, ctx, api, testData)

	// test duplicate Create - should fail
	_, err = api.CreateAppInst(ctx, &testData[0])
	require.NotNil(t, err, "Create duplicate AppInst")

	// test show all items
	basicAppInstShowTest(t, ctx, api, createdData)

	// test Delete
	_, err = api.DeleteAppInst(ctx, &createdData[0])
	require.Nil(t, err, "Delete AppInst %s", testData[0].GetKey().GetKeyString())
	show := ShowAppInst{}
	show.Init()
	filterNone := edgeproto.AppInst{}
	err = api.ShowAppInst(ctx, &filterNone, &show)
	require.Nil(t, err, "show data")
	require.Equal(t, len(createdData)-1+AppInstShowExtraCount, len(show.Data), "Show count")
	show.AssertNotFound(t, &createdData[0])
	// test update of missing object
	_, err = api.UpdateAppInst(ctx, &createdData[0])
	require.NotNil(t, err, "Update missing object")
	// Create it back
	_, err = api.CreateAppInst(ctx, &testData[0])
	require.Nil(t, err, "Create AppInst %s", testData[0].GetKey().GetKeyString())

	// test invalid keys
	bad := edgeproto.AppInst{}
	_, err = api.CreateAppInst(ctx, &bad)
	require.NotNil(t, err, "Create AppInst with no key info")

}

func InternalAppInstCreate(t *testing.T, api edgeproto.AppInstApiServer, testData []edgeproto.AppInst) {
	span := log.StartSpan(log.DebugLevelApi, "InternalAppInstCreate")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	CreateAppInstData(t, ctx, NewInternalAppInstApi(api), testData)
}

func ClientAppInstCreate(t *testing.T, api edgeproto.AppInstApiClient, testData []edgeproto.AppInst) {
	span := log.StartSpan(log.DebugLevelApi, "ClientAppInstCreate")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	CreateAppInstData(t, ctx, NewClientAppInstApi(api), testData)
}

func CreateAppInstData(t *testing.T, ctx context.Context, api *AppInstCommonApi, testData []edgeproto.AppInst) {
	var err error

	for ii := range testData {
		obj := testData[ii]
		_, err = api.CreateAppInst(ctx, &obj)
		require.Nil(t, err, "Create AppInst %s", obj.GetKey().GetKeyString())
	}
}

func InternalAppInstDelete(t *testing.T, api edgeproto.AppInstApiServer, testData []edgeproto.AppInst) {
	span := log.StartSpan(log.DebugLevelApi, "InternalAppInstDelete")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	DeleteAppInstData(t, ctx, NewInternalAppInstApi(api), testData)
}

func ClientAppInstDelete(t *testing.T, api edgeproto.AppInstApiClient, testData []edgeproto.AppInst) {
	span := log.StartSpan(log.DebugLevelApi, "ClientAppInstDelete")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	DeleteAppInstData(t, ctx, NewClientAppInstApi(api), testData)
}

func DeleteAppInstData(t *testing.T, ctx context.Context, api *AppInstCommonApi, testData []edgeproto.AppInst) {
	var err error

	for ii := range testData {
		obj := testData[ii]
		_, err = api.DeleteAppInst(ctx, &obj)
		require.Nil(t, err, "Delete AppInst %s", obj.GetKey().GetKeyString())
	}
}

func FindAppInstData(key *edgeproto.AppInstKey, testData []edgeproto.AppInst) (*edgeproto.AppInst, bool) {
	for ii, _ := range testData {
		if testData[ii].GetKey().Matches(key) {
			return &testData[ii], true
		}
	}
	return nil, false
}

type ShowAppInstInfo struct {
	Data map[string]edgeproto.AppInstInfo
	grpc.ServerStream
	Ctx context.Context
}

func (x *ShowAppInstInfo) Init() {
	x.Data = make(map[string]edgeproto.AppInstInfo)
}

func (x *ShowAppInstInfo) Send(m *edgeproto.AppInstInfo) error {
	x.Data[m.GetKey().GetKeyString()] = *m
	return nil
}

func (x *ShowAppInstInfo) Context() context.Context {
	return x.Ctx
}

var AppInstInfoShowExtraCount = 0

func (x *ShowAppInstInfo) ReadStream(stream edgeproto.AppInstInfoApi_ShowAppInstInfoClient, err error) {
	x.Data = make(map[string]edgeproto.AppInstInfo)
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

func (x *ShowAppInstInfo) CheckFound(obj *edgeproto.AppInstInfo) bool {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	return found
}

func (x *ShowAppInstInfo) AssertFound(t *testing.T, obj *edgeproto.AppInstInfo) {
	check, found := x.Data[obj.GetKey().GetKeyString()]
	require.True(t, found, "find AppInstInfo %s", obj.GetKey().GetKeyString())
	if found && !check.Matches(obj, edgeproto.MatchIgnoreBackend(), edgeproto.MatchSortArrayedKeys()) {
		require.Equal(t, *obj, check, "AppInstInfo are equal")
	}
	if found {
		// remove in case there are dups in the list, so the
		// same object cannot be used again
		delete(x.Data, obj.GetKey().GetKeyString())
	}
}

func (x *ShowAppInstInfo) AssertNotFound(t *testing.T, obj *edgeproto.AppInstInfo) {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	require.False(t, found, "do not find AppInstInfo %s", obj.GetKey().GetKeyString())
}

func WaitAssertFoundAppInstInfo(t *testing.T, api edgeproto.AppInstInfoApiClient, obj *edgeproto.AppInstInfo, count int, retry time.Duration) {
	show := ShowAppInstInfo{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowAppInstInfo(ctx, obj)
		show.ReadStream(stream, err)
		cancel()
		if show.CheckFound(obj) {
			break
		}
		time.Sleep(retry)
	}
	show.AssertFound(t, obj)
}

func WaitAssertNotFoundAppInstInfo(t *testing.T, api edgeproto.AppInstInfoApiClient, obj *edgeproto.AppInstInfo, count int, retry time.Duration) {
	show := ShowAppInstInfo{}
	filterNone := edgeproto.AppInstInfo{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowAppInstInfo(ctx, &filterNone)
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
type AppInstInfoCommonApi struct {
	internal_api edgeproto.AppInstInfoApiServer
	client_api   edgeproto.AppInstInfoApiClient
}

func (x *AppInstInfoCommonApi) ShowAppInstInfo(ctx context.Context, filter *edgeproto.AppInstInfo, showData *ShowAppInstInfo) error {
	if x.internal_api != nil {
		showData.Ctx = ctx
		return x.internal_api.ShowAppInstInfo(filter, showData)
	} else {
		stream, err := x.client_api.ShowAppInstInfo(ctx, filter)
		showData.ReadStream(stream, err)
		return unwrapGrpcError(err)
	}
}

func NewInternalAppInstInfoApi(api edgeproto.AppInstInfoApiServer) *AppInstInfoCommonApi {
	apiWrap := AppInstInfoCommonApi{}
	apiWrap.internal_api = api
	return &apiWrap
}

func NewClientAppInstInfoApi(api edgeproto.AppInstInfoApiClient) *AppInstInfoCommonApi {
	apiWrap := AppInstInfoCommonApi{}
	apiWrap.client_api = api
	return &apiWrap
}

type AppInstInfoTestOptions struct {
	createdData []edgeproto.AppInstInfo
}

type AppInstInfoTestOp func(opts *AppInstInfoTestOptions)

func WithCreatedAppInstInfoTestData(createdData []edgeproto.AppInstInfo) AppInstInfoTestOp {
	return func(opts *AppInstInfoTestOptions) { opts.createdData = createdData }
}

func InternalAppInstInfoTest(t *testing.T, test string, api edgeproto.AppInstInfoApiServer, testData []edgeproto.AppInstInfo, ops ...AppInstInfoTestOp) {
	span := log.StartSpan(log.DebugLevelApi, "InternalAppInstInfoTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "show":
		basicAppInstInfoShowTest(t, ctx, NewInternalAppInstInfoApi(api), testData)
	}
}

func ClientAppInstInfoTest(t *testing.T, test string, api edgeproto.AppInstInfoApiClient, testData []edgeproto.AppInstInfo, ops ...AppInstInfoTestOp) {
	span := log.StartSpan(log.DebugLevelApi, "ClientAppInstInfoTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "show":
		basicAppInstInfoShowTest(t, ctx, NewClientAppInstInfoApi(api), testData)
	}
}

func basicAppInstInfoShowTest(t *testing.T, ctx context.Context, api *AppInstInfoCommonApi, testData []edgeproto.AppInstInfo) {
	var err error

	show := ShowAppInstInfo{}
	show.Init()
	filterNone := edgeproto.AppInstInfo{}
	err = api.ShowAppInstInfo(ctx, &filterNone, &show)
	require.Nil(t, err, "show data")
	require.Equal(t, len(testData)+AppInstInfoShowExtraCount, len(show.Data), "Show count")
	for _, obj := range testData {
		show.AssertFound(t, &obj)
	}
}

func GetAppInstInfo(t *testing.T, ctx context.Context, api *AppInstInfoCommonApi, key *edgeproto.AppInstKey, out *edgeproto.AppInstInfo) bool {
	var err error

	show := ShowAppInstInfo{}
	show.Init()
	filter := edgeproto.AppInstInfo{}
	filter.SetKey(key)
	err = api.ShowAppInstInfo(ctx, &filter, &show)
	require.Nil(t, err, "show data")
	obj, found := show.Data[key.GetKeyString()]
	if found {
		*out = obj
	}
	return found
}

func FindAppInstInfoData(key *edgeproto.AppInstKey, testData []edgeproto.AppInstInfo) (*edgeproto.AppInstInfo, bool) {
	for ii, _ := range testData {
		if testData[ii].GetKey().Matches(key) {
			return &testData[ii], true
		}
	}
	return nil, false
}

func (r *Run) AppInstApi(data *[]edgeproto.AppInst, dataMap interface{}, dataOut interface{}) {
	log.DebugLog(log.DebugLevelApi, "API for AppInst", "mode", r.Mode)
	if r.Mode == "show" {
		obj := &edgeproto.AppInst{}
		out, err := r.client.ShowAppInst(r.ctx, obj)
		if err != nil {
			r.logErr("AppInstApi", err)
		} else {
			outp, ok := dataOut.(*[]edgeproto.AppInst)
			if !ok {
				panic(fmt.Sprintf("RunAppInstApi expected dataOut type *[]edgeproto.AppInst, but was %T", dataOut))
			}
			*outp = append(*outp, out...)
		}
		return
	}
	for ii, objD := range *data {
		obj := &objD
		switch r.Mode {
		case "create":
			out, err := r.client.CreateAppInst(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("AppInstApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[][]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunAppInstApi expected dataOut type *[][]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, out)
			}
		case "delete":
			out, err := r.client.DeleteAppInst(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("AppInstApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[][]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunAppInstApi expected dataOut type *[][]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, out)
			}
		case "refresh":
			out, err := r.client.RefreshAppInst(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("AppInstApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[][]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunAppInstApi expected dataOut type *[][]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, out)
			}
		case "update":
			// set specified fields
			objMap, err := cli.GetGenericObjFromList(dataMap, ii)
			if err != nil {
				log.DebugLog(log.DebugLevelApi, "bad dataMap for AppInst", "err", err)
				*r.Rc = false
				return
			}
			yamlData := cli.MapData{
				Namespace: cli.YamlNamespace,
				Data:      objMap,
			}
			obj.Fields = cli.GetSpecifiedFields(&yamlData, obj)

			out, err := r.client.UpdateAppInst(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("AppInstApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[][]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunAppInstApi expected dataOut type *[][]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, out)
			}
		case "showfiltered":
			out, err := r.client.ShowAppInst(r.ctx, obj)
			if err != nil {
				r.logErr(fmt.Sprintf("AppInstApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.AppInst)
				if !ok {
					panic(fmt.Sprintf("RunAppInstApi expected dataOut type *[]edgeproto.AppInst, but was %T", dataOut))
				}
				*outp = append(*outp, out...)
			}
		}
	}
}

func (r *Run) AppInstApi_FedAppInstEvent(data *[]edgeproto.FedAppInstEvent, dataMap interface{}, dataOut interface{}) {
	log.DebugLog(log.DebugLevelApi, "API for FedAppInstEvent", "mode", r.Mode)
	for ii, objD := range *data {
		obj := &objD
		switch r.Mode {
		case "handle":
			out, err := r.client.HandleFedAppInstEvent(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("AppInstApi_FedAppInstEvent[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunAppInstApi_FedAppInstEvent expected dataOut type *[]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		}
	}
}

func (s *DummyServer) CreateAppInst(in *edgeproto.AppInst, server edgeproto.AppInstApi_CreateAppInstServer) error {
	var err error
	if true {
		for ii := 0; ii < s.ShowDummyCount; ii++ {
			server.Send(&edgeproto.Result{Message: "some message"})
		}
		if ch, ok := s.MidstreamFailChs["CreateAppInst"]; ok {
			// Wait until client receives the SendMsg, since they
			// are buffered and dropped once we return err here.
			select {
			case <-ch:
			case <-time.After(5 * time.Second):
			}
			return fmt.Errorf("midstream failure!")
		}
	}
	s.AppInstCache.Update(server.Context(), in, 0)
	return err
}

func (s *DummyServer) DeleteAppInst(in *edgeproto.AppInst, server edgeproto.AppInstApi_DeleteAppInstServer) error {
	var err error
	if true {
		for ii := 0; ii < s.ShowDummyCount; ii++ {
			server.Send(&edgeproto.Result{Message: "some message"})
		}
		if ch, ok := s.MidstreamFailChs["DeleteAppInst"]; ok {
			// Wait until client receives the SendMsg, since they
			// are buffered and dropped once we return err here.
			select {
			case <-ch:
			case <-time.After(5 * time.Second):
			}
			return fmt.Errorf("midstream failure!")
		}
	}
	s.AppInstCache.Delete(server.Context(), in, 0)
	return err
}

func (s *DummyServer) RefreshAppInst(in *edgeproto.AppInst, server edgeproto.AppInstApi_RefreshAppInstServer) error {
	var err error
	if true {
		for ii := 0; ii < s.ShowDummyCount; ii++ {
			server.Send(&edgeproto.Result{})
		}
		if ch, ok := s.MidstreamFailChs["RefreshAppInst"]; ok {
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

func (s *DummyServer) UpdateAppInst(in *edgeproto.AppInst, server edgeproto.AppInstApi_UpdateAppInstServer) error {
	var err error
	if true {
		for ii := 0; ii < s.ShowDummyCount; ii++ {
			server.Send(&edgeproto.Result{Message: "some message"})
		}
		if ch, ok := s.MidstreamFailChs["UpdateAppInst"]; ok {
			// Wait until client receives the SendMsg, since they
			// are buffered and dropped once we return err here.
			select {
			case <-ch:
			case <-time.After(5 * time.Second):
			}
			return fmt.Errorf("midstream failure!")
		}
	}
	s.AppInstCache.Update(server.Context(), in, 0)
	return err
}

func (s *DummyServer) ShowAppInst(in *edgeproto.AppInst, server edgeproto.AppInstApi_ShowAppInstServer) error {
	var err error
	obj := &edgeproto.AppInst{}
	if obj.Matches(in, edgeproto.MatchFilter()) {
		for ii := 0; ii < s.ShowDummyCount; ii++ {
			server.Send(&edgeproto.AppInst{})
		}
		if ch, ok := s.MidstreamFailChs["ShowAppInst"]; ok {
			// Wait until client receives the SendMsg, since they
			// are buffered and dropped once we return err here.
			select {
			case <-ch:
			case <-time.After(5 * time.Second):
			}
			return fmt.Errorf("midstream failure!")
		}
	}
	err = s.AppInstCache.Show(in, func(obj *edgeproto.AppInst) error {
		err := server.Send(obj)
		return err
	})
	return err
}

func (r *Run) AppInstInfoApi(data *[]edgeproto.AppInstInfo, dataMap interface{}, dataOut interface{}) {
	log.DebugLog(log.DebugLevelApi, "API for AppInstInfo", "mode", r.Mode)
	if r.Mode == "show" {
		obj := &edgeproto.AppInstInfo{}
		out, err := r.client.ShowAppInstInfo(r.ctx, obj)
		if err != nil {
			r.logErr("AppInstInfoApi", err)
		} else {
			outp, ok := dataOut.(*[]edgeproto.AppInstInfo)
			if !ok {
				panic(fmt.Sprintf("RunAppInstInfoApi expected dataOut type *[]edgeproto.AppInstInfo, but was %T", dataOut))
			}
			*outp = append(*outp, out...)
		}
		return
	}
	for ii, objD := range *data {
		obj := &objD
		switch r.Mode {
		case "showfiltered":
			out, err := r.client.ShowAppInstInfo(r.ctx, obj)
			if err != nil {
				r.logErr(fmt.Sprintf("AppInstInfoApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.AppInstInfo)
				if !ok {
					panic(fmt.Sprintf("RunAppInstInfoApi expected dataOut type *[]edgeproto.AppInstInfo, but was %T", dataOut))
				}
				*outp = append(*outp, out...)
			}
		}
	}
}

func (s *DummyServer) ShowAppInstInfo(in *edgeproto.AppInstInfo, server edgeproto.AppInstInfoApi_ShowAppInstInfoServer) error {
	var err error
	obj := &edgeproto.AppInstInfo{}
	if obj.Matches(in, edgeproto.MatchFilter()) {
		for ii := 0; ii < s.ShowDummyCount; ii++ {
			server.Send(&edgeproto.AppInstInfo{})
		}
		if ch, ok := s.MidstreamFailChs["ShowAppInstInfo"]; ok {
			// Wait until client receives the SendMsg, since they
			// are buffered and dropped once we return err here.
			select {
			case <-ch:
			case <-time.After(5 * time.Second):
			}
			return fmt.Errorf("midstream failure!")
		}
	}
	err = s.AppInstInfoCache.Show(in, func(obj *edgeproto.AppInstInfo) error {
		err := server.Send(obj)
		return err
	})
	return err
}

func (r *Run) AppInstMetricsApi(data *[]edgeproto.AppInstMetrics, dataMap interface{}, dataOut interface{}) {
	log.DebugLog(log.DebugLevelApi, "API for AppInstMetrics", "mode", r.Mode)
	if r.Mode == "show" {
		obj := &edgeproto.AppInstMetrics{}
		out, err := r.client.ShowAppInstMetrics(r.ctx, obj)
		if err != nil {
			r.logErr("AppInstMetricsApi", err)
		} else {
			outp, ok := dataOut.(*[]edgeproto.AppInstMetrics)
			if !ok {
				panic(fmt.Sprintf("RunAppInstMetricsApi expected dataOut type *[]edgeproto.AppInstMetrics, but was %T", dataOut))
			}
			*outp = append(*outp, out...)
		}
		return
	}
	for ii, objD := range *data {
		obj := &objD
		switch r.Mode {
		case "showfiltered":
			out, err := r.client.ShowAppInstMetrics(r.ctx, obj)
			if err != nil {
				r.logErr(fmt.Sprintf("AppInstMetricsApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.AppInstMetrics)
				if !ok {
					panic(fmt.Sprintf("RunAppInstMetricsApi expected dataOut type *[]edgeproto.AppInstMetrics, but was %T", dataOut))
				}
				*outp = append(*outp, out...)
			}
		}
	}
}

func (r *Run) AppInstLatencyApi(data *[]edgeproto.AppInstLatency, dataMap interface{}, dataOut interface{}) {
	log.DebugLog(log.DebugLevelApi, "API for AppInstLatency", "mode", r.Mode)
	for ii, objD := range *data {
		obj := &objD
		switch r.Mode {
		case "request":
			out, err := r.client.RequestAppInstLatency(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("AppInstLatencyApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunAppInstLatencyApi expected dataOut type *[]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		}
	}
}

func (s *ApiClient) CreateAppInst(ctx context.Context, in *edgeproto.AppInst) ([]edgeproto.Result, error) {
	api := edgeproto.NewAppInstApiClient(s.Conn)
	stream, err := api.CreateAppInst(ctx, in)
	if err != nil {
		return nil, err
	}
	return ResultReadStream(stream)
}

func (s *CliClient) CreateAppInst(ctx context.Context, in *edgeproto.AppInst) ([]edgeproto.Result, error) {
	output := []edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "CreateAppInst")
	err := wrapper.RunEdgectlObjs(args, in, &output, s.RunOps...)
	return output, err
}

func (s *ApiClient) DeleteAppInst(ctx context.Context, in *edgeproto.AppInst) ([]edgeproto.Result, error) {
	api := edgeproto.NewAppInstApiClient(s.Conn)
	stream, err := api.DeleteAppInst(ctx, in)
	if err != nil {
		return nil, err
	}
	return ResultReadStream(stream)
}

func (s *CliClient) DeleteAppInst(ctx context.Context, in *edgeproto.AppInst) ([]edgeproto.Result, error) {
	output := []edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "DeleteAppInst")
	err := wrapper.RunEdgectlObjs(args, in, &output, s.RunOps...)
	return output, err
}

func (s *ApiClient) RefreshAppInst(ctx context.Context, in *edgeproto.AppInst) ([]edgeproto.Result, error) {
	api := edgeproto.NewAppInstApiClient(s.Conn)
	stream, err := api.RefreshAppInst(ctx, in)
	if err != nil {
		return nil, err
	}
	return ResultReadStream(stream)
}

func (s *CliClient) RefreshAppInst(ctx context.Context, in *edgeproto.AppInst) ([]edgeproto.Result, error) {
	output := []edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "RefreshAppInst")
	err := wrapper.RunEdgectlObjs(args, in, &output, s.RunOps...)
	return output, err
}

func (s *ApiClient) UpdateAppInst(ctx context.Context, in *edgeproto.AppInst) ([]edgeproto.Result, error) {
	api := edgeproto.NewAppInstApiClient(s.Conn)
	stream, err := api.UpdateAppInst(ctx, in)
	if err != nil {
		return nil, err
	}
	return ResultReadStream(stream)
}

func (s *CliClient) UpdateAppInst(ctx context.Context, in *edgeproto.AppInst) ([]edgeproto.Result, error) {
	output := []edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "UpdateAppInst")
	err := wrapper.RunEdgectlObjs(args, in, &output, s.RunOps...)
	return output, err
}

type AppInstStream interface {
	Recv() (*edgeproto.AppInst, error)
}

func AppInstReadStream(stream AppInstStream) ([]edgeproto.AppInst, error) {
	output := []edgeproto.AppInst{}
	for {
		obj, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return output, fmt.Errorf("read AppInst stream failed, %v", err)
		}
		output = append(output, *obj)
	}
	return output, nil
}

func (s *ApiClient) ShowAppInst(ctx context.Context, in *edgeproto.AppInst) ([]edgeproto.AppInst, error) {
	api := edgeproto.NewAppInstApiClient(s.Conn)
	stream, err := api.ShowAppInst(ctx, in)
	if err != nil {
		return nil, err
	}
	return AppInstReadStream(stream)
}

func (s *CliClient) ShowAppInst(ctx context.Context, in *edgeproto.AppInst) ([]edgeproto.AppInst, error) {
	output := []edgeproto.AppInst{}
	args := append(s.BaseArgs, "controller", "ShowAppInst")
	err := wrapper.RunEdgectlObjs(args, in, &output, s.RunOps...)
	return output, err
}

func (s *ApiClient) HandleFedAppInstEvent(ctx context.Context, in *edgeproto.FedAppInstEvent) (*edgeproto.Result, error) {
	api := edgeproto.NewAppInstApiClient(s.Conn)
	return api.HandleFedAppInstEvent(ctx, in)
}

func (s *CliClient) HandleFedAppInstEvent(ctx context.Context, in *edgeproto.FedAppInstEvent) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "HandleFedAppInstEvent")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

type AppInstApiClient interface {
	CreateAppInst(ctx context.Context, in *edgeproto.AppInst) ([]edgeproto.Result, error)
	DeleteAppInst(ctx context.Context, in *edgeproto.AppInst) ([]edgeproto.Result, error)
	RefreshAppInst(ctx context.Context, in *edgeproto.AppInst) ([]edgeproto.Result, error)
	UpdateAppInst(ctx context.Context, in *edgeproto.AppInst) ([]edgeproto.Result, error)
	ShowAppInst(ctx context.Context, in *edgeproto.AppInst) ([]edgeproto.AppInst, error)
	HandleFedAppInstEvent(ctx context.Context, in *edgeproto.FedAppInstEvent) (*edgeproto.Result, error)
}

type AppInstInfoStream interface {
	Recv() (*edgeproto.AppInstInfo, error)
}

func AppInstInfoReadStream(stream AppInstInfoStream) ([]edgeproto.AppInstInfo, error) {
	output := []edgeproto.AppInstInfo{}
	for {
		obj, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return output, fmt.Errorf("read AppInstInfo stream failed, %v", err)
		}
		output = append(output, *obj)
	}
	return output, nil
}

func (s *ApiClient) ShowAppInstInfo(ctx context.Context, in *edgeproto.AppInstInfo) ([]edgeproto.AppInstInfo, error) {
	api := edgeproto.NewAppInstInfoApiClient(s.Conn)
	stream, err := api.ShowAppInstInfo(ctx, in)
	if err != nil {
		return nil, err
	}
	return AppInstInfoReadStream(stream)
}

func (s *CliClient) ShowAppInstInfo(ctx context.Context, in *edgeproto.AppInstInfo) ([]edgeproto.AppInstInfo, error) {
	output := []edgeproto.AppInstInfo{}
	args := append(s.BaseArgs, "controller", "ShowAppInstInfo")
	err := wrapper.RunEdgectlObjs(args, in, &output, s.RunOps...)
	return output, err
}

type AppInstInfoApiClient interface {
	ShowAppInstInfo(ctx context.Context, in *edgeproto.AppInstInfo) ([]edgeproto.AppInstInfo, error)
}

type AppInstMetricsStream interface {
	Recv() (*edgeproto.AppInstMetrics, error)
}

func AppInstMetricsReadStream(stream AppInstMetricsStream) ([]edgeproto.AppInstMetrics, error) {
	output := []edgeproto.AppInstMetrics{}
	for {
		obj, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return output, fmt.Errorf("read AppInstMetrics stream failed, %v", err)
		}
		output = append(output, *obj)
	}
	return output, nil
}

func (s *ApiClient) ShowAppInstMetrics(ctx context.Context, in *edgeproto.AppInstMetrics) ([]edgeproto.AppInstMetrics, error) {
	api := edgeproto.NewAppInstMetricsApiClient(s.Conn)
	stream, err := api.ShowAppInstMetrics(ctx, in)
	if err != nil {
		return nil, err
	}
	return AppInstMetricsReadStream(stream)
}

func (s *CliClient) ShowAppInstMetrics(ctx context.Context, in *edgeproto.AppInstMetrics) ([]edgeproto.AppInstMetrics, error) {
	output := []edgeproto.AppInstMetrics{}
	args := append(s.BaseArgs, "controller", "ShowAppInstMetrics")
	err := wrapper.RunEdgectlObjs(args, in, &output, s.RunOps...)
	return output, err
}

type AppInstMetricsApiClient interface {
	ShowAppInstMetrics(ctx context.Context, in *edgeproto.AppInstMetrics) ([]edgeproto.AppInstMetrics, error)
}

func (s *ApiClient) RequestAppInstLatency(ctx context.Context, in *edgeproto.AppInstLatency) (*edgeproto.Result, error) {
	api := edgeproto.NewAppInstLatencyApiClient(s.Conn)
	return api.RequestAppInstLatency(ctx, in)
}

func (s *CliClient) RequestAppInstLatency(ctx context.Context, in *edgeproto.AppInstLatency) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "RequestAppInstLatency")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

type AppInstLatencyApiClient interface {
	RequestAppInstLatency(ctx context.Context, in *edgeproto.AppInstLatency) (*edgeproto.Result, error)
}
