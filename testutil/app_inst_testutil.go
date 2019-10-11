// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: app_inst.proto

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
import _ "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
import _ "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
import _ "github.com/gogo/protobuf/gogoproto"

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

type AppInstStream interface {
	Recv() (*edgeproto.Result, error)
}

func AppInstReadResultStream(stream AppInstStream, err error) error {
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
		return &edgeproto.Result{}, err
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
		return &edgeproto.Result{}, err
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
		return &edgeproto.Result{}, err
	}
}

func (x *AppInstCommonApi) ShowAppInst(ctx context.Context, filter *edgeproto.AppInst, showData *ShowAppInst) error {
	if x.internal_api != nil {
		showData.Ctx = ctx
		return x.internal_api.ShowAppInst(filter, showData)
	} else {
		stream, err := x.client_api.ShowAppInst(ctx, filter)
		showData.ReadStream(stream, err)
		return err
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

func InternalAppInstTest(t *testing.T, test string, api edgeproto.AppInstApiServer, testData []edgeproto.AppInst) {
	span := log.StartSpan(log.DebugLevelApi, "InternalAppInstTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "cud":
		basicAppInstCudTest(t, ctx, NewInternalAppInstApi(api), testData)
	case "show":
		basicAppInstShowTest(t, ctx, NewInternalAppInstApi(api), testData)
	}
}

func ClientAppInstTest(t *testing.T, test string, api edgeproto.AppInstApiClient, testData []edgeproto.AppInst) {
	span := log.StartSpan(log.DebugLevelApi, "ClientAppInstTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "cud":
		basicAppInstCudTest(t, ctx, NewClientAppInstApi(api), testData)
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

func basicAppInstCudTest(t *testing.T, ctx context.Context, api *AppInstCommonApi, testData []edgeproto.AppInst) {
	var err error

	if len(testData) < 3 {
		require.True(t, false, "Need at least 3 test data objects")
		return
	}

	// test create
	CreateAppInstData(t, ctx, api, testData)

	// test duplicate Create - should fail
	_, err = api.CreateAppInst(ctx, &testData[0])
	require.NotNil(t, err, "Create duplicate AppInst")

	// test show all items
	basicAppInstShowTest(t, ctx, api, testData)

	// test Delete
	_, err = api.DeleteAppInst(ctx, &testData[0])
	require.Nil(t, err, "Delete AppInst %s", testData[0].GetKey().GetKeyString())
	show := ShowAppInst{}
	show.Init()
	filterNone := edgeproto.AppInst{}
	err = api.ShowAppInst(ctx, &filterNone, &show)
	require.Nil(t, err, "show data")
	require.Equal(t, len(testData)-1+AppInstShowExtraCount, len(show.Data), "Show count")
	show.AssertNotFound(t, &testData[0])
	// test update of missing object
	_, err = api.UpdateAppInst(ctx, &testData[0])
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

	for _, obj := range testData {
		_, err = api.CreateAppInst(ctx, &obj)
		require.Nil(t, err, "Create AppInst %s", obj.GetKey().GetKeyString())
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
		return err
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

func InternalAppInstInfoTest(t *testing.T, test string, api edgeproto.AppInstInfoApiServer, testData []edgeproto.AppInstInfo) {
	span := log.StartSpan(log.DebugLevelApi, "InternalAppInstInfoTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "show":
		basicAppInstInfoShowTest(t, ctx, NewInternalAppInstInfoApi(api), testData)
	}
}

func ClientAppInstInfoTest(t *testing.T, test string, api edgeproto.AppInstInfoApiClient, testData []edgeproto.AppInstInfo) {
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

func (s *DummyServer) CreateAppInst(in *edgeproto.AppInst, server edgeproto.AppInstApi_CreateAppInstServer) error {
	var err error
	s.AppInstCache.Update(server.Context(), in, 0)
	if true {
		for ii := 0; ii < s.ShowDummyCount; ii++ {
			server.Send(&edgeproto.Result{})
		}
	}
	return err
}

func (s *DummyServer) DeleteAppInst(in *edgeproto.AppInst, server edgeproto.AppInstApi_DeleteAppInstServer) error {
	var err error
	s.AppInstCache.Delete(server.Context(), in, 0)
	if true {
		for ii := 0; ii < s.ShowDummyCount; ii++ {
			server.Send(&edgeproto.Result{})
		}
	}
	return err
}

func (s *DummyServer) UpdateAppInst(in *edgeproto.AppInst, server edgeproto.AppInstApi_UpdateAppInstServer) error {
	var err error
	s.AppInstCache.Update(server.Context(), in, 0)
	if true {
		for ii := 0; ii < s.ShowDummyCount; ii++ {
			server.Send(&edgeproto.Result{})
		}
	}
	return err
}

func (s *DummyServer) ShowAppInst(in *edgeproto.AppInst, server edgeproto.AppInstApi_ShowAppInstServer) error {
	var err error
	obj := &edgeproto.AppInst{}
	if obj.Matches(in, edgeproto.MatchFilter()) {
		for ii := 0; ii < s.ShowDummyCount; ii++ {
			server.Send(&edgeproto.AppInst{})
		}
	}
	err = s.AppInstCache.Show(in, func(obj *edgeproto.AppInst) error {
		err := server.Send(obj)
		return err
	})
	return err
}

func (s *DummyServer) ShowAppInstInfo(in *edgeproto.AppInstInfo, server edgeproto.AppInstInfoApi_ShowAppInstInfoServer) error {
	var err error
	obj := &edgeproto.AppInstInfo{}
	if obj.Matches(in, edgeproto.MatchFilter()) {
		for ii := 0; ii < s.ShowDummyCount; ii++ {
			server.Send(&edgeproto.AppInstInfo{})
		}
	}
	err = s.AppInstInfoCache.Show(in, func(obj *edgeproto.AppInstInfo) error {
		err := server.Send(obj)
		return err
	})
	return err
}
