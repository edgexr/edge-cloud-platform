// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: cloudlet.proto

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
import _ "github.com/mobiledgex/edge-cloud/protoc-gen-cmd/protocmd"
import _ "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
import _ "github.com/gogo/protobuf/gogoproto"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

type ShowCloudlet struct {
	Data map[string]edgeproto.Cloudlet
	grpc.ServerStream
}

func (x *ShowCloudlet) Init() {
	x.Data = make(map[string]edgeproto.Cloudlet)
}

func (x *ShowCloudlet) Send(m *edgeproto.Cloudlet) error {
	x.Data[m.Key.GetKeyString()] = *m
	return nil
}

type CudStreamoutCloudlet struct {
	grpc.ServerStream
	ctx context.Context
}

func (x *CudStreamoutCloudlet) Send(res *edgeproto.Result) error {
	fmt.Println(res)
	return nil
}

func (x *CudStreamoutCloudlet) Context() context.Context {
	return x.ctx
}

func NewCudStreamoutCloudlet(ctx context.Context) *CudStreamoutCloudlet {
	return &CudStreamoutCloudlet{
		ctx: ctx,
	}
}

type CloudletStream interface {
	Recv() (*edgeproto.Result, error)
}

func CloudletReadResultStream(stream CloudletStream, err error) error {
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

func (x *ShowCloudlet) ReadStream(stream edgeproto.CloudletApi_ShowCloudletClient, err error) {
	x.Data = make(map[string]edgeproto.Cloudlet)
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

func (x *ShowCloudlet) CheckFound(obj *edgeproto.Cloudlet) bool {
	_, found := x.Data[obj.Key.GetKeyString()]
	return found
}

func (x *ShowCloudlet) AssertFound(t *testing.T, obj *edgeproto.Cloudlet) {
	check, found := x.Data[obj.Key.GetKeyString()]
	require.True(t, found, "find Cloudlet %s", obj.Key.GetKeyString())
	if found && !check.Matches(obj, edgeproto.MatchIgnoreBackend(), edgeproto.MatchSortArrayedKeys()) {
		require.Equal(t, *obj, check, "Cloudlet are equal")
	}
	if found {
		// remove in case there are dups in the list, so the
		// same object cannot be used again
		delete(x.Data, obj.Key.GetKeyString())
	}
}

func (x *ShowCloudlet) AssertNotFound(t *testing.T, obj *edgeproto.Cloudlet) {
	_, found := x.Data[obj.Key.GetKeyString()]
	require.False(t, found, "do not find Cloudlet %s", obj.Key.GetKeyString())
}

func WaitAssertFoundCloudlet(t *testing.T, api edgeproto.CloudletApiClient, obj *edgeproto.Cloudlet, count int, retry time.Duration) {
	show := ShowCloudlet{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowCloudlet(ctx, obj)
		show.ReadStream(stream, err)
		cancel()
		if show.CheckFound(obj) {
			break
		}
		time.Sleep(retry)
	}
	show.AssertFound(t, obj)
}

func WaitAssertNotFoundCloudlet(t *testing.T, api edgeproto.CloudletApiClient, obj *edgeproto.Cloudlet, count int, retry time.Duration) {
	show := ShowCloudlet{}
	filterNone := edgeproto.Cloudlet{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowCloudlet(ctx, &filterNone)
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
type CloudletCommonApi struct {
	internal_api edgeproto.CloudletApiServer
	client_api   edgeproto.CloudletApiClient
}

func (x *CloudletCommonApi) CreateCloudlet(ctx context.Context, in *edgeproto.Cloudlet) (*edgeproto.Result, error) {
	copy := &edgeproto.Cloudlet{}
	*copy = *in
	if x.internal_api != nil {
		err := x.internal_api.CreateCloudlet(copy, NewCudStreamoutCloudlet(ctx))
		return &edgeproto.Result{}, err
	} else {
		stream, err := x.client_api.CreateCloudlet(ctx, copy)
		err = CloudletReadResultStream(stream, err)
		return &edgeproto.Result{}, err
	}
}

func (x *CloudletCommonApi) UpdateCloudlet(ctx context.Context, in *edgeproto.Cloudlet) (*edgeproto.Result, error) {
	copy := &edgeproto.Cloudlet{}
	*copy = *in
	if x.internal_api != nil {
		err := x.internal_api.UpdateCloudlet(copy, NewCudStreamoutCloudlet(ctx))
		return &edgeproto.Result{}, err
	} else {
		stream, err := x.client_api.UpdateCloudlet(ctx, copy)
		err = CloudletReadResultStream(stream, err)
		return &edgeproto.Result{}, err
	}
}

func (x *CloudletCommonApi) DeleteCloudlet(ctx context.Context, in *edgeproto.Cloudlet) (*edgeproto.Result, error) {
	copy := &edgeproto.Cloudlet{}
	*copy = *in
	if x.internal_api != nil {
		err := x.internal_api.DeleteCloudlet(copy, NewCudStreamoutCloudlet(ctx))
		return &edgeproto.Result{}, err
	} else {
		stream, err := x.client_api.DeleteCloudlet(ctx, copy)
		err = CloudletReadResultStream(stream, err)
		return &edgeproto.Result{}, err
	}
}

func (x *CloudletCommonApi) ShowCloudlet(ctx context.Context, filter *edgeproto.Cloudlet, showData *ShowCloudlet) error {
	if x.internal_api != nil {
		return x.internal_api.ShowCloudlet(filter, showData)
	} else {
		stream, err := x.client_api.ShowCloudlet(ctx, filter)
		showData.ReadStream(stream, err)
		return err
	}
}

func NewInternalCloudletApi(api edgeproto.CloudletApiServer) *CloudletCommonApi {
	apiWrap := CloudletCommonApi{}
	apiWrap.internal_api = api
	return &apiWrap
}

func NewClientCloudletApi(api edgeproto.CloudletApiClient) *CloudletCommonApi {
	apiWrap := CloudletCommonApi{}
	apiWrap.client_api = api
	return &apiWrap
}

func InternalCloudletTest(t *testing.T, test string, api edgeproto.CloudletApiServer, testData []edgeproto.Cloudlet) {
	span := log.StartSpan(log.DebugLevelApi, "InternalCloudletTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "cud":
		basicCloudletCudTest(t, ctx, NewInternalCloudletApi(api), testData)
	case "show":
		basicCloudletShowTest(t, ctx, NewInternalCloudletApi(api), testData)
	}
}

func ClientCloudletTest(t *testing.T, test string, api edgeproto.CloudletApiClient, testData []edgeproto.Cloudlet) {
	span := log.StartSpan(log.DebugLevelApi, "ClientCloudletTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "cud":
		basicCloudletCudTest(t, ctx, NewClientCloudletApi(api), testData)
	case "show":
		basicCloudletShowTest(t, ctx, NewClientCloudletApi(api), testData)
	}
}

func basicCloudletShowTest(t *testing.T, ctx context.Context, api *CloudletCommonApi, testData []edgeproto.Cloudlet) {
	var err error

	show := ShowCloudlet{}
	show.Init()
	filterNone := edgeproto.Cloudlet{}
	err = api.ShowCloudlet(ctx, &filterNone, &show)
	require.Nil(t, err, "show data")
	require.Equal(t, len(testData), len(show.Data), "Show count")
	for _, obj := range testData {
		show.AssertFound(t, &obj)
	}
}

func GetCloudlet(t *testing.T, ctx context.Context, api *CloudletCommonApi, key *edgeproto.CloudletKey, out *edgeproto.Cloudlet) bool {
	var err error

	show := ShowCloudlet{}
	show.Init()
	filter := edgeproto.Cloudlet{}
	filter.Key = *key
	err = api.ShowCloudlet(ctx, &filter, &show)
	require.Nil(t, err, "show data")
	obj, found := show.Data[key.GetKeyString()]
	if found {
		*out = obj
	}
	return found
}

func basicCloudletCudTest(t *testing.T, ctx context.Context, api *CloudletCommonApi, testData []edgeproto.Cloudlet) {
	var err error

	if len(testData) < 3 {
		require.True(t, false, "Need at least 3 test data objects")
		return
	}

	// test create
	createCloudletData(t, ctx, api, testData)

	// test duplicate create - should fail
	_, err = api.CreateCloudlet(ctx, &testData[0])
	require.NotNil(t, err, "Create duplicate Cloudlet")

	// test show all items
	basicCloudletShowTest(t, ctx, api, testData)

	// test delete
	_, err = api.DeleteCloudlet(ctx, &testData[0])
	require.Nil(t, err, "delete Cloudlet %s", testData[0].Key.GetKeyString())
	show := ShowCloudlet{}
	show.Init()
	filterNone := edgeproto.Cloudlet{}
	err = api.ShowCloudlet(ctx, &filterNone, &show)
	require.Nil(t, err, "show data")
	require.Equal(t, len(testData)-1, len(show.Data), "Show count")
	show.AssertNotFound(t, &testData[0])
	// test update of missing object
	_, err = api.UpdateCloudlet(ctx, &testData[0])
	require.NotNil(t, err, "Update missing object")
	// create it back
	_, err = api.CreateCloudlet(ctx, &testData[0])
	require.Nil(t, err, "Create Cloudlet %s", testData[0].Key.GetKeyString())

	// test invalid keys
	bad := edgeproto.Cloudlet{}
	_, err = api.CreateCloudlet(ctx, &bad)
	require.NotNil(t, err, "Create Cloudlet with no key info")

	// test update
	updater := edgeproto.Cloudlet{}
	updater.Key = testData[0].Key
	updater.AccessCredentials = "update just this"
	updater.Fields = make([]string, 0)
	updater.Fields = append(updater.Fields, edgeproto.CloudletFieldAccessCredentials)
	_, err = api.UpdateCloudlet(ctx, &updater)
	require.Nil(t, err, "Update Cloudlet %s", testData[0].Key.GetKeyString())

	show.Init()
	updater = testData[0]
	updater.AccessCredentials = "update just this"
	err = api.ShowCloudlet(ctx, &filterNone, &show)
	require.Nil(t, err, "show Cloudlet")
	show.AssertFound(t, &updater)

	// revert change
	updater.AccessCredentials = testData[0].AccessCredentials
	_, err = api.UpdateCloudlet(ctx, &updater)
	require.Nil(t, err, "Update back Cloudlet")
}

func InternalCloudletCreate(t *testing.T, api edgeproto.CloudletApiServer, testData []edgeproto.Cloudlet) {
	span := log.StartSpan(log.DebugLevelApi, "InternalCloudletCreate")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	createCloudletData(t, ctx, NewInternalCloudletApi(api), testData)
}

func ClientCloudletCreate(t *testing.T, api edgeproto.CloudletApiClient, testData []edgeproto.Cloudlet) {
	span := log.StartSpan(log.DebugLevelApi, "ClientCloudletCreate")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	createCloudletData(t, ctx, NewClientCloudletApi(api), testData)
}

func createCloudletData(t *testing.T, ctx context.Context, api *CloudletCommonApi, testData []edgeproto.Cloudlet) {
	var err error

	for _, obj := range testData {
		_, err = api.CreateCloudlet(ctx, &obj)
		require.Nil(t, err, "Create Cloudlet %s", obj.Key.GetKeyString())
	}
}

type ShowCloudletInfo struct {
	Data map[string]edgeproto.CloudletInfo
	grpc.ServerStream
}

func (x *ShowCloudletInfo) Init() {
	x.Data = make(map[string]edgeproto.CloudletInfo)
}

func (x *ShowCloudletInfo) Send(m *edgeproto.CloudletInfo) error {
	x.Data[m.Key.GetKeyString()] = *m
	return nil
}

func (x *ShowCloudletInfo) ReadStream(stream edgeproto.CloudletInfoApi_ShowCloudletInfoClient, err error) {
	x.Data = make(map[string]edgeproto.CloudletInfo)
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

func (x *ShowCloudletInfo) CheckFound(obj *edgeproto.CloudletInfo) bool {
	_, found := x.Data[obj.Key.GetKeyString()]
	return found
}

func (x *ShowCloudletInfo) AssertFound(t *testing.T, obj *edgeproto.CloudletInfo) {
	check, found := x.Data[obj.Key.GetKeyString()]
	require.True(t, found, "find CloudletInfo %s", obj.Key.GetKeyString())
	if found && !check.Matches(obj, edgeproto.MatchIgnoreBackend(), edgeproto.MatchSortArrayedKeys()) {
		require.Equal(t, *obj, check, "CloudletInfo are equal")
	}
	if found {
		// remove in case there are dups in the list, so the
		// same object cannot be used again
		delete(x.Data, obj.Key.GetKeyString())
	}
}

func (x *ShowCloudletInfo) AssertNotFound(t *testing.T, obj *edgeproto.CloudletInfo) {
	_, found := x.Data[obj.Key.GetKeyString()]
	require.False(t, found, "do not find CloudletInfo %s", obj.Key.GetKeyString())
}

func WaitAssertFoundCloudletInfo(t *testing.T, api edgeproto.CloudletInfoApiClient, obj *edgeproto.CloudletInfo, count int, retry time.Duration) {
	show := ShowCloudletInfo{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowCloudletInfo(ctx, obj)
		show.ReadStream(stream, err)
		cancel()
		if show.CheckFound(obj) {
			break
		}
		time.Sleep(retry)
	}
	show.AssertFound(t, obj)
}

func WaitAssertNotFoundCloudletInfo(t *testing.T, api edgeproto.CloudletInfoApiClient, obj *edgeproto.CloudletInfo, count int, retry time.Duration) {
	show := ShowCloudletInfo{}
	filterNone := edgeproto.CloudletInfo{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowCloudletInfo(ctx, &filterNone)
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
type CloudletInfoCommonApi struct {
	internal_api edgeproto.CloudletInfoApiServer
	client_api   edgeproto.CloudletInfoApiClient
}

func (x *CloudletInfoCommonApi) ShowCloudletInfo(ctx context.Context, filter *edgeproto.CloudletInfo, showData *ShowCloudletInfo) error {
	if x.internal_api != nil {
		return x.internal_api.ShowCloudletInfo(filter, showData)
	} else {
		stream, err := x.client_api.ShowCloudletInfo(ctx, filter)
		showData.ReadStream(stream, err)
		return err
	}
}

func NewInternalCloudletInfoApi(api edgeproto.CloudletInfoApiServer) *CloudletInfoCommonApi {
	apiWrap := CloudletInfoCommonApi{}
	apiWrap.internal_api = api
	return &apiWrap
}

func NewClientCloudletInfoApi(api edgeproto.CloudletInfoApiClient) *CloudletInfoCommonApi {
	apiWrap := CloudletInfoCommonApi{}
	apiWrap.client_api = api
	return &apiWrap
}

func InternalCloudletInfoTest(t *testing.T, test string, api edgeproto.CloudletInfoApiServer, testData []edgeproto.CloudletInfo) {
	span := log.StartSpan(log.DebugLevelApi, "InternalCloudletInfoTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "show":
		basicCloudletInfoShowTest(t, ctx, NewInternalCloudletInfoApi(api), testData)
	}
}

func ClientCloudletInfoTest(t *testing.T, test string, api edgeproto.CloudletInfoApiClient, testData []edgeproto.CloudletInfo) {
	span := log.StartSpan(log.DebugLevelApi, "ClientCloudletInfoTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "show":
		basicCloudletInfoShowTest(t, ctx, NewClientCloudletInfoApi(api), testData)
	}
}

func basicCloudletInfoShowTest(t *testing.T, ctx context.Context, api *CloudletInfoCommonApi, testData []edgeproto.CloudletInfo) {
	var err error

	show := ShowCloudletInfo{}
	show.Init()
	filterNone := edgeproto.CloudletInfo{}
	err = api.ShowCloudletInfo(ctx, &filterNone, &show)
	require.Nil(t, err, "show data")
	require.Equal(t, len(testData), len(show.Data), "Show count")
	for _, obj := range testData {
		show.AssertFound(t, &obj)
	}
}

func GetCloudletInfo(t *testing.T, ctx context.Context, api *CloudletInfoCommonApi, key *edgeproto.CloudletKey, out *edgeproto.CloudletInfo) bool {
	var err error

	show := ShowCloudletInfo{}
	show.Init()
	filter := edgeproto.CloudletInfo{}
	filter.Key = *key
	err = api.ShowCloudletInfo(ctx, &filter, &show)
	require.Nil(t, err, "show data")
	obj, found := show.Data[key.GetKeyString()]
	if found {
		*out = obj
	}
	return found
}

func (s *DummyServer) CreateCloudlet(in *edgeproto.Cloudlet, server edgeproto.CloudletApi_CreateCloudletServer) error {
	if true {
		server.Send(&edgeproto.Result{})
		server.Send(&edgeproto.Result{})
		server.Send(&edgeproto.Result{})
	}
	return nil
}

func (s *DummyServer) DeleteCloudlet(in *edgeproto.Cloudlet, server edgeproto.CloudletApi_DeleteCloudletServer) error {
	if true {
		server.Send(&edgeproto.Result{})
		server.Send(&edgeproto.Result{})
		server.Send(&edgeproto.Result{})
	}
	return nil
}

func (s *DummyServer) UpdateCloudlet(in *edgeproto.Cloudlet, server edgeproto.CloudletApi_UpdateCloudletServer) error {
	if true {
		server.Send(&edgeproto.Result{})
		server.Send(&edgeproto.Result{})
		server.Send(&edgeproto.Result{})
	}
	return nil
}

func (s *DummyServer) ShowCloudlet(in *edgeproto.Cloudlet, server edgeproto.CloudletApi_ShowCloudletServer) error {
	obj := &edgeproto.Cloudlet{}
	if obj.Matches(in, edgeproto.MatchFilter()) {
		server.Send(&edgeproto.Cloudlet{})
		server.Send(&edgeproto.Cloudlet{})
		server.Send(&edgeproto.Cloudlet{})
	}
	for _, out := range s.Cloudlets {
		if !out.Matches(in, edgeproto.MatchFilter()) {
			continue
		}
		server.Send(&out)
	}
	return nil
}

func (s *DummyServer) ShowCloudletInfo(in *edgeproto.CloudletInfo, server edgeproto.CloudletInfoApi_ShowCloudletInfoServer) error {
	obj := &edgeproto.CloudletInfo{}
	if obj.Matches(in, edgeproto.MatchFilter()) {
		server.Send(&edgeproto.CloudletInfo{})
		server.Send(&edgeproto.CloudletInfo{})
		server.Send(&edgeproto.CloudletInfo{})
	}
	for _, out := range s.CloudletInfos {
		if !out.Matches(in, edgeproto.MatchFilter()) {
			continue
		}
		server.Send(&out)
	}
	return nil
}

func (s *DummyServer) InjectCloudletInfo(ctx context.Context, in *edgeproto.CloudletInfo) (*edgeproto.Result, error) {
	return &edgeproto.Result{}, nil
}

func (s *DummyServer) EvictCloudletInfo(ctx context.Context, in *edgeproto.CloudletInfo) (*edgeproto.Result, error) {
	return &edgeproto.Result{}, nil
}
