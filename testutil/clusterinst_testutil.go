// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: clusterinst.proto

package testutil

import (
	"context"
	fmt "fmt"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	"github.com/mobiledgex/edge-cloud/cli"
	_ "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
	"github.com/mobiledgex/edge-cloud/edgectl/wrapper"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	_ "github.com/mobiledgex/edge-cloud/protogen"
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

type ShowClusterInst struct {
	Data map[string]edgeproto.ClusterInst
	grpc.ServerStream
	Ctx context.Context
}

func (x *ShowClusterInst) Init() {
	x.Data = make(map[string]edgeproto.ClusterInst)
}

func (x *ShowClusterInst) Send(m *edgeproto.ClusterInst) error {
	x.Data[m.GetKey().GetKeyString()] = *m
	return nil
}

func (x *ShowClusterInst) Context() context.Context {
	return x.Ctx
}

var ClusterInstShowExtraCount = 0

type CudStreamoutClusterInst struct {
	grpc.ServerStream
	Ctx context.Context
}

func (x *CudStreamoutClusterInst) Send(res *edgeproto.Result) error {
	fmt.Println(res)
	return nil
}

func (x *CudStreamoutClusterInst) Context() context.Context {
	return x.Ctx
}

func NewCudStreamoutClusterInst(ctx context.Context) *CudStreamoutClusterInst {
	return &CudStreamoutClusterInst{
		Ctx: ctx,
	}
}

func ClusterInstReadResultStream(stream ResultStream, err error) error {
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

func (x *ShowClusterInst) ReadStream(stream edgeproto.ClusterInstApi_ShowClusterInstClient, err error) {
	x.Data = make(map[string]edgeproto.ClusterInst)
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

func (x *ShowClusterInst) CheckFound(obj *edgeproto.ClusterInst) bool {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	return found
}

func (x *ShowClusterInst) AssertFound(t *testing.T, obj *edgeproto.ClusterInst) {
	check, found := x.Data[obj.GetKey().GetKeyString()]
	require.True(t, found, "find ClusterInst %s", obj.GetKey().GetKeyString())
	if found && !check.Matches(obj, edgeproto.MatchIgnoreBackend(), edgeproto.MatchSortArrayedKeys()) {
		require.Equal(t, *obj, check, "ClusterInst are equal")
	}
	if found {
		// remove in case there are dups in the list, so the
		// same object cannot be used again
		delete(x.Data, obj.GetKey().GetKeyString())
	}
}

func (x *ShowClusterInst) AssertNotFound(t *testing.T, obj *edgeproto.ClusterInst) {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	require.False(t, found, "do not find ClusterInst %s", obj.GetKey().GetKeyString())
}

func WaitAssertFoundClusterInst(t *testing.T, api edgeproto.ClusterInstApiClient, obj *edgeproto.ClusterInst, count int, retry time.Duration) {
	show := ShowClusterInst{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowClusterInst(ctx, obj)
		show.ReadStream(stream, err)
		cancel()
		if show.CheckFound(obj) {
			break
		}
		time.Sleep(retry)
	}
	show.AssertFound(t, obj)
}

func WaitAssertNotFoundClusterInst(t *testing.T, api edgeproto.ClusterInstApiClient, obj *edgeproto.ClusterInst, count int, retry time.Duration) {
	show := ShowClusterInst{}
	filterNone := edgeproto.ClusterInst{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowClusterInst(ctx, &filterNone)
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
type ClusterInstCommonApi struct {
	internal_api edgeproto.ClusterInstApiServer
	client_api   edgeproto.ClusterInstApiClient
}

func (x *ClusterInstCommonApi) CreateClusterInst(ctx context.Context, in *edgeproto.ClusterInst) (*edgeproto.Result, error) {
	copy := &edgeproto.ClusterInst{}
	*copy = *in
	if x.internal_api != nil {
		err := x.internal_api.CreateClusterInst(copy, NewCudStreamoutClusterInst(ctx))
		return &edgeproto.Result{}, err
	} else {
		stream, err := x.client_api.CreateClusterInst(ctx, copy)
		err = ClusterInstReadResultStream(stream, err)
		return &edgeproto.Result{}, err
	}
}

func (x *ClusterInstCommonApi) DeleteClusterInst(ctx context.Context, in *edgeproto.ClusterInst) (*edgeproto.Result, error) {
	copy := &edgeproto.ClusterInst{}
	*copy = *in
	if x.internal_api != nil {
		err := x.internal_api.DeleteClusterInst(copy, NewCudStreamoutClusterInst(ctx))
		return &edgeproto.Result{}, err
	} else {
		stream, err := x.client_api.DeleteClusterInst(ctx, copy)
		err = ClusterInstReadResultStream(stream, err)
		return &edgeproto.Result{}, err
	}
}

func (x *ClusterInstCommonApi) UpdateClusterInst(ctx context.Context, in *edgeproto.ClusterInst) (*edgeproto.Result, error) {
	copy := &edgeproto.ClusterInst{}
	*copy = *in
	if x.internal_api != nil {
		err := x.internal_api.UpdateClusterInst(copy, NewCudStreamoutClusterInst(ctx))
		return &edgeproto.Result{}, err
	} else {
		stream, err := x.client_api.UpdateClusterInst(ctx, copy)
		err = ClusterInstReadResultStream(stream, err)
		return &edgeproto.Result{}, err
	}
}

func (x *ClusterInstCommonApi) ShowClusterInst(ctx context.Context, filter *edgeproto.ClusterInst, showData *ShowClusterInst) error {
	if x.internal_api != nil {
		showData.Ctx = ctx
		return x.internal_api.ShowClusterInst(filter, showData)
	} else {
		stream, err := x.client_api.ShowClusterInst(ctx, filter)
		showData.ReadStream(stream, err)
		return err
	}
}

func NewInternalClusterInstApi(api edgeproto.ClusterInstApiServer) *ClusterInstCommonApi {
	apiWrap := ClusterInstCommonApi{}
	apiWrap.internal_api = api
	return &apiWrap
}

func NewClientClusterInstApi(api edgeproto.ClusterInstApiClient) *ClusterInstCommonApi {
	apiWrap := ClusterInstCommonApi{}
	apiWrap.client_api = api
	return &apiWrap
}

type ClusterInstTestOptions struct {
	createdData []edgeproto.ClusterInst
}

type ClusterInstTestOp func(opts *ClusterInstTestOptions)

func WithCreatedClusterInstTestData(createdData []edgeproto.ClusterInst) ClusterInstTestOp {
	return func(opts *ClusterInstTestOptions) { opts.createdData = createdData }
}

func InternalClusterInstTest(t *testing.T, test string, api edgeproto.ClusterInstApiServer, testData []edgeproto.ClusterInst, ops ...ClusterInstTestOp) {
	span := log.StartSpan(log.DebugLevelApi, "InternalClusterInstTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "cud":
		basicClusterInstCudTest(t, ctx, NewInternalClusterInstApi(api), testData, ops...)
	case "show":
		basicClusterInstShowTest(t, ctx, NewInternalClusterInstApi(api), testData)
	}
}

func ClientClusterInstTest(t *testing.T, test string, api edgeproto.ClusterInstApiClient, testData []edgeproto.ClusterInst, ops ...ClusterInstTestOp) {
	span := log.StartSpan(log.DebugLevelApi, "ClientClusterInstTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "cud":
		basicClusterInstCudTest(t, ctx, NewClientClusterInstApi(api), testData, ops...)
	case "show":
		basicClusterInstShowTest(t, ctx, NewClientClusterInstApi(api), testData)
	}
}

func basicClusterInstShowTest(t *testing.T, ctx context.Context, api *ClusterInstCommonApi, testData []edgeproto.ClusterInst) {
	var err error

	show := ShowClusterInst{}
	show.Init()
	filterNone := edgeproto.ClusterInst{}
	err = api.ShowClusterInst(ctx, &filterNone, &show)
	require.Nil(t, err, "show data")
	require.Equal(t, len(testData)+ClusterInstShowExtraCount, len(show.Data), "Show count")
	for _, obj := range testData {
		show.AssertFound(t, &obj)
	}
}

func GetClusterInst(t *testing.T, ctx context.Context, api *ClusterInstCommonApi, key *edgeproto.ClusterInstKey, out *edgeproto.ClusterInst) bool {
	var err error

	show := ShowClusterInst{}
	show.Init()
	filter := edgeproto.ClusterInst{}
	filter.SetKey(key)
	err = api.ShowClusterInst(ctx, &filter, &show)
	require.Nil(t, err, "show data")
	obj, found := show.Data[key.GetKeyString()]
	if found {
		*out = obj
	}
	return found
}

func basicClusterInstCudTest(t *testing.T, ctx context.Context, api *ClusterInstCommonApi, testData []edgeproto.ClusterInst, ops ...ClusterInstTestOp) {
	var err error

	if len(testData) < 3 {
		require.True(t, false, "Need at least 3 test data objects")
		return
	}
	options := ClusterInstTestOptions{}
	for _, op := range ops {
		op(&options)
	}
	createdData := testData
	if options.createdData != nil {
		createdData = options.createdData
	}

	// test create
	CreateClusterInstData(t, ctx, api, testData)

	// test duplicate Create - should fail
	_, err = api.CreateClusterInst(ctx, &testData[0])
	require.NotNil(t, err, "Create duplicate ClusterInst")

	// test show all items
	basicClusterInstShowTest(t, ctx, api, createdData)

	// test Delete
	_, err = api.DeleteClusterInst(ctx, &createdData[0])
	require.Nil(t, err, "Delete ClusterInst %s", testData[0].GetKey().GetKeyString())
	show := ShowClusterInst{}
	show.Init()
	filterNone := edgeproto.ClusterInst{}
	err = api.ShowClusterInst(ctx, &filterNone, &show)
	require.Nil(t, err, "show data")
	require.Equal(t, len(createdData)-1+ClusterInstShowExtraCount, len(show.Data), "Show count")
	show.AssertNotFound(t, &createdData[0])
	// test update of missing object
	_, err = api.UpdateClusterInst(ctx, &createdData[0])
	require.NotNil(t, err, "Update missing object")
	// Create it back
	_, err = api.CreateClusterInst(ctx, &testData[0])
	require.Nil(t, err, "Create ClusterInst %s", testData[0].GetKey().GetKeyString())

	// test invalid keys
	bad := edgeproto.ClusterInst{}
	_, err = api.CreateClusterInst(ctx, &bad)
	require.NotNil(t, err, "Create ClusterInst with no key info")

}

func InternalClusterInstCreate(t *testing.T, api edgeproto.ClusterInstApiServer, testData []edgeproto.ClusterInst) {
	span := log.StartSpan(log.DebugLevelApi, "InternalClusterInstCreate")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	CreateClusterInstData(t, ctx, NewInternalClusterInstApi(api), testData)
}

func ClientClusterInstCreate(t *testing.T, api edgeproto.ClusterInstApiClient, testData []edgeproto.ClusterInst) {
	span := log.StartSpan(log.DebugLevelApi, "ClientClusterInstCreate")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	CreateClusterInstData(t, ctx, NewClientClusterInstApi(api), testData)
}

func CreateClusterInstData(t *testing.T, ctx context.Context, api *ClusterInstCommonApi, testData []edgeproto.ClusterInst) {
	var err error

	for _, obj := range testData {
		_, err = api.CreateClusterInst(ctx, &obj)
		require.Nil(t, err, "Create ClusterInst %s", obj.GetKey().GetKeyString())
	}
}

func FindClusterInstData(key *edgeproto.ClusterInstKey, testData []edgeproto.ClusterInst) (*edgeproto.ClusterInst, bool) {
	for ii, _ := range testData {
		if testData[ii].GetKey().Matches(key) {
			return &testData[ii], true
		}
	}
	return nil, false
}

type ShowClusterInstInfo struct {
	Data map[string]edgeproto.ClusterInstInfo
	grpc.ServerStream
	Ctx context.Context
}

func (x *ShowClusterInstInfo) Init() {
	x.Data = make(map[string]edgeproto.ClusterInstInfo)
}

func (x *ShowClusterInstInfo) Send(m *edgeproto.ClusterInstInfo) error {
	x.Data[m.GetKey().GetKeyString()] = *m
	return nil
}

func (x *ShowClusterInstInfo) Context() context.Context {
	return x.Ctx
}

var ClusterInstInfoShowExtraCount = 0

func (x *ShowClusterInstInfo) ReadStream(stream edgeproto.ClusterInstInfoApi_ShowClusterInstInfoClient, err error) {
	x.Data = make(map[string]edgeproto.ClusterInstInfo)
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

func (x *ShowClusterInstInfo) CheckFound(obj *edgeproto.ClusterInstInfo) bool {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	return found
}

func (x *ShowClusterInstInfo) AssertFound(t *testing.T, obj *edgeproto.ClusterInstInfo) {
	check, found := x.Data[obj.GetKey().GetKeyString()]
	require.True(t, found, "find ClusterInstInfo %s", obj.GetKey().GetKeyString())
	if found && !check.Matches(obj, edgeproto.MatchIgnoreBackend(), edgeproto.MatchSortArrayedKeys()) {
		require.Equal(t, *obj, check, "ClusterInstInfo are equal")
	}
	if found {
		// remove in case there are dups in the list, so the
		// same object cannot be used again
		delete(x.Data, obj.GetKey().GetKeyString())
	}
}

func (x *ShowClusterInstInfo) AssertNotFound(t *testing.T, obj *edgeproto.ClusterInstInfo) {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	require.False(t, found, "do not find ClusterInstInfo %s", obj.GetKey().GetKeyString())
}

func WaitAssertFoundClusterInstInfo(t *testing.T, api edgeproto.ClusterInstInfoApiClient, obj *edgeproto.ClusterInstInfo, count int, retry time.Duration) {
	show := ShowClusterInstInfo{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowClusterInstInfo(ctx, obj)
		show.ReadStream(stream, err)
		cancel()
		if show.CheckFound(obj) {
			break
		}
		time.Sleep(retry)
	}
	show.AssertFound(t, obj)
}

func WaitAssertNotFoundClusterInstInfo(t *testing.T, api edgeproto.ClusterInstInfoApiClient, obj *edgeproto.ClusterInstInfo, count int, retry time.Duration) {
	show := ShowClusterInstInfo{}
	filterNone := edgeproto.ClusterInstInfo{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowClusterInstInfo(ctx, &filterNone)
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
type ClusterInstInfoCommonApi struct {
	internal_api edgeproto.ClusterInstInfoApiServer
	client_api   edgeproto.ClusterInstInfoApiClient
}

func (x *ClusterInstInfoCommonApi) ShowClusterInstInfo(ctx context.Context, filter *edgeproto.ClusterInstInfo, showData *ShowClusterInstInfo) error {
	if x.internal_api != nil {
		showData.Ctx = ctx
		return x.internal_api.ShowClusterInstInfo(filter, showData)
	} else {
		stream, err := x.client_api.ShowClusterInstInfo(ctx, filter)
		showData.ReadStream(stream, err)
		return err
	}
}

func NewInternalClusterInstInfoApi(api edgeproto.ClusterInstInfoApiServer) *ClusterInstInfoCommonApi {
	apiWrap := ClusterInstInfoCommonApi{}
	apiWrap.internal_api = api
	return &apiWrap
}

func NewClientClusterInstInfoApi(api edgeproto.ClusterInstInfoApiClient) *ClusterInstInfoCommonApi {
	apiWrap := ClusterInstInfoCommonApi{}
	apiWrap.client_api = api
	return &apiWrap
}

type ClusterInstInfoTestOptions struct {
	createdData []edgeproto.ClusterInstInfo
}

type ClusterInstInfoTestOp func(opts *ClusterInstInfoTestOptions)

func WithCreatedClusterInstInfoTestData(createdData []edgeproto.ClusterInstInfo) ClusterInstInfoTestOp {
	return func(opts *ClusterInstInfoTestOptions) { opts.createdData = createdData }
}

func InternalClusterInstInfoTest(t *testing.T, test string, api edgeproto.ClusterInstInfoApiServer, testData []edgeproto.ClusterInstInfo, ops ...ClusterInstInfoTestOp) {
	span := log.StartSpan(log.DebugLevelApi, "InternalClusterInstInfoTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "show":
		basicClusterInstInfoShowTest(t, ctx, NewInternalClusterInstInfoApi(api), testData)
	}
}

func ClientClusterInstInfoTest(t *testing.T, test string, api edgeproto.ClusterInstInfoApiClient, testData []edgeproto.ClusterInstInfo, ops ...ClusterInstInfoTestOp) {
	span := log.StartSpan(log.DebugLevelApi, "ClientClusterInstInfoTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "show":
		basicClusterInstInfoShowTest(t, ctx, NewClientClusterInstInfoApi(api), testData)
	}
}

func basicClusterInstInfoShowTest(t *testing.T, ctx context.Context, api *ClusterInstInfoCommonApi, testData []edgeproto.ClusterInstInfo) {
	var err error

	show := ShowClusterInstInfo{}
	show.Init()
	filterNone := edgeproto.ClusterInstInfo{}
	err = api.ShowClusterInstInfo(ctx, &filterNone, &show)
	require.Nil(t, err, "show data")
	require.Equal(t, len(testData)+ClusterInstInfoShowExtraCount, len(show.Data), "Show count")
	for _, obj := range testData {
		show.AssertFound(t, &obj)
	}
}

func GetClusterInstInfo(t *testing.T, ctx context.Context, api *ClusterInstInfoCommonApi, key *edgeproto.ClusterInstKey, out *edgeproto.ClusterInstInfo) bool {
	var err error

	show := ShowClusterInstInfo{}
	show.Init()
	filter := edgeproto.ClusterInstInfo{}
	filter.SetKey(key)
	err = api.ShowClusterInstInfo(ctx, &filter, &show)
	require.Nil(t, err, "show data")
	obj, found := show.Data[key.GetKeyString()]
	if found {
		*out = obj
	}
	return found
}

func FindClusterInstInfoData(key *edgeproto.ClusterInstKey, testData []edgeproto.ClusterInstInfo) (*edgeproto.ClusterInstInfo, bool) {
	for ii, _ := range testData {
		if testData[ii].GetKey().Matches(key) {
			return &testData[ii], true
		}
	}
	return nil, false
}

func (r *Run) ClusterInstApi(data *[]edgeproto.ClusterInst, dataMap interface{}, dataOut interface{}) {
	log.DebugLog(log.DebugLevelApi, "API for ClusterInst", "mode", r.Mode)
	if r.Mode == "show" {
		obj := &edgeproto.ClusterInst{}
		out, err := r.client.ShowClusterInst(r.ctx, obj)
		if err != nil {
			r.logErr("ClusterInstApi", err)
		} else {
			outp, ok := dataOut.(*[]edgeproto.ClusterInst)
			if !ok {
				panic(fmt.Sprintf("RunClusterInstApi expected dataOut type *[]edgeproto.ClusterInst, but was %T", dataOut))
			}
			*outp = append(*outp, out...)
		}
		return
	}
	for ii, objD := range *data {
		obj := &objD
		switch r.Mode {
		case "create":
			out, err := r.client.CreateClusterInst(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("ClusterInstApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[][]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunClusterInstApi expected dataOut type *[][]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, out)
			}
		case "delete":
			out, err := r.client.DeleteClusterInst(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("ClusterInstApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[][]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunClusterInstApi expected dataOut type *[][]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, out)
			}
		case "update":
			// set specified fields
			objMap, err := cli.GetGenericObjFromList(dataMap, ii)
			if err != nil {
				log.DebugLog(log.DebugLevelApi, "bad dataMap for ClusterInst", "err", err)
				*r.Rc = false
				return
			}
			obj.Fields = cli.GetSpecifiedFields(objMap, obj, cli.YamlNamespace)

			out, err := r.client.UpdateClusterInst(r.ctx, obj)
			if err != nil {
				err = ignoreExpectedErrors(r.Mode, obj.GetKey(), err)
				r.logErr(fmt.Sprintf("ClusterInstApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[][]edgeproto.Result)
				if !ok {
					panic(fmt.Sprintf("RunClusterInstApi expected dataOut type *[][]edgeproto.Result, but was %T", dataOut))
				}
				*outp = append(*outp, out)
			}
		case "showfiltered":
			out, err := r.client.ShowClusterInst(r.ctx, obj)
			if err != nil {
				r.logErr(fmt.Sprintf("ClusterInstApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.ClusterInst)
				if !ok {
					panic(fmt.Sprintf("RunClusterInstApi expected dataOut type *[]edgeproto.ClusterInst, but was %T", dataOut))
				}
				*outp = append(*outp, out...)
			}
		}
	}
}

func (r *Run) ClusterInstApi_IdleReservableClusterInsts(obj *edgeproto.IdleReservableClusterInsts, dataMap interface{}, dataOut interface{}) {
	log.DebugLog(log.DebugLevelApi, "API for IdleReservableClusterInsts", "mode", r.Mode)
	if obj == nil {
		return
	}
	switch r.Mode {
	case "delete":
		out, err := r.client.DeleteIdleReservableClusterInsts(r.ctx, obj)
		if err != nil {
			r.logErr("ClusterInstApi_IdleReservableClusterInsts", err)
		} else {
			outp, ok := dataOut.(**edgeproto.Result)
			if !ok {
				panic(fmt.Sprintf("RunClusterInstApi_IdleReservableClusterInsts expected dataOut type **edgeproto.Result, but was %T", dataOut))
			}
			*outp = out
		}
	}
}

func (s *DummyServer) CreateClusterInst(in *edgeproto.ClusterInst, server edgeproto.ClusterInstApi_CreateClusterInstServer) error {
	var err error
	s.ClusterInstCache.Update(server.Context(), in, 0)
	if true {
		for ii := 0; ii < s.ShowDummyCount; ii++ {
			server.Send(&edgeproto.Result{})
		}
	}
	return err
}

func (s *DummyServer) DeleteClusterInst(in *edgeproto.ClusterInst, server edgeproto.ClusterInstApi_DeleteClusterInstServer) error {
	var err error
	s.ClusterInstCache.Delete(server.Context(), in, 0)
	if true {
		for ii := 0; ii < s.ShowDummyCount; ii++ {
			server.Send(&edgeproto.Result{})
		}
	}
	return err
}

func (s *DummyServer) UpdateClusterInst(in *edgeproto.ClusterInst, server edgeproto.ClusterInstApi_UpdateClusterInstServer) error {
	var err error
	s.ClusterInstCache.Update(server.Context(), in, 0)
	if true {
		for ii := 0; ii < s.ShowDummyCount; ii++ {
			server.Send(&edgeproto.Result{})
		}
	}
	return err
}

func (s *DummyServer) ShowClusterInst(in *edgeproto.ClusterInst, server edgeproto.ClusterInstApi_ShowClusterInstServer) error {
	var err error
	obj := &edgeproto.ClusterInst{}
	if obj.Matches(in, edgeproto.MatchFilter()) {
		for ii := 0; ii < s.ShowDummyCount; ii++ {
			server.Send(&edgeproto.ClusterInst{})
		}
	}
	err = s.ClusterInstCache.Show(in, func(obj *edgeproto.ClusterInst) error {
		err := server.Send(obj)
		return err
	})
	return err
}

func (r *Run) ClusterInstInfoApi(data *[]edgeproto.ClusterInstInfo, dataMap interface{}, dataOut interface{}) {
	log.DebugLog(log.DebugLevelApi, "API for ClusterInstInfo", "mode", r.Mode)
	if r.Mode == "show" {
		obj := &edgeproto.ClusterInstInfo{}
		out, err := r.client.ShowClusterInstInfo(r.ctx, obj)
		if err != nil {
			r.logErr("ClusterInstInfoApi", err)
		} else {
			outp, ok := dataOut.(*[]edgeproto.ClusterInstInfo)
			if !ok {
				panic(fmt.Sprintf("RunClusterInstInfoApi expected dataOut type *[]edgeproto.ClusterInstInfo, but was %T", dataOut))
			}
			*outp = append(*outp, out...)
		}
		return
	}
	for ii, objD := range *data {
		obj := &objD
		switch r.Mode {
		case "showfiltered":
			out, err := r.client.ShowClusterInstInfo(r.ctx, obj)
			if err != nil {
				r.logErr(fmt.Sprintf("ClusterInstInfoApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.ClusterInstInfo)
				if !ok {
					panic(fmt.Sprintf("RunClusterInstInfoApi expected dataOut type *[]edgeproto.ClusterInstInfo, but was %T", dataOut))
				}
				*outp = append(*outp, out...)
			}
		}
	}
}

func (s *DummyServer) ShowClusterInstInfo(in *edgeproto.ClusterInstInfo, server edgeproto.ClusterInstInfoApi_ShowClusterInstInfoServer) error {
	var err error
	obj := &edgeproto.ClusterInstInfo{}
	if obj.Matches(in, edgeproto.MatchFilter()) {
		for ii := 0; ii < s.ShowDummyCount; ii++ {
			server.Send(&edgeproto.ClusterInstInfo{})
		}
	}
	err = s.ClusterInstInfoCache.Show(in, func(obj *edgeproto.ClusterInstInfo) error {
		err := server.Send(obj)
		return err
	})
	return err
}

func (s *ApiClient) CreateClusterInst(ctx context.Context, in *edgeproto.ClusterInst) ([]edgeproto.Result, error) {
	api := edgeproto.NewClusterInstApiClient(s.Conn)
	stream, err := api.CreateClusterInst(ctx, in)
	if err != nil {
		return nil, err
	}
	return ResultReadStream(stream)
}

func (s *CliClient) CreateClusterInst(ctx context.Context, in *edgeproto.ClusterInst) ([]edgeproto.Result, error) {
	output := []edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "CreateClusterInst")
	err := wrapper.RunEdgectlObjs(args, in, &output, s.RunOps...)
	return output, err
}

func (s *ApiClient) DeleteClusterInst(ctx context.Context, in *edgeproto.ClusterInst) ([]edgeproto.Result, error) {
	api := edgeproto.NewClusterInstApiClient(s.Conn)
	stream, err := api.DeleteClusterInst(ctx, in)
	if err != nil {
		return nil, err
	}
	return ResultReadStream(stream)
}

func (s *CliClient) DeleteClusterInst(ctx context.Context, in *edgeproto.ClusterInst) ([]edgeproto.Result, error) {
	output := []edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "DeleteClusterInst")
	err := wrapper.RunEdgectlObjs(args, in, &output, s.RunOps...)
	return output, err
}

func (s *ApiClient) UpdateClusterInst(ctx context.Context, in *edgeproto.ClusterInst) ([]edgeproto.Result, error) {
	api := edgeproto.NewClusterInstApiClient(s.Conn)
	stream, err := api.UpdateClusterInst(ctx, in)
	if err != nil {
		return nil, err
	}
	return ResultReadStream(stream)
}

func (s *CliClient) UpdateClusterInst(ctx context.Context, in *edgeproto.ClusterInst) ([]edgeproto.Result, error) {
	output := []edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "UpdateClusterInst")
	err := wrapper.RunEdgectlObjs(args, in, &output, s.RunOps...)
	return output, err
}

type ClusterInstStream interface {
	Recv() (*edgeproto.ClusterInst, error)
}

func ClusterInstReadStream(stream ClusterInstStream) ([]edgeproto.ClusterInst, error) {
	output := []edgeproto.ClusterInst{}
	for {
		obj, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return output, fmt.Errorf("read ClusterInst stream failed, %v", err)
		}
		output = append(output, *obj)
	}
	return output, nil
}

func (s *ApiClient) ShowClusterInst(ctx context.Context, in *edgeproto.ClusterInst) ([]edgeproto.ClusterInst, error) {
	api := edgeproto.NewClusterInstApiClient(s.Conn)
	stream, err := api.ShowClusterInst(ctx, in)
	if err != nil {
		return nil, err
	}
	return ClusterInstReadStream(stream)
}

func (s *CliClient) ShowClusterInst(ctx context.Context, in *edgeproto.ClusterInst) ([]edgeproto.ClusterInst, error) {
	output := []edgeproto.ClusterInst{}
	args := append(s.BaseArgs, "controller", "ShowClusterInst")
	err := wrapper.RunEdgectlObjs(args, in, &output, s.RunOps...)
	return output, err
}

func (s *ApiClient) DeleteIdleReservableClusterInsts(ctx context.Context, in *edgeproto.IdleReservableClusterInsts) (*edgeproto.Result, error) {
	api := edgeproto.NewClusterInstApiClient(s.Conn)
	return api.DeleteIdleReservableClusterInsts(ctx, in)
}

func (s *CliClient) DeleteIdleReservableClusterInsts(ctx context.Context, in *edgeproto.IdleReservableClusterInsts) (*edgeproto.Result, error) {
	out := edgeproto.Result{}
	args := append(s.BaseArgs, "controller", "DeleteIdleReservableClusterInsts")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

type ClusterInstApiClient interface {
	CreateClusterInst(ctx context.Context, in *edgeproto.ClusterInst) ([]edgeproto.Result, error)
	DeleteClusterInst(ctx context.Context, in *edgeproto.ClusterInst) ([]edgeproto.Result, error)
	UpdateClusterInst(ctx context.Context, in *edgeproto.ClusterInst) ([]edgeproto.Result, error)
	ShowClusterInst(ctx context.Context, in *edgeproto.ClusterInst) ([]edgeproto.ClusterInst, error)
	DeleteIdleReservableClusterInsts(ctx context.Context, in *edgeproto.IdleReservableClusterInsts) (*edgeproto.Result, error)
}

type ClusterInstInfoStream interface {
	Recv() (*edgeproto.ClusterInstInfo, error)
}

func ClusterInstInfoReadStream(stream ClusterInstInfoStream) ([]edgeproto.ClusterInstInfo, error) {
	output := []edgeproto.ClusterInstInfo{}
	for {
		obj, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return output, fmt.Errorf("read ClusterInstInfo stream failed, %v", err)
		}
		output = append(output, *obj)
	}
	return output, nil
}

func (s *ApiClient) ShowClusterInstInfo(ctx context.Context, in *edgeproto.ClusterInstInfo) ([]edgeproto.ClusterInstInfo, error) {
	api := edgeproto.NewClusterInstInfoApiClient(s.Conn)
	stream, err := api.ShowClusterInstInfo(ctx, in)
	if err != nil {
		return nil, err
	}
	return ClusterInstInfoReadStream(stream)
}

func (s *CliClient) ShowClusterInstInfo(ctx context.Context, in *edgeproto.ClusterInstInfo) ([]edgeproto.ClusterInstInfo, error) {
	output := []edgeproto.ClusterInstInfo{}
	args := append(s.BaseArgs, "controller", "ShowClusterInstInfo")
	err := wrapper.RunEdgectlObjs(args, in, &output, s.RunOps...)
	return output, err
}

type ClusterInstInfoApiClient interface {
	ShowClusterInstInfo(ctx context.Context, in *edgeproto.ClusterInstInfo) ([]edgeproto.ClusterInstInfo, error)
}
