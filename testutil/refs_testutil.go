// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: refs.proto

package testutil

import "google.golang.org/grpc"
import "github.com/mobiledgex/edge-cloud/edgeproto"
import "io"
import "testing"
import "context"
import "time"
import "github.com/stretchr/testify/require"
import "github.com/mobiledgex/edge-cloud/log"
import "github.com/mobiledgex/edge-cloud/edgectl/wrapper"
import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/mobiledgex/edge-cloud/protogen"
import _ "github.com/gogo/protobuf/gogoproto"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

type ShowCloudletRefs struct {
	Data map[string]edgeproto.CloudletRefs
	grpc.ServerStream
	Ctx context.Context
}

func (x *ShowCloudletRefs) Init() {
	x.Data = make(map[string]edgeproto.CloudletRefs)
}

func (x *ShowCloudletRefs) Send(m *edgeproto.CloudletRefs) error {
	x.Data[m.GetKey().GetKeyString()] = *m
	return nil
}

func (x *ShowCloudletRefs) Context() context.Context {
	return x.Ctx
}

var CloudletRefsShowExtraCount = 0

func (x *ShowCloudletRefs) ReadStream(stream edgeproto.CloudletRefsApi_ShowCloudletRefsClient, err error) {
	x.Data = make(map[string]edgeproto.CloudletRefs)
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

func (x *ShowCloudletRefs) CheckFound(obj *edgeproto.CloudletRefs) bool {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	return found
}

func (x *ShowCloudletRefs) AssertFound(t *testing.T, obj *edgeproto.CloudletRefs) {
	check, found := x.Data[obj.GetKey().GetKeyString()]
	require.True(t, found, "find CloudletRefs %s", obj.GetKey().GetKeyString())
	if found && !check.Matches(obj, edgeproto.MatchIgnoreBackend(), edgeproto.MatchSortArrayedKeys()) {
		require.Equal(t, *obj, check, "CloudletRefs are equal")
	}
	if found {
		// remove in case there are dups in the list, so the
		// same object cannot be used again
		delete(x.Data, obj.GetKey().GetKeyString())
	}
}

func (x *ShowCloudletRefs) AssertNotFound(t *testing.T, obj *edgeproto.CloudletRefs) {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	require.False(t, found, "do not find CloudletRefs %s", obj.GetKey().GetKeyString())
}

func WaitAssertFoundCloudletRefs(t *testing.T, api edgeproto.CloudletRefsApiClient, obj *edgeproto.CloudletRefs, count int, retry time.Duration) {
	show := ShowCloudletRefs{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowCloudletRefs(ctx, obj)
		show.ReadStream(stream, err)
		cancel()
		if show.CheckFound(obj) {
			break
		}
		time.Sleep(retry)
	}
	show.AssertFound(t, obj)
}

func WaitAssertNotFoundCloudletRefs(t *testing.T, api edgeproto.CloudletRefsApiClient, obj *edgeproto.CloudletRefs, count int, retry time.Duration) {
	show := ShowCloudletRefs{}
	filterNone := edgeproto.CloudletRefs{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowCloudletRefs(ctx, &filterNone)
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
type CloudletRefsCommonApi struct {
	internal_api edgeproto.CloudletRefsApiServer
	client_api   edgeproto.CloudletRefsApiClient
}

func (x *CloudletRefsCommonApi) ShowCloudletRefs(ctx context.Context, filter *edgeproto.CloudletRefs, showData *ShowCloudletRefs) error {
	if x.internal_api != nil {
		showData.Ctx = ctx
		return x.internal_api.ShowCloudletRefs(filter, showData)
	} else {
		stream, err := x.client_api.ShowCloudletRefs(ctx, filter)
		showData.ReadStream(stream, err)
		return err
	}
}

func NewInternalCloudletRefsApi(api edgeproto.CloudletRefsApiServer) *CloudletRefsCommonApi {
	apiWrap := CloudletRefsCommonApi{}
	apiWrap.internal_api = api
	return &apiWrap
}

func NewClientCloudletRefsApi(api edgeproto.CloudletRefsApiClient) *CloudletRefsCommonApi {
	apiWrap := CloudletRefsCommonApi{}
	apiWrap.client_api = api
	return &apiWrap
}

func InternalCloudletRefsTest(t *testing.T, test string, api edgeproto.CloudletRefsApiServer, testData []edgeproto.CloudletRefs) {
	span := log.StartSpan(log.DebugLevelApi, "InternalCloudletRefsTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "show":
		basicCloudletRefsShowTest(t, ctx, NewInternalCloudletRefsApi(api), testData)
	}
}

func ClientCloudletRefsTest(t *testing.T, test string, api edgeproto.CloudletRefsApiClient, testData []edgeproto.CloudletRefs) {
	span := log.StartSpan(log.DebugLevelApi, "ClientCloudletRefsTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "show":
		basicCloudletRefsShowTest(t, ctx, NewClientCloudletRefsApi(api), testData)
	}
}

func basicCloudletRefsShowTest(t *testing.T, ctx context.Context, api *CloudletRefsCommonApi, testData []edgeproto.CloudletRefs) {
	var err error

	show := ShowCloudletRefs{}
	show.Init()
	filterNone := edgeproto.CloudletRefs{}
	err = api.ShowCloudletRefs(ctx, &filterNone, &show)
	require.Nil(t, err, "show data")
	require.Equal(t, len(testData)+CloudletRefsShowExtraCount, len(show.Data), "Show count")
	for _, obj := range testData {
		show.AssertFound(t, &obj)
	}
}

func GetCloudletRefs(t *testing.T, ctx context.Context, api *CloudletRefsCommonApi, key *edgeproto.CloudletKey, out *edgeproto.CloudletRefs) bool {
	var err error

	show := ShowCloudletRefs{}
	show.Init()
	filter := edgeproto.CloudletRefs{}
	filter.SetKey(key)
	err = api.ShowCloudletRefs(ctx, &filter, &show)
	require.Nil(t, err, "show data")
	obj, found := show.Data[key.GetKeyString()]
	if found {
		*out = obj
	}
	return found
}

func FindCloudletRefsData(key *edgeproto.CloudletKey, testData []edgeproto.CloudletRefs) (*edgeproto.CloudletRefs, bool) {
	for ii, _ := range testData {
		if testData[ii].GetKey().Matches(key) {
			return &testData[ii], true
		}
	}
	return nil, false
}

type ShowClusterRefs struct {
	Data map[string]edgeproto.ClusterRefs
	grpc.ServerStream
	Ctx context.Context
}

func (x *ShowClusterRefs) Init() {
	x.Data = make(map[string]edgeproto.ClusterRefs)
}

func (x *ShowClusterRefs) Send(m *edgeproto.ClusterRefs) error {
	x.Data[m.GetKey().GetKeyString()] = *m
	return nil
}

func (x *ShowClusterRefs) Context() context.Context {
	return x.Ctx
}

var ClusterRefsShowExtraCount = 0

func (x *ShowClusterRefs) ReadStream(stream edgeproto.ClusterRefsApi_ShowClusterRefsClient, err error) {
	x.Data = make(map[string]edgeproto.ClusterRefs)
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

func (x *ShowClusterRefs) CheckFound(obj *edgeproto.ClusterRefs) bool {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	return found
}

func (x *ShowClusterRefs) AssertFound(t *testing.T, obj *edgeproto.ClusterRefs) {
	check, found := x.Data[obj.GetKey().GetKeyString()]
	require.True(t, found, "find ClusterRefs %s", obj.GetKey().GetKeyString())
	if found && !check.Matches(obj, edgeproto.MatchIgnoreBackend(), edgeproto.MatchSortArrayedKeys()) {
		require.Equal(t, *obj, check, "ClusterRefs are equal")
	}
	if found {
		// remove in case there are dups in the list, so the
		// same object cannot be used again
		delete(x.Data, obj.GetKey().GetKeyString())
	}
}

func (x *ShowClusterRefs) AssertNotFound(t *testing.T, obj *edgeproto.ClusterRefs) {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	require.False(t, found, "do not find ClusterRefs %s", obj.GetKey().GetKeyString())
}

func WaitAssertFoundClusterRefs(t *testing.T, api edgeproto.ClusterRefsApiClient, obj *edgeproto.ClusterRefs, count int, retry time.Duration) {
	show := ShowClusterRefs{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowClusterRefs(ctx, obj)
		show.ReadStream(stream, err)
		cancel()
		if show.CheckFound(obj) {
			break
		}
		time.Sleep(retry)
	}
	show.AssertFound(t, obj)
}

func WaitAssertNotFoundClusterRefs(t *testing.T, api edgeproto.ClusterRefsApiClient, obj *edgeproto.ClusterRefs, count int, retry time.Duration) {
	show := ShowClusterRefs{}
	filterNone := edgeproto.ClusterRefs{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowClusterRefs(ctx, &filterNone)
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
type ClusterRefsCommonApi struct {
	internal_api edgeproto.ClusterRefsApiServer
	client_api   edgeproto.ClusterRefsApiClient
}

func (x *ClusterRefsCommonApi) ShowClusterRefs(ctx context.Context, filter *edgeproto.ClusterRefs, showData *ShowClusterRefs) error {
	if x.internal_api != nil {
		showData.Ctx = ctx
		return x.internal_api.ShowClusterRefs(filter, showData)
	} else {
		stream, err := x.client_api.ShowClusterRefs(ctx, filter)
		showData.ReadStream(stream, err)
		return err
	}
}

func NewInternalClusterRefsApi(api edgeproto.ClusterRefsApiServer) *ClusterRefsCommonApi {
	apiWrap := ClusterRefsCommonApi{}
	apiWrap.internal_api = api
	return &apiWrap
}

func NewClientClusterRefsApi(api edgeproto.ClusterRefsApiClient) *ClusterRefsCommonApi {
	apiWrap := ClusterRefsCommonApi{}
	apiWrap.client_api = api
	return &apiWrap
}

func InternalClusterRefsTest(t *testing.T, test string, api edgeproto.ClusterRefsApiServer, testData []edgeproto.ClusterRefs) {
	span := log.StartSpan(log.DebugLevelApi, "InternalClusterRefsTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "show":
		basicClusterRefsShowTest(t, ctx, NewInternalClusterRefsApi(api), testData)
	}
}

func ClientClusterRefsTest(t *testing.T, test string, api edgeproto.ClusterRefsApiClient, testData []edgeproto.ClusterRefs) {
	span := log.StartSpan(log.DebugLevelApi, "ClientClusterRefsTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "show":
		basicClusterRefsShowTest(t, ctx, NewClientClusterRefsApi(api), testData)
	}
}

func basicClusterRefsShowTest(t *testing.T, ctx context.Context, api *ClusterRefsCommonApi, testData []edgeproto.ClusterRefs) {
	var err error

	show := ShowClusterRefs{}
	show.Init()
	filterNone := edgeproto.ClusterRefs{}
	err = api.ShowClusterRefs(ctx, &filterNone, &show)
	require.Nil(t, err, "show data")
	require.Equal(t, len(testData)+ClusterRefsShowExtraCount, len(show.Data), "Show count")
	for _, obj := range testData {
		show.AssertFound(t, &obj)
	}
}

func GetClusterRefs(t *testing.T, ctx context.Context, api *ClusterRefsCommonApi, key *edgeproto.ClusterInstKey, out *edgeproto.ClusterRefs) bool {
	var err error

	show := ShowClusterRefs{}
	show.Init()
	filter := edgeproto.ClusterRefs{}
	filter.SetKey(key)
	err = api.ShowClusterRefs(ctx, &filter, &show)
	require.Nil(t, err, "show data")
	obj, found := show.Data[key.GetKeyString()]
	if found {
		*out = obj
	}
	return found
}

func FindClusterRefsData(key *edgeproto.ClusterInstKey, testData []edgeproto.ClusterRefs) (*edgeproto.ClusterRefs, bool) {
	for ii, _ := range testData {
		if testData[ii].GetKey().Matches(key) {
			return &testData[ii], true
		}
	}
	return nil, false
}

func (r *Run) CloudletRefsApi(data *[]edgeproto.CloudletRefs, dataMap interface{}, dataOut interface{}) {
	log.DebugLog(log.DebugLevelApi, "API for CloudletRefs", "mode", r.Mode)
	if r.Mode == "show" {
		obj := &edgeproto.CloudletRefs{}
		out, err := r.client.ShowCloudletRefs(r.ctx, obj)
		if err != nil {
			r.logErr("CloudletRefsApi", err)
		} else {
			outp, ok := dataOut.(*[]edgeproto.CloudletRefs)
			if !ok {
				panic(fmt.Sprintf("RunCloudletRefsApi expected dataOut type *[]edgeproto.CloudletRefs, but was %T", dataOut))
			}
			*outp = append(*outp, out...)
		}
		return
	}
	for ii, objD := range *data {
		obj := &objD
		switch r.Mode {
		case "showfiltered":
			out, err := r.client.ShowCloudletRefs(r.ctx, obj)
			if err != nil {
				r.logErr(fmt.Sprintf("CloudletRefsApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.CloudletRefs)
				if !ok {
					panic(fmt.Sprintf("RunCloudletRefsApi expected dataOut type *[]edgeproto.CloudletRefs, but was %T", dataOut))
				}
				*outp = append(*outp, out...)
			}
		}
	}
}

func (s *DummyServer) ShowCloudletRefs(in *edgeproto.CloudletRefs, server edgeproto.CloudletRefsApi_ShowCloudletRefsServer) error {
	var err error
	obj := &edgeproto.CloudletRefs{}
	if obj.Matches(in, edgeproto.MatchFilter()) {
		for ii := 0; ii < s.ShowDummyCount; ii++ {
			server.Send(&edgeproto.CloudletRefs{})
		}
	}
	err = s.CloudletRefsCache.Show(in, func(obj *edgeproto.CloudletRefs) error {
		err := server.Send(obj)
		return err
	})
	return err
}

func (r *Run) ClusterRefsApi(data *[]edgeproto.ClusterRefs, dataMap interface{}, dataOut interface{}) {
	log.DebugLog(log.DebugLevelApi, "API for ClusterRefs", "mode", r.Mode)
	if r.Mode == "show" {
		obj := &edgeproto.ClusterRefs{}
		out, err := r.client.ShowClusterRefs(r.ctx, obj)
		if err != nil {
			r.logErr("ClusterRefsApi", err)
		} else {
			outp, ok := dataOut.(*[]edgeproto.ClusterRefs)
			if !ok {
				panic(fmt.Sprintf("RunClusterRefsApi expected dataOut type *[]edgeproto.ClusterRefs, but was %T", dataOut))
			}
			*outp = append(*outp, out...)
		}
		return
	}
	for ii, objD := range *data {
		obj := &objD
		switch r.Mode {
		case "showfiltered":
			out, err := r.client.ShowClusterRefs(r.ctx, obj)
			if err != nil {
				r.logErr(fmt.Sprintf("ClusterRefsApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.ClusterRefs)
				if !ok {
					panic(fmt.Sprintf("RunClusterRefsApi expected dataOut type *[]edgeproto.ClusterRefs, but was %T", dataOut))
				}
				*outp = append(*outp, out...)
			}
		}
	}
}

func (s *DummyServer) ShowClusterRefs(in *edgeproto.ClusterRefs, server edgeproto.ClusterRefsApi_ShowClusterRefsServer) error {
	var err error
	obj := &edgeproto.ClusterRefs{}
	if obj.Matches(in, edgeproto.MatchFilter()) {
		for ii := 0; ii < s.ShowDummyCount; ii++ {
			server.Send(&edgeproto.ClusterRefs{})
		}
	}
	err = s.ClusterRefsCache.Show(in, func(obj *edgeproto.ClusterRefs) error {
		err := server.Send(obj)
		return err
	})
	return err
}

type CloudletRefsStream interface {
	Recv() (*edgeproto.CloudletRefs, error)
}

func CloudletRefsReadStream(stream CloudletRefsStream) ([]edgeproto.CloudletRefs, error) {
	output := []edgeproto.CloudletRefs{}
	for {
		obj, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return output, fmt.Errorf("read CloudletRefs stream failed, %v", err)
		}
		output = append(output, *obj)
	}
	return output, nil
}

func (s *ApiClient) ShowCloudletRefs(ctx context.Context, in *edgeproto.CloudletRefs) ([]edgeproto.CloudletRefs, error) {
	api := edgeproto.NewCloudletRefsApiClient(s.Conn)
	stream, err := api.ShowCloudletRefs(ctx, in)
	if err != nil {
		return nil, err
	}
	return CloudletRefsReadStream(stream)
}

func (s *CliClient) ShowCloudletRefs(ctx context.Context, in *edgeproto.CloudletRefs) ([]edgeproto.CloudletRefs, error) {
	output := []edgeproto.CloudletRefs{}
	args := append(s.BaseArgs, "controller", "ShowCloudletRefs")
	err := wrapper.RunEdgectlObjs(args, in, &output, s.RunOps...)
	return output, err
}

type CloudletRefsApiClient interface {
	ShowCloudletRefs(ctx context.Context, in *edgeproto.CloudletRefs) ([]edgeproto.CloudletRefs, error)
}

type ClusterRefsStream interface {
	Recv() (*edgeproto.ClusterRefs, error)
}

func ClusterRefsReadStream(stream ClusterRefsStream) ([]edgeproto.ClusterRefs, error) {
	output := []edgeproto.ClusterRefs{}
	for {
		obj, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return output, fmt.Errorf("read ClusterRefs stream failed, %v", err)
		}
		output = append(output, *obj)
	}
	return output, nil
}

func (s *ApiClient) ShowClusterRefs(ctx context.Context, in *edgeproto.ClusterRefs) ([]edgeproto.ClusterRefs, error) {
	api := edgeproto.NewClusterRefsApiClient(s.Conn)
	stream, err := api.ShowClusterRefs(ctx, in)
	if err != nil {
		return nil, err
	}
	return ClusterRefsReadStream(stream)
}

func (s *CliClient) ShowClusterRefs(ctx context.Context, in *edgeproto.ClusterRefs) ([]edgeproto.ClusterRefs, error) {
	output := []edgeproto.ClusterRefs{}
	args := append(s.BaseArgs, "controller", "ShowClusterRefs")
	err := wrapper.RunEdgectlObjs(args, in, &output, s.RunOps...)
	return output, err
}

type ClusterRefsApiClient interface {
	ShowClusterRefs(ctx context.Context, in *edgeproto.ClusterRefs) ([]edgeproto.ClusterRefs, error)
}
