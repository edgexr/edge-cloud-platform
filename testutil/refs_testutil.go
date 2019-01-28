// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: refs.proto

package testutil

import "google.golang.org/grpc"
import "github.com/mobiledgex/edge-cloud/edgeproto"
import "io"
import "testing"
import "context"
import "time"
import "github.com/stretchr/testify/assert"
import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/googleapis/google/api"
import _ "github.com/mobiledgex/edge-cloud/protogen"
import _ "github.com/mobiledgex/edge-cloud/protoc-gen-cmd/protocmd"
import _ "github.com/gogo/protobuf/gogoproto"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

type ShowCloudletRefs struct {
	Data map[string]edgeproto.CloudletRefs
	grpc.ServerStream
}

func (x *ShowCloudletRefs) Init() {
	x.Data = make(map[string]edgeproto.CloudletRefs)
}

func (x *ShowCloudletRefs) Send(m *edgeproto.CloudletRefs) error {
	x.Data[m.Key.GetKeyString()] = *m
	return nil
}

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
		x.Data[obj.Key.GetKeyString()] = *obj
	}
}

func (x *ShowCloudletRefs) CheckFound(obj *edgeproto.CloudletRefs) bool {
	_, found := x.Data[obj.Key.GetKeyString()]
	return found
}

func (x *ShowCloudletRefs) AssertFound(t *testing.T, obj *edgeproto.CloudletRefs) {
	check, found := x.Data[obj.Key.GetKeyString()]
	assert.True(t, found, "find CloudletRefs %s", obj.Key.GetKeyString())
	if found && !check.Matches(obj, edgeproto.MatchIgnoreBackend(), edgeproto.MatchSortArrayedKeys()) {
		assert.Equal(t, *obj, check, "CloudletRefs are equal")
	}
	if found {
		// remove in case there are dups in the list, so the
		// same object cannot be used again
		delete(x.Data, obj.Key.GetKeyString())
	}
}

func (x *ShowCloudletRefs) AssertNotFound(t *testing.T, obj *edgeproto.CloudletRefs) {
	_, found := x.Data[obj.Key.GetKeyString()]
	assert.False(t, found, "do not find CloudletRefs %s", obj.Key.GetKeyString())
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
	switch test {
	case "show":
		basicCloudletRefsShowTest(t, NewInternalCloudletRefsApi(api), testData)
	}
}

func ClientCloudletRefsTest(t *testing.T, test string, api edgeproto.CloudletRefsApiClient, testData []edgeproto.CloudletRefs) {
	switch test {
	case "show":
		basicCloudletRefsShowTest(t, NewClientCloudletRefsApi(api), testData)
	}
}

func basicCloudletRefsShowTest(t *testing.T, api *CloudletRefsCommonApi, testData []edgeproto.CloudletRefs) {
	var err error
	ctx := context.TODO()

	show := ShowCloudletRefs{}
	show.Init()
	filterNone := edgeproto.CloudletRefs{}
	err = api.ShowCloudletRefs(ctx, &filterNone, &show)
	assert.Nil(t, err, "show data")
	assert.Equal(t, len(testData), len(show.Data), "Show count")
	for _, obj := range testData {
		show.AssertFound(t, &obj)
	}
}

func GetCloudletRefs(t *testing.T, api *CloudletRefsCommonApi, key *edgeproto.CloudletKey, out *edgeproto.CloudletRefs) bool {
	var err error
	ctx := context.TODO()

	show := ShowCloudletRefs{}
	show.Init()
	filter := edgeproto.CloudletRefs{}
	filter.Key = *key
	err = api.ShowCloudletRefs(ctx, &filter, &show)
	assert.Nil(t, err, "show data")
	obj, found := show.Data[key.GetKeyString()]
	if found {
		*out = obj
	}
	return found
}

type ShowClusterRefs struct {
	Data map[string]edgeproto.ClusterRefs
	grpc.ServerStream
}

func (x *ShowClusterRefs) Init() {
	x.Data = make(map[string]edgeproto.ClusterRefs)
}

func (x *ShowClusterRefs) Send(m *edgeproto.ClusterRefs) error {
	x.Data[m.Key.GetKeyString()] = *m
	return nil
}

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
		x.Data[obj.Key.GetKeyString()] = *obj
	}
}

func (x *ShowClusterRefs) CheckFound(obj *edgeproto.ClusterRefs) bool {
	_, found := x.Data[obj.Key.GetKeyString()]
	return found
}

func (x *ShowClusterRefs) AssertFound(t *testing.T, obj *edgeproto.ClusterRefs) {
	check, found := x.Data[obj.Key.GetKeyString()]
	assert.True(t, found, "find ClusterRefs %s", obj.Key.GetKeyString())
	if found && !check.Matches(obj, edgeproto.MatchIgnoreBackend(), edgeproto.MatchSortArrayedKeys()) {
		assert.Equal(t, *obj, check, "ClusterRefs are equal")
	}
	if found {
		// remove in case there are dups in the list, so the
		// same object cannot be used again
		delete(x.Data, obj.Key.GetKeyString())
	}
}

func (x *ShowClusterRefs) AssertNotFound(t *testing.T, obj *edgeproto.ClusterRefs) {
	_, found := x.Data[obj.Key.GetKeyString()]
	assert.False(t, found, "do not find ClusterRefs %s", obj.Key.GetKeyString())
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
	switch test {
	case "show":
		basicClusterRefsShowTest(t, NewInternalClusterRefsApi(api), testData)
	}
}

func ClientClusterRefsTest(t *testing.T, test string, api edgeproto.ClusterRefsApiClient, testData []edgeproto.ClusterRefs) {
	switch test {
	case "show":
		basicClusterRefsShowTest(t, NewClientClusterRefsApi(api), testData)
	}
}

func basicClusterRefsShowTest(t *testing.T, api *ClusterRefsCommonApi, testData []edgeproto.ClusterRefs) {
	var err error
	ctx := context.TODO()

	show := ShowClusterRefs{}
	show.Init()
	filterNone := edgeproto.ClusterRefs{}
	err = api.ShowClusterRefs(ctx, &filterNone, &show)
	assert.Nil(t, err, "show data")
	assert.Equal(t, len(testData), len(show.Data), "Show count")
	for _, obj := range testData {
		show.AssertFound(t, &obj)
	}
}

func GetClusterRefs(t *testing.T, api *ClusterRefsCommonApi, key *edgeproto.ClusterInstKey, out *edgeproto.ClusterRefs) bool {
	var err error
	ctx := context.TODO()

	show := ShowClusterRefs{}
	show.Init()
	filter := edgeproto.ClusterRefs{}
	filter.Key = *key
	err = api.ShowClusterRefs(ctx, &filter, &show)
	assert.Nil(t, err, "show data")
	obj, found := show.Data[key.GetKeyString()]
	if found {
		*out = obj
	}
	return found
}

func (s *DummyServer) ShowCloudletRefs(in *edgeproto.CloudletRefs, server edgeproto.CloudletRefsApi_ShowCloudletRefsServer) error {
	server.Send(&edgeproto.CloudletRefs{})
	server.Send(&edgeproto.CloudletRefs{})
	server.Send(&edgeproto.CloudletRefs{})
	return nil
}

func (s *DummyServer) ShowClusterRefs(in *edgeproto.ClusterRefs, server edgeproto.ClusterRefsApi_ShowClusterRefsServer) error {
	server.Send(&edgeproto.ClusterRefs{})
	server.Send(&edgeproto.ClusterRefs{})
	server.Send(&edgeproto.ClusterRefs{})
	return nil
}
