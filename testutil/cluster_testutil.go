// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: cluster.proto

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

type ShowCluster struct {
	Data map[string]edgeproto.Cluster
	grpc.ServerStream
}

func (x *ShowCluster) Init() {
	x.Data = make(map[string]edgeproto.Cluster)
}

func (x *ShowCluster) Send(m *edgeproto.Cluster) error {
	x.Data[m.Key.GetKeyString()] = *m
	return nil
}

func (x *ShowCluster) ReadStream(stream edgeproto.ClusterApi_ShowClusterClient, err error) {
	x.Data = make(map[string]edgeproto.Cluster)
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

func (x *ShowCluster) CheckFound(obj *edgeproto.Cluster) bool {
	_, found := x.Data[obj.Key.GetKeyString()]
	return found
}

func (x *ShowCluster) AssertFound(t *testing.T, obj *edgeproto.Cluster) {
	check, found := x.Data[obj.Key.GetKeyString()]
	assert.True(t, found, "find Cluster %s", obj.Key.GetKeyString())
	if found && !check.MatchesIgnoreBackend(obj) {
		assert.Equal(t, *obj, check, "Cluster are equal")
	}
}

func (x *ShowCluster) AssertNotFound(t *testing.T, obj *edgeproto.Cluster) {
	_, found := x.Data[obj.Key.GetKeyString()]
	assert.False(t, found, "do not find Cluster %s", obj.Key.GetKeyString())
}

func WaitAssertFoundCluster(t *testing.T, api edgeproto.ClusterApiClient, obj *edgeproto.Cluster, count int, retry time.Duration) {
	show := ShowCluster{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowCluster(ctx, obj)
		show.ReadStream(stream, err)
		cancel()
		if show.CheckFound(obj) {
			break
		}
		time.Sleep(retry)
	}
	show.AssertFound(t, obj)
}

func WaitAssertNotFoundCluster(t *testing.T, api edgeproto.ClusterApiClient, obj *edgeproto.Cluster, count int, retry time.Duration) {
	show := ShowCluster{}
	filterNone := edgeproto.Cluster{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowCluster(ctx, &filterNone)
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
type ClusterCommonApi struct {
	internal_api edgeproto.ClusterApiServer
	client_api   edgeproto.ClusterApiClient
}

func (x *ClusterCommonApi) CreateCluster(ctx context.Context, in *edgeproto.Cluster) (*edgeproto.Result, error) {
	if x.internal_api != nil {
		return x.internal_api.CreateCluster(ctx, in)
	} else {
		return x.client_api.CreateCluster(ctx, in)
	}
}

func (x *ClusterCommonApi) UpdateCluster(ctx context.Context, in *edgeproto.Cluster) (*edgeproto.Result, error) {
	if x.internal_api != nil {
		return x.internal_api.UpdateCluster(ctx, in)
	} else {
		return x.client_api.UpdateCluster(ctx, in)
	}
}

func (x *ClusterCommonApi) DeleteCluster(ctx context.Context, in *edgeproto.Cluster) (*edgeproto.Result, error) {
	if x.internal_api != nil {
		return x.internal_api.DeleteCluster(ctx, in)
	} else {
		return x.client_api.DeleteCluster(ctx, in)
	}
}

func (x *ClusterCommonApi) ShowCluster(ctx context.Context, filter *edgeproto.Cluster, showData *ShowCluster) error {
	if x.internal_api != nil {
		return x.internal_api.ShowCluster(filter, showData)
	} else {
		stream, err := x.client_api.ShowCluster(ctx, filter)
		showData.ReadStream(stream, err)
		return err
	}
}

func NewInternalClusterApi(api edgeproto.ClusterApiServer) *ClusterCommonApi {
	apiWrap := ClusterCommonApi{}
	apiWrap.internal_api = api
	return &apiWrap
}

func NewClientClusterApi(api edgeproto.ClusterApiClient) *ClusterCommonApi {
	apiWrap := ClusterCommonApi{}
	apiWrap.client_api = api
	return &apiWrap
}
func InternalClusterCudTest(t *testing.T, api edgeproto.ClusterApiServer, testData []edgeproto.Cluster) {
	basicClusterCudTest(t, NewInternalClusterApi(api), testData)
}

func ClientClusterCudTest(t *testing.T, api edgeproto.ClusterApiClient, testData []edgeproto.Cluster) {
	basicClusterCudTest(t, NewClientClusterApi(api), testData)
}

func basicClusterCudTest(t *testing.T, api *ClusterCommonApi, testData []edgeproto.Cluster) {
	var err error
	ctx := context.TODO()

	if len(testData) < 3 {
		assert.True(t, false, "Need at least 3 test data objects")
		return
	}

	// test create
	for _, obj := range testData {
		_, err = api.CreateCluster(ctx, &obj)
		assert.Nil(t, err, "Create Cluster %s", obj.Key.GetKeyString())
	}
	_, err = api.CreateCluster(ctx, &testData[0])
	assert.NotNil(t, err, "Create duplicate Cluster")

	// test show all items
	show := ShowCluster{}
	show.Init()
	filterNone := edgeproto.Cluster{}
	err = api.ShowCluster(ctx, &filterNone, &show)
	assert.Nil(t, err, "show data")
	for _, obj := range testData {
		show.AssertFound(t, &obj)
	}
	assert.Equal(t, len(testData), len(show.Data), "Show count")

	// test delete
	_, err = api.DeleteCluster(ctx, &testData[0])
	assert.Nil(t, err, "delete Cluster %s", testData[0].Key.GetKeyString())
	show.Init()
	err = api.ShowCluster(ctx, &filterNone, &show)
	assert.Nil(t, err, "show data")
	assert.Equal(t, len(testData)-1, len(show.Data), "Show count")
	show.AssertNotFound(t, &testData[0])
	// test update of missing object
	_, err = api.UpdateCluster(ctx, &testData[0])
	assert.NotNil(t, err, "Update missing object")
	// create it back
	_, err = api.CreateCluster(ctx, &testData[0])
	assert.Nil(t, err, "Create Cluster %s", testData[0].Key.GetKeyString())

	// test invalid keys
	bad := edgeproto.Cluster{}
	_, err = api.CreateCluster(ctx, &bad)
	assert.NotNil(t, err, "Create Cluster with no key info")

}
