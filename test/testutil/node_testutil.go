// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: node.proto

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

type ShowNode struct {
	Data map[string]edgeproto.Node
	grpc.ServerStream
	Ctx context.Context
}

func (x *ShowNode) Init() {
	x.Data = make(map[string]edgeproto.Node)
}

func (x *ShowNode) Send(m *edgeproto.Node) error {
	x.Data[m.GetKey().GetKeyString()] = *m
	return nil
}

func (x *ShowNode) Context() context.Context {
	return x.Ctx
}

var NodeShowExtraCount = 0

func (x *ShowNode) ReadStream(stream edgeproto.NodeApi_ShowNodeClient, err error) {
	x.Data = make(map[string]edgeproto.Node)
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

func (x *ShowNode) CheckFound(obj *edgeproto.Node) bool {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	return found
}

func (x *ShowNode) AssertFound(t *testing.T, obj *edgeproto.Node) {
	check, found := x.Data[obj.GetKey().GetKeyString()]
	require.True(t, found, "find Node %s", obj.GetKey().GetKeyString())
	if found && !check.Matches(obj, edgeproto.MatchIgnoreBackend(), edgeproto.MatchSortArrayedKeys()) {
		require.Equal(t, *obj, check, "Node are equal")
	}
	if found {
		// remove in case there are dups in the list, so the
		// same object cannot be used again
		delete(x.Data, obj.GetKey().GetKeyString())
	}
}

func (x *ShowNode) AssertNotFound(t *testing.T, obj *edgeproto.Node) {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	require.False(t, found, "do not find Node %s", obj.GetKey().GetKeyString())
}

func WaitAssertFoundNode(t *testing.T, api edgeproto.NodeApiClient, obj *edgeproto.Node, count int, retry time.Duration) {
	show := ShowNode{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowNode(ctx, obj)
		show.ReadStream(stream, err)
		cancel()
		if show.CheckFound(obj) {
			break
		}
		time.Sleep(retry)
	}
	show.AssertFound(t, obj)
}

func WaitAssertNotFoundNode(t *testing.T, api edgeproto.NodeApiClient, obj *edgeproto.Node, count int, retry time.Duration) {
	show := ShowNode{}
	filterNone := edgeproto.Node{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowNode(ctx, &filterNone)
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
type NodeCommonApi struct {
	internal_api edgeproto.NodeApiServer
	client_api   edgeproto.NodeApiClient
}

func (x *NodeCommonApi) ShowNode(ctx context.Context, filter *edgeproto.Node, showData *ShowNode) error {
	if x.internal_api != nil {
		showData.Ctx = ctx
		return x.internal_api.ShowNode(filter, showData)
	} else {
		stream, err := x.client_api.ShowNode(ctx, filter)
		showData.ReadStream(stream, err)
		return unwrapGrpcError(err)
	}
}

func NewInternalNodeApi(api edgeproto.NodeApiServer) *NodeCommonApi {
	apiWrap := NodeCommonApi{}
	apiWrap.internal_api = api
	return &apiWrap
}

func NewClientNodeApi(api edgeproto.NodeApiClient) *NodeCommonApi {
	apiWrap := NodeCommonApi{}
	apiWrap.client_api = api
	return &apiWrap
}

type NodeTestOptions struct {
	createdData []edgeproto.Node
}

type NodeTestOp func(opts *NodeTestOptions)

func WithCreatedNodeTestData(createdData []edgeproto.Node) NodeTestOp {
	return func(opts *NodeTestOptions) { opts.createdData = createdData }
}

func InternalNodeTest(t *testing.T, test string, api edgeproto.NodeApiServer, testData []edgeproto.Node, ops ...NodeTestOp) {
	span := log.StartSpan(log.DebugLevelApi, "InternalNodeTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "show":
		basicNodeShowTest(t, ctx, NewInternalNodeApi(api), testData)
	}
}

func ClientNodeTest(t *testing.T, test string, api edgeproto.NodeApiClient, testData []edgeproto.Node, ops ...NodeTestOp) {
	span := log.StartSpan(log.DebugLevelApi, "ClientNodeTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "show":
		basicNodeShowTest(t, ctx, NewClientNodeApi(api), testData)
	}
}

func basicNodeShowTest(t *testing.T, ctx context.Context, api *NodeCommonApi, testData []edgeproto.Node) {
	var err error

	show := ShowNode{}
	show.Init()
	filterNone := edgeproto.Node{}
	err = api.ShowNode(ctx, &filterNone, &show)
	require.Nil(t, err, "show data")
	require.Equal(t, len(testData)+NodeShowExtraCount, len(show.Data), "Show count")
	for _, obj := range testData {
		show.AssertFound(t, &obj)
	}
}

func GetNode(t *testing.T, ctx context.Context, api *NodeCommonApi, key *edgeproto.NodeKey, out *edgeproto.Node) bool {
	var err error

	show := ShowNode{}
	show.Init()
	filter := edgeproto.Node{}
	filter.SetKey(key)
	err = api.ShowNode(ctx, &filter, &show)
	require.Nil(t, err, "show data")
	obj, found := show.Data[key.GetKeyString()]
	if found {
		*out = obj
	}
	return found
}

func FindNodeData(key *edgeproto.NodeKey, testData []edgeproto.Node) (*edgeproto.Node, bool) {
	for ii, _ := range testData {
		if testData[ii].GetKey().Matches(key) {
			return &testData[ii], true
		}
	}
	return nil, false
}

type NodeDataOut struct {
	Errors []Err
}

// used to intersperse other creates/deletes/checks
// note the objs value is the previous one for create,
// but the next one for delete
type RunNodeDataApiCallback func(objs string)

func RunNodeDataApis(run *Run, in *edgeproto.NodeData, inMap map[string]interface{}, out *NodeDataOut, apicb RunNodeDataApiCallback) {
	apicb("")
	out.Errors = run.Errs
}

func RunNodeDataReverseApis(run *Run, in *edgeproto.NodeData, inMap map[string]interface{}, out *NodeDataOut, apicb RunNodeDataApiCallback) {
	apicb("")
	out.Errors = run.Errs
}

func RunNodeDataShowApis(run *Run, in *edgeproto.NodeData, selector edgeproto.AllSelector, out *edgeproto.NodeData) {
	if selector.Has("nodes") {
		run.NodeApi(&in.Nodes, nil, &out.Nodes)
	}
}

func DeleteAllNodeDataInternal(t *testing.T, ctx context.Context, apis InternalCUDAPIs, in *edgeproto.NodeData) {
}

func (r *Run) NodeApi(data *[]edgeproto.Node, dataMap interface{}, dataOut interface{}) {
	log.DebugLog(log.DebugLevelApi, "API for Node", "mode", r.Mode)
	if r.Mode == "show" {
		obj := &edgeproto.Node{}
		out, err := r.client.ShowNode(r.ctx, obj)
		if err != nil {
			r.logErr("NodeApi", err)
		} else {
			outp, ok := dataOut.(*[]edgeproto.Node)
			if !ok {
				panic(fmt.Sprintf("RunNodeApi expected dataOut type *[]edgeproto.Node, but was %T", dataOut))
			}
			*outp = append(*outp, out...)
		}
		return
	}
	for ii, objD := range *data {
		obj := &objD
		switch r.Mode {
		case "showfiltered":
			out, err := r.client.ShowNode(r.ctx, obj)
			if err != nil {
				r.logErr(fmt.Sprintf("NodeApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.Node)
				if !ok {
					panic(fmt.Sprintf("RunNodeApi expected dataOut type *[]edgeproto.Node, but was %T", dataOut))
				}
				*outp = append(*outp, out...)
			}
		}
	}
}

func (s *DummyServer) ShowNode(in *edgeproto.Node, server edgeproto.NodeApi_ShowNodeServer) error {
	var err error
	obj := &edgeproto.Node{}
	if obj.Matches(in, edgeproto.MatchFilter()) {
		for ii := 0; ii < s.ShowDummyCount; ii++ {
			server.Send(&edgeproto.Node{})
		}
		if ch, ok := s.MidstreamFailChs["ShowNode"]; ok {
			// Wait until client receives the SendMsg, since they
			// are buffered and dropped once we return err here.
			select {
			case <-ch:
			case <-time.After(5 * time.Second):
			}
			return fmt.Errorf("midstream failure!")
		}
	}
	err = s.NodeCache.Show(in, func(obj *edgeproto.Node) error {
		err := server.Send(obj)
		return err
	})
	return err
}

type NodeStream interface {
	Recv() (*edgeproto.Node, error)
}

func NodeReadStream(stream NodeStream) ([]edgeproto.Node, error) {
	output := []edgeproto.Node{}
	for {
		obj, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return output, fmt.Errorf("read Node stream failed, %v", err)
		}
		output = append(output, *obj)
	}
	return output, nil
}

func (s *ApiClient) ShowNode(ctx context.Context, in *edgeproto.Node) ([]edgeproto.Node, error) {
	api := edgeproto.NewNodeApiClient(s.Conn)
	stream, err := api.ShowNode(ctx, in)
	if err != nil {
		return nil, err
	}
	return NodeReadStream(stream)
}

func (s *CliClient) ShowNode(ctx context.Context, in *edgeproto.Node) ([]edgeproto.Node, error) {
	output := []edgeproto.Node{}
	args := append(s.BaseArgs, "controller", "ShowNode")
	err := wrapper.RunEdgectlObjs(args, in, &output, s.RunOps...)
	return output, err
}

type NodeApiClient interface {
	ShowNode(ctx context.Context, in *edgeproto.Node) ([]edgeproto.Node, error)
}
