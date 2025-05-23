// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: svcnode.proto

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

type ShowSvcNode struct {
	Data map[string]edgeproto.SvcNode
	grpc.ServerStream
	Ctx context.Context
}

func (x *ShowSvcNode) Init() {
	x.Data = make(map[string]edgeproto.SvcNode)
}

func (x *ShowSvcNode) Send(m *edgeproto.SvcNode) error {
	x.Data[m.GetKey().GetKeyString()] = *m
	return nil
}

func (x *ShowSvcNode) Context() context.Context {
	return x.Ctx
}

var SvcNodeShowExtraCount = 0

func (x *ShowSvcNode) ReadStream(stream edgeproto.SvcNodeApi_ShowSvcNodeClient, err error) {
	x.Data = make(map[string]edgeproto.SvcNode)
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

func (x *ShowSvcNode) CheckFound(obj *edgeproto.SvcNode) bool {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	return found
}

func (x *ShowSvcNode) AssertFound(t *testing.T, obj *edgeproto.SvcNode) {
	check, found := x.Data[obj.GetKey().GetKeyString()]
	require.True(t, found, "find SvcNode %s", obj.GetKey().GetKeyString())
	if found && !check.Matches(obj, edgeproto.MatchIgnoreBackend(), edgeproto.MatchSortArrayedKeys()) {
		require.Equal(t, *obj, check, "SvcNode are equal")
	}
	if found {
		// remove in case there are dups in the list, so the
		// same object cannot be used again
		delete(x.Data, obj.GetKey().GetKeyString())
	}
}

func (x *ShowSvcNode) AssertNotFound(t *testing.T, obj *edgeproto.SvcNode) {
	_, found := x.Data[obj.GetKey().GetKeyString()]
	require.False(t, found, "do not find SvcNode %s", obj.GetKey().GetKeyString())
}

func WaitAssertFoundSvcNode(t *testing.T, api edgeproto.SvcNodeApiClient, obj *edgeproto.SvcNode, count int, retry time.Duration) {
	show := ShowSvcNode{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowSvcNode(ctx, obj)
		show.ReadStream(stream, err)
		cancel()
		if show.CheckFound(obj) {
			break
		}
		time.Sleep(retry)
	}
	show.AssertFound(t, obj)
}

func WaitAssertNotFoundSvcNode(t *testing.T, api edgeproto.SvcNodeApiClient, obj *edgeproto.SvcNode, count int, retry time.Duration) {
	show := ShowSvcNode{}
	filterNone := edgeproto.SvcNode{}
	for ii := 0; ii < count; ii++ {
		ctx, cancel := context.WithTimeout(context.Background(), retry)
		stream, err := api.ShowSvcNode(ctx, &filterNone)
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
type SvcNodeCommonApi struct {
	internal_api edgeproto.SvcNodeApiServer
	client_api   edgeproto.SvcNodeApiClient
}

func (x *SvcNodeCommonApi) ShowSvcNode(ctx context.Context, filter *edgeproto.SvcNode, showData *ShowSvcNode) error {
	if x.internal_api != nil {
		showData.Ctx = ctx
		return x.internal_api.ShowSvcNode(filter, showData)
	} else {
		stream, err := x.client_api.ShowSvcNode(ctx, filter)
		showData.ReadStream(stream, err)
		return unwrapGrpcError(err)
	}
}

func NewInternalSvcNodeApi(api edgeproto.SvcNodeApiServer) *SvcNodeCommonApi {
	apiWrap := SvcNodeCommonApi{}
	apiWrap.internal_api = api
	return &apiWrap
}

func NewClientSvcNodeApi(api edgeproto.SvcNodeApiClient) *SvcNodeCommonApi {
	apiWrap := SvcNodeCommonApi{}
	apiWrap.client_api = api
	return &apiWrap
}

type SvcNodeTestOptions struct {
	createdData []edgeproto.SvcNode
}

type SvcNodeTestOp func(opts *SvcNodeTestOptions)

func WithCreatedSvcNodeTestData(createdData []edgeproto.SvcNode) SvcNodeTestOp {
	return func(opts *SvcNodeTestOptions) { opts.createdData = createdData }
}

func InternalSvcNodeTest(t *testing.T, test string, api edgeproto.SvcNodeApiServer, testData []edgeproto.SvcNode, ops ...SvcNodeTestOp) {
	span := log.StartSpan(log.DebugLevelApi, "InternalSvcNodeTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "show":
		basicSvcNodeShowTest(t, ctx, NewInternalSvcNodeApi(api), testData)
	}
}

func ClientSvcNodeTest(t *testing.T, test string, api edgeproto.SvcNodeApiClient, testData []edgeproto.SvcNode, ops ...SvcNodeTestOp) {
	span := log.StartSpan(log.DebugLevelApi, "ClientSvcNodeTest")
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	switch test {
	case "show":
		basicSvcNodeShowTest(t, ctx, NewClientSvcNodeApi(api), testData)
	}
}

func basicSvcNodeShowTest(t *testing.T, ctx context.Context, api *SvcNodeCommonApi, testData []edgeproto.SvcNode) {
	var err error

	show := ShowSvcNode{}
	show.Init()
	filterNone := edgeproto.SvcNode{}
	err = api.ShowSvcNode(ctx, &filterNone, &show)
	require.Nil(t, err, "show data")
	require.Equal(t, len(testData)+SvcNodeShowExtraCount, len(show.Data), "Show count")
	for _, obj := range testData {
		show.AssertFound(t, &obj)
	}
}

func GetSvcNode(t *testing.T, ctx context.Context, api *SvcNodeCommonApi, key *edgeproto.SvcNodeKey, out *edgeproto.SvcNode) bool {
	var err error

	show := ShowSvcNode{}
	show.Init()
	filter := edgeproto.SvcNode{}
	filter.SetKey(key)
	err = api.ShowSvcNode(ctx, &filter, &show)
	require.Nil(t, err, "show data")
	obj, found := show.Data[key.GetKeyString()]
	if found {
		*out = obj
	}
	return found
}

func FindSvcNodeData(key *edgeproto.SvcNodeKey, testData []edgeproto.SvcNode) (*edgeproto.SvcNode, bool) {
	for ii, _ := range testData {
		if testData[ii].GetKey().Matches(key) {
			return &testData[ii], true
		}
	}
	return nil, false
}

type SvcNodeDataOut struct {
	Errors []Err
}

// used to intersperse other creates/deletes/checks
// note the objs value is the previous one for create,
// but the next one for delete
type RunSvcNodeDataApiCallback func(objs string)

func RunSvcNodeDataApis(run *Run, in *edgeproto.SvcNodeData, inMap map[string]interface{}, out *SvcNodeDataOut, apicb RunSvcNodeDataApiCallback) {
	apicb("")
	out.Errors = run.Errs
}

func RunSvcNodeDataReverseApis(run *Run, in *edgeproto.SvcNodeData, inMap map[string]interface{}, out *SvcNodeDataOut, apicb RunSvcNodeDataApiCallback) {
	apicb("")
	out.Errors = run.Errs
}

func RunSvcNodeDataShowApis(run *Run, in *edgeproto.SvcNodeData, selector edgeproto.AllSelector, out *edgeproto.SvcNodeData) {
	if selector.Has("nodes") {
		run.SvcNodeApi(&in.Nodes, nil, &out.Nodes)
	}
}

func DeleteAllSvcNodeDataInternal(t *testing.T, ctx context.Context, apis InternalCUDAPIs, in *edgeproto.SvcNodeData) {
}

func (r *Run) SvcNodeApi(data *[]edgeproto.SvcNode, dataMap interface{}, dataOut interface{}) {
	log.DebugLog(log.DebugLevelApi, "API for SvcNode", "mode", r.Mode)
	if r.Mode == "show" {
		obj := &edgeproto.SvcNode{}
		out, err := r.client.ShowSvcNode(r.ctx, obj)
		if err != nil {
			r.logErr("SvcNodeApi", err)
		} else {
			outp, ok := dataOut.(*[]edgeproto.SvcNode)
			if !ok {
				panic(fmt.Sprintf("RunSvcNodeApi expected dataOut type *[]edgeproto.SvcNode, but was %T", dataOut))
			}
			*outp = append(*outp, out...)
		}
		return
	}
	for ii, objD := range *data {
		obj := &objD
		switch r.Mode {
		case "showfiltered":
			out, err := r.client.ShowSvcNode(r.ctx, obj)
			if err != nil {
				r.logErr(fmt.Sprintf("SvcNodeApi[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]edgeproto.SvcNode)
				if !ok {
					panic(fmt.Sprintf("RunSvcNodeApi expected dataOut type *[]edgeproto.SvcNode, but was %T", dataOut))
				}
				*outp = append(*outp, out...)
			}
		}
	}
}

func (s *DummyServer) ShowSvcNode(in *edgeproto.SvcNode, server edgeproto.SvcNodeApi_ShowSvcNodeServer) error {
	var err error
	obj := &edgeproto.SvcNode{}
	if obj.Matches(in, edgeproto.MatchFilter()) {
		for ii := 0; ii < s.ShowDummyCount; ii++ {
			server.Send(&edgeproto.SvcNode{})
		}
		if ch, ok := s.MidstreamFailChs["ShowSvcNode"]; ok {
			// Wait until client receives the SendMsg, since they
			// are buffered and dropped once we return err here.
			select {
			case <-ch:
			case <-time.After(5 * time.Second):
			}
			return fmt.Errorf("midstream failure!")
		}
	}
	err = s.SvcNodeCache.Show(in, func(obj *edgeproto.SvcNode) error {
		err := server.Send(obj)
		return err
	})
	return err
}

type SvcNodeStream interface {
	Recv() (*edgeproto.SvcNode, error)
}

func SvcNodeReadStream(stream SvcNodeStream) ([]edgeproto.SvcNode, error) {
	output := []edgeproto.SvcNode{}
	for {
		obj, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return output, fmt.Errorf("read SvcNode stream failed, %v", err)
		}
		output = append(output, *obj)
	}
	return output, nil
}

func (s *ApiClient) ShowSvcNode(ctx context.Context, in *edgeproto.SvcNode) ([]edgeproto.SvcNode, error) {
	api := edgeproto.NewSvcNodeApiClient(s.Conn)
	stream, err := api.ShowSvcNode(ctx, in)
	if err != nil {
		return nil, err
	}
	return SvcNodeReadStream(stream)
}

func (s *CliClient) ShowSvcNode(ctx context.Context, in *edgeproto.SvcNode) ([]edgeproto.SvcNode, error) {
	output := []edgeproto.SvcNode{}
	args := append(s.BaseArgs, "controller", "ShowSvcNode")
	err := wrapper.RunEdgectlObjs(args, in, &output, s.RunOps...)
	return output, err
}

type SvcNodeApiClient interface {
	ShowSvcNode(ctx context.Context, in *edgeproto.SvcNode) ([]edgeproto.SvcNode, error)
}
