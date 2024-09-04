// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: sample.proto

package testutil

import (
	"context"
	fmt "fmt"
	_ "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/pkg/edgectl/wrapper"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	testgen "github.com/edgexr/edge-cloud-platform/test/testgen"
	_ "github.com/edgexr/edge-cloud-platform/tools/protogen"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	"google.golang.org/grpc"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

func (r *Run) TestApi_TestGen(data *[]testgen.TestGen, dataMap interface{}, dataOut interface{}) {
	log.DebugLog(log.DebugLevelApi, "API for TestGen", "mode", r.Mode)
	for ii, objD := range *data {
		obj := &objD
		switch r.Mode {
		case "request":
			out, err := r.client.Request(r.ctx, obj)
			if err != nil {
				r.logErr(fmt.Sprintf("TestApi_TestGen[%d]", ii), err)
			} else {
				outp, ok := dataOut.(*[]testgen.TestGen)
				if !ok {
					panic(fmt.Sprintf("RunTestApi_TestGen expected dataOut type *[]testgen.TestGen, but was %T", dataOut))
				}
				*outp = append(*outp, *out)
			}
		}
	}
}

func (s *ApiClient) Request(ctx context.Context, in *testgen.TestGen) (*testgen.TestGen, error) {
	api := testgen.NewTestApiClient(s.Conn)
	return api.Request(ctx, in)
}

func (s *CliClient) Request(ctx context.Context, in *testgen.TestGen) (*testgen.TestGen, error) {
	out := testgen.TestGen{}
	args := append(s.BaseArgs, "controller", "Request")
	err := wrapper.RunEdgectlObjs(args, in, &out, s.RunOps...)
	return &out, err
}

type TestApiClient interface {
	Request(ctx context.Context, in *testgen.TestGen) (*testgen.TestGen, error)
}

type DummyServer struct {
	CustomData
	ShowDummyCount   int
	CudNoop          bool
	MidstreamFailChs map[string]chan bool
}

func RegisterDummyServer(server *grpc.Server) *DummyServer {
	d := &DummyServer{}
	d.MidstreamFailChs = make(map[string]chan bool)
	return d
}

func (s *DummyServer) EnableMidstreamFailure(api string, syncCh chan bool) {
	s.MidstreamFailChs[api] = syncCh
}

func (s *DummyServer) DisableMidstreamFailure(api string) {
	delete(s.MidstreamFailChs, api)
}

type ApiClient struct {
	Conn *grpc.ClientConn
}

type CliClient struct {
	BaseArgs []string
	RunOps   []wrapper.RunOp
}

type Client interface {
	TestApiClient
}

type InternalCUDAPIs interface {
}
