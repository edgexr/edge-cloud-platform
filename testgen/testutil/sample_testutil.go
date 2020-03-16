// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: sample.proto

/*
Package testutil is a generated protocol buffer package.

It is generated from these files:
	sample.proto

It has these top-level messages:
	NestedMessage
	IncludeMessage
	IncludeFields
	TestGen
*/
package testutil

import "google.golang.org/grpc"
import "github.com/mobiledgex/edge-cloud/testgen"
import "context"
import "github.com/mobiledgex/edge-cloud/log"
import "github.com/mobiledgex/edge-cloud/edgectl/wrapper"
import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/protobuf/gogoproto"
import _ "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
import _ "github.com/mobiledgex/edge-cloud/protogen"

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
	ShowDummyCount int
	CudNoop        bool
}

func RegisterDummyServer(server *grpc.Server) *DummyServer {
	d := &DummyServer{}
	return d
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