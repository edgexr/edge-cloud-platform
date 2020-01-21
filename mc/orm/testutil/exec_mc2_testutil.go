// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: exec.proto

package testutil

import edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
import "github.com/mobiledgex/edge-cloud-infra/mc/ormclient"
import "github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/googleapis/google/api"
import _ "github.com/mobiledgex/edge-cloud/protogen"
import _ "github.com/gogo/protobuf/gogoproto"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

func TestRunCommand(mcClient *ormclient.Client, uri, token, region string, in *edgeproto.ExecRequest) (*edgeproto.ExecRequest, int, error) {
	dat := &ormapi.RegionExecRequest{}
	dat.Region = region
	dat.ExecRequest = *in
	return mcClient.RunCommand(uri, token, dat)
}
func TestPermRunCommand(mcClient *ormclient.Client, uri, token, region, org string) (*edgeproto.ExecRequest, int, error) {
	in := &edgeproto.ExecRequest{}
	in.AppInstKey.AppKey.DeveloperKey.Name = org
	return TestRunCommand(mcClient, uri, token, region, in)
}
