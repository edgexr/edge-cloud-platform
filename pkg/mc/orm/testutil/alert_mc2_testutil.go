// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: alert.proto

package testutil

import (
	"context"
	fmt "fmt"
	_ "github.com/edgexr/edge-cloud-platform/api/dme-proto"
	edgeproto "github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/mcctl/mctestclient"
	_ "github.com/edgexr/edge-cloud-platform/tools/protogen"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

func TestShowAlert(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.Alert, modFuncs ...func(*edgeproto.Alert)) ([]edgeproto.Alert, int, error) {
	dat := &ormapi.RegionAlert{}
	dat.Region = region
	dat.Alert = *in
	for _, fn := range modFuncs {
		fn(&dat.Alert)
	}
	return mcClient.ShowAlert(uri, token, dat)
}
func TestPermShowAlert(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.Alert)) ([]edgeproto.Alert, int, error) {
	in := &edgeproto.Alert{}
	return TestShowAlert(mcClient, uri, token, region, in, modFuncs...)
}

func (s *TestClient) ShowAlert(ctx context.Context, in *edgeproto.Alert) ([]edgeproto.Alert, error) {
	inR := &ormapi.RegionAlert{
		Region: s.Region,
		Alert:  *in,
	}
	out, status, err := s.McClient.ShowAlert(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}