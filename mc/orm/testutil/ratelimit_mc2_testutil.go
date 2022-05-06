// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: ratelimit.proto

package testutil

import (
	"context"
	fmt "fmt"
	"github.com/edgexr/edge-cloud-infra/mc/mcctl/mctestclient"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	edgeproto "github.com/edgexr/edge-cloud/edgeproto"
	_ "github.com/edgexr/edge-cloud/protogen"
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

func TestShowRateLimitSettings(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.RateLimitSettings, modFuncs ...func(*edgeproto.RateLimitSettings)) ([]edgeproto.RateLimitSettings, int, error) {
	dat := &ormapi.RegionRateLimitSettings{}
	dat.Region = region
	dat.RateLimitSettings = *in
	for _, fn := range modFuncs {
		fn(&dat.RateLimitSettings)
	}
	return mcClient.ShowRateLimitSettings(uri, token, dat)
}
func TestPermShowRateLimitSettings(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.RateLimitSettings)) ([]edgeproto.RateLimitSettings, int, error) {
	in := &edgeproto.RateLimitSettings{}
	return TestShowRateLimitSettings(mcClient, uri, token, region, in, modFuncs...)
}

func TestCreateFlowRateLimitSettings(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.FlowRateLimitSettings, modFuncs ...func(*edgeproto.FlowRateLimitSettings)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionFlowRateLimitSettings{}
	dat.Region = region
	dat.FlowRateLimitSettings = *in
	for _, fn := range modFuncs {
		fn(&dat.FlowRateLimitSettings)
	}
	return mcClient.CreateFlowRateLimitSettings(uri, token, dat)
}
func TestPermCreateFlowRateLimitSettings(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.FlowRateLimitSettings)) (*edgeproto.Result, int, error) {
	in := &edgeproto.FlowRateLimitSettings{}
	return TestCreateFlowRateLimitSettings(mcClient, uri, token, region, in, modFuncs...)
}

func TestUpdateFlowRateLimitSettings(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.FlowRateLimitSettings, modFuncs ...func(*edgeproto.FlowRateLimitSettings)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionFlowRateLimitSettings{}
	dat.Region = region
	dat.FlowRateLimitSettings = *in
	for _, fn := range modFuncs {
		fn(&dat.FlowRateLimitSettings)
	}
	return mcClient.UpdateFlowRateLimitSettings(uri, token, dat)
}
func TestPermUpdateFlowRateLimitSettings(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.FlowRateLimitSettings)) (*edgeproto.Result, int, error) {
	in := &edgeproto.FlowRateLimitSettings{}
	return TestUpdateFlowRateLimitSettings(mcClient, uri, token, region, in, modFuncs...)
}

func TestDeleteFlowRateLimitSettings(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.FlowRateLimitSettings, modFuncs ...func(*edgeproto.FlowRateLimitSettings)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionFlowRateLimitSettings{}
	dat.Region = region
	dat.FlowRateLimitSettings = *in
	for _, fn := range modFuncs {
		fn(&dat.FlowRateLimitSettings)
	}
	return mcClient.DeleteFlowRateLimitSettings(uri, token, dat)
}
func TestPermDeleteFlowRateLimitSettings(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.FlowRateLimitSettings)) (*edgeproto.Result, int, error) {
	in := &edgeproto.FlowRateLimitSettings{}
	return TestDeleteFlowRateLimitSettings(mcClient, uri, token, region, in, modFuncs...)
}

func TestShowFlowRateLimitSettings(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.FlowRateLimitSettings, modFuncs ...func(*edgeproto.FlowRateLimitSettings)) ([]edgeproto.FlowRateLimitSettings, int, error) {
	dat := &ormapi.RegionFlowRateLimitSettings{}
	dat.Region = region
	dat.FlowRateLimitSettings = *in
	for _, fn := range modFuncs {
		fn(&dat.FlowRateLimitSettings)
	}
	return mcClient.ShowFlowRateLimitSettings(uri, token, dat)
}
func TestPermShowFlowRateLimitSettings(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.FlowRateLimitSettings)) ([]edgeproto.FlowRateLimitSettings, int, error) {
	in := &edgeproto.FlowRateLimitSettings{}
	return TestShowFlowRateLimitSettings(mcClient, uri, token, region, in, modFuncs...)
}

func TestCreateMaxReqsRateLimitSettings(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.MaxReqsRateLimitSettings, modFuncs ...func(*edgeproto.MaxReqsRateLimitSettings)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionMaxReqsRateLimitSettings{}
	dat.Region = region
	dat.MaxReqsRateLimitSettings = *in
	for _, fn := range modFuncs {
		fn(&dat.MaxReqsRateLimitSettings)
	}
	return mcClient.CreateMaxReqsRateLimitSettings(uri, token, dat)
}
func TestPermCreateMaxReqsRateLimitSettings(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.MaxReqsRateLimitSettings)) (*edgeproto.Result, int, error) {
	in := &edgeproto.MaxReqsRateLimitSettings{}
	return TestCreateMaxReqsRateLimitSettings(mcClient, uri, token, region, in, modFuncs...)
}

func TestUpdateMaxReqsRateLimitSettings(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.MaxReqsRateLimitSettings, modFuncs ...func(*edgeproto.MaxReqsRateLimitSettings)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionMaxReqsRateLimitSettings{}
	dat.Region = region
	dat.MaxReqsRateLimitSettings = *in
	for _, fn := range modFuncs {
		fn(&dat.MaxReqsRateLimitSettings)
	}
	return mcClient.UpdateMaxReqsRateLimitSettings(uri, token, dat)
}
func TestPermUpdateMaxReqsRateLimitSettings(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.MaxReqsRateLimitSettings)) (*edgeproto.Result, int, error) {
	in := &edgeproto.MaxReqsRateLimitSettings{}
	return TestUpdateMaxReqsRateLimitSettings(mcClient, uri, token, region, in, modFuncs...)
}

func TestDeleteMaxReqsRateLimitSettings(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.MaxReqsRateLimitSettings, modFuncs ...func(*edgeproto.MaxReqsRateLimitSettings)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionMaxReqsRateLimitSettings{}
	dat.Region = region
	dat.MaxReqsRateLimitSettings = *in
	for _, fn := range modFuncs {
		fn(&dat.MaxReqsRateLimitSettings)
	}
	return mcClient.DeleteMaxReqsRateLimitSettings(uri, token, dat)
}
func TestPermDeleteMaxReqsRateLimitSettings(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.MaxReqsRateLimitSettings)) (*edgeproto.Result, int, error) {
	in := &edgeproto.MaxReqsRateLimitSettings{}
	return TestDeleteMaxReqsRateLimitSettings(mcClient, uri, token, region, in, modFuncs...)
}

func TestShowMaxReqsRateLimitSettings(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.MaxReqsRateLimitSettings, modFuncs ...func(*edgeproto.MaxReqsRateLimitSettings)) ([]edgeproto.MaxReqsRateLimitSettings, int, error) {
	dat := &ormapi.RegionMaxReqsRateLimitSettings{}
	dat.Region = region
	dat.MaxReqsRateLimitSettings = *in
	for _, fn := range modFuncs {
		fn(&dat.MaxReqsRateLimitSettings)
	}
	return mcClient.ShowMaxReqsRateLimitSettings(uri, token, dat)
}
func TestPermShowMaxReqsRateLimitSettings(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.MaxReqsRateLimitSettings)) ([]edgeproto.MaxReqsRateLimitSettings, int, error) {
	in := &edgeproto.MaxReqsRateLimitSettings{}
	return TestShowMaxReqsRateLimitSettings(mcClient, uri, token, region, in, modFuncs...)
}

func (s *TestClient) CreateFlowRateLimitSettings(ctx context.Context, in *edgeproto.FlowRateLimitSettings) (*edgeproto.Result, error) {
	inR := &ormapi.RegionFlowRateLimitSettings{
		Region:                s.Region,
		FlowRateLimitSettings: *in,
	}
	out, status, err := s.McClient.CreateFlowRateLimitSettings(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) UpdateFlowRateLimitSettings(ctx context.Context, in *edgeproto.FlowRateLimitSettings) (*edgeproto.Result, error) {
	inR := &ormapi.RegionFlowRateLimitSettings{
		Region:                s.Region,
		FlowRateLimitSettings: *in,
	}
	out, status, err := s.McClient.UpdateFlowRateLimitSettings(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) DeleteFlowRateLimitSettings(ctx context.Context, in *edgeproto.FlowRateLimitSettings) (*edgeproto.Result, error) {
	inR := &ormapi.RegionFlowRateLimitSettings{
		Region:                s.Region,
		FlowRateLimitSettings: *in,
	}
	out, status, err := s.McClient.DeleteFlowRateLimitSettings(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) ShowFlowRateLimitSettings(ctx context.Context, in *edgeproto.FlowRateLimitSettings) ([]edgeproto.FlowRateLimitSettings, error) {
	inR := &ormapi.RegionFlowRateLimitSettings{
		Region:                s.Region,
		FlowRateLimitSettings: *in,
	}
	out, status, err := s.McClient.ShowFlowRateLimitSettings(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) CreateMaxReqsRateLimitSettings(ctx context.Context, in *edgeproto.MaxReqsRateLimitSettings) (*edgeproto.Result, error) {
	inR := &ormapi.RegionMaxReqsRateLimitSettings{
		Region:                   s.Region,
		MaxReqsRateLimitSettings: *in,
	}
	out, status, err := s.McClient.CreateMaxReqsRateLimitSettings(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) UpdateMaxReqsRateLimitSettings(ctx context.Context, in *edgeproto.MaxReqsRateLimitSettings) (*edgeproto.Result, error) {
	inR := &ormapi.RegionMaxReqsRateLimitSettings{
		Region:                   s.Region,
		MaxReqsRateLimitSettings: *in,
	}
	out, status, err := s.McClient.UpdateMaxReqsRateLimitSettings(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) DeleteMaxReqsRateLimitSettings(ctx context.Context, in *edgeproto.MaxReqsRateLimitSettings) (*edgeproto.Result, error) {
	inR := &ormapi.RegionMaxReqsRateLimitSettings{
		Region:                   s.Region,
		MaxReqsRateLimitSettings: *in,
	}
	out, status, err := s.McClient.DeleteMaxReqsRateLimitSettings(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) ShowMaxReqsRateLimitSettings(ctx context.Context, in *edgeproto.MaxReqsRateLimitSettings) ([]edgeproto.MaxReqsRateLimitSettings, error) {
	inR := &ormapi.RegionMaxReqsRateLimitSettings{
		Region:                   s.Region,
		MaxReqsRateLimitSettings: *in,
	}
	out, status, err := s.McClient.ShowMaxReqsRateLimitSettings(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) ShowRateLimitSettings(ctx context.Context, in *edgeproto.RateLimitSettings) ([]edgeproto.RateLimitSettings, error) {
	inR := &ormapi.RegionRateLimitSettings{
		Region:            s.Region,
		RateLimitSettings: *in,
	}
	out, status, err := s.McClient.ShowRateLimitSettings(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}
