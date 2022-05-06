// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: settings.proto

package testutil

import (
	"context"
	fmt "fmt"
	edgeproto "github.com/edgexr/edge-cloud-platform/edgeproto"
	"github.com/edgexr/edge-cloud-platform/mc/mcctl/mctestclient"
	"github.com/edgexr/edge-cloud-platform/mc/ormapi"
	_ "github.com/edgexr/edge-cloud-platform/protogen"
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

func TestUpdateSettings(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.Settings, modFuncs ...func(*edgeproto.Settings)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionSettings{}
	dat.Region = region
	dat.Settings = *in
	for _, fn := range modFuncs {
		fn(&dat.Settings)
	}
	return mcClient.UpdateSettings(uri, token, dat)
}
func TestPermUpdateSettings(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.Settings)) (*edgeproto.Result, int, error) {
	in := &edgeproto.Settings{}
	return TestUpdateSettings(mcClient, uri, token, region, in, modFuncs...)
}

func TestResetSettings(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.Settings, modFuncs ...func(*edgeproto.Settings)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionSettings{}
	dat.Region = region
	dat.Settings = *in
	for _, fn := range modFuncs {
		fn(&dat.Settings)
	}
	return mcClient.ResetSettings(uri, token, dat)
}
func TestPermResetSettings(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.Settings)) (*edgeproto.Result, int, error) {
	in := &edgeproto.Settings{}
	return TestResetSettings(mcClient, uri, token, region, in, modFuncs...)
}

func TestShowSettings(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.Settings, modFuncs ...func(*edgeproto.Settings)) (*edgeproto.Settings, int, error) {
	dat := &ormapi.RegionSettings{}
	dat.Region = region
	dat.Settings = *in
	for _, fn := range modFuncs {
		fn(&dat.Settings)
	}
	return mcClient.ShowSettings(uri, token, dat)
}
func TestPermShowSettings(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.Settings)) (*edgeproto.Settings, int, error) {
	in := &edgeproto.Settings{}
	return TestShowSettings(mcClient, uri, token, region, in, modFuncs...)
}

func (s *TestClient) UpdateSettings(ctx context.Context, in *edgeproto.Settings) (*edgeproto.Result, error) {
	inR := &ormapi.RegionSettings{
		Region:   s.Region,
		Settings: *in,
	}
	out, status, err := s.McClient.UpdateSettings(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) ResetSettings(ctx context.Context, in *edgeproto.Settings) (*edgeproto.Result, error) {
	inR := &ormapi.RegionSettings{
		Region:   s.Region,
		Settings: *in,
	}
	out, status, err := s.McClient.ResetSettings(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) ShowSettings(ctx context.Context, in *edgeproto.Settings) (*edgeproto.Settings, error) {
	inR := &ormapi.RegionSettings{
		Region:   s.Region,
		Settings: *in,
	}
	out, status, err := s.McClient.ShowSettings(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	if status == 403 {
		err = nil
	}
	return out, err
}
