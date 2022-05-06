// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: stream.proto

package testutil

import (
	"context"
	fmt "fmt"
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

func TestStreamAppInst(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.AppInstKey, modFuncs ...func(*edgeproto.AppInstKey)) ([]edgeproto.Result, int, error) {
	dat := &ormapi.RegionAppInstKey{}
	dat.Region = region
	dat.AppInstKey = *in
	for _, fn := range modFuncs {
		fn(&dat.AppInstKey)
	}
	return mcClient.StreamAppInst(uri, token, dat)
}
func TestPermStreamAppInst(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.AppInstKey)) ([]edgeproto.Result, int, error) {
	in := &edgeproto.AppInstKey{}
	in.AppKey.Organization = org
	return TestStreamAppInst(mcClient, uri, token, region, in, modFuncs...)
}

func TestStreamClusterInst(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.ClusterInstKey, modFuncs ...func(*edgeproto.ClusterInstKey)) ([]edgeproto.Result, int, error) {
	dat := &ormapi.RegionClusterInstKey{}
	dat.Region = region
	dat.ClusterInstKey = *in
	for _, fn := range modFuncs {
		fn(&dat.ClusterInstKey)
	}
	return mcClient.StreamClusterInst(uri, token, dat)
}
func TestPermStreamClusterInst(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.ClusterInstKey)) ([]edgeproto.Result, int, error) {
	in := &edgeproto.ClusterInstKey{}
	in.Organization = org
	return TestStreamClusterInst(mcClient, uri, token, region, in, modFuncs...)
}

func TestStreamCloudlet(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.CloudletKey)) ([]edgeproto.Result, int, error) {
	dat := &ormapi.RegionCloudletKey{}
	dat.Region = region
	dat.CloudletKey = *in
	for _, fn := range modFuncs {
		fn(&dat.CloudletKey)
	}
	return mcClient.StreamCloudlet(uri, token, dat)
}
func TestPermStreamCloudlet(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.CloudletKey)) ([]edgeproto.Result, int, error) {
	in := &edgeproto.CloudletKey{}
	in.Organization = org
	return TestStreamCloudlet(mcClient, uri, token, region, in, modFuncs...)
}

func TestStreamGPUDriver(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.GPUDriverKey, modFuncs ...func(*edgeproto.GPUDriverKey)) ([]edgeproto.Result, int, error) {
	dat := &ormapi.RegionGPUDriverKey{}
	dat.Region = region
	dat.GPUDriverKey = *in
	for _, fn := range modFuncs {
		fn(&dat.GPUDriverKey)
	}
	return mcClient.StreamGPUDriver(uri, token, dat)
}
func TestPermStreamGPUDriver(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.GPUDriverKey)) ([]edgeproto.Result, int, error) {
	in := &edgeproto.GPUDriverKey{}
	in.Organization = org
	return TestStreamGPUDriver(mcClient, uri, token, region, in, modFuncs...)
}

func (s *TestClient) StreamAppInst(ctx context.Context, in *edgeproto.AppInstKey) ([]edgeproto.Result, error) {
	inR := &ormapi.RegionAppInstKey{
		Region:     s.Region,
		AppInstKey: *in,
	}
	out, status, err := s.McClient.StreamAppInst(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) StreamCloudlet(ctx context.Context, in *edgeproto.CloudletKey) ([]edgeproto.Result, error) {
	inR := &ormapi.RegionCloudletKey{
		Region:      s.Region,
		CloudletKey: *in,
	}
	out, status, err := s.McClient.StreamCloudlet(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) StreamClusterInst(ctx context.Context, in *edgeproto.ClusterInstKey) ([]edgeproto.Result, error) {
	inR := &ormapi.RegionClusterInstKey{
		Region:         s.Region,
		ClusterInstKey: *in,
	}
	out, status, err := s.McClient.StreamClusterInst(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) StreamGPUDriver(ctx context.Context, in *edgeproto.GPUDriverKey) ([]edgeproto.Result, error) {
	inR := &ormapi.RegionGPUDriverKey{
		Region:       s.Region,
		GPUDriverKey: *in,
	}
	out, status, err := s.McClient.StreamGPUDriver(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}
