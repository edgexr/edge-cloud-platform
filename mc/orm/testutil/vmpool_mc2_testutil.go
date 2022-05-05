// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: vmpool.proto

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
	_ "github.com/gogo/protobuf/types"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

func TestCreateVMPool(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.VMPool, modFuncs ...func(*edgeproto.VMPool)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionVMPool{}
	dat.Region = region
	dat.VMPool = *in
	for _, fn := range modFuncs {
		fn(&dat.VMPool)
	}
	return mcClient.CreateVMPool(uri, token, dat)
}
func TestPermCreateVMPool(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.VMPool)) (*edgeproto.Result, int, error) {
	in := &edgeproto.VMPool{}
	in.Key.Organization = org
	return TestCreateVMPool(mcClient, uri, token, region, in, modFuncs...)
}

func TestDeleteVMPool(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.VMPool, modFuncs ...func(*edgeproto.VMPool)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionVMPool{}
	dat.Region = region
	dat.VMPool = *in
	for _, fn := range modFuncs {
		fn(&dat.VMPool)
	}
	return mcClient.DeleteVMPool(uri, token, dat)
}
func TestPermDeleteVMPool(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.VMPool)) (*edgeproto.Result, int, error) {
	in := &edgeproto.VMPool{}
	in.Key.Organization = org
	return TestDeleteVMPool(mcClient, uri, token, region, in, modFuncs...)
}

func TestUpdateVMPool(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.VMPool, modFuncs ...func(*edgeproto.VMPool)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionVMPool{}
	dat.Region = region
	dat.VMPool = *in
	for _, fn := range modFuncs {
		fn(&dat.VMPool)
	}
	return mcClient.UpdateVMPool(uri, token, dat)
}
func TestPermUpdateVMPool(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.VMPool)) (*edgeproto.Result, int, error) {
	in := &edgeproto.VMPool{}
	in.Key.Organization = org
	in.Fields = append(in.Fields, edgeproto.VMPoolFieldKeyOrganization)
	return TestUpdateVMPool(mcClient, uri, token, region, in, modFuncs...)
}

func TestShowVMPool(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.VMPool, modFuncs ...func(*edgeproto.VMPool)) ([]edgeproto.VMPool, int, error) {
	dat := &ormapi.RegionVMPool{}
	dat.Region = region
	dat.VMPool = *in
	for _, fn := range modFuncs {
		fn(&dat.VMPool)
	}
	return mcClient.ShowVMPool(uri, token, dat)
}
func TestPermShowVMPool(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.VMPool)) ([]edgeproto.VMPool, int, error) {
	in := &edgeproto.VMPool{}
	in.Key.Organization = org
	return TestShowVMPool(mcClient, uri, token, region, in, modFuncs...)
}

func TestAddVMPoolMember(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.VMPoolMember, modFuncs ...func(*edgeproto.VMPoolMember)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionVMPoolMember{}
	dat.Region = region
	dat.VMPoolMember = *in
	for _, fn := range modFuncs {
		fn(&dat.VMPoolMember)
	}
	return mcClient.AddVMPoolMember(uri, token, dat)
}
func TestPermAddVMPoolMember(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.VMPoolMember)) (*edgeproto.Result, int, error) {
	in := &edgeproto.VMPoolMember{}
	in.Key.Organization = org
	return TestAddVMPoolMember(mcClient, uri, token, region, in, modFuncs...)
}

func TestRemoveVMPoolMember(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.VMPoolMember, modFuncs ...func(*edgeproto.VMPoolMember)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionVMPoolMember{}
	dat.Region = region
	dat.VMPoolMember = *in
	for _, fn := range modFuncs {
		fn(&dat.VMPoolMember)
	}
	return mcClient.RemoveVMPoolMember(uri, token, dat)
}
func TestPermRemoveVMPoolMember(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.VMPoolMember)) (*edgeproto.Result, int, error) {
	in := &edgeproto.VMPoolMember{}
	in.Key.Organization = org
	return TestRemoveVMPoolMember(mcClient, uri, token, region, in, modFuncs...)
}

func (s *TestClient) CreateVMPool(ctx context.Context, in *edgeproto.VMPool) (*edgeproto.Result, error) {
	inR := &ormapi.RegionVMPool{
		Region: s.Region,
		VMPool: *in,
	}
	out, status, err := s.McClient.CreateVMPool(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) DeleteVMPool(ctx context.Context, in *edgeproto.VMPool) (*edgeproto.Result, error) {
	inR := &ormapi.RegionVMPool{
		Region: s.Region,
		VMPool: *in,
	}
	out, status, err := s.McClient.DeleteVMPool(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) UpdateVMPool(ctx context.Context, in *edgeproto.VMPool) (*edgeproto.Result, error) {
	inR := &ormapi.RegionVMPool{
		Region: s.Region,
		VMPool: *in,
	}
	out, status, err := s.McClient.UpdateVMPool(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) ShowVMPool(ctx context.Context, in *edgeproto.VMPool) ([]edgeproto.VMPool, error) {
	inR := &ormapi.RegionVMPool{
		Region: s.Region,
		VMPool: *in,
	}
	out, status, err := s.McClient.ShowVMPool(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) AddVMPoolMember(ctx context.Context, in *edgeproto.VMPoolMember) (*edgeproto.Result, error) {
	inR := &ormapi.RegionVMPoolMember{
		Region:       s.Region,
		VMPoolMember: *in,
	}
	out, status, err := s.McClient.AddVMPoolMember(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) RemoveVMPoolMember(ctx context.Context, in *edgeproto.VMPoolMember) (*edgeproto.Result, error) {
	inR := &ormapi.RegionVMPoolMember{
		Region:       s.Region,
		VMPoolMember: *in,
	}
	out, status, err := s.McClient.RemoveVMPoolMember(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}
