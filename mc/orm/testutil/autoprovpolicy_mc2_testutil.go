// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: autoprovpolicy.proto

package testutil

import (
	"context"
	fmt "fmt"
	"github.com/edgexr/edge-cloud-infra/mc/mcctl/mctestclient"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	_ "github.com/edgexr/edge-cloud/d-match-engine/dme-proto"
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

func TestCreateAutoProvPolicy(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.AutoProvPolicy, modFuncs ...func(*edgeproto.AutoProvPolicy)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionAutoProvPolicy{}
	dat.Region = region
	dat.AutoProvPolicy = *in
	for _, fn := range modFuncs {
		fn(&dat.AutoProvPolicy)
	}
	return mcClient.CreateAutoProvPolicy(uri, token, dat)
}
func TestPermCreateAutoProvPolicy(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.AutoProvPolicy)) (*edgeproto.Result, int, error) {
	in := &edgeproto.AutoProvPolicy{}
	in.Key.Organization = org
	return TestCreateAutoProvPolicy(mcClient, uri, token, region, in, modFuncs...)
}

func TestDeleteAutoProvPolicy(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.AutoProvPolicy, modFuncs ...func(*edgeproto.AutoProvPolicy)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionAutoProvPolicy{}
	dat.Region = region
	dat.AutoProvPolicy = *in
	for _, fn := range modFuncs {
		fn(&dat.AutoProvPolicy)
	}
	return mcClient.DeleteAutoProvPolicy(uri, token, dat)
}
func TestPermDeleteAutoProvPolicy(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.AutoProvPolicy)) (*edgeproto.Result, int, error) {
	in := &edgeproto.AutoProvPolicy{}
	in.Key.Organization = org
	return TestDeleteAutoProvPolicy(mcClient, uri, token, region, in, modFuncs...)
}

func TestUpdateAutoProvPolicy(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.AutoProvPolicy, modFuncs ...func(*edgeproto.AutoProvPolicy)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionAutoProvPolicy{}
	dat.Region = region
	dat.AutoProvPolicy = *in
	for _, fn := range modFuncs {
		fn(&dat.AutoProvPolicy)
	}
	return mcClient.UpdateAutoProvPolicy(uri, token, dat)
}
func TestPermUpdateAutoProvPolicy(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.AutoProvPolicy)) (*edgeproto.Result, int, error) {
	in := &edgeproto.AutoProvPolicy{}
	in.Key.Organization = org
	in.Fields = append(in.Fields, edgeproto.AutoProvPolicyFieldKeyOrganization)
	return TestUpdateAutoProvPolicy(mcClient, uri, token, region, in, modFuncs...)
}

func TestShowAutoProvPolicy(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.AutoProvPolicy, modFuncs ...func(*edgeproto.AutoProvPolicy)) ([]edgeproto.AutoProvPolicy, int, error) {
	dat := &ormapi.RegionAutoProvPolicy{}
	dat.Region = region
	dat.AutoProvPolicy = *in
	for _, fn := range modFuncs {
		fn(&dat.AutoProvPolicy)
	}
	return mcClient.ShowAutoProvPolicy(uri, token, dat)
}
func TestPermShowAutoProvPolicy(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.AutoProvPolicy)) ([]edgeproto.AutoProvPolicy, int, error) {
	in := &edgeproto.AutoProvPolicy{}
	in.Key.Organization = org
	return TestShowAutoProvPolicy(mcClient, uri, token, region, in, modFuncs...)
}

func TestAddAutoProvPolicyCloudlet(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.AutoProvPolicyCloudlet, modFuncs ...func(*edgeproto.AutoProvPolicyCloudlet)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionAutoProvPolicyCloudlet{}
	dat.Region = region
	dat.AutoProvPolicyCloudlet = *in
	for _, fn := range modFuncs {
		fn(&dat.AutoProvPolicyCloudlet)
	}
	return mcClient.AddAutoProvPolicyCloudlet(uri, token, dat)
}
func TestPermAddAutoProvPolicyCloudlet(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.AutoProvPolicyCloudlet)) (*edgeproto.Result, int, error) {
	in := &edgeproto.AutoProvPolicyCloudlet{}
	in.Key.Organization = org
	return TestAddAutoProvPolicyCloudlet(mcClient, uri, token, region, in, modFuncs...)
}

func TestRemoveAutoProvPolicyCloudlet(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.AutoProvPolicyCloudlet, modFuncs ...func(*edgeproto.AutoProvPolicyCloudlet)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionAutoProvPolicyCloudlet{}
	dat.Region = region
	dat.AutoProvPolicyCloudlet = *in
	for _, fn := range modFuncs {
		fn(&dat.AutoProvPolicyCloudlet)
	}
	return mcClient.RemoveAutoProvPolicyCloudlet(uri, token, dat)
}
func TestPermRemoveAutoProvPolicyCloudlet(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.AutoProvPolicyCloudlet)) (*edgeproto.Result, int, error) {
	in := &edgeproto.AutoProvPolicyCloudlet{}
	in.Key.Organization = org
	return TestRemoveAutoProvPolicyCloudlet(mcClient, uri, token, region, in, modFuncs...)
}

func (s *TestClient) CreateAutoProvPolicy(ctx context.Context, in *edgeproto.AutoProvPolicy) (*edgeproto.Result, error) {
	inR := &ormapi.RegionAutoProvPolicy{
		Region:         s.Region,
		AutoProvPolicy: *in,
	}
	out, status, err := s.McClient.CreateAutoProvPolicy(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) DeleteAutoProvPolicy(ctx context.Context, in *edgeproto.AutoProvPolicy) (*edgeproto.Result, error) {
	inR := &ormapi.RegionAutoProvPolicy{
		Region:         s.Region,
		AutoProvPolicy: *in,
	}
	out, status, err := s.McClient.DeleteAutoProvPolicy(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) UpdateAutoProvPolicy(ctx context.Context, in *edgeproto.AutoProvPolicy) (*edgeproto.Result, error) {
	inR := &ormapi.RegionAutoProvPolicy{
		Region:         s.Region,
		AutoProvPolicy: *in,
	}
	out, status, err := s.McClient.UpdateAutoProvPolicy(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) ShowAutoProvPolicy(ctx context.Context, in *edgeproto.AutoProvPolicy) ([]edgeproto.AutoProvPolicy, error) {
	inR := &ormapi.RegionAutoProvPolicy{
		Region:         s.Region,
		AutoProvPolicy: *in,
	}
	out, status, err := s.McClient.ShowAutoProvPolicy(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) AddAutoProvPolicyCloudlet(ctx context.Context, in *edgeproto.AutoProvPolicyCloudlet) (*edgeproto.Result, error) {
	inR := &ormapi.RegionAutoProvPolicyCloudlet{
		Region:                 s.Region,
		AutoProvPolicyCloudlet: *in,
	}
	out, status, err := s.McClient.AddAutoProvPolicyCloudlet(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) RemoveAutoProvPolicyCloudlet(ctx context.Context, in *edgeproto.AutoProvPolicyCloudlet) (*edgeproto.Result, error) {
	inR := &ormapi.RegionAutoProvPolicyCloudlet{
		Region:                 s.Region,
		AutoProvPolicyCloudlet: *in,
	}
	out, status, err := s.McClient.RemoveAutoProvPolicyCloudlet(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}
