// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: trustpolicy.proto

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

func TestCreateTrustPolicy(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.TrustPolicy, modFuncs ...func(*edgeproto.TrustPolicy)) ([]edgeproto.Result, int, error) {
	dat := &ormapi.RegionTrustPolicy{}
	dat.Region = region
	dat.TrustPolicy = *in
	for _, fn := range modFuncs {
		fn(&dat.TrustPolicy)
	}
	return mcClient.CreateTrustPolicy(uri, token, dat)
}
func TestPermCreateTrustPolicy(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.TrustPolicy)) ([]edgeproto.Result, int, error) {
	in := &edgeproto.TrustPolicy{}
	in.Key.Organization = org
	return TestCreateTrustPolicy(mcClient, uri, token, region, in, modFuncs...)
}

func TestDeleteTrustPolicy(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.TrustPolicy, modFuncs ...func(*edgeproto.TrustPolicy)) ([]edgeproto.Result, int, error) {
	dat := &ormapi.RegionTrustPolicy{}
	dat.Region = region
	dat.TrustPolicy = *in
	for _, fn := range modFuncs {
		fn(&dat.TrustPolicy)
	}
	return mcClient.DeleteTrustPolicy(uri, token, dat)
}
func TestPermDeleteTrustPolicy(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.TrustPolicy)) ([]edgeproto.Result, int, error) {
	in := &edgeproto.TrustPolicy{}
	in.Key.Organization = org
	return TestDeleteTrustPolicy(mcClient, uri, token, region, in, modFuncs...)
}

func TestUpdateTrustPolicy(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.TrustPolicy, modFuncs ...func(*edgeproto.TrustPolicy)) ([]edgeproto.Result, int, error) {
	dat := &ormapi.RegionTrustPolicy{}
	dat.Region = region
	dat.TrustPolicy = *in
	for _, fn := range modFuncs {
		fn(&dat.TrustPolicy)
	}
	return mcClient.UpdateTrustPolicy(uri, token, dat)
}
func TestPermUpdateTrustPolicy(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.TrustPolicy)) ([]edgeproto.Result, int, error) {
	in := &edgeproto.TrustPolicy{}
	in.Key.Organization = org
	in.Fields = append(in.Fields, edgeproto.TrustPolicyFieldKeyOrganization)
	return TestUpdateTrustPolicy(mcClient, uri, token, region, in, modFuncs...)
}

func TestShowTrustPolicy(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.TrustPolicy, modFuncs ...func(*edgeproto.TrustPolicy)) ([]edgeproto.TrustPolicy, int, error) {
	dat := &ormapi.RegionTrustPolicy{}
	dat.Region = region
	dat.TrustPolicy = *in
	for _, fn := range modFuncs {
		fn(&dat.TrustPolicy)
	}
	return mcClient.ShowTrustPolicy(uri, token, dat)
}
func TestPermShowTrustPolicy(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.TrustPolicy)) ([]edgeproto.TrustPolicy, int, error) {
	in := &edgeproto.TrustPolicy{}
	in.Key.Organization = org
	return TestShowTrustPolicy(mcClient, uri, token, region, in, modFuncs...)
}

func (s *TestClient) CreateTrustPolicy(ctx context.Context, in *edgeproto.TrustPolicy) ([]edgeproto.Result, error) {
	inR := &ormapi.RegionTrustPolicy{
		Region:      s.Region,
		TrustPolicy: *in,
	}
	out, status, err := s.McClient.CreateTrustPolicy(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) DeleteTrustPolicy(ctx context.Context, in *edgeproto.TrustPolicy) ([]edgeproto.Result, error) {
	inR := &ormapi.RegionTrustPolicy{
		Region:      s.Region,
		TrustPolicy: *in,
	}
	out, status, err := s.McClient.DeleteTrustPolicy(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) UpdateTrustPolicy(ctx context.Context, in *edgeproto.TrustPolicy) ([]edgeproto.Result, error) {
	inR := &ormapi.RegionTrustPolicy{
		Region:      s.Region,
		TrustPolicy: *in,
	}
	out, status, err := s.McClient.UpdateTrustPolicy(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) ShowTrustPolicy(ctx context.Context, in *edgeproto.TrustPolicy) ([]edgeproto.TrustPolicy, error) {
	inR := &ormapi.RegionTrustPolicy{
		Region:      s.Region,
		TrustPolicy: *in,
	}
	out, status, err := s.McClient.ShowTrustPolicy(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}
