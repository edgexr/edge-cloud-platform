// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: autoscalepolicy.proto

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

func TestCreateAutoScalePolicy(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.AutoScalePolicy, modFuncs ...func(*edgeproto.AutoScalePolicy)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionAutoScalePolicy{}
	dat.Region = region
	dat.AutoScalePolicy = *in
	for _, fn := range modFuncs {
		fn(&dat.AutoScalePolicy)
	}
	return mcClient.CreateAutoScalePolicy(uri, token, dat)
}
func TestPermCreateAutoScalePolicy(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.AutoScalePolicy)) (*edgeproto.Result, int, error) {
	in := &edgeproto.AutoScalePolicy{}
	in.Key.Organization = org
	return TestCreateAutoScalePolicy(mcClient, uri, token, region, in, modFuncs...)
}

func TestDeleteAutoScalePolicy(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.AutoScalePolicy, modFuncs ...func(*edgeproto.AutoScalePolicy)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionAutoScalePolicy{}
	dat.Region = region
	dat.AutoScalePolicy = *in
	for _, fn := range modFuncs {
		fn(&dat.AutoScalePolicy)
	}
	return mcClient.DeleteAutoScalePolicy(uri, token, dat)
}
func TestPermDeleteAutoScalePolicy(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.AutoScalePolicy)) (*edgeproto.Result, int, error) {
	in := &edgeproto.AutoScalePolicy{}
	in.Key.Organization = org
	return TestDeleteAutoScalePolicy(mcClient, uri, token, region, in, modFuncs...)
}

func TestUpdateAutoScalePolicy(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.AutoScalePolicy, modFuncs ...func(*edgeproto.AutoScalePolicy)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionAutoScalePolicy{}
	dat.Region = region
	dat.AutoScalePolicy = *in
	for _, fn := range modFuncs {
		fn(&dat.AutoScalePolicy)
	}
	return mcClient.UpdateAutoScalePolicy(uri, token, dat)
}
func TestPermUpdateAutoScalePolicy(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.AutoScalePolicy)) (*edgeproto.Result, int, error) {
	in := &edgeproto.AutoScalePolicy{}
	in.Key.Organization = org
	in.Fields = append(in.Fields, edgeproto.AutoScalePolicyFieldKeyOrganization)
	return TestUpdateAutoScalePolicy(mcClient, uri, token, region, in, modFuncs...)
}

func TestShowAutoScalePolicy(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.AutoScalePolicy, modFuncs ...func(*edgeproto.AutoScalePolicy)) ([]edgeproto.AutoScalePolicy, int, error) {
	dat := &ormapi.RegionAutoScalePolicy{}
	dat.Region = region
	dat.AutoScalePolicy = *in
	for _, fn := range modFuncs {
		fn(&dat.AutoScalePolicy)
	}
	return mcClient.ShowAutoScalePolicy(uri, token, dat)
}
func TestPermShowAutoScalePolicy(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.AutoScalePolicy)) ([]edgeproto.AutoScalePolicy, int, error) {
	in := &edgeproto.AutoScalePolicy{}
	in.Key.Organization = org
	return TestShowAutoScalePolicy(mcClient, uri, token, region, in, modFuncs...)
}

func (s *TestClient) CreateAutoScalePolicy(ctx context.Context, in *edgeproto.AutoScalePolicy) (*edgeproto.Result, error) {
	inR := &ormapi.RegionAutoScalePolicy{
		Region:          s.Region,
		AutoScalePolicy: *in,
	}
	out, status, err := s.McClient.CreateAutoScalePolicy(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) DeleteAutoScalePolicy(ctx context.Context, in *edgeproto.AutoScalePolicy) (*edgeproto.Result, error) {
	inR := &ormapi.RegionAutoScalePolicy{
		Region:          s.Region,
		AutoScalePolicy: *in,
	}
	out, status, err := s.McClient.DeleteAutoScalePolicy(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) UpdateAutoScalePolicy(ctx context.Context, in *edgeproto.AutoScalePolicy) (*edgeproto.Result, error) {
	inR := &ormapi.RegionAutoScalePolicy{
		Region:          s.Region,
		AutoScalePolicy: *in,
	}
	out, status, err := s.McClient.UpdateAutoScalePolicy(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) ShowAutoScalePolicy(ctx context.Context, in *edgeproto.AutoScalePolicy) ([]edgeproto.AutoScalePolicy, error) {
	inR := &ormapi.RegionAutoScalePolicy{
		Region:          s.Region,
		AutoScalePolicy: *in,
	}
	out, status, err := s.McClient.ShowAutoScalePolicy(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}
