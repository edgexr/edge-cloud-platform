// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: alertpolicy.proto

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

func TestCreateAlertPolicy(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.AlertPolicy, modFuncs ...func(*edgeproto.AlertPolicy)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionAlertPolicy{}
	dat.Region = region
	dat.AlertPolicy = *in
	for _, fn := range modFuncs {
		fn(&dat.AlertPolicy)
	}
	return mcClient.CreateAlertPolicy(uri, token, dat)
}
func TestPermCreateAlertPolicy(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.AlertPolicy)) (*edgeproto.Result, int, error) {
	in := &edgeproto.AlertPolicy{}
	in.Key.Organization = org
	return TestCreateAlertPolicy(mcClient, uri, token, region, in, modFuncs...)
}

func TestDeleteAlertPolicy(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.AlertPolicy, modFuncs ...func(*edgeproto.AlertPolicy)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionAlertPolicy{}
	dat.Region = region
	dat.AlertPolicy = *in
	for _, fn := range modFuncs {
		fn(&dat.AlertPolicy)
	}
	return mcClient.DeleteAlertPolicy(uri, token, dat)
}
func TestPermDeleteAlertPolicy(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.AlertPolicy)) (*edgeproto.Result, int, error) {
	in := &edgeproto.AlertPolicy{}
	in.Key.Organization = org
	return TestDeleteAlertPolicy(mcClient, uri, token, region, in, modFuncs...)
}

func TestUpdateAlertPolicy(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.AlertPolicy, modFuncs ...func(*edgeproto.AlertPolicy)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionAlertPolicy{}
	dat.Region = region
	dat.AlertPolicy = *in
	for _, fn := range modFuncs {
		fn(&dat.AlertPolicy)
	}
	return mcClient.UpdateAlertPolicy(uri, token, dat)
}
func TestPermUpdateAlertPolicy(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.AlertPolicy)) (*edgeproto.Result, int, error) {
	in := &edgeproto.AlertPolicy{}
	in.Key.Organization = org
	in.Fields = append(in.Fields, edgeproto.AlertPolicyFieldKeyOrganization)
	return TestUpdateAlertPolicy(mcClient, uri, token, region, in, modFuncs...)
}

func TestShowAlertPolicy(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.AlertPolicy, modFuncs ...func(*edgeproto.AlertPolicy)) ([]edgeproto.AlertPolicy, int, error) {
	dat := &ormapi.RegionAlertPolicy{}
	dat.Region = region
	dat.AlertPolicy = *in
	for _, fn := range modFuncs {
		fn(&dat.AlertPolicy)
	}
	return mcClient.ShowAlertPolicy(uri, token, dat)
}
func TestPermShowAlertPolicy(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.AlertPolicy)) ([]edgeproto.AlertPolicy, int, error) {
	in := &edgeproto.AlertPolicy{}
	in.Key.Organization = org
	return TestShowAlertPolicy(mcClient, uri, token, region, in, modFuncs...)
}

func (s *TestClient) CreateAlertPolicy(ctx context.Context, in *edgeproto.AlertPolicy) (*edgeproto.Result, error) {
	inR := &ormapi.RegionAlertPolicy{
		Region:      s.Region,
		AlertPolicy: *in,
	}
	out, status, err := s.McClient.CreateAlertPolicy(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) DeleteAlertPolicy(ctx context.Context, in *edgeproto.AlertPolicy) (*edgeproto.Result, error) {
	inR := &ormapi.RegionAlertPolicy{
		Region:      s.Region,
		AlertPolicy: *in,
	}
	out, status, err := s.McClient.DeleteAlertPolicy(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) UpdateAlertPolicy(ctx context.Context, in *edgeproto.AlertPolicy) (*edgeproto.Result, error) {
	inR := &ormapi.RegionAlertPolicy{
		Region:      s.Region,
		AlertPolicy: *in,
	}
	out, status, err := s.McClient.UpdateAlertPolicy(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) ShowAlertPolicy(ctx context.Context, in *edgeproto.AlertPolicy) ([]edgeproto.AlertPolicy, error) {
	inR := &ormapi.RegionAlertPolicy{
		Region:      s.Region,
		AlertPolicy: *in,
	}
	out, status, err := s.McClient.ShowAlertPolicy(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}