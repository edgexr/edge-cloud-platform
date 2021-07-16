// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: useralert.proto

package testutil

import (
	"context"
	fmt "fmt"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	"github.com/mobiledgex/edge-cloud-infra/mc/mcctl/mctestclient"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
	_ "github.com/mobiledgex/edge-cloud/protogen"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

func TestCreateUserAlert(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.UserAlert, modFuncs ...func(*edgeproto.UserAlert)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionUserAlert{}
	dat.Region = region
	dat.UserAlert = *in
	for _, fn := range modFuncs {
		fn(&dat.UserAlert)
	}
	return mcClient.CreateUserAlert(uri, token, dat)
}
func TestPermCreateUserAlert(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.UserAlert)) (*edgeproto.Result, int, error) {
	in := &edgeproto.UserAlert{}
	in.Key.Organization = org
	return TestCreateUserAlert(mcClient, uri, token, region, in, modFuncs...)
}

func TestDeleteUserAlert(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.UserAlert, modFuncs ...func(*edgeproto.UserAlert)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionUserAlert{}
	dat.Region = region
	dat.UserAlert = *in
	for _, fn := range modFuncs {
		fn(&dat.UserAlert)
	}
	return mcClient.DeleteUserAlert(uri, token, dat)
}
func TestPermDeleteUserAlert(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.UserAlert)) (*edgeproto.Result, int, error) {
	in := &edgeproto.UserAlert{}
	in.Key.Organization = org
	return TestDeleteUserAlert(mcClient, uri, token, region, in, modFuncs...)
}

func TestUpdateUserAlert(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.UserAlert, modFuncs ...func(*edgeproto.UserAlert)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionUserAlert{}
	dat.Region = region
	dat.UserAlert = *in
	for _, fn := range modFuncs {
		fn(&dat.UserAlert)
	}
	return mcClient.UpdateUserAlert(uri, token, dat)
}
func TestPermUpdateUserAlert(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.UserAlert)) (*edgeproto.Result, int, error) {
	in := &edgeproto.UserAlert{}
	in.Key.Organization = org
	in.Fields = append(in.Fields, edgeproto.UserAlertFieldKeyOrganization)
	return TestUpdateUserAlert(mcClient, uri, token, region, in, modFuncs...)
}

func TestShowUserAlert(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.UserAlert, modFuncs ...func(*edgeproto.UserAlert)) ([]edgeproto.UserAlert, int, error) {
	dat := &ormapi.RegionUserAlert{}
	dat.Region = region
	dat.UserAlert = *in
	for _, fn := range modFuncs {
		fn(&dat.UserAlert)
	}
	return mcClient.ShowUserAlert(uri, token, dat)
}
func TestPermShowUserAlert(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.UserAlert)) ([]edgeproto.UserAlert, int, error) {
	in := &edgeproto.UserAlert{}
	in.Key.Organization = org
	return TestShowUserAlert(mcClient, uri, token, region, in, modFuncs...)
}

func (s *TestClient) CreateUserAlert(ctx context.Context, in *edgeproto.UserAlert) (*edgeproto.Result, error) {
	inR := &ormapi.RegionUserAlert{
		Region:    s.Region,
		UserAlert: *in,
	}
	out, status, err := s.McClient.CreateUserAlert(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) DeleteUserAlert(ctx context.Context, in *edgeproto.UserAlert) (*edgeproto.Result, error) {
	inR := &ormapi.RegionUserAlert{
		Region:    s.Region,
		UserAlert: *in,
	}
	out, status, err := s.McClient.DeleteUserAlert(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) UpdateUserAlert(ctx context.Context, in *edgeproto.UserAlert) (*edgeproto.Result, error) {
	inR := &ormapi.RegionUserAlert{
		Region:    s.Region,
		UserAlert: *in,
	}
	out, status, err := s.McClient.UpdateUserAlert(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) ShowUserAlert(ctx context.Context, in *edgeproto.UserAlert) ([]edgeproto.UserAlert, error) {
	inR := &ormapi.RegionUserAlert{
		Region:    s.Region,
		UserAlert: *in,
	}
	out, status, err := s.McClient.ShowUserAlert(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}
