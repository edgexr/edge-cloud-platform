// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: app.proto

package testutil

import (
	"context"
	fmt "fmt"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	"github.com/mobiledgex/edge-cloud-infra/mc/mcctl/mctestclient"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	_ "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
	edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
	_ "github.com/mobiledgex/edge-cloud/protogen"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

func TestCreateApp(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.App, modFuncs ...func(*edgeproto.App)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionApp{}
	dat.Region = region
	dat.App = *in
	for _, fn := range modFuncs {
		fn(&dat.App)
	}
	return mcClient.CreateApp(uri, token, dat)
}
func TestPermCreateApp(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.App)) (*edgeproto.Result, int, error) {
	in := &edgeproto.App{}
	in.Key.Organization = org
	return TestCreateApp(mcClient, uri, token, region, in, modFuncs...)
}

func TestDeleteApp(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.App, modFuncs ...func(*edgeproto.App)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionApp{}
	dat.Region = region
	dat.App = *in
	for _, fn := range modFuncs {
		fn(&dat.App)
	}
	return mcClient.DeleteApp(uri, token, dat)
}
func TestPermDeleteApp(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.App)) (*edgeproto.Result, int, error) {
	in := &edgeproto.App{}
	in.Key.Organization = org
	return TestDeleteApp(mcClient, uri, token, region, in, modFuncs...)
}

func TestUpdateApp(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.App, modFuncs ...func(*edgeproto.App)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionApp{}
	dat.Region = region
	dat.App = *in
	for _, fn := range modFuncs {
		fn(&dat.App)
	}
	return mcClient.UpdateApp(uri, token, dat)
}
func TestPermUpdateApp(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.App)) (*edgeproto.Result, int, error) {
	in := &edgeproto.App{}
	in.Key.Organization = org
	in.Fields = append(in.Fields, edgeproto.AppFieldKeyOrganization)
	return TestUpdateApp(mcClient, uri, token, region, in, modFuncs...)
}

func TestShowApp(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.App, modFuncs ...func(*edgeproto.App)) ([]edgeproto.App, int, error) {
	dat := &ormapi.RegionApp{}
	dat.Region = region
	dat.App = *in
	for _, fn := range modFuncs {
		fn(&dat.App)
	}
	return mcClient.ShowApp(uri, token, dat)
}
func TestPermShowApp(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.App)) ([]edgeproto.App, int, error) {
	in := &edgeproto.App{}
	in.Key.Organization = org
	return TestShowApp(mcClient, uri, token, region, in, modFuncs...)
}

func TestAddAppAutoProvPolicy(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.AppAutoProvPolicy, modFuncs ...func(*edgeproto.AppAutoProvPolicy)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionAppAutoProvPolicy{}
	dat.Region = region
	dat.AppAutoProvPolicy = *in
	for _, fn := range modFuncs {
		fn(&dat.AppAutoProvPolicy)
	}
	return mcClient.AddAppAutoProvPolicy(uri, token, dat)
}
func TestPermAddAppAutoProvPolicy(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.AppAutoProvPolicy)) (*edgeproto.Result, int, error) {
	in := &edgeproto.AppAutoProvPolicy{}
	in.AppKey.Organization = org
	return TestAddAppAutoProvPolicy(mcClient, uri, token, region, in, modFuncs...)
}

func TestRemoveAppAutoProvPolicy(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.AppAutoProvPolicy, modFuncs ...func(*edgeproto.AppAutoProvPolicy)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionAppAutoProvPolicy{}
	dat.Region = region
	dat.AppAutoProvPolicy = *in
	for _, fn := range modFuncs {
		fn(&dat.AppAutoProvPolicy)
	}
	return mcClient.RemoveAppAutoProvPolicy(uri, token, dat)
}
func TestPermRemoveAppAutoProvPolicy(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.AppAutoProvPolicy)) (*edgeproto.Result, int, error) {
	in := &edgeproto.AppAutoProvPolicy{}
	in.AppKey.Organization = org
	return TestRemoveAppAutoProvPolicy(mcClient, uri, token, region, in, modFuncs...)
}

func TestAddAppAlertPolicy(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.AppAlertPolicy, modFuncs ...func(*edgeproto.AppAlertPolicy)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionAppAlertPolicy{}
	dat.Region = region
	dat.AppAlertPolicy = *in
	for _, fn := range modFuncs {
		fn(&dat.AppAlertPolicy)
	}
	return mcClient.AddAppAlertPolicy(uri, token, dat)
}
func TestPermAddAppAlertPolicy(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.AppAlertPolicy)) (*edgeproto.Result, int, error) {
	in := &edgeproto.AppAlertPolicy{}
	in.AppKey.Organization = org
	return TestAddAppAlertPolicy(mcClient, uri, token, region, in, modFuncs...)
}

func TestRemoveAppAlertPolicy(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.AppAlertPolicy, modFuncs ...func(*edgeproto.AppAlertPolicy)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionAppAlertPolicy{}
	dat.Region = region
	dat.AppAlertPolicy = *in
	for _, fn := range modFuncs {
		fn(&dat.AppAlertPolicy)
	}
	return mcClient.RemoveAppAlertPolicy(uri, token, dat)
}
func TestPermRemoveAppAlertPolicy(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.AppAlertPolicy)) (*edgeproto.Result, int, error) {
	in := &edgeproto.AppAlertPolicy{}
	in.AppKey.Organization = org
	return TestRemoveAppAlertPolicy(mcClient, uri, token, region, in, modFuncs...)
}

func TestShowCloudletsForAppDeployment(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.DeploymentCloudletRequest, modFuncs ...func(*edgeproto.DeploymentCloudletRequest)) ([]edgeproto.CloudletKey, int, error) {
	dat := &ormapi.RegionDeploymentCloudletRequest{}
	dat.Region = region
	dat.DeploymentCloudletRequest = *in
	for _, fn := range modFuncs {
		fn(&dat.DeploymentCloudletRequest)
	}
	return mcClient.ShowCloudletsForAppDeployment(uri, token, dat)
}
func TestPermShowCloudletsForAppDeployment(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.DeploymentCloudletRequest)) ([]edgeproto.CloudletKey, int, error) {
	in := &edgeproto.DeploymentCloudletRequest{}
	return TestShowCloudletsForAppDeployment(mcClient, uri, token, region, in, modFuncs...)
}

func (s *TestClient) CreateApp(ctx context.Context, in *edgeproto.App) (*edgeproto.Result, error) {
	inR := &ormapi.RegionApp{
		Region: s.Region,
		App:    *in,
	}
	out, status, err := s.McClient.CreateApp(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) DeleteApp(ctx context.Context, in *edgeproto.App) (*edgeproto.Result, error) {
	inR := &ormapi.RegionApp{
		Region: s.Region,
		App:    *in,
	}
	out, status, err := s.McClient.DeleteApp(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) UpdateApp(ctx context.Context, in *edgeproto.App) (*edgeproto.Result, error) {
	inR := &ormapi.RegionApp{
		Region: s.Region,
		App:    *in,
	}
	out, status, err := s.McClient.UpdateApp(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) ShowApp(ctx context.Context, in *edgeproto.App) ([]edgeproto.App, error) {
	inR := &ormapi.RegionApp{
		Region: s.Region,
		App:    *in,
	}
	out, status, err := s.McClient.ShowApp(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) AddAppAlertPolicy(ctx context.Context, in *edgeproto.AppAlertPolicy) (*edgeproto.Result, error) {
	inR := &ormapi.RegionAppAlertPolicy{
		Region:         s.Region,
		AppAlertPolicy: *in,
	}
	out, status, err := s.McClient.AddAppAlertPolicy(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) RemoveAppAlertPolicy(ctx context.Context, in *edgeproto.AppAlertPolicy) (*edgeproto.Result, error) {
	inR := &ormapi.RegionAppAlertPolicy{
		Region:         s.Region,
		AppAlertPolicy: *in,
	}
	out, status, err := s.McClient.RemoveAppAlertPolicy(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) AddAppAutoProvPolicy(ctx context.Context, in *edgeproto.AppAutoProvPolicy) (*edgeproto.Result, error) {
	inR := &ormapi.RegionAppAutoProvPolicy{
		Region:            s.Region,
		AppAutoProvPolicy: *in,
	}
	out, status, err := s.McClient.AddAppAutoProvPolicy(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) RemoveAppAutoProvPolicy(ctx context.Context, in *edgeproto.AppAutoProvPolicy) (*edgeproto.Result, error) {
	inR := &ormapi.RegionAppAutoProvPolicy{
		Region:            s.Region,
		AppAutoProvPolicy: *in,
	}
	out, status, err := s.McClient.RemoveAppAutoProvPolicy(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) ShowCloudletsForAppDeployment(ctx context.Context, in *edgeproto.DeploymentCloudletRequest) ([]edgeproto.CloudletKey, error) {
	inR := &ormapi.RegionDeploymentCloudletRequest{
		Region:                    s.Region,
		DeploymentCloudletRequest: *in,
	}
	out, status, err := s.McClient.ShowCloudletsForAppDeployment(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}
