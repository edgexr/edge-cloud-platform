// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: cloudlet.proto

package testutil

import (
	"context"
	fmt "fmt"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormclient"
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

func TestCreateCloudlet(mcClient *ormclient.Client, uri, token, region string, in *edgeproto.Cloudlet, modFuncs ...func(*edgeproto.Cloudlet)) ([]edgeproto.Result, int, error) {
	dat := &ormapi.RegionCloudlet{}
	dat.Region = region
	dat.Cloudlet = *in
	for _, fn := range modFuncs {
		fn(&dat.Cloudlet)
	}
	return mcClient.CreateCloudlet(uri, token, dat)
}
func TestPermCreateCloudlet(mcClient *ormclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.Cloudlet)) ([]edgeproto.Result, int, error) {
	in := &edgeproto.Cloudlet{}
	in.Key.Organization = org
	return TestCreateCloudlet(mcClient, uri, token, region, in, modFuncs...)
}

func TestDeleteCloudlet(mcClient *ormclient.Client, uri, token, region string, in *edgeproto.Cloudlet, modFuncs ...func(*edgeproto.Cloudlet)) ([]edgeproto.Result, int, error) {
	dat := &ormapi.RegionCloudlet{}
	dat.Region = region
	dat.Cloudlet = *in
	for _, fn := range modFuncs {
		fn(&dat.Cloudlet)
	}
	return mcClient.DeleteCloudlet(uri, token, dat)
}
func TestPermDeleteCloudlet(mcClient *ormclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.Cloudlet)) ([]edgeproto.Result, int, error) {
	in := &edgeproto.Cloudlet{}
	in.Key.Organization = org
	return TestDeleteCloudlet(mcClient, uri, token, region, in, modFuncs...)
}

func TestUpdateCloudlet(mcClient *ormclient.Client, uri, token, region string, in *edgeproto.Cloudlet, modFuncs ...func(*edgeproto.Cloudlet)) ([]edgeproto.Result, int, error) {
	dat := &ormapi.RegionCloudlet{}
	dat.Region = region
	dat.Cloudlet = *in
	for _, fn := range modFuncs {
		fn(&dat.Cloudlet)
	}
	return mcClient.UpdateCloudlet(uri, token, dat)
}
func TestPermUpdateCloudlet(mcClient *ormclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.Cloudlet)) ([]edgeproto.Result, int, error) {
	in := &edgeproto.Cloudlet{}
	in.Key.Organization = org
	return TestUpdateCloudlet(mcClient, uri, token, region, in, modFuncs...)
}

func TestShowCloudlet(mcClient *ormclient.Client, uri, token, region string, in *edgeproto.Cloudlet, modFuncs ...func(*edgeproto.Cloudlet)) ([]edgeproto.Cloudlet, int, error) {
	dat := &ormapi.RegionCloudlet{}
	dat.Region = region
	dat.Cloudlet = *in
	for _, fn := range modFuncs {
		fn(&dat.Cloudlet)
	}
	return mcClient.ShowCloudlet(uri, token, dat)
}
func TestPermShowCloudlet(mcClient *ormclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.Cloudlet)) ([]edgeproto.Cloudlet, int, error) {
	in := &edgeproto.Cloudlet{}
	return TestShowCloudlet(mcClient, uri, token, region, in, modFuncs...)
}

func TestGetCloudletManifest(mcClient *ormclient.Client, uri, token, region string, in *edgeproto.Cloudlet, modFuncs ...func(*edgeproto.Cloudlet)) (*edgeproto.CloudletManifest, int, error) {
	dat := &ormapi.RegionCloudlet{}
	dat.Region = region
	dat.Cloudlet = *in
	for _, fn := range modFuncs {
		fn(&dat.Cloudlet)
	}
	return mcClient.GetCloudletManifest(uri, token, dat)
}
func TestPermGetCloudletManifest(mcClient *ormclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.Cloudlet)) (*edgeproto.CloudletManifest, int, error) {
	in := &edgeproto.Cloudlet{}
	in.Key.Organization = org
	return TestGetCloudletManifest(mcClient, uri, token, region, in, modFuncs...)
}

func TestGetCloudletProps(mcClient *ormclient.Client, uri, token, region string, in *edgeproto.CloudletProps, modFuncs ...func(*edgeproto.CloudletProps)) (*edgeproto.CloudletProps, int, error) {
	dat := &ormapi.RegionCloudletProps{}
	dat.Region = region
	dat.CloudletProps = *in
	for _, fn := range modFuncs {
		fn(&dat.CloudletProps)
	}
	return mcClient.GetCloudletProps(uri, token, dat)
}
func TestPermGetCloudletProps(mcClient *ormclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.CloudletProps)) (*edgeproto.CloudletProps, int, error) {
	in := &edgeproto.CloudletProps{}
	return TestGetCloudletProps(mcClient, uri, token, region, in, modFuncs...)
}

func TestAddCloudletResMapping(mcClient *ormclient.Client, uri, token, region string, in *edgeproto.CloudletResMap, modFuncs ...func(*edgeproto.CloudletResMap)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionCloudletResMap{}
	dat.Region = region
	dat.CloudletResMap = *in
	for _, fn := range modFuncs {
		fn(&dat.CloudletResMap)
	}
	return mcClient.AddCloudletResMapping(uri, token, dat)
}
func TestPermAddCloudletResMapping(mcClient *ormclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.CloudletResMap)) (*edgeproto.Result, int, error) {
	in := &edgeproto.CloudletResMap{}
	in.Key.Organization = org
	return TestAddCloudletResMapping(mcClient, uri, token, region, in, modFuncs...)
}

func TestRemoveCloudletResMapping(mcClient *ormclient.Client, uri, token, region string, in *edgeproto.CloudletResMap, modFuncs ...func(*edgeproto.CloudletResMap)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionCloudletResMap{}
	dat.Region = region
	dat.CloudletResMap = *in
	for _, fn := range modFuncs {
		fn(&dat.CloudletResMap)
	}
	return mcClient.RemoveCloudletResMapping(uri, token, dat)
}
func TestPermRemoveCloudletResMapping(mcClient *ormclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.CloudletResMap)) (*edgeproto.Result, int, error) {
	in := &edgeproto.CloudletResMap{}
	in.Key.Organization = org
	return TestRemoveCloudletResMapping(mcClient, uri, token, region, in, modFuncs...)
}

func TestFindFlavorMatch(mcClient *ormclient.Client, uri, token, region string, in *edgeproto.FlavorMatch, modFuncs ...func(*edgeproto.FlavorMatch)) (*edgeproto.FlavorMatch, int, error) {
	dat := &ormapi.RegionFlavorMatch{}
	dat.Region = region
	dat.FlavorMatch = *in
	for _, fn := range modFuncs {
		fn(&dat.FlavorMatch)
	}
	return mcClient.FindFlavorMatch(uri, token, dat)
}
func TestPermFindFlavorMatch(mcClient *ormclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.FlavorMatch)) (*edgeproto.FlavorMatch, int, error) {
	in := &edgeproto.FlavorMatch{}
	in.Key.Organization = org
	return TestFindFlavorMatch(mcClient, uri, token, region, in, modFuncs...)
}

func TestRevokeAccessKey(mcClient *ormclient.Client, uri, token, region string, in *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.CloudletKey)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionCloudletKey{}
	dat.Region = region
	dat.CloudletKey = *in
	for _, fn := range modFuncs {
		fn(&dat.CloudletKey)
	}
	return mcClient.RevokeAccessKey(uri, token, dat)
}
func TestPermRevokeAccessKey(mcClient *ormclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.CloudletKey)) (*edgeproto.Result, int, error) {
	in := &edgeproto.CloudletKey{}
	in.Organization = org
	return TestRevokeAccessKey(mcClient, uri, token, region, in, modFuncs...)
}

func TestGenerateAccessKey(mcClient *ormclient.Client, uri, token, region string, in *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.CloudletKey)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionCloudletKey{}
	dat.Region = region
	dat.CloudletKey = *in
	for _, fn := range modFuncs {
		fn(&dat.CloudletKey)
	}
	return mcClient.GenerateAccessKey(uri, token, dat)
}
func TestPermGenerateAccessKey(mcClient *ormclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.CloudletKey)) (*edgeproto.Result, int, error) {
	in := &edgeproto.CloudletKey{}
	in.Organization = org
	return TestGenerateAccessKey(mcClient, uri, token, region, in, modFuncs...)
}

func (s *TestClient) CreateCloudlet(ctx context.Context, in *edgeproto.Cloudlet) ([]edgeproto.Result, error) {
	inR := &ormapi.RegionCloudlet{
		Region:   s.Region,
		Cloudlet: *in,
	}
	out, status, err := s.McClient.CreateCloudlet(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) DeleteCloudlet(ctx context.Context, in *edgeproto.Cloudlet) ([]edgeproto.Result, error) {
	inR := &ormapi.RegionCloudlet{
		Region:   s.Region,
		Cloudlet: *in,
	}
	out, status, err := s.McClient.DeleteCloudlet(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) UpdateCloudlet(ctx context.Context, in *edgeproto.Cloudlet) ([]edgeproto.Result, error) {
	inR := &ormapi.RegionCloudlet{
		Region:   s.Region,
		Cloudlet: *in,
	}
	out, status, err := s.McClient.UpdateCloudlet(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) ShowCloudlet(ctx context.Context, in *edgeproto.Cloudlet) ([]edgeproto.Cloudlet, error) {
	inR := &ormapi.RegionCloudlet{
		Region:   s.Region,
		Cloudlet: *in,
	}
	out, status, err := s.McClient.ShowCloudlet(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) GetCloudletManifest(ctx context.Context, in *edgeproto.Cloudlet) (*edgeproto.CloudletManifest, error) {
	inR := &ormapi.RegionCloudlet{
		Region:   s.Region,
		Cloudlet: *in,
	}
	out, status, err := s.McClient.GetCloudletManifest(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) RevokeAccessKey(ctx context.Context, in *edgeproto.CloudletKey) (*edgeproto.Result, error) {
	inR := &ormapi.RegionCloudletKey{
		Region:      s.Region,
		CloudletKey: *in,
	}
	out, status, err := s.McClient.RevokeAccessKey(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) GenerateAccessKey(ctx context.Context, in *edgeproto.CloudletKey) (*edgeproto.Result, error) {
	inR := &ormapi.RegionCloudletKey{
		Region:      s.Region,
		CloudletKey: *in,
	}
	out, status, err := s.McClient.GenerateAccessKey(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) GetCloudletProps(ctx context.Context, in *edgeproto.CloudletProps) (*edgeproto.CloudletProps, error) {
	inR := &ormapi.RegionCloudletProps{
		Region:        s.Region,
		CloudletProps: *in,
	}
	out, status, err := s.McClient.GetCloudletProps(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) AddCloudletResMapping(ctx context.Context, in *edgeproto.CloudletResMap) (*edgeproto.Result, error) {
	inR := &ormapi.RegionCloudletResMap{
		Region:         s.Region,
		CloudletResMap: *in,
	}
	out, status, err := s.McClient.AddCloudletResMapping(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) RemoveCloudletResMapping(ctx context.Context, in *edgeproto.CloudletResMap) (*edgeproto.Result, error) {
	inR := &ormapi.RegionCloudletResMap{
		Region:         s.Region,
		CloudletResMap: *in,
	}
	out, status, err := s.McClient.RemoveCloudletResMapping(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) FindFlavorMatch(ctx context.Context, in *edgeproto.FlavorMatch) (*edgeproto.FlavorMatch, error) {
	inR := &ormapi.RegionFlavorMatch{
		Region:      s.Region,
		FlavorMatch: *in,
	}
	out, status, err := s.McClient.FindFlavorMatch(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func TestShowCloudletInfo(mcClient *ormclient.Client, uri, token, region string, in *edgeproto.CloudletInfo, modFuncs ...func(*edgeproto.CloudletInfo)) ([]edgeproto.CloudletInfo, int, error) {
	dat := &ormapi.RegionCloudletInfo{}
	dat.Region = region
	dat.CloudletInfo = *in
	for _, fn := range modFuncs {
		fn(&dat.CloudletInfo)
	}
	return mcClient.ShowCloudletInfo(uri, token, dat)
}
func TestPermShowCloudletInfo(mcClient *ormclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.CloudletInfo)) ([]edgeproto.CloudletInfo, int, error) {
	in := &edgeproto.CloudletInfo{}
	in.Key.Organization = org
	return TestShowCloudletInfo(mcClient, uri, token, region, in, modFuncs...)
}

func TestInjectCloudletInfo(mcClient *ormclient.Client, uri, token, region string, in *edgeproto.CloudletInfo, modFuncs ...func(*edgeproto.CloudletInfo)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionCloudletInfo{}
	dat.Region = region
	dat.CloudletInfo = *in
	for _, fn := range modFuncs {
		fn(&dat.CloudletInfo)
	}
	return mcClient.InjectCloudletInfo(uri, token, dat)
}
func TestPermInjectCloudletInfo(mcClient *ormclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.CloudletInfo)) (*edgeproto.Result, int, error) {
	in := &edgeproto.CloudletInfo{}
	in.Key.Organization = org
	return TestInjectCloudletInfo(mcClient, uri, token, region, in, modFuncs...)
}

func TestEvictCloudletInfo(mcClient *ormclient.Client, uri, token, region string, in *edgeproto.CloudletInfo, modFuncs ...func(*edgeproto.CloudletInfo)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionCloudletInfo{}
	dat.Region = region
	dat.CloudletInfo = *in
	for _, fn := range modFuncs {
		fn(&dat.CloudletInfo)
	}
	return mcClient.EvictCloudletInfo(uri, token, dat)
}
func TestPermEvictCloudletInfo(mcClient *ormclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.CloudletInfo)) (*edgeproto.Result, int, error) {
	in := &edgeproto.CloudletInfo{}
	in.Key.Organization = org
	return TestEvictCloudletInfo(mcClient, uri, token, region, in, modFuncs...)
}

func (s *TestClient) ShowCloudletInfo(ctx context.Context, in *edgeproto.CloudletInfo) ([]edgeproto.CloudletInfo, error) {
	inR := &ormapi.RegionCloudletInfo{
		Region:       s.Region,
		CloudletInfo: *in,
	}
	out, status, err := s.McClient.ShowCloudletInfo(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) InjectCloudletInfo(ctx context.Context, in *edgeproto.CloudletInfo) (*edgeproto.Result, error) {
	inR := &ormapi.RegionCloudletInfo{
		Region:       s.Region,
		CloudletInfo: *in,
	}
	out, status, err := s.McClient.InjectCloudletInfo(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) EvictCloudletInfo(ctx context.Context, in *edgeproto.CloudletInfo) (*edgeproto.Result, error) {
	inR := &ormapi.RegionCloudletInfo{
		Region:       s.Region,
		CloudletInfo: *in,
	}
	out, status, err := s.McClient.EvictCloudletInfo(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) ShowCloudletMetrics(ctx context.Context, in *edgeproto.CloudletMetrics) ([]edgeproto.CloudletMetrics, error) {
	return nil, nil
}
