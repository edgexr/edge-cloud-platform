// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: cloudlet.proto

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

func TestCreateGPUDriver(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.GPUDriver, modFuncs ...func(*edgeproto.GPUDriver)) ([]edgeproto.Result, int, error) {
	dat := &ormapi.RegionGPUDriver{}
	dat.Region = region
	dat.GPUDriver = *in
	for _, fn := range modFuncs {
		fn(&dat.GPUDriver)
	}
	return mcClient.CreateGPUDriver(uri, token, dat)
}
func TestPermCreateGPUDriver(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.GPUDriver)) ([]edgeproto.Result, int, error) {
	in := &edgeproto.GPUDriver{}
	in.Key.Organization = org
	return TestCreateGPUDriver(mcClient, uri, token, region, in, modFuncs...)
}

func TestDeleteGPUDriver(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.GPUDriver, modFuncs ...func(*edgeproto.GPUDriver)) ([]edgeproto.Result, int, error) {
	dat := &ormapi.RegionGPUDriver{}
	dat.Region = region
	dat.GPUDriver = *in
	for _, fn := range modFuncs {
		fn(&dat.GPUDriver)
	}
	return mcClient.DeleteGPUDriver(uri, token, dat)
}
func TestPermDeleteGPUDriver(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.GPUDriver)) ([]edgeproto.Result, int, error) {
	in := &edgeproto.GPUDriver{}
	in.Key.Organization = org
	return TestDeleteGPUDriver(mcClient, uri, token, region, in, modFuncs...)
}

func TestUpdateGPUDriver(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.GPUDriver, modFuncs ...func(*edgeproto.GPUDriver)) ([]edgeproto.Result, int, error) {
	dat := &ormapi.RegionGPUDriver{}
	dat.Region = region
	dat.GPUDriver = *in
	for _, fn := range modFuncs {
		fn(&dat.GPUDriver)
	}
	return mcClient.UpdateGPUDriver(uri, token, dat)
}
func TestPermUpdateGPUDriver(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.GPUDriver)) ([]edgeproto.Result, int, error) {
	in := &edgeproto.GPUDriver{}
	in.Key.Organization = org
	return TestUpdateGPUDriver(mcClient, uri, token, region, in, modFuncs...)
}

func TestShowGPUDriver(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.GPUDriver, modFuncs ...func(*edgeproto.GPUDriver)) ([]edgeproto.GPUDriver, int, error) {
	dat := &ormapi.RegionGPUDriver{}
	dat.Region = region
	dat.GPUDriver = *in
	for _, fn := range modFuncs {
		fn(&dat.GPUDriver)
	}
	return mcClient.ShowGPUDriver(uri, token, dat)
}
func TestPermShowGPUDriver(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.GPUDriver)) ([]edgeproto.GPUDriver, int, error) {
	in := &edgeproto.GPUDriver{}
	in.Key.Organization = org
	return TestShowGPUDriver(mcClient, uri, token, region, in, modFuncs...)
}

func TestAddGPUDriverBuild(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.GPUDriverBuildMember, modFuncs ...func(*edgeproto.GPUDriverBuildMember)) ([]edgeproto.Result, int, error) {
	dat := &ormapi.RegionGPUDriverBuildMember{}
	dat.Region = region
	dat.GPUDriverBuildMember = *in
	for _, fn := range modFuncs {
		fn(&dat.GPUDriverBuildMember)
	}
	return mcClient.AddGPUDriverBuild(uri, token, dat)
}
func TestPermAddGPUDriverBuild(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.GPUDriverBuildMember)) ([]edgeproto.Result, int, error) {
	in := &edgeproto.GPUDriverBuildMember{}
	in.Key.Organization = org
	return TestAddGPUDriverBuild(mcClient, uri, token, region, in, modFuncs...)
}

func TestRemoveGPUDriverBuild(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.GPUDriverBuildMember, modFuncs ...func(*edgeproto.GPUDriverBuildMember)) ([]edgeproto.Result, int, error) {
	dat := &ormapi.RegionGPUDriverBuildMember{}
	dat.Region = region
	dat.GPUDriverBuildMember = *in
	for _, fn := range modFuncs {
		fn(&dat.GPUDriverBuildMember)
	}
	return mcClient.RemoveGPUDriverBuild(uri, token, dat)
}
func TestPermRemoveGPUDriverBuild(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.GPUDriverBuildMember)) ([]edgeproto.Result, int, error) {
	in := &edgeproto.GPUDriverBuildMember{}
	in.Key.Organization = org
	return TestRemoveGPUDriverBuild(mcClient, uri, token, region, in, modFuncs...)
}

func TestGetGPUDriverBuildURL(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.GPUDriverBuildMember, modFuncs ...func(*edgeproto.GPUDriverBuildMember)) (*edgeproto.GPUDriverBuildURL, int, error) {
	dat := &ormapi.RegionGPUDriverBuildMember{}
	dat.Region = region
	dat.GPUDriverBuildMember = *in
	for _, fn := range modFuncs {
		fn(&dat.GPUDriverBuildMember)
	}
	return mcClient.GetGPUDriverBuildURL(uri, token, dat)
}
func TestPermGetGPUDriverBuildURL(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.GPUDriverBuildMember)) (*edgeproto.GPUDriverBuildURL, int, error) {
	in := &edgeproto.GPUDriverBuildMember{}
	in.Key.Organization = org
	return TestGetGPUDriverBuildURL(mcClient, uri, token, region, in, modFuncs...)
}

func (s *TestClient) CreateGPUDriver(ctx context.Context, in *edgeproto.GPUDriver) ([]edgeproto.Result, error) {
	inR := &ormapi.RegionGPUDriver{
		Region:    s.Region,
		GPUDriver: *in,
	}
	out, status, err := s.McClient.CreateGPUDriver(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) DeleteGPUDriver(ctx context.Context, in *edgeproto.GPUDriver) ([]edgeproto.Result, error) {
	inR := &ormapi.RegionGPUDriver{
		Region:    s.Region,
		GPUDriver: *in,
	}
	out, status, err := s.McClient.DeleteGPUDriver(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) UpdateGPUDriver(ctx context.Context, in *edgeproto.GPUDriver) ([]edgeproto.Result, error) {
	inR := &ormapi.RegionGPUDriver{
		Region:    s.Region,
		GPUDriver: *in,
	}
	out, status, err := s.McClient.UpdateGPUDriver(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) ShowGPUDriver(ctx context.Context, in *edgeproto.GPUDriver) ([]edgeproto.GPUDriver, error) {
	inR := &ormapi.RegionGPUDriver{
		Region:    s.Region,
		GPUDriver: *in,
	}
	out, status, err := s.McClient.ShowGPUDriver(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) AddGPUDriverBuild(ctx context.Context, in *edgeproto.GPUDriverBuildMember) ([]edgeproto.Result, error) {
	inR := &ormapi.RegionGPUDriverBuildMember{
		Region:               s.Region,
		GPUDriverBuildMember: *in,
	}
	out, status, err := s.McClient.AddGPUDriverBuild(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) RemoveGPUDriverBuild(ctx context.Context, in *edgeproto.GPUDriverBuildMember) ([]edgeproto.Result, error) {
	inR := &ormapi.RegionGPUDriverBuildMember{
		Region:               s.Region,
		GPUDriverBuildMember: *in,
	}
	out, status, err := s.McClient.RemoveGPUDriverBuild(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) GetGPUDriverBuildURL(ctx context.Context, in *edgeproto.GPUDriverBuildMember) (*edgeproto.GPUDriverBuildURL, error) {
	inR := &ormapi.RegionGPUDriverBuildMember{
		Region:               s.Region,
		GPUDriverBuildMember: *in,
	}
	out, status, err := s.McClient.GetGPUDriverBuildURL(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func TestCreateCloudlet(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.Cloudlet, modFuncs ...func(*edgeproto.Cloudlet)) ([]edgeproto.Result, int, error) {
	dat := &ormapi.RegionCloudlet{}
	dat.Region = region
	dat.Cloudlet = *in
	for _, fn := range modFuncs {
		fn(&dat.Cloudlet)
	}
	return mcClient.CreateCloudlet(uri, token, dat)
}
func TestPermCreateCloudlet(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.Cloudlet)) ([]edgeproto.Result, int, error) {
	in := &edgeproto.Cloudlet{}
	in.Key.Organization = org
	return TestCreateCloudlet(mcClient, uri, token, region, in, modFuncs...)
}

func TestDeleteCloudlet(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.Cloudlet, modFuncs ...func(*edgeproto.Cloudlet)) ([]edgeproto.Result, int, error) {
	dat := &ormapi.RegionCloudlet{}
	dat.Region = region
	dat.Cloudlet = *in
	for _, fn := range modFuncs {
		fn(&dat.Cloudlet)
	}
	return mcClient.DeleteCloudlet(uri, token, dat)
}
func TestPermDeleteCloudlet(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.Cloudlet)) ([]edgeproto.Result, int, error) {
	in := &edgeproto.Cloudlet{}
	in.Key.Organization = org
	return TestDeleteCloudlet(mcClient, uri, token, region, in, modFuncs...)
}

func TestUpdateCloudlet(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.Cloudlet, modFuncs ...func(*edgeproto.Cloudlet)) ([]edgeproto.Result, int, error) {
	dat := &ormapi.RegionCloudlet{}
	dat.Region = region
	dat.Cloudlet = *in
	for _, fn := range modFuncs {
		fn(&dat.Cloudlet)
	}
	return mcClient.UpdateCloudlet(uri, token, dat)
}
func TestPermUpdateCloudlet(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.Cloudlet)) ([]edgeproto.Result, int, error) {
	in := &edgeproto.Cloudlet{}
	in.Key.Organization = org
	return TestUpdateCloudlet(mcClient, uri, token, region, in, modFuncs...)
}

func TestShowCloudlet(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.Cloudlet, modFuncs ...func(*edgeproto.Cloudlet)) ([]edgeproto.Cloudlet, int, error) {
	dat := &ormapi.RegionCloudlet{}
	dat.Region = region
	dat.Cloudlet = *in
	for _, fn := range modFuncs {
		fn(&dat.Cloudlet)
	}
	return mcClient.ShowCloudlet(uri, token, dat)
}
func TestPermShowCloudlet(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.Cloudlet)) ([]edgeproto.Cloudlet, int, error) {
	in := &edgeproto.Cloudlet{}
	return TestShowCloudlet(mcClient, uri, token, region, in, modFuncs...)
}

func TestGetCloudletManifest(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.CloudletKey)) (*edgeproto.CloudletManifest, int, error) {
	dat := &ormapi.RegionCloudletKey{}
	dat.Region = region
	dat.CloudletKey = *in
	for _, fn := range modFuncs {
		fn(&dat.CloudletKey)
	}
	return mcClient.GetCloudletManifest(uri, token, dat)
}
func TestPermGetCloudletManifest(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.CloudletKey)) (*edgeproto.CloudletManifest, int, error) {
	in := &edgeproto.CloudletKey{}
	in.Organization = org
	return TestGetCloudletManifest(mcClient, uri, token, region, in, modFuncs...)
}

func TestGetCloudletProps(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.CloudletProps, modFuncs ...func(*edgeproto.CloudletProps)) (*edgeproto.CloudletProps, int, error) {
	dat := &ormapi.RegionCloudletProps{}
	dat.Region = region
	dat.CloudletProps = *in
	for _, fn := range modFuncs {
		fn(&dat.CloudletProps)
	}
	return mcClient.GetCloudletProps(uri, token, dat)
}
func TestPermGetCloudletProps(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.CloudletProps)) (*edgeproto.CloudletProps, int, error) {
	in := &edgeproto.CloudletProps{}
	in.Organization = org
	return TestGetCloudletProps(mcClient, uri, token, region, in, modFuncs...)
}

func TestGetCloudletResourceQuotaProps(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.CloudletResourceQuotaProps, modFuncs ...func(*edgeproto.CloudletResourceQuotaProps)) (*edgeproto.CloudletResourceQuotaProps, int, error) {
	dat := &ormapi.RegionCloudletResourceQuotaProps{}
	dat.Region = region
	dat.CloudletResourceQuotaProps = *in
	for _, fn := range modFuncs {
		fn(&dat.CloudletResourceQuotaProps)
	}
	return mcClient.GetCloudletResourceQuotaProps(uri, token, dat)
}
func TestPermGetCloudletResourceQuotaProps(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.CloudletResourceQuotaProps)) (*edgeproto.CloudletResourceQuotaProps, int, error) {
	in := &edgeproto.CloudletResourceQuotaProps{}
	in.Organization = org
	return TestGetCloudletResourceQuotaProps(mcClient, uri, token, region, in, modFuncs...)
}

func TestGetCloudletResourceUsage(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.CloudletResourceUsage, modFuncs ...func(*edgeproto.CloudletResourceUsage)) (*edgeproto.CloudletResourceUsage, int, error) {
	dat := &ormapi.RegionCloudletResourceUsage{}
	dat.Region = region
	dat.CloudletResourceUsage = *in
	for _, fn := range modFuncs {
		fn(&dat.CloudletResourceUsage)
	}
	return mcClient.GetCloudletResourceUsage(uri, token, dat)
}
func TestPermGetCloudletResourceUsage(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.CloudletResourceUsage)) (*edgeproto.CloudletResourceUsage, int, error) {
	in := &edgeproto.CloudletResourceUsage{}
	in.Key.Organization = org
	return TestGetCloudletResourceUsage(mcClient, uri, token, region, in, modFuncs...)
}

func TestAddCloudletResMapping(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.CloudletResMap, modFuncs ...func(*edgeproto.CloudletResMap)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionCloudletResMap{}
	dat.Region = region
	dat.CloudletResMap = *in
	for _, fn := range modFuncs {
		fn(&dat.CloudletResMap)
	}
	return mcClient.AddCloudletResMapping(uri, token, dat)
}
func TestPermAddCloudletResMapping(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.CloudletResMap)) (*edgeproto.Result, int, error) {
	in := &edgeproto.CloudletResMap{}
	in.Key.Organization = org
	return TestAddCloudletResMapping(mcClient, uri, token, region, in, modFuncs...)
}

func TestRemoveCloudletResMapping(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.CloudletResMap, modFuncs ...func(*edgeproto.CloudletResMap)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionCloudletResMap{}
	dat.Region = region
	dat.CloudletResMap = *in
	for _, fn := range modFuncs {
		fn(&dat.CloudletResMap)
	}
	return mcClient.RemoveCloudletResMapping(uri, token, dat)
}
func TestPermRemoveCloudletResMapping(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.CloudletResMap)) (*edgeproto.Result, int, error) {
	in := &edgeproto.CloudletResMap{}
	in.Key.Organization = org
	return TestRemoveCloudletResMapping(mcClient, uri, token, region, in, modFuncs...)
}

func TestFindFlavorMatch(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.FlavorMatch, modFuncs ...func(*edgeproto.FlavorMatch)) (*edgeproto.FlavorMatch, int, error) {
	dat := &ormapi.RegionFlavorMatch{}
	dat.Region = region
	dat.FlavorMatch = *in
	for _, fn := range modFuncs {
		fn(&dat.FlavorMatch)
	}
	return mcClient.FindFlavorMatch(uri, token, dat)
}
func TestPermFindFlavorMatch(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.FlavorMatch)) (*edgeproto.FlavorMatch, int, error) {
	in := &edgeproto.FlavorMatch{}
	in.Key.Organization = org
	return TestFindFlavorMatch(mcClient, uri, token, region, in, modFuncs...)
}

func TestShowFlavorsForCloudlet(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.CloudletKey)) ([]edgeproto.FlavorKey, int, error) {
	dat := &ormapi.RegionCloudletKey{}
	dat.Region = region
	dat.CloudletKey = *in
	for _, fn := range modFuncs {
		fn(&dat.CloudletKey)
	}
	return mcClient.ShowFlavorsForCloudlet(uri, token, dat)
}
func TestPermShowFlavorsForCloudlet(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.CloudletKey)) ([]edgeproto.FlavorKey, int, error) {
	in := &edgeproto.CloudletKey{}
	return TestShowFlavorsForCloudlet(mcClient, uri, token, region, in, modFuncs...)
}

func TestRevokeAccessKey(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.CloudletKey)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionCloudletKey{}
	dat.Region = region
	dat.CloudletKey = *in
	for _, fn := range modFuncs {
		fn(&dat.CloudletKey)
	}
	return mcClient.RevokeAccessKey(uri, token, dat)
}
func TestPermRevokeAccessKey(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.CloudletKey)) (*edgeproto.Result, int, error) {
	in := &edgeproto.CloudletKey{}
	in.Organization = org
	return TestRevokeAccessKey(mcClient, uri, token, region, in, modFuncs...)
}

func TestGenerateAccessKey(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.CloudletKey, modFuncs ...func(*edgeproto.CloudletKey)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionCloudletKey{}
	dat.Region = region
	dat.CloudletKey = *in
	for _, fn := range modFuncs {
		fn(&dat.CloudletKey)
	}
	return mcClient.GenerateAccessKey(uri, token, dat)
}
func TestPermGenerateAccessKey(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.CloudletKey)) (*edgeproto.Result, int, error) {
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

func (s *TestClient) PlatformDeleteCloudlet(ctx context.Context, in *edgeproto.Cloudlet) ([]edgeproto.Result, error) {
	return nil, nil
}

func (s *TestClient) GetCloudletManifest(ctx context.Context, in *edgeproto.CloudletKey) (*edgeproto.CloudletManifest, error) {
	inR := &ormapi.RegionCloudletKey{
		Region:      s.Region,
		CloudletKey: *in,
	}
	out, status, err := s.McClient.GetCloudletManifest(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) ShowFlavorsForCloudlet(ctx context.Context, in *edgeproto.CloudletKey) ([]edgeproto.FlavorKey, error) {
	inR := &ormapi.RegionCloudletKey{
		Region:      s.Region,
		CloudletKey: *in,
	}
	out, status, err := s.McClient.ShowFlavorsForCloudlet(s.Uri, s.Token, inR)
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

func (s *TestClient) GetCloudletResourceQuotaProps(ctx context.Context, in *edgeproto.CloudletResourceQuotaProps) (*edgeproto.CloudletResourceQuotaProps, error) {
	inR := &ormapi.RegionCloudletResourceQuotaProps{
		Region:                     s.Region,
		CloudletResourceQuotaProps: *in,
	}
	out, status, err := s.McClient.GetCloudletResourceQuotaProps(s.Uri, s.Token, inR)
	if err == nil && status != 200 {
		err = fmt.Errorf("status: %d\n", status)
	}
	return out, err
}

func (s *TestClient) GetCloudletResourceUsage(ctx context.Context, in *edgeproto.CloudletResourceUsage) (*edgeproto.CloudletResourceUsage, error) {
	inR := &ormapi.RegionCloudletResourceUsage{
		Region:                s.Region,
		CloudletResourceUsage: *in,
	}
	out, status, err := s.McClient.GetCloudletResourceUsage(s.Uri, s.Token, inR)
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

func TestShowCloudletInfo(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.CloudletInfo, modFuncs ...func(*edgeproto.CloudletInfo)) ([]edgeproto.CloudletInfo, int, error) {
	dat := &ormapi.RegionCloudletInfo{}
	dat.Region = region
	dat.CloudletInfo = *in
	for _, fn := range modFuncs {
		fn(&dat.CloudletInfo)
	}
	return mcClient.ShowCloudletInfo(uri, token, dat)
}
func TestPermShowCloudletInfo(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.CloudletInfo)) ([]edgeproto.CloudletInfo, int, error) {
	in := &edgeproto.CloudletInfo{}
	in.Key.Organization = org
	return TestShowCloudletInfo(mcClient, uri, token, region, in, modFuncs...)
}

func TestInjectCloudletInfo(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.CloudletInfo, modFuncs ...func(*edgeproto.CloudletInfo)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionCloudletInfo{}
	dat.Region = region
	dat.CloudletInfo = *in
	for _, fn := range modFuncs {
		fn(&dat.CloudletInfo)
	}
	return mcClient.InjectCloudletInfo(uri, token, dat)
}
func TestPermInjectCloudletInfo(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.CloudletInfo)) (*edgeproto.Result, int, error) {
	in := &edgeproto.CloudletInfo{}
	in.Key.Organization = org
	return TestInjectCloudletInfo(mcClient, uri, token, region, in, modFuncs...)
}

func TestEvictCloudletInfo(mcClient *mctestclient.Client, uri, token, region string, in *edgeproto.CloudletInfo, modFuncs ...func(*edgeproto.CloudletInfo)) (*edgeproto.Result, int, error) {
	dat := &ormapi.RegionCloudletInfo{}
	dat.Region = region
	dat.CloudletInfo = *in
	for _, fn := range modFuncs {
		fn(&dat.CloudletInfo)
	}
	return mcClient.EvictCloudletInfo(uri, token, dat)
}
func TestPermEvictCloudletInfo(mcClient *mctestclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.CloudletInfo)) (*edgeproto.Result, int, error) {
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
