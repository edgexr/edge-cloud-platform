// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: cloudlet.proto

package ormapi

import (
	fmt "fmt"
	_ "github.com/edgexr/edge-cloud-platform/api/dme-proto"
	edgeproto "github.com/edgexr/edge-cloud-platform/api/edgeproto"
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

// Request summary for CreateGPUDriver
// swagger:parameters CreateGPUDriver
type swaggerCreateGPUDriver struct {
	// in: body
	Body RegionGPUDriver
}

type RegionGPUDriver struct {
	// Region name
	// required: true
	Region string
	// GPUDriver in region
	GPUDriver edgeproto.GPUDriver
}

func (s *RegionGPUDriver) GetRegion() string {
	return s.Region
}

func (s *RegionGPUDriver) GetObj() interface{} {
	return &s.GPUDriver
}

func (s *RegionGPUDriver) GetObjName() string {
	return "GPUDriver"
}
func (s *RegionGPUDriver) GetObjFields() []string {
	return s.GPUDriver.Fields
}

func (s *RegionGPUDriver) SetObjFields(fields []string) {
	s.GPUDriver.Fields = fields
}

// Request summary for DeleteGPUDriver
// swagger:parameters DeleteGPUDriver
type swaggerDeleteGPUDriver struct {
	// in: body
	Body RegionGPUDriver
}

// Request summary for UpdateGPUDriver
// swagger:parameters UpdateGPUDriver
type swaggerUpdateGPUDriver struct {
	// in: body
	Body RegionGPUDriver
}

// Request summary for ShowGPUDriver
// swagger:parameters ShowGPUDriver
type swaggerShowGPUDriver struct {
	// in: body
	Body RegionGPUDriver
}

// Request summary for AddGPUDriverBuild
// swagger:parameters AddGPUDriverBuild
type swaggerAddGPUDriverBuild struct {
	// in: body
	Body RegionGPUDriverBuildMember
}

type RegionGPUDriverBuildMember struct {
	// Region name
	// required: true
	Region string
	// GPUDriverBuildMember in region
	GPUDriverBuildMember edgeproto.GPUDriverBuildMember
}

func (s *RegionGPUDriverBuildMember) GetRegion() string {
	return s.Region
}

func (s *RegionGPUDriverBuildMember) GetObj() interface{} {
	return &s.GPUDriverBuildMember
}

func (s *RegionGPUDriverBuildMember) GetObjName() string {
	return "GPUDriverBuildMember"
}

// Request summary for RemoveGPUDriverBuild
// swagger:parameters RemoveGPUDriverBuild
type swaggerRemoveGPUDriverBuild struct {
	// in: body
	Body RegionGPUDriverBuildMember
}

// Request summary for GetGPUDriverBuildURL
// swagger:parameters GetGPUDriverBuildURL
type swaggerGetGPUDriverBuildURL struct {
	// in: body
	Body RegionGPUDriverBuildMember
}

// Request summary for GetGPUDriverLicenseConfig
// swagger:parameters GetGPUDriverLicenseConfig
type swaggerGetGPUDriverLicenseConfig struct {
	// in: body
	Body RegionGPUDriverKey
}

type RegionGPUDriverKey struct {
	// Region name
	// required: true
	Region string
	// GPUDriverKey in region
	GPUDriverKey edgeproto.GPUDriverKey
}

func (s *RegionGPUDriverKey) GetRegion() string {
	return s.Region
}

func (s *RegionGPUDriverKey) GetObj() interface{} {
	return &s.GPUDriverKey
}

func (s *RegionGPUDriverKey) GetObjName() string {
	return "GPUDriverKey"
}

// Request summary for CreateCloudlet
// swagger:parameters CreateCloudlet
type swaggerCreateCloudlet struct {
	// in: body
	Body RegionCloudlet
}

type RegionCloudlet struct {
	// Region name
	// required: true
	Region string
	// Cloudlet in region
	Cloudlet edgeproto.Cloudlet
}

func (s *RegionCloudlet) GetRegion() string {
	return s.Region
}

func (s *RegionCloudlet) GetObj() interface{} {
	return &s.Cloudlet
}

func (s *RegionCloudlet) GetObjName() string {
	return "Cloudlet"
}
func (s *RegionCloudlet) GetObjFields() []string {
	return s.Cloudlet.Fields
}

func (s *RegionCloudlet) SetObjFields(fields []string) {
	s.Cloudlet.Fields = fields
}

// Request summary for DeleteCloudlet
// swagger:parameters DeleteCloudlet
type swaggerDeleteCloudlet struct {
	// in: body
	Body RegionCloudlet
}

// Request summary for UpdateCloudlet
// swagger:parameters UpdateCloudlet
type swaggerUpdateCloudlet struct {
	// in: body
	Body RegionCloudlet
}

// Request summary for ShowCloudlet
// swagger:parameters ShowCloudlet
type swaggerShowCloudlet struct {
	// in: body
	Body RegionCloudlet
}

// Request summary for GetCloudletManifest
// swagger:parameters GetCloudletManifest
type swaggerGetCloudletManifest struct {
	// in: body
	Body RegionCloudletKey
}

type RegionCloudletKey struct {
	// Region name
	// required: true
	Region string
	// CloudletKey in region
	CloudletKey edgeproto.CloudletKey
}

func (s *RegionCloudletKey) GetRegion() string {
	return s.Region
}

func (s *RegionCloudletKey) GetObj() interface{} {
	return &s.CloudletKey
}

func (s *RegionCloudletKey) GetObjName() string {
	return "CloudletKey"
}

// Request summary for ShowCloudletPlatformFeatures
// swagger:parameters ShowCloudletPlatformFeatures
type swaggerShowCloudletPlatformFeatures struct {
	// in: body
	Body RegionPlatformFeatures
}

type RegionPlatformFeatures struct {
	// Region name
	// required: true
	Region string
	// PlatformFeatures in region
	PlatformFeatures edgeproto.PlatformFeatures
}

func (s *RegionPlatformFeatures) GetRegion() string {
	return s.Region
}

func (s *RegionPlatformFeatures) GetObj() interface{} {
	return &s.PlatformFeatures
}

func (s *RegionPlatformFeatures) GetObjName() string {
	return "PlatformFeatures"
}

// Request summary for GetCloudletProps
// swagger:parameters GetCloudletProps
type swaggerGetCloudletProps struct {
	// in: body
	Body RegionCloudletProps
}

type RegionCloudletProps struct {
	// Region name
	// required: true
	Region string
	// CloudletProps in region
	CloudletProps edgeproto.CloudletProps
}

func (s *RegionCloudletProps) GetRegion() string {
	return s.Region
}

func (s *RegionCloudletProps) GetObj() interface{} {
	return &s.CloudletProps
}

func (s *RegionCloudletProps) GetObjName() string {
	return "CloudletProps"
}

// Request summary for GetCloudletResourceQuotaProps
// swagger:parameters GetCloudletResourceQuotaProps
type swaggerGetCloudletResourceQuotaProps struct {
	// in: body
	Body RegionCloudletResourceQuotaProps
}

type RegionCloudletResourceQuotaProps struct {
	// Region name
	// required: true
	Region string
	// CloudletResourceQuotaProps in region
	CloudletResourceQuotaProps edgeproto.CloudletResourceQuotaProps
}

func (s *RegionCloudletResourceQuotaProps) GetRegion() string {
	return s.Region
}

func (s *RegionCloudletResourceQuotaProps) GetObj() interface{} {
	return &s.CloudletResourceQuotaProps
}

func (s *RegionCloudletResourceQuotaProps) GetObjName() string {
	return "CloudletResourceQuotaProps"
}

// Request summary for GetCloudletResourceUsage
// swagger:parameters GetCloudletResourceUsage
type swaggerGetCloudletResourceUsage struct {
	// in: body
	Body RegionCloudletResourceUsage
}

type RegionCloudletResourceUsage struct {
	// Region name
	// required: true
	Region string
	// CloudletResourceUsage in region
	CloudletResourceUsage edgeproto.CloudletResourceUsage
}

func (s *RegionCloudletResourceUsage) GetRegion() string {
	return s.Region
}

func (s *RegionCloudletResourceUsage) GetObj() interface{} {
	return &s.CloudletResourceUsage
}

func (s *RegionCloudletResourceUsage) GetObjName() string {
	return "CloudletResourceUsage"
}

// Request summary for AddCloudletResMapping
// swagger:parameters AddCloudletResMapping
type swaggerAddCloudletResMapping struct {
	// in: body
	Body RegionCloudletResMap
}

type RegionCloudletResMap struct {
	// Region name
	// required: true
	Region string
	// CloudletResMap in region
	CloudletResMap edgeproto.CloudletResMap
}

func (s *RegionCloudletResMap) GetRegion() string {
	return s.Region
}

func (s *RegionCloudletResMap) GetObj() interface{} {
	return &s.CloudletResMap
}

func (s *RegionCloudletResMap) GetObjName() string {
	return "CloudletResMap"
}

// Request summary for RemoveCloudletResMapping
// swagger:parameters RemoveCloudletResMapping
type swaggerRemoveCloudletResMapping struct {
	// in: body
	Body RegionCloudletResMap
}

// Request summary for AddCloudletAllianceOrg
// swagger:parameters AddCloudletAllianceOrg
type swaggerAddCloudletAllianceOrg struct {
	// in: body
	Body RegionCloudletAllianceOrg
}

type RegionCloudletAllianceOrg struct {
	// Region name
	// required: true
	Region string
	// CloudletAllianceOrg in region
	CloudletAllianceOrg edgeproto.CloudletAllianceOrg
}

func (s *RegionCloudletAllianceOrg) GetRegion() string {
	return s.Region
}

func (s *RegionCloudletAllianceOrg) GetObj() interface{} {
	return &s.CloudletAllianceOrg
}

func (s *RegionCloudletAllianceOrg) GetObjName() string {
	return "CloudletAllianceOrg"
}

// Request summary for RemoveCloudletAllianceOrg
// swagger:parameters RemoveCloudletAllianceOrg
type swaggerRemoveCloudletAllianceOrg struct {
	// in: body
	Body RegionCloudletAllianceOrg
}

// Request summary for FindFlavorMatch
// swagger:parameters FindFlavorMatch
type swaggerFindFlavorMatch struct {
	// in: body
	Body RegionFlavorMatch
}

type RegionFlavorMatch struct {
	// Region name
	// required: true
	Region string
	// FlavorMatch in region
	FlavorMatch edgeproto.FlavorMatch
}

func (s *RegionFlavorMatch) GetRegion() string {
	return s.Region
}

func (s *RegionFlavorMatch) GetObj() interface{} {
	return &s.FlavorMatch
}

func (s *RegionFlavorMatch) GetObjName() string {
	return "FlavorMatch"
}

// Request summary for ShowFlavorsForCloudlet
// swagger:parameters ShowFlavorsForCloudlet
type swaggerShowFlavorsForCloudlet struct {
	// in: body
	Body RegionCloudletKey
}

// Request summary for GetOrganizationsOnCloudlet
// swagger:parameters GetOrganizationsOnCloudlet
type swaggerGetOrganizationsOnCloudlet struct {
	// in: body
	Body RegionCloudletKey
}

// Request summary for RevokeAccessKey
// swagger:parameters RevokeAccessKey
type swaggerRevokeAccessKey struct {
	// in: body
	Body RegionCloudletKey
}

// Request summary for GenerateAccessKey
// swagger:parameters GenerateAccessKey
type swaggerGenerateAccessKey struct {
	// in: body
	Body RegionCloudletKey
}

// Request summary for GetCloudletGPUDriverLicenseConfig
// swagger:parameters GetCloudletGPUDriverLicenseConfig
type swaggerGetCloudletGPUDriverLicenseConfig struct {
	// in: body
	Body RegionCloudletKey
}

// Request summary for ShowCloudletInfo
// swagger:parameters ShowCloudletInfo
type swaggerShowCloudletInfo struct {
	// in: body
	Body RegionCloudletInfo
}

type RegionCloudletInfo struct {
	// Region name
	// required: true
	Region string
	// CloudletInfo in region
	CloudletInfo edgeproto.CloudletInfo
}

func (s *RegionCloudletInfo) GetRegion() string {
	return s.Region
}

func (s *RegionCloudletInfo) GetObj() interface{} {
	return &s.CloudletInfo
}

func (s *RegionCloudletInfo) GetObjName() string {
	return "CloudletInfo"
}
func (s *RegionCloudletInfo) GetObjFields() []string {
	return s.CloudletInfo.Fields
}

func (s *RegionCloudletInfo) SetObjFields(fields []string) {
	s.CloudletInfo.Fields = fields
}

// Request summary for InjectCloudletInfo
// swagger:parameters InjectCloudletInfo
type swaggerInjectCloudletInfo struct {
	// in: body
	Body RegionCloudletInfo
}

// Request summary for EvictCloudletInfo
// swagger:parameters EvictCloudletInfo
type swaggerEvictCloudletInfo struct {
	// in: body
	Body RegionCloudletInfo
}
