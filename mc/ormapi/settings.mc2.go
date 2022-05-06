// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: settings.proto

package ormapi

import (
	fmt "fmt"
	edgeproto "github.com/edgexr/edge-cloud-platform/edgeproto"
	_ "github.com/edgexr/edge-cloud-platform/protogen"
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

// Request summary for UpdateSettings
// swagger:parameters UpdateSettings
type swaggerUpdateSettings struct {
	// in: body
	Body RegionSettings
}

type RegionSettings struct {
	// Region name
	// required: true
	Region string
	// Settings in region
	Settings edgeproto.Settings
}

func (s *RegionSettings) GetRegion() string {
	return s.Region
}

func (s *RegionSettings) GetObj() interface{} {
	return &s.Settings
}

func (s *RegionSettings) GetObjName() string {
	return "Settings"
}
func (s *RegionSettings) GetObjFields() []string {
	return s.Settings.Fields
}

func (s *RegionSettings) SetObjFields(fields []string) {
	s.Settings.Fields = fields
}

// Request summary for ResetSettings
// swagger:parameters ResetSettings
type swaggerResetSettings struct {
	// in: body
	Body RegionSettings
}

// Request summary for ShowSettings
// swagger:parameters ShowSettings
type swaggerShowSettings struct {
	// in: body
	Body RegionSettings
}
