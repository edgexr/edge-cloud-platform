// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: ratelimit.proto

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

// Request summary for ShowRateLimitSettings
// swagger:parameters ShowRateLimitSettings
type swaggerShowRateLimitSettings struct {
	// in: body
	Body RegionRateLimitSettings
}

type RegionRateLimitSettings struct {
	// Region name
	// required: true
	Region string
	// RateLimitSettings in region
	RateLimitSettings edgeproto.RateLimitSettings
}

func (s *RegionRateLimitSettings) GetRegion() string {
	return s.Region
}

func (s *RegionRateLimitSettings) GetObj() interface{} {
	return &s.RateLimitSettings
}

func (s *RegionRateLimitSettings) GetObjName() string {
	return "RateLimitSettings"
}

// Request summary for CreateFlowRateLimitSettings
// swagger:parameters CreateFlowRateLimitSettings
type swaggerCreateFlowRateLimitSettings struct {
	// in: body
	Body RegionFlowRateLimitSettings
}

type RegionFlowRateLimitSettings struct {
	// Region name
	// required: true
	Region string
	// FlowRateLimitSettings in region
	FlowRateLimitSettings edgeproto.FlowRateLimitSettings
}

func (s *RegionFlowRateLimitSettings) GetRegion() string {
	return s.Region
}

func (s *RegionFlowRateLimitSettings) GetObj() interface{} {
	return &s.FlowRateLimitSettings
}

func (s *RegionFlowRateLimitSettings) GetObjName() string {
	return "FlowRateLimitSettings"
}
func (s *RegionFlowRateLimitSettings) GetObjFields() []string {
	return s.FlowRateLimitSettings.Fields
}

func (s *RegionFlowRateLimitSettings) SetObjFields(fields []string) {
	s.FlowRateLimitSettings.Fields = fields
}

// Request summary for UpdateFlowRateLimitSettings
// swagger:parameters UpdateFlowRateLimitSettings
type swaggerUpdateFlowRateLimitSettings struct {
	// in: body
	Body RegionFlowRateLimitSettings
}

// Request summary for DeleteFlowRateLimitSettings
// swagger:parameters DeleteFlowRateLimitSettings
type swaggerDeleteFlowRateLimitSettings struct {
	// in: body
	Body RegionFlowRateLimitSettings
}

// Request summary for ShowFlowRateLimitSettings
// swagger:parameters ShowFlowRateLimitSettings
type swaggerShowFlowRateLimitSettings struct {
	// in: body
	Body RegionFlowRateLimitSettings
}

// Request summary for CreateMaxReqsRateLimitSettings
// swagger:parameters CreateMaxReqsRateLimitSettings
type swaggerCreateMaxReqsRateLimitSettings struct {
	// in: body
	Body RegionMaxReqsRateLimitSettings
}

type RegionMaxReqsRateLimitSettings struct {
	// Region name
	// required: true
	Region string
	// MaxReqsRateLimitSettings in region
	MaxReqsRateLimitSettings edgeproto.MaxReqsRateLimitSettings
}

func (s *RegionMaxReqsRateLimitSettings) GetRegion() string {
	return s.Region
}

func (s *RegionMaxReqsRateLimitSettings) GetObj() interface{} {
	return &s.MaxReqsRateLimitSettings
}

func (s *RegionMaxReqsRateLimitSettings) GetObjName() string {
	return "MaxReqsRateLimitSettings"
}
func (s *RegionMaxReqsRateLimitSettings) GetObjFields() []string {
	return s.MaxReqsRateLimitSettings.Fields
}

func (s *RegionMaxReqsRateLimitSettings) SetObjFields(fields []string) {
	s.MaxReqsRateLimitSettings.Fields = fields
}

// Request summary for UpdateMaxReqsRateLimitSettings
// swagger:parameters UpdateMaxReqsRateLimitSettings
type swaggerUpdateMaxReqsRateLimitSettings struct {
	// in: body
	Body RegionMaxReqsRateLimitSettings
}

// Request summary for DeleteMaxReqsRateLimitSettings
// swagger:parameters DeleteMaxReqsRateLimitSettings
type swaggerDeleteMaxReqsRateLimitSettings struct {
	// in: body
	Body RegionMaxReqsRateLimitSettings
}

// Request summary for ShowMaxReqsRateLimitSettings
// swagger:parameters ShowMaxReqsRateLimitSettings
type swaggerShowMaxReqsRateLimitSettings struct {
	// in: body
	Body RegionMaxReqsRateLimitSettings
}
