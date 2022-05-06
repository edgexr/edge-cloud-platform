// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: autoprovpolicy.proto

package ormapi

import (
	fmt "fmt"
	_ "github.com/edgexr/edge-cloud-platform/d-match-engine/dme-proto"
	edgeproto "github.com/edgexr/edge-cloud-platform/edgeproto"
	_ "github.com/edgexr/edge-cloud-platform/protogen"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	_ "github.com/gogo/protobuf/types"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

// Request summary for CreateAutoProvPolicy
// swagger:parameters CreateAutoProvPolicy
type swaggerCreateAutoProvPolicy struct {
	// in: body
	Body RegionAutoProvPolicy
}

type RegionAutoProvPolicy struct {
	// Region name
	// required: true
	Region string
	// AutoProvPolicy in region
	AutoProvPolicy edgeproto.AutoProvPolicy
}

func (s *RegionAutoProvPolicy) GetRegion() string {
	return s.Region
}

func (s *RegionAutoProvPolicy) GetObj() interface{} {
	return &s.AutoProvPolicy
}

func (s *RegionAutoProvPolicy) GetObjName() string {
	return "AutoProvPolicy"
}
func (s *RegionAutoProvPolicy) GetObjFields() []string {
	return s.AutoProvPolicy.Fields
}

func (s *RegionAutoProvPolicy) SetObjFields(fields []string) {
	s.AutoProvPolicy.Fields = fields
}

// Request summary for DeleteAutoProvPolicy
// swagger:parameters DeleteAutoProvPolicy
type swaggerDeleteAutoProvPolicy struct {
	// in: body
	Body RegionAutoProvPolicy
}

// Request summary for UpdateAutoProvPolicy
// swagger:parameters UpdateAutoProvPolicy
type swaggerUpdateAutoProvPolicy struct {
	// in: body
	Body RegionAutoProvPolicy
}

// Request summary for ShowAutoProvPolicy
// swagger:parameters ShowAutoProvPolicy
type swaggerShowAutoProvPolicy struct {
	// in: body
	Body RegionAutoProvPolicy
}

// Request summary for AddAutoProvPolicyCloudlet
// swagger:parameters AddAutoProvPolicyCloudlet
type swaggerAddAutoProvPolicyCloudlet struct {
	// in: body
	Body RegionAutoProvPolicyCloudlet
}

type RegionAutoProvPolicyCloudlet struct {
	// Region name
	// required: true
	Region string
	// AutoProvPolicyCloudlet in region
	AutoProvPolicyCloudlet edgeproto.AutoProvPolicyCloudlet
}

func (s *RegionAutoProvPolicyCloudlet) GetRegion() string {
	return s.Region
}

func (s *RegionAutoProvPolicyCloudlet) GetObj() interface{} {
	return &s.AutoProvPolicyCloudlet
}

func (s *RegionAutoProvPolicyCloudlet) GetObjName() string {
	return "AutoProvPolicyCloudlet"
}

// Request summary for RemoveAutoProvPolicyCloudlet
// swagger:parameters RemoveAutoProvPolicyCloudlet
type swaggerRemoveAutoProvPolicyCloudlet struct {
	// in: body
	Body RegionAutoProvPolicyCloudlet
}