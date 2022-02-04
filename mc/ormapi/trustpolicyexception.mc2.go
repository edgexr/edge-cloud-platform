// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: trustpolicyexception.proto

package ormapi

import (
	fmt "fmt"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
	_ "github.com/mobiledgex/edge-cloud/protogen"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

// Request summary for CreateTrustPolicyException
// swagger:parameters CreateTrustPolicyException
type swaggerCreateTrustPolicyException struct {
	// in: body
	Body RegionTrustPolicyException
}

type RegionTrustPolicyException struct {
	// Region name
	// required: true
	Region string
	// TrustPolicyException in region
	TrustPolicyException edgeproto.TrustPolicyException
}

func (s *RegionTrustPolicyException) GetRegion() string {
	return s.Region
}

func (s *RegionTrustPolicyException) GetObj() interface{} {
	return &s.TrustPolicyException
}

func (s *RegionTrustPolicyException) GetObjName() string {
	return "TrustPolicyException"
}
func (s *RegionTrustPolicyException) GetObjFields() []string {
	return s.TrustPolicyException.Fields
}

func (s *RegionTrustPolicyException) SetObjFields(fields []string) {
	s.TrustPolicyException.Fields = fields
}

// Request summary for UpdateTrustPolicyException
// swagger:parameters UpdateTrustPolicyException
type swaggerUpdateTrustPolicyException struct {
	// in: body
	Body RegionTrustPolicyException
}

// Request summary for DeleteTrustPolicyException
// swagger:parameters DeleteTrustPolicyException
type swaggerDeleteTrustPolicyException struct {
	// in: body
	Body RegionTrustPolicyException
}

// Request summary for ShowTrustPolicyException
// swagger:parameters ShowTrustPolicyException
type swaggerShowTrustPolicyException struct {
	// in: body
	Body RegionTrustPolicyException
}
