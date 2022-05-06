// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: restagtable.proto

package ormapi

import (
	fmt "fmt"
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

// Request summary for CreateResTagTable
// swagger:parameters CreateResTagTable
type swaggerCreateResTagTable struct {
	// in: body
	Body RegionResTagTable
}

type RegionResTagTable struct {
	// Region name
	// required: true
	Region string
	// ResTagTable in region
	ResTagTable edgeproto.ResTagTable
}

func (s *RegionResTagTable) GetRegion() string {
	return s.Region
}

func (s *RegionResTagTable) GetObj() interface{} {
	return &s.ResTagTable
}

func (s *RegionResTagTable) GetObjName() string {
	return "ResTagTable"
}
func (s *RegionResTagTable) GetObjFields() []string {
	return s.ResTagTable.Fields
}

func (s *RegionResTagTable) SetObjFields(fields []string) {
	s.ResTagTable.Fields = fields
}

// Request summary for DeleteResTagTable
// swagger:parameters DeleteResTagTable
type swaggerDeleteResTagTable struct {
	// in: body
	Body RegionResTagTable
}

// Request summary for UpdateResTagTable
// swagger:parameters UpdateResTagTable
type swaggerUpdateResTagTable struct {
	// in: body
	Body RegionResTagTable
}

// Request summary for ShowResTagTable
// swagger:parameters ShowResTagTable
type swaggerShowResTagTable struct {
	// in: body
	Body RegionResTagTable
}

// Request summary for AddResTag
// swagger:parameters AddResTag
type swaggerAddResTag struct {
	// in: body
	Body RegionResTagTable
}

// Request summary for RemoveResTag
// swagger:parameters RemoveResTag
type swaggerRemoveResTag struct {
	// in: body
	Body RegionResTagTable
}

// Request summary for GetResTagTable
// swagger:parameters GetResTagTable
type swaggerGetResTagTable struct {
	// in: body
	Body RegionResTagTableKey
}

type RegionResTagTableKey struct {
	// Region name
	// required: true
	Region string
	// ResTagTableKey in region
	ResTagTableKey edgeproto.ResTagTableKey
}

func (s *RegionResTagTableKey) GetRegion() string {
	return s.Region
}

func (s *RegionResTagTableKey) GetObj() interface{} {
	return &s.ResTagTableKey
}

func (s *RegionResTagTableKey) GetObjName() string {
	return "ResTagTableKey"
}
