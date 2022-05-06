// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: node.proto

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

// Request summary for ShowNode
// swagger:parameters ShowNode
type swaggerShowNode struct {
	// in: body
	Body RegionNode
}

type RegionNode struct {
	// Region name
	// required: true
	Region string
	// Node in region
	Node edgeproto.Node
}

func (s *RegionNode) GetRegion() string {
	return s.Region
}

func (s *RegionNode) GetObj() interface{} {
	return &s.Node
}

func (s *RegionNode) GetObjName() string {
	return "Node"
}
func (s *RegionNode) GetObjFields() []string {
	return s.Node.Fields
}

func (s *RegionNode) SetObjFields(fields []string) {
	s.Node.Fields = fields
}
