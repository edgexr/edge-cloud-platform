// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: alert.proto

package ormapi

import (
	fmt "fmt"
	_ "github.com/edgexr/edge-cloud/d-match-engine/dme-proto"
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

// Request summary for ShowAlert
// swagger:parameters ShowAlert
type swaggerShowAlert struct {
	// in: body
	Body RegionAlert
}

type RegionAlert struct {
	// Region name
	// required: true
	Region string
	// Alert in region
	Alert edgeproto.Alert
}

func (s *RegionAlert) GetRegion() string {
	return s.Region
}

func (s *RegionAlert) GetObj() interface{} {
	return &s.Alert
}

func (s *RegionAlert) GetObjName() string {
	return "Alert"
}
