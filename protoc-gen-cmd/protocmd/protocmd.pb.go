// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: protocmd.proto

/*
Package protocmd is a generated protocol buffer package.

It is generated from these files:
	protocmd.proto

It has these top-level messages:
*/
package protocmd

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import google_protobuf "github.com/gogo/protobuf/protoc-gen-gogo/descriptor"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

var E_Noconfig = &proto.ExtensionDesc{
	ExtendedType:  (*google_protobuf.MessageOptions)(nil),
	ExtensionType: (*string)(nil),
	Field:         52001,
	Name:          "protocmd.noconfig",
	Tag:           "bytes,52001,opt,name=noconfig",
	Filename:      "protocmd.proto",
}

var E_StreamOutIncremental = &proto.ExtensionDesc{
	ExtendedType:  (*google_protobuf.MethodOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         52003,
	Name:          "protocmd.stream_out_incremental",
	Tag:           "varint,52003,opt,name=stream_out_incremental,json=streamOutIncremental",
	Filename:      "protocmd.proto",
}

func init() {
	proto.RegisterExtension(E_Noconfig)
	proto.RegisterExtension(E_StreamOutIncremental)
}

func init() { proto.RegisterFile("protocmd.proto", fileDescriptorProtocmd) }

var fileDescriptorProtocmd = []byte{
	// 184 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0x2b, 0x28, 0xca, 0x2f,
	0xc9, 0x4f, 0xce, 0x4d, 0xd1, 0x03, 0x33, 0x84, 0x38, 0x60, 0x7c, 0x29, 0x85, 0xf4, 0xfc, 0xfc,
	0xf4, 0x9c, 0x54, 0x7d, 0xb0, 0x40, 0x52, 0x69, 0x9a, 0x7e, 0x4a, 0x6a, 0x71, 0x72, 0x51, 0x66,
	0x41, 0x49, 0x7e, 0x11, 0x44, 0xad, 0x95, 0x2d, 0x17, 0x47, 0x5e, 0x7e, 0x72, 0x7e, 0x5e, 0x5a,
	0x66, 0xba, 0x90, 0xbc, 0x1e, 0x44, 0xb9, 0x1e, 0x4c, 0xb9, 0x9e, 0x6f, 0x6a, 0x71, 0x71, 0x62,
	0x7a, 0xaa, 0x7f, 0x41, 0x49, 0x66, 0x7e, 0x5e, 0xb1, 0xc4, 0xc2, 0x69, 0xcc, 0x0a, 0x8c, 0x1a,
	0x9c, 0x41, 0x70, 0x2d, 0x56, 0x61, 0x5c, 0x62, 0xc5, 0x25, 0x45, 0xa9, 0x89, 0xb9, 0xf1, 0xf9,
	0xa5, 0x25, 0xf1, 0x99, 0x79, 0xc9, 0x45, 0xa9, 0xb9, 0xa9, 0x79, 0x25, 0x89, 0x39, 0x42, 0x72,
	0x58, 0x0c, 0x2b, 0xc9, 0xc8, 0x4f, 0x81, 0x99, 0xb5, 0x18, 0x6c, 0x16, 0x47, 0x90, 0x08, 0x44,
	0xbf, 0x7f, 0x69, 0x89, 0x27, 0x42, 0xb7, 0x13, 0xcf, 0x89, 0x47, 0x72, 0x8c, 0x17, 0x1e, 0xc9,
	0x31, 0x3e, 0x78, 0x24, 0xc7, 0x98, 0xc4, 0x06, 0x36, 0xc3, 0x18, 0x10, 0x00, 0x00, 0xff, 0xff,
	0x33, 0x1b, 0xa7, 0x2d, 0xe9, 0x00, 0x00, 0x00,
}
