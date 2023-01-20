// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: version.proto

package edgeproto

import (
	"encoding/json"
	fmt "fmt"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	_ "github.com/edgexr/edge-cloud-platform/tools/protogen"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	math "math"
	reflect "reflect"
	"strconv"
	strings "strings"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

// Below enum lists hashes as well as corresponding versions
type VersionHash int32

const (
	VersionHash_HASH_d41d8cd98f00b204e9800998ecf8427e VersionHash = 0
	//interim versions deleted
	VersionHash_HASH_d4ca5418a77d22d968ce7a2afc549dfe VersionHash = 9
	VersionHash_HASH_7848d42e3a2eaf36e53bbd3af581b13a VersionHash = 10
	VersionHash_HASH_f31b7a9d7e06f72107e0ab13c708704e VersionHash = 11
	VersionHash_HASH_03fad51f0343d41f617329151f474d2b VersionHash = 12
	VersionHash_HASH_7d32a983fafc3da768e045b1dc4d5f50 VersionHash = 13
	VersionHash_HASH_747c14bdfe2043f09d251568e4a722c6 VersionHash = 14
	VersionHash_HASH_c7fb20f545a5bc9869b00bb770753c31 VersionHash = 15
	VersionHash_HASH_83cd5c44b5c7387ebf7d055e7345ab42 VersionHash = 16
	VersionHash_HASH_d8a4e697d0d693479cfd9c1c523d7e06 VersionHash = 17
	VersionHash_HASH_e8360aa30f234ecefdfdb9fb2dc79c20 VersionHash = 18
	VersionHash_HASH_c53c7840d242efc7209549a36fcf9e04 VersionHash = 19
	VersionHash_HASH_1a57396698c4ade15f0579c9f5714cd6 VersionHash = 20
	VersionHash_HASH_71c580746ee2a6b7d1a4182b3a54407a VersionHash = 21
	VersionHash_HASH_a18636af1f4272c38ca72881b2a8bcea VersionHash = 22
	VersionHash_HASH_efbddcee4ba444e3656f64e430a5e3be VersionHash = 23
	VersionHash_HASH_c2c322505017054033953f6104002bf5 VersionHash = 24
	VersionHash_HASH_facc3c3c9c76463c8d8b3c874ce43487 VersionHash = 25
	VersionHash_HASH_8ba950479a03ab77edfad426ea53c173 VersionHash = 26
	VersionHash_HASH_f4eb139f7a8373a484ab9749eadc31f5 VersionHash = 27
	VersionHash_HASH_09fae4d440aa06acb9664167d2e1f036 VersionHash = 28
	VersionHash_HASH_8c5a9c29caff4ace0a23a9dab9a15bf7 VersionHash = 29
	VersionHash_HASH_b7c6a74ce2f30b3bda179e00617459cf VersionHash = 30
	VersionHash_HASH_911d86a4eb2bbfbff1173ffbdd197a8c VersionHash = 31
	VersionHash_HASH_99349a696d0b5872542f81b4b0b4788e VersionHash = 32
	VersionHash_HASH_264850a5c1f7a054b4de1a87e5d28dcc VersionHash = 33
	VersionHash_HASH_748b47eaf414b0f2c15e4c6a9298b5f1 VersionHash = 34
	VersionHash_HASH_1480647750f7638ff5494c0e715bb98c VersionHash = 35
	VersionHash_HASH_208a22352e46f6bbe34f3b72aaf99ee5 VersionHash = 36
	VersionHash_HASH_6f8f268d3945699608651e1a8bb38e5e VersionHash = 37
	VersionHash_HASH_2dfdb2ed2cf52241b2b3db1d39e11bc6 VersionHash = 38
	VersionHash_HASH_6585ad5e26ee92a955abd26c38067065 VersionHash = 39
	VersionHash_HASH_4ddeb801651b2acb84f5d182e445fce1 VersionHash = 40
	VersionHash_HASH_156def83eec72a44248fabd79199efbe VersionHash = 41
	VersionHash_HASH_636a7d17efd0532933313e27e6de0a5b VersionHash = 42
	VersionHash_HASH_0a418578eee77cabd2b8e1dd1fa64dbe VersionHash = 43
	VersionHash_HASH_93e8b0c0bb73ce790ebcd69d8437539c VersionHash = 44
	VersionHash_HASH_29fb22509ab88f8106c5b27f147a8aaa VersionHash = 45
	VersionHash_HASH_44e6191740bcaa95237c2f3e1ba13d3c VersionHash = 46
	VersionHash_HASH_611b28894b117c2aaa22c12adcd81f74 VersionHash = 47
)

var VersionHash_name = map[int32]string{
	0:  "HASH_d41d8cd98f00b204e9800998ecf8427e",
	9:  "HASH_d4ca5418a77d22d968ce7a2afc549dfe",
	10: "HASH_7848d42e3a2eaf36e53bbd3af581b13a",
	11: "HASH_f31b7a9d7e06f72107e0ab13c708704e",
	12: "HASH_03fad51f0343d41f617329151f474d2b",
	13: "HASH_7d32a983fafc3da768e045b1dc4d5f50",
	14: "HASH_747c14bdfe2043f09d251568e4a722c6",
	15: "HASH_c7fb20f545a5bc9869b00bb770753c31",
	16: "HASH_83cd5c44b5c7387ebf7d055e7345ab42",
	17: "HASH_d8a4e697d0d693479cfd9c1c523d7e06",
	18: "HASH_e8360aa30f234ecefdfdb9fb2dc79c20",
	19: "HASH_c53c7840d242efc7209549a36fcf9e04",
	20: "HASH_1a57396698c4ade15f0579c9f5714cd6",
	21: "HASH_71c580746ee2a6b7d1a4182b3a54407a",
	22: "HASH_a18636af1f4272c38ca72881b2a8bcea",
	23: "HASH_efbddcee4ba444e3656f64e430a5e3be",
	24: "HASH_c2c322505017054033953f6104002bf5",
	25: "HASH_facc3c3c9c76463c8d8b3c874ce43487",
	26: "HASH_8ba950479a03ab77edfad426ea53c173",
	27: "HASH_f4eb139f7a8373a484ab9749eadc31f5",
	28: "HASH_09fae4d440aa06acb9664167d2e1f036",
	29: "HASH_8c5a9c29caff4ace0a23a9dab9a15bf7",
	30: "HASH_b7c6a74ce2f30b3bda179e00617459cf",
	31: "HASH_911d86a4eb2bbfbff1173ffbdd197a8c",
	32: "HASH_99349a696d0b5872542f81b4b0b4788e",
	33: "HASH_264850a5c1f7a054b4de1a87e5d28dcc",
	34: "HASH_748b47eaf414b0f2c15e4c6a9298b5f1",
	35: "HASH_1480647750f7638ff5494c0e715bb98c",
	36: "HASH_208a22352e46f6bbe34f3b72aaf99ee5",
	37: "HASH_6f8f268d3945699608651e1a8bb38e5e",
	38: "HASH_2dfdb2ed2cf52241b2b3db1d39e11bc6",
	39: "HASH_6585ad5e26ee92a955abd26c38067065",
	40: "HASH_4ddeb801651b2acb84f5d182e445fce1",
	41: "HASH_156def83eec72a44248fabd79199efbe",
	42: "HASH_636a7d17efd0532933313e27e6de0a5b",
	43: "HASH_0a418578eee77cabd2b8e1dd1fa64dbe",
	44: "HASH_93e8b0c0bb73ce790ebcd69d8437539c",
	45: "HASH_29fb22509ab88f8106c5b27f147a8aaa",
	46: "HASH_44e6191740bcaa95237c2f3e1ba13d3c",
	47: "HASH_611b28894b117c2aaa22c12adcd81f74",
}

var VersionHash_value = map[string]int32{
	"HASH_d41d8cd98f00b204e9800998ecf8427e": 0,
	"HASH_d4ca5418a77d22d968ce7a2afc549dfe": 9,
	"HASH_7848d42e3a2eaf36e53bbd3af581b13a": 10,
	"HASH_f31b7a9d7e06f72107e0ab13c708704e": 11,
	"HASH_03fad51f0343d41f617329151f474d2b": 12,
	"HASH_7d32a983fafc3da768e045b1dc4d5f50": 13,
	"HASH_747c14bdfe2043f09d251568e4a722c6": 14,
	"HASH_c7fb20f545a5bc9869b00bb770753c31": 15,
	"HASH_83cd5c44b5c7387ebf7d055e7345ab42": 16,
	"HASH_d8a4e697d0d693479cfd9c1c523d7e06": 17,
	"HASH_e8360aa30f234ecefdfdb9fb2dc79c20": 18,
	"HASH_c53c7840d242efc7209549a36fcf9e04": 19,
	"HASH_1a57396698c4ade15f0579c9f5714cd6": 20,
	"HASH_71c580746ee2a6b7d1a4182b3a54407a": 21,
	"HASH_a18636af1f4272c38ca72881b2a8bcea": 22,
	"HASH_efbddcee4ba444e3656f64e430a5e3be": 23,
	"HASH_c2c322505017054033953f6104002bf5": 24,
	"HASH_facc3c3c9c76463c8d8b3c874ce43487": 25,
	"HASH_8ba950479a03ab77edfad426ea53c173": 26,
	"HASH_f4eb139f7a8373a484ab9749eadc31f5": 27,
	"HASH_09fae4d440aa06acb9664167d2e1f036": 28,
	"HASH_8c5a9c29caff4ace0a23a9dab9a15bf7": 29,
	"HASH_b7c6a74ce2f30b3bda179e00617459cf": 30,
	"HASH_911d86a4eb2bbfbff1173ffbdd197a8c": 31,
	"HASH_99349a696d0b5872542f81b4b0b4788e": 32,
	"HASH_264850a5c1f7a054b4de1a87e5d28dcc": 33,
	"HASH_748b47eaf414b0f2c15e4c6a9298b5f1": 34,
	"HASH_1480647750f7638ff5494c0e715bb98c": 35,
	"HASH_208a22352e46f6bbe34f3b72aaf99ee5": 36,
	"HASH_6f8f268d3945699608651e1a8bb38e5e": 37,
	"HASH_2dfdb2ed2cf52241b2b3db1d39e11bc6": 38,
	"HASH_6585ad5e26ee92a955abd26c38067065": 39,
	"HASH_4ddeb801651b2acb84f5d182e445fce1": 40,
	"HASH_156def83eec72a44248fabd79199efbe": 41,
	"HASH_636a7d17efd0532933313e27e6de0a5b": 42,
	"HASH_0a418578eee77cabd2b8e1dd1fa64dbe": 43,
	"HASH_93e8b0c0bb73ce790ebcd69d8437539c": 44,
	"HASH_29fb22509ab88f8106c5b27f147a8aaa": 45,
	"HASH_44e6191740bcaa95237c2f3e1ba13d3c": 46,
	"HASH_611b28894b117c2aaa22c12adcd81f74": 47,
}

func (x VersionHash) String() string {
	return proto.EnumName(VersionHash_name, int32(x))
}

func (VersionHash) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_7d2c07d79758f814, []int{0}
}

func init() {
	proto.RegisterEnum("edgeproto.VersionHash", VersionHash_name, VersionHash_value)
}

func init() { proto.RegisterFile("version.proto", fileDescriptor_7d2c07d79758f814) }

var fileDescriptor_7d2c07d79758f814 = []byte{
	// 1438 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x4c, 0x56, 0x4b, 0x73, 0x5c, 0x47,
	0x15, 0xb6, 0x59, 0x50, 0x15, 0x25, 0x36, 0xed, 0xc9, 0x6b, 0x98, 0x18, 0x39, 0x10, 0x12, 0x88,
	0xc1, 0x76, 0x3f, 0x4e, 0xf7, 0xe9, 0x2e, 0xa0, 0x0a, 0xd9, 0xc2, 0x0f, 0x92, 0x72, 0x09, 0x2b,
	0x66, 0x4b, 0x9d, 0x57, 0xcb, 0x2a, 0x14, 0xdd, 0x61, 0x66, 0xe4, 0x72, 0xb6, 0x2c, 0x67, 0xc5,
	0xcf, 0xf2, 0x32, 0x4b, 0x96, 0x60, 0xff, 0x05, 0xa6, 0x8a, 0x65, 0x6a, 0x64, 0x49, 0xe3, 0xd5,
	0x3d, 0xb7, 0xeb, 0xbb, 0xe7, 0xf1, 0xf5, 0xf7, 0x9d, 0xba, 0x5b, 0x57, 0x9e, 0xdb, 0x6c, 0x7e,
	0x38, 0x1c, 0xdf, 0x9e, 0xce, 0x86, 0xc5, 0x30, 0x7a, 0xc7, 0xf4, 0xc0, 0x4e, 0xc3, 0xc9, 0xbd,
	0x83, 0xc3, 0xc5, 0xb3, 0x13, 0xbe, 0x2d, 0xc3, 0xb7, 0x77, 0xd6, 0xa7, 0x2f, 0x66, 0xa7, 0x8f,
	0x5b, 0x72, 0x34, 0x9c, 0xe8, 0xad, 0xe9, 0x11, 0x2d, 0xfa, 0x30, 0xfb, 0xf6, 0xce, 0x62, 0x18,
	0x8e, 0xe6, 0x77, 0x4e, 0x3f, 0x39, 0xb0, 0xe3, 0x8b, 0xe0, 0x4d, 0xbe, 0xc9, 0x07, 0x07, 0xc3,
	0xc1, 0x70, 0x1a, 0xde, 0x59, 0x47, 0x6f, 0x4e, 0x6f, 0xbe, 0x74, 0x5b, 0xef, 0xfe, 0xf5, 0x4d,
	0xdd, 0x87, 0x34, 0x7f, 0x36, 0xfa, 0x72, 0xeb, 0xf3, 0x87, 0x3b, 0xfb, 0x0f, 0xff, 0xa6, 0x10,
	0xb4, 0x8a, 0xb6, 0xda, 0xbd, 0xe7, 0xe8, 0xc1, 0x5a, 0xf5, 0xbe, 0xb5, 0x6a, 0xd2, 0x2b, 0x44,
	0x34, 0x77, 0xe9, 0x2d, 0xa8, 0x50, 0x86, 0x50, 0x09, 0x51, 0x63, 0xd4, 0x56, 0xaa, 0x18, 0x52,
	0xa4, 0x2e, 0x19, 0x9a, 0x76, 0x73, 0xef, 0x5c, 0x40, 0xb1, 0x42, 0x55, 0x88, 0x96, 0x28, 0x1a,
	0xf5, 0x54, 0x2c, 0x27, 0x66, 0x4d, 0xd4, 0x73, 0x0d, 0x1c, 0x12, 0xb9, 0xad, 0x0b, 0x68, 0x4f,
	0x81, 0x91, 0x9a, 0xa2, 0xf9, 0xd2, 0x31, 0x06, 0x8f, 0xe6, 0x89, 0x43, 0x12, 0xf4, 0x15, 0x3d,
	0x98, 0x7b, 0xf7, 0x02, 0xea, 0x53, 0x27, 0xcd, 0xa1, 0xfb, 0x04, 0x49, 0x21, 0xf4, 0x12, 0x30,
	0xc5, 0x16, 0x72, 0xe8, 0x80, 0xa0, 0x91, 0xdd, 0x7b, 0x9b, 0x06, 0x34, 0x45, 0x6a, 0x35, 0x75,
	0xea, 0x92, 0x94, 0xb0, 0x54, 0xf3, 0x90, 0x39, 0xa8, 0x80, 0xe6, 0x9e, 0xbd, 0xbb, 0xb2, 0x81,
	0x02, 0x4a, 0x00, 0xd6, 0x6e, 0xd1, 0x43, 0xea, 0xbe, 0x69, 0xcc, 0x21, 0x97, 0x6a, 0x40, 0x18,
	0xa3, 0x14, 0x77, 0xf5, 0x02, 0x2a, 0xd8, 0x39, 0xfa, 0x9e, 0x21, 0x53, 0x66, 0x69, 0xb5, 0x34,
	0xf6, 0x9e, 0x19, 0xd1, 0x63, 0x4e, 0x92, 0x82, 0xfb, 0xc9, 0x05, 0xb4, 0x26, 0xd1, 0x2c, 0x00,
	0x9c, 0x05, 0x53, 0x45, 0xe3, 0x8e, 0xea, 0x73, 0x36, 0x4c, 0x90, 0x89, 0x21, 0x3a, 0xb7, 0xe1,
	0xb5, 0x12, 0x58, 0x69, 0xa8, 0x5e, 0x4b, 0x4b, 0x80, 0x4d, 0xba, 0x36, 0x09, 0x92, 0x63, 0x3a,
	0x65, 0xc5, 0x5d, 0xbb, 0x80, 0x5a, 0x4d, 0xc5, 0x13, 0x25, 0xdf, 0x63, 0x02, 0x13, 0xeb, 0xda,
	0x95, 0x5b, 0xe7, 0xa8, 0x82, 0x4d, 0xa2, 0x77, 0xa3, 0x4d, 0xaf, 0x39, 0x09, 0x56, 0xf0, 0x1a,
	0x21, 0x5a, 0x17, 0x8c, 0xbe, 0x65, 0x68, 0x94, 0x4a, 0x97, 0xde, 0xcc, 0x83, 0x7b, 0x7f, 0xf4,
	0xc7, 0x33, 0x68, 0xa0, 0x8c, 0xa9, 0x95, 0xd2, 0xaa, 0x00, 0xa9, 0x85, 0xdc, 0x7d, 0xc6, 0x26,
	0xad, 0x67, 0x0c, 0x20, 0x5a, 0xdc, 0x07, 0x93, 0x0f, 0x97, 0xab, 0xf1, 0xb5, 0x7b, 0xcf, 0x4c,
	0xfe, 0x7e, 0x7f, 0x98, 0x3d, 0x5c, 0x2c, 0xa6, 0x7b, 0xc3, 0x6c, 0x31, 0x1f, 0x3d, 0x3a, 0xe7,
	0x30, 0x48, 0xae, 0x1e, 0xa1, 0x98, 0x45, 0x2a, 0x8c, 0x1a, 0x08, 0x42, 0x8d, 0x9c, 0x28, 0x03,
	0x78, 0x24, 0xf7, 0xe1, 0x64, 0x7b, 0xb9, 0x1a, 0x4f, 0xf6, 0x66, 0x27, 0xc7, 0xb6, 0x77, 0x44,
	0x8b, 0x61, 0xbe, 0x77, 0xa6, 0xe6, 0x5d, 0x7b, 0x7e, 0x28, 0x36, 0x1f, 0xb5, 0xb3, 0x54, 0x14,
	0x6a, 0x49, 0x85, 0x7a, 0xe8, 0x10, 0x31, 0x4a, 0xaa, 0x42, 0x18, 0x6b, 0x0d, 0x1c, 0xa9, 0xb2,
	0x18, 0xb9, 0x8f, 0x26, 0x57, 0x97, 0xab, 0xf1, 0xd6, 0xbe, 0x2d, 0xbe, 0x99, 0x9d, 0xcc, 0x17,
	0xa6, 0x1b, 0x76, 0x3a, 0xab, 0x8a, 0x19, 0x30, 0x01, 0x80, 0xa5, 0x92, 0x4b, 0x2f, 0x60, 0x90,
	0x3c, 0x65, 0x4b, 0x6c, 0xee, 0xe3, 0xd1, 0x9f, 0xcf, 0xd9, 0x89, 0x92, 0x62, 0xcc, 0x3e, 0xfb,
	0x80, 0x3e, 0x83, 0x4f, 0xa9, 0xe5, 0xd4, 0x4b, 0xf0, 0xe0, 0x7d, 0xe4, 0x9e, 0xdd, 0x78, 0x72,
	0x63, 0xb9, 0x1a, 0x7f, 0x72, 0x6f, 0xed, 0xbc, 0x23, 0x5b, 0x3c, 0xb1, 0xf9, 0x70, 0x32, 0x13,
	0x7b, 0x3a, 0x3d, 0x98, 0x91, 0xda, 0xfd, 0x93, 0x63, 0xd9, 0x28, 0x98, 0x44, 0x92, 0x24, 0x69,
	0x82, 0x05, 0x4a, 0x92, 0xaa, 0x95, 0x93, 0x54, 0x04, 0x31, 0x48, 0x50, 0xd1, 0xfd, 0x74, 0xa3,
	0x0a, 0xa6, 0x96, 0x3d, 0x60, 0x23, 0x9f, 0x88, 0x11, 0x4d, 0x3b, 0x29, 0xc4, 0x62, 0x94, 0x93,
	0x04, 0x4c, 0x6e, 0xb2, 0xc9, 0x0a, 0xc6, 0x21, 0xb5, 0x8e, 0x54, 0x13, 0x26, 0x82, 0x0a, 0xc4,
	0x0d, 0xa1, 0x19, 0xa9, 0xa4, 0xd0, 0xb3, 0xfb, 0x64, 0xe3, 0x8b, 0xd6, 0xc9, 0x40, 0x01, 0x3c,
	0x91, 0x2f, 0x24, 0xdc, 0x4a, 0x81, 0x50, 0x50, 0xa3, 0xad, 0xcd, 0x52, 0xdc, 0xf5, 0x4d, 0x03,
	0x92, 0xa9, 0x49, 0x6c, 0x42, 0xbd, 0x03, 0x89, 0x79, 0x8a, 0x89, 0x9a, 0x12, 0x37, 0x0a, 0x99,
	0x3b, 0xba, 0x9f, 0x8d, 0x7e, 0x7f, 0x06, 0x65, 0x94, 0x42, 0xeb, 0x21, 0x62, 0x4f, 0x9e, 0x13,
	0x2b, 0x05, 0x6c, 0xe6, 0x7d, 0x09, 0x08, 0xb9, 0x49, 0x77, 0xdb, 0x93, 0x6b, 0xcb, 0xd5, 0xf8,
	0xca, 0xce, 0x74, 0xfa, 0xe8, 0x78, 0xbe, 0x78, 0x62, 0x7d, 0xbe, 0xfb, 0xe4, 0xa2, 0x50, 0x0b,
	0x41, 0x6b, 0x21, 0x30, 0x8e, 0xcc, 0x9d, 0x7b, 0x0f, 0x01, 0x53, 0x5f, 0x5f, 0x50, 0x68, 0x48,
	0x55, 0xdc, 0x8d, 0x0d, 0xb4, 0x25, 0x68, 0x54, 0x5a, 0x51, 0xcf, 0xb9, 0x62, 0xcc, 0x10, 0x7b,
	0x0d, 0x0c, 0xec, 0x19, 0xb0, 0x56, 0x73, 0x9f, 0x8e, 0x1e, 0x9f, 0x41, 0x63, 0x81, 0x9a, 0x3d,
	0x65, 0x09, 0x1d, 0xc9, 0x67, 0x60, 0x50, 0x0b, 0x54, 0xd1, 0xb2, 0xc6, 0xaa, 0x22, 0xee, 0xe7,
	0x93, 0xcf, 0x96, 0xab, 0xf1, 0x8d, 0x53, 0x65, 0xec, 0x0d, 0x47, 0x87, 0xf2, 0xdd, 0x9f, 0x5e,
	0x88, 0x4d, 0x17, 0x87, 0xc3, 0xf1, 0xdb, 0x57, 0xf7, 0x87, 0x0b, 0xef, 0x57, 0x06, 0x34, 0xea,
	0x10, 0x80, 0x7d, 0x8f, 0x12, 0xb2, 0x81, 0x14, 0x6a, 0xb1, 0x55, 0xce, 0x3d, 0xb8, 0x5f, 0x4c,
	0x46, 0xcb, 0xd5, 0xf8, 0xea, 0x8e, 0xea, 0xbd, 0xa3, 0xb5, 0xd8, 0x66, 0xeb, 0x31, 0x2f, 0x3a,
	0x0f, 0x50, 0x7d, 0x01, 0xc4, 0xec, 0x3b, 0x96, 0x54, 0x7b, 0xcf, 0xd0, 0x40, 0xbc, 0x61, 0xc8,
	0xcc, 0xad, 0x8a, 0xfb, 0x6c, 0xb4, 0x73, 0xde, 0xb9, 0xaf, 0x14, 0x63, 0xca, 0xd1, 0xa0, 0xf4,
	0xc2, 0x6c, 0x09, 0x7a, 0x62, 0x8c, 0x44, 0xbd, 0x35, 0xb3, 0xec, 0x7e, 0x39, 0xf9, 0x68, 0xb9,
	0x1a, 0x8f, 0x76, 0x54, 0xcf, 0x08, 0x7d, 0x7a, 0x7c, 0xf8, 0x8f, 0x13, 0x7b, 0xb4, 0x91, 0x77,
	0xe9, 0xb5, 0xc7, 0x52, 0x35, 0x35, 0xc8, 0xa5, 0xb5, 0xe2, 0x6b, 0xc9, 0x61, 0x3d, 0x3e, 0x73,
	0xaa, 0x96, 0xcd, 0x7d, 0x3e, 0xfa, 0xdd, 0x79, 0xb5, 0xf5, 0x5e, 0x88, 0xa6, 0x51, 0x7a, 0x8e,
	0x11, 0x02, 0x47, 0x4e, 0xca, 0x41, 0x53, 0xb3, 0x10, 0x58, 0x8a, 0xfb, 0x62, 0xe2, 0x96, 0xab,
	0xf1, 0x7b, 0x3b, 0xaa, 0xbb, 0xc7, 0xf3, 0xaf, 0x89, 0xed, 0x68, 0x3e, 0xfa, 0xea, 0xbc, 0x4e,
	0xae, 0x99, 0x34, 0x5b, 0x2c, 0x66, 0x2d, 0x52, 0xcb, 0x99, 0x58, 0x63, 0x91, 0x54, 0x7d, 0x41,
	0x5f, 0xb2, 0xfb, 0xd5, 0xe4, 0xd3, 0xe5, 0x6a, 0x7c, 0xfd, 0x94, 0x94, 0x37, 0xf6, 0xf8, 0xca,
	0xbe, 0xfb, 0x66, 0x38, 0x7f, 0xd9, 0x1b, 0x86, 0xa3, 0xd1, 0xd3, 0xb3, 0x64, 0xa0, 0x6a, 0x5c,
	0x7d, 0x28, 0x79, 0xed, 0x60, 0xe1, 0x0a, 0x3d, 0x6b, 0xa8, 0xd1, 0x00, 0x72, 0x17, 0x0b, 0xee,
	0xd7, 0x93, 0x9b, 0xcb, 0xd5, 0xf8, 0x8b, 0x1d, 0xd5, 0x7d, 0x5b, 0x9c, 0x4c, 0xf7, 0xa7, 0x26,
	0x87, 0xfd, 0x50, 0x76, 0xa6, 0xd3, 0xdd, 0xc7, 0xfb, 0x4f, 0x86, 0x61, 0x71, 0x7f, 0x98, 0x9d,
	0x67, 0x7e, 0x8b, 0xf9, 0x5c, 0xd4, 0x7a, 0x4d, 0x66, 0x82, 0x91, 0x00, 0x22, 0xd4, 0x4e, 0xac,
	0xd8, 0x42, 0x6b, 0xd6, 0xd9, 0xdc, 0x97, 0x1b, 0xda, 0x52, 0x21, 0xd4, 0x80, 0xd6, 0xd5, 0xe7,
	0x14, 0x5b, 0x4a, 0x29, 0x24, 0x8b, 0x68, 0x45, 0xcd, 0x53, 0x66, 0x77, 0x73, 0x63, 0xa4, 0xf5,
	0xd6, 0xca, 0x58, 0xcd, 0x0c, 0x51, 0xd6, 0x53, 0x73, 0xb5, 0xa0, 0x1a, 0x3a, 0x15, 0x50, 0x36,
	0xf7, 0x9b, 0xd1, 0x83, 0x73, 0xd1, 0x26, 0xab, 0xec, 0x65, 0xbd, 0xfd, 0x93, 0x18, 0x36, 0x6f,
	0x2c, 0x5a, 0x9a, 0x56, 0x48, 0x98, 0x53, 0x13, 0xf7, 0xdb, 0xc9, 0xf5, 0xe5, 0x6a, 0x3c, 0xde,
	0x51, 0x7d, 0xb0, 0xf7, 0x74, 0x77, 0x76, 0xf8, 0xdc, 0x66, 0xfb, 0x8b, 0x61, 0x46, 0x07, 0xb6,
	0x47, 0x8b, 0x67, 0xf3, 0xd1, 0xdd, 0xf3, 0xab, 0x5a, 0xaf, 0xef, 0x98, 0x7d, 0x23, 0xae, 0xb5,
	0xd7, 0xe0, 0x8b, 0x64, 0x8e, 0xd8, 0x03, 0x20, 0x55, 0x22, 0x72, 0xb7, 0x26, 0x1f, 0x2f, 0x57,
	0xe3, 0xf7, 0xef, 0x1f, 0xbe, 0xd8, 0x7f, 0x46, 0x33, 0xd3, 0x35, 0x27, 0x5f, 0xdf, 0xbd, 0xff,
	0x97, 0xdd, 0xc7, 0x17, 0x32, 0x06, 0xb0, 0x12, 0x5a, 0x40, 0xf0, 0x2c, 0x44, 0x2d, 0xc7, 0x84,
	0x12, 0x7b, 0xb2, 0xc0, 0x14, 0x92, 0x26, 0x71, 0xb7, 0xdf, 0xc8, 0x78, 0xdf, 0x16, 0x3b, 0xd3,
	0xe9, 0x83, 0xa3, 0x81, 0xe9, 0xe8, 0x6d, 0x61, 0x85, 0xc0, 0xb1, 0xd6, 0x06, 0x1c, 0x02, 0x4a,
	0x24, 0xa2, 0x18, 0x25, 0x44, 0x52, 0xd1, 0x1a, 0x3a, 0x82, 0xbb, 0x33, 0xd9, 0xfa, 0xff, 0xff,
	0xc6, 0x97, 0xff, 0xb9, 0x1a, 0xff, 0x28, 0xf8, 0xbb, 0xd7, 0x5f, 0xfe, 0x77, 0xfb, 0xd2, 0xcb,
	0x57, 0xdb, 0x97, 0xbf, 0x7f, 0xb5, 0x7d, 0xf9, 0x3f, 0xaf, 0xb6, 0x2f, 0xff, 0xeb, 0xf5, 0xf6,
	0xa5, 0xef, 0x5f, 0x6f, 0x5f, 0xfa, 0xf7, 0xeb, 0xed, 0x4b, 0xfc, 0xe3, 0xd3, 0xff, 0x8d, 0xf4,
	0x43, 0x00, 0x00, 0x00, 0xff, 0xff, 0x55, 0x3c, 0x0a, 0xbe, 0xe6, 0x08, 0x00, 0x00,
}
var VersionHashStrings = []string{
	"HASH_d41d8cd98f00b204e9800998ecf8427e",
	"HASH_d4ca5418a77d22d968ce7a2afc549dfe",
	"HASH_7848d42e3a2eaf36e53bbd3af581b13a",
	"HASH_f31b7a9d7e06f72107e0ab13c708704e",
	"HASH_03fad51f0343d41f617329151f474d2b",
	"HASH_7d32a983fafc3da768e045b1dc4d5f50",
	"HASH_747c14bdfe2043f09d251568e4a722c6",
	"HASH_c7fb20f545a5bc9869b00bb770753c31",
	"HASH_83cd5c44b5c7387ebf7d055e7345ab42",
	"HASH_d8a4e697d0d693479cfd9c1c523d7e06",
	"HASH_e8360aa30f234ecefdfdb9fb2dc79c20",
	"HASH_c53c7840d242efc7209549a36fcf9e04",
	"HASH_1a57396698c4ade15f0579c9f5714cd6",
	"HASH_71c580746ee2a6b7d1a4182b3a54407a",
	"HASH_a18636af1f4272c38ca72881b2a8bcea",
	"HASH_efbddcee4ba444e3656f64e430a5e3be",
	"HASH_c2c322505017054033953f6104002bf5",
	"HASH_facc3c3c9c76463c8d8b3c874ce43487",
	"HASH_8ba950479a03ab77edfad426ea53c173",
	"HASH_f4eb139f7a8373a484ab9749eadc31f5",
	"HASH_09fae4d440aa06acb9664167d2e1f036",
	"HASH_8c5a9c29caff4ace0a23a9dab9a15bf7",
	"HASH_b7c6a74ce2f30b3bda179e00617459cf",
	"HASH_911d86a4eb2bbfbff1173ffbdd197a8c",
	"HASH_99349a696d0b5872542f81b4b0b4788e",
	"HASH_264850a5c1f7a054b4de1a87e5d28dcc",
	"HASH_748b47eaf414b0f2c15e4c6a9298b5f1",
	"HASH_1480647750f7638ff5494c0e715bb98c",
	"HASH_208a22352e46f6bbe34f3b72aaf99ee5",
	"HASH_6f8f268d3945699608651e1a8bb38e5e",
	"HASH_2dfdb2ed2cf52241b2b3db1d39e11bc6",
	"HASH_6585ad5e26ee92a955abd26c38067065",
	"HASH_4ddeb801651b2acb84f5d182e445fce1",
	"HASH_156def83eec72a44248fabd79199efbe",
	"HASH_636a7d17efd0532933313e27e6de0a5b",
	"HASH_0a418578eee77cabd2b8e1dd1fa64dbe",
	"HASH_93e8b0c0bb73ce790ebcd69d8437539c",
	"HASH_29fb22509ab88f8106c5b27f147a8aaa",
	"HASH_44e6191740bcaa95237c2f3e1ba13d3c",
	"HASH_611b28894b117c2aaa22c12adcd81f74",
}

const (
	VersionHashHASHD41D8Cd98F00B204E9800998Ecf8427E  uint64 = 1 << 0
	VersionHashHASHD4Ca5418A77D22D968Ce7A2Afc549Dfe  uint64 = 1 << 1
	VersionHashHASH_7848D42E3A2Eaf36E53Bbd3Af581B13A uint64 = 1 << 2
	VersionHashHASHF31B7A9D7E06F72107E0Ab13C708704E  uint64 = 1 << 3
	VersionHashHASH_03Fad51F0343D41F617329151F474D2B uint64 = 1 << 4
	VersionHashHASH_7D32A983Fafc3Da768E045B1Dc4D5F50 uint64 = 1 << 5
	VersionHashHASH_747C14Bdfe2043F09D251568E4A722C6 uint64 = 1 << 6
	VersionHashHASHC7Fb20F545A5Bc9869B00Bb770753C31  uint64 = 1 << 7
	VersionHashHASH_83Cd5C44B5C7387Ebf7D055E7345Ab42 uint64 = 1 << 8
	VersionHashHASHD8A4E697D0D693479Cfd9C1C523D7E06  uint64 = 1 << 9
	VersionHashHASHE8360Aa30F234Ecefdfdb9Fb2Dc79C20  uint64 = 1 << 10
	VersionHashHASHC53C7840D242Efc7209549A36Fcf9E04  uint64 = 1 << 11
	VersionHashHASH_1A57396698C4Ade15F0579C9F5714Cd6 uint64 = 1 << 12
	VersionHashHASH_71C580746Ee2A6B7D1A4182B3A54407A uint64 = 1 << 13
	VersionHashHASHA18636Af1F4272C38Ca72881B2A8Bcea  uint64 = 1 << 14
	VersionHashHASHEfbddcee4Ba444E3656F64E430A5E3Be  uint64 = 1 << 15
	VersionHashHASHC2C322505017054033953F6104002Bf5  uint64 = 1 << 16
	VersionHashHASHFacc3C3C9C76463C8D8B3C874Ce43487  uint64 = 1 << 17
	VersionHashHASH_8Ba950479A03Ab77Edfad426Ea53C173 uint64 = 1 << 18
	VersionHashHASHF4Eb139F7A8373A484Ab9749Eadc31F5  uint64 = 1 << 19
	VersionHashHASH_09Fae4D440Aa06Acb9664167D2E1F036 uint64 = 1 << 20
	VersionHashHASH_8C5A9C29Caff4Ace0A23A9Dab9A15Bf7 uint64 = 1 << 21
	VersionHashHASHB7C6A74Ce2F30B3Bda179E00617459Cf  uint64 = 1 << 22
	VersionHashHASH_911D86A4Eb2Bbfbff1173Ffbdd197A8C uint64 = 1 << 23
	VersionHashHASH_99349A696D0B5872542F81B4B0B4788E uint64 = 1 << 24
	VersionHashHASH_264850A5C1F7A054B4De1A87E5D28Dcc uint64 = 1 << 25
	VersionHashHASH_748B47Eaf414B0F2C15E4C6A9298B5F1 uint64 = 1 << 26
	VersionHashHASH_1480647750F7638Ff5494C0E715Bb98C uint64 = 1 << 27
	VersionHashHASH_208A22352E46F6Bbe34F3B72Aaf99Ee5 uint64 = 1 << 28
	VersionHashHASH_6F8F268D3945699608651E1A8Bb38E5E uint64 = 1 << 29
	VersionHashHASH_2Dfdb2Ed2Cf52241B2B3Db1D39E11Bc6 uint64 = 1 << 30
	VersionHashHASH_6585Ad5E26Ee92A955Abd26C38067065 uint64 = 1 << 31
	VersionHashHASH_4Ddeb801651B2Acb84F5D182E445Fce1 uint64 = 1 << 32
	VersionHashHASH_156Def83Eec72A44248Fabd79199Efbe uint64 = 1 << 33
	VersionHashHASH_636A7D17Efd0532933313E27E6De0A5B uint64 = 1 << 34
	VersionHashHASH_0A418578Eee77Cabd2B8E1Dd1Fa64Dbe uint64 = 1 << 35
	VersionHashHASH_93E8B0C0Bb73Ce790Ebcd69D8437539C uint64 = 1 << 36
	VersionHashHASH_29Fb22509Ab88F8106C5B27F147A8Aaa uint64 = 1 << 37
	VersionHashHASH_44E6191740Bcaa95237C2F3E1Ba13D3C uint64 = 1 << 38
	VersionHashHASH_611B28894B117C2Aaa22C12Adcd81F74 uint64 = 1 << 39
)

var VersionHash_CamelName = map[int32]string{
	// HASH_d41d8cd98f00b204e9800998ecf8427e -> HashD41D8Cd98F00B204E9800998Ecf8427E
	0: "HashD41D8Cd98F00B204E9800998Ecf8427E",
	// HASH_d4ca5418a77d22d968ce7a2afc549dfe -> HashD4Ca5418A77D22D968Ce7A2Afc549Dfe
	9: "HashD4Ca5418A77D22D968Ce7A2Afc549Dfe",
	// HASH_7848d42e3a2eaf36e53bbd3af581b13a -> Hash7848D42E3A2Eaf36E53Bbd3Af581B13A
	10: "Hash7848D42E3A2Eaf36E53Bbd3Af581B13A",
	// HASH_f31b7a9d7e06f72107e0ab13c708704e -> HashF31B7A9D7E06F72107E0Ab13C708704E
	11: "HashF31B7A9D7E06F72107E0Ab13C708704E",
	// HASH_03fad51f0343d41f617329151f474d2b -> Hash03Fad51F0343D41F617329151F474D2B
	12: "Hash03Fad51F0343D41F617329151F474D2B",
	// HASH_7d32a983fafc3da768e045b1dc4d5f50 -> Hash7D32A983Fafc3Da768E045B1Dc4D5F50
	13: "Hash7D32A983Fafc3Da768E045B1Dc4D5F50",
	// HASH_747c14bdfe2043f09d251568e4a722c6 -> Hash747C14Bdfe2043F09D251568E4A722C6
	14: "Hash747C14Bdfe2043F09D251568E4A722C6",
	// HASH_c7fb20f545a5bc9869b00bb770753c31 -> HashC7Fb20F545A5Bc9869B00Bb770753C31
	15: "HashC7Fb20F545A5Bc9869B00Bb770753C31",
	// HASH_83cd5c44b5c7387ebf7d055e7345ab42 -> Hash83Cd5C44B5C7387Ebf7D055E7345Ab42
	16: "Hash83Cd5C44B5C7387Ebf7D055E7345Ab42",
	// HASH_d8a4e697d0d693479cfd9c1c523d7e06 -> HashD8A4E697D0D693479Cfd9C1C523D7E06
	17: "HashD8A4E697D0D693479Cfd9C1C523D7E06",
	// HASH_e8360aa30f234ecefdfdb9fb2dc79c20 -> HashE8360Aa30F234Ecefdfdb9Fb2Dc79C20
	18: "HashE8360Aa30F234Ecefdfdb9Fb2Dc79C20",
	// HASH_c53c7840d242efc7209549a36fcf9e04 -> HashC53C7840D242Efc7209549A36Fcf9E04
	19: "HashC53C7840D242Efc7209549A36Fcf9E04",
	// HASH_1a57396698c4ade15f0579c9f5714cd6 -> Hash1A57396698C4Ade15F0579C9F5714Cd6
	20: "Hash1A57396698C4Ade15F0579C9F5714Cd6",
	// HASH_71c580746ee2a6b7d1a4182b3a54407a -> Hash71C580746Ee2A6B7D1A4182B3A54407A
	21: "Hash71C580746Ee2A6B7D1A4182B3A54407A",
	// HASH_a18636af1f4272c38ca72881b2a8bcea -> HashA18636Af1F4272C38Ca72881B2A8Bcea
	22: "HashA18636Af1F4272C38Ca72881B2A8Bcea",
	// HASH_efbddcee4ba444e3656f64e430a5e3be -> HashEfbddcee4Ba444E3656F64E430A5E3Be
	23: "HashEfbddcee4Ba444E3656F64E430A5E3Be",
	// HASH_c2c322505017054033953f6104002bf5 -> HashC2C322505017054033953F6104002Bf5
	24: "HashC2C322505017054033953F6104002Bf5",
	// HASH_facc3c3c9c76463c8d8b3c874ce43487 -> HashFacc3C3C9C76463C8D8B3C874Ce43487
	25: "HashFacc3C3C9C76463C8D8B3C874Ce43487",
	// HASH_8ba950479a03ab77edfad426ea53c173 -> Hash8Ba950479A03Ab77Edfad426Ea53C173
	26: "Hash8Ba950479A03Ab77Edfad426Ea53C173",
	// HASH_f4eb139f7a8373a484ab9749eadc31f5 -> HashF4Eb139F7A8373A484Ab9749Eadc31F5
	27: "HashF4Eb139F7A8373A484Ab9749Eadc31F5",
	// HASH_09fae4d440aa06acb9664167d2e1f036 -> Hash09Fae4D440Aa06Acb9664167D2E1F036
	28: "Hash09Fae4D440Aa06Acb9664167D2E1F036",
	// HASH_8c5a9c29caff4ace0a23a9dab9a15bf7 -> Hash8C5A9C29Caff4Ace0A23A9Dab9A15Bf7
	29: "Hash8C5A9C29Caff4Ace0A23A9Dab9A15Bf7",
	// HASH_b7c6a74ce2f30b3bda179e00617459cf -> HashB7C6A74Ce2F30B3Bda179E00617459Cf
	30: "HashB7C6A74Ce2F30B3Bda179E00617459Cf",
	// HASH_911d86a4eb2bbfbff1173ffbdd197a8c -> Hash911D86A4Eb2Bbfbff1173Ffbdd197A8C
	31: "Hash911D86A4Eb2Bbfbff1173Ffbdd197A8C",
	// HASH_99349a696d0b5872542f81b4b0b4788e -> Hash99349A696D0B5872542F81B4B0B4788E
	32: "Hash99349A696D0B5872542F81B4B0B4788E",
	// HASH_264850a5c1f7a054b4de1a87e5d28dcc -> Hash264850A5C1F7A054B4De1A87E5D28Dcc
	33: "Hash264850A5C1F7A054B4De1A87E5D28Dcc",
	// HASH_748b47eaf414b0f2c15e4c6a9298b5f1 -> Hash748B47Eaf414B0F2C15E4C6A9298B5F1
	34: "Hash748B47Eaf414B0F2C15E4C6A9298B5F1",
	// HASH_1480647750f7638ff5494c0e715bb98c -> Hash1480647750F7638Ff5494C0E715Bb98C
	35: "Hash1480647750F7638Ff5494C0E715Bb98C",
	// HASH_208a22352e46f6bbe34f3b72aaf99ee5 -> Hash208A22352E46F6Bbe34F3B72Aaf99Ee5
	36: "Hash208A22352E46F6Bbe34F3B72Aaf99Ee5",
	// HASH_6f8f268d3945699608651e1a8bb38e5e -> Hash6F8F268D3945699608651E1A8Bb38E5E
	37: "Hash6F8F268D3945699608651E1A8Bb38E5E",
	// HASH_2dfdb2ed2cf52241b2b3db1d39e11bc6 -> Hash2Dfdb2Ed2Cf52241B2B3Db1D39E11Bc6
	38: "Hash2Dfdb2Ed2Cf52241B2B3Db1D39E11Bc6",
	// HASH_6585ad5e26ee92a955abd26c38067065 -> Hash6585Ad5E26Ee92A955Abd26C38067065
	39: "Hash6585Ad5E26Ee92A955Abd26C38067065",
	// HASH_4ddeb801651b2acb84f5d182e445fce1 -> Hash4Ddeb801651B2Acb84F5D182E445Fce1
	40: "Hash4Ddeb801651B2Acb84F5D182E445Fce1",
	// HASH_156def83eec72a44248fabd79199efbe -> Hash156Def83Eec72A44248Fabd79199Efbe
	41: "Hash156Def83Eec72A44248Fabd79199Efbe",
	// HASH_636a7d17efd0532933313e27e6de0a5b -> Hash636A7D17Efd0532933313E27E6De0A5B
	42: "Hash636A7D17Efd0532933313E27E6De0A5B",
	// HASH_0a418578eee77cabd2b8e1dd1fa64dbe -> Hash0A418578Eee77Cabd2B8E1Dd1Fa64Dbe
	43: "Hash0A418578Eee77Cabd2B8E1Dd1Fa64Dbe",
	// HASH_93e8b0c0bb73ce790ebcd69d8437539c -> Hash93E8B0C0Bb73Ce790Ebcd69D8437539C
	44: "Hash93E8B0C0Bb73Ce790Ebcd69D8437539C",
	// HASH_29fb22509ab88f8106c5b27f147a8aaa -> Hash29Fb22509Ab88F8106C5B27F147A8Aaa
	45: "Hash29Fb22509Ab88F8106C5B27F147A8Aaa",
	// HASH_44e6191740bcaa95237c2f3e1ba13d3c -> Hash44E6191740Bcaa95237C2F3E1Ba13D3C
	46: "Hash44E6191740Bcaa95237C2F3E1Ba13D3C",
	// HASH_611b28894b117c2aaa22c12adcd81f74 -> Hash611B28894B117C2Aaa22C12Adcd81F74
	47: "Hash611B28894B117C2Aaa22C12Adcd81F74",
}
var VersionHash_CamelValue = map[string]int32{
	"HashD41D8Cd98F00B204E9800998Ecf8427E": 0,
	"HashD4Ca5418A77D22D968Ce7A2Afc549Dfe": 9,
	"Hash7848D42E3A2Eaf36E53Bbd3Af581B13A": 10,
	"HashF31B7A9D7E06F72107E0Ab13C708704E": 11,
	"Hash03Fad51F0343D41F617329151F474D2B": 12,
	"Hash7D32A983Fafc3Da768E045B1Dc4D5F50": 13,
	"Hash747C14Bdfe2043F09D251568E4A722C6": 14,
	"HashC7Fb20F545A5Bc9869B00Bb770753C31": 15,
	"Hash83Cd5C44B5C7387Ebf7D055E7345Ab42": 16,
	"HashD8A4E697D0D693479Cfd9C1C523D7E06": 17,
	"HashE8360Aa30F234Ecefdfdb9Fb2Dc79C20": 18,
	"HashC53C7840D242Efc7209549A36Fcf9E04": 19,
	"Hash1A57396698C4Ade15F0579C9F5714Cd6": 20,
	"Hash71C580746Ee2A6B7D1A4182B3A54407A": 21,
	"HashA18636Af1F4272C38Ca72881B2A8Bcea": 22,
	"HashEfbddcee4Ba444E3656F64E430A5E3Be": 23,
	"HashC2C322505017054033953F6104002Bf5": 24,
	"HashFacc3C3C9C76463C8D8B3C874Ce43487": 25,
	"Hash8Ba950479A03Ab77Edfad426Ea53C173": 26,
	"HashF4Eb139F7A8373A484Ab9749Eadc31F5": 27,
	"Hash09Fae4D440Aa06Acb9664167D2E1F036": 28,
	"Hash8C5A9C29Caff4Ace0A23A9Dab9A15Bf7": 29,
	"HashB7C6A74Ce2F30B3Bda179E00617459Cf": 30,
	"Hash911D86A4Eb2Bbfbff1173Ffbdd197A8C": 31,
	"Hash99349A696D0B5872542F81B4B0B4788E": 32,
	"Hash264850A5C1F7A054B4De1A87E5D28Dcc": 33,
	"Hash748B47Eaf414B0F2C15E4C6A9298B5F1": 34,
	"Hash1480647750F7638Ff5494C0E715Bb98C": 35,
	"Hash208A22352E46F6Bbe34F3B72Aaf99Ee5": 36,
	"Hash6F8F268D3945699608651E1A8Bb38E5E": 37,
	"Hash2Dfdb2Ed2Cf52241B2B3Db1D39E11Bc6": 38,
	"Hash6585Ad5E26Ee92A955Abd26C38067065": 39,
	"Hash4Ddeb801651B2Acb84F5D182E445Fce1": 40,
	"Hash156Def83Eec72A44248Fabd79199Efbe": 41,
	"Hash636A7D17Efd0532933313E27E6De0A5B": 42,
	"Hash0A418578Eee77Cabd2B8E1Dd1Fa64Dbe": 43,
	"Hash93E8B0C0Bb73Ce790Ebcd69D8437539C": 44,
	"Hash29Fb22509Ab88F8106C5B27F147A8Aaa": 45,
	"Hash44E6191740Bcaa95237C2F3E1Ba13D3C": 46,
	"Hash611B28894B117C2Aaa22C12Adcd81F74": 47,
}

func ParseVersionHash(data interface{}) (VersionHash, error) {
	if val, ok := data.(VersionHash); ok {
		return val, nil
	} else if str, ok := data.(string); ok {
		val, ok := VersionHash_CamelValue[util.CamelCase(str)]
		if !ok {
			// may have omitted common prefix
			val, ok = VersionHash_CamelValue["Hash"+util.CamelCase(str)]
		}
		if !ok {
			// may be int value instead of enum name
			ival, err := strconv.Atoi(str)
			val = int32(ival)
			if err == nil {
				_, ok = VersionHash_CamelName[val]
			}
		}
		if !ok {
			return VersionHash(0), fmt.Errorf("Invalid VersionHash value %q", str)
		}
		return VersionHash(val), nil
	} else if ival, ok := data.(int32); ok {
		if _, ok := VersionHash_CamelName[ival]; ok {
			return VersionHash(ival), nil
		} else {
			return VersionHash(0), fmt.Errorf("Invalid VersionHash value %d", ival)
		}
	}
	return VersionHash(0), fmt.Errorf("Invalid VersionHash value %v", data)
}

func (e *VersionHash) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var str string
	err := unmarshal(&str)
	if err != nil {
		return err
	}
	val, err := ParseVersionHash(str)
	if err != nil {
		return err
	}
	*e = val
	return nil
}

func (e VersionHash) MarshalYAML() (interface{}, error) {
	str := proto.EnumName(VersionHash_CamelName, int32(e))
	str = strings.TrimPrefix(str, "Hash")
	return str, nil
}

// custom JSON encoding/decoding
func (e *VersionHash) UnmarshalJSON(b []byte) error {
	var str string
	err := json.Unmarshal(b, &str)
	if err == nil {
		val, err := ParseVersionHash(str)
		if err != nil {
			return &json.UnmarshalTypeError{
				Value: "string " + str,
				Type:  reflect.TypeOf(VersionHash(0)),
			}
		}
		*e = VersionHash(val)
		return nil
	}
	var ival int32
	err = json.Unmarshal(b, &ival)
	if err == nil {
		val, err := ParseVersionHash(ival)
		if err == nil {
			*e = val
			return nil
		}
	}
	return &json.UnmarshalTypeError{
		Value: "value " + string(b),
		Type:  reflect.TypeOf(VersionHash(0)),
	}
}

func (e VersionHash) MarshalJSON() ([]byte, error) {
	str := proto.EnumName(VersionHash_CamelName, int32(e))
	str = strings.TrimPrefix(str, "Hash")
	return json.Marshal(str)
}

var VersionHashCommonPrefix = "Hash"

// Keys being hashed:
// AlertPolicyKey
// AppInstKey
// AppInstRefKey
// AppKey
// CloudletKey
// CloudletPoolKey
// ClusterInstKey
// ClusterInstRefKey
// ClusterKey
// ClusterRefsAppInstKey
// ControllerKey
// DeviceKey
// FedAppInstKey
// FlavorKey
// FlowRateLimitSettingsKey
// GPUDriverKey
// MaxReqsRateLimitSettingsKey
// NetworkKey
// NodeKey
// PolicyKey
// RateLimitSettingsKey
// ResTagTableKey
// TrustPolicyExceptionKey
// VMPoolKey
// VirtualClusterInstKey
var versionHashString = "611b28894b117c2aaa22c12adcd81f74"

func GetDataModelVersion() string {
	return versionHashString
}
