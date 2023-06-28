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
	VersionHash_HASH_611b28894b117c2aaa22c12adcd81f74 VersionHash = 47
	VersionHash_HASH_37dea30756fed2b0c0ecbc3e7b084855 VersionHash = 48
	VersionHash_HASH_1304c4ec69343ced28fd3ebc85f4a3a9 VersionHash = 49
	VersionHash_HASH_601fa4f6a8109f39e46adf1ea3b89197 VersionHash = 50
)

var VersionHash_name = map[int32]string{
	0:  "HASH_d41d8cd98f00b204e9800998ecf8427e",
	47: "HASH_611b28894b117c2aaa22c12adcd81f74",
	48: "HASH_37dea30756fed2b0c0ecbc3e7b084855",
	49: "HASH_1304c4ec69343ced28fd3ebc85f4a3a9",
	50: "HASH_601fa4f6a8109f39e46adf1ea3b89197",
}

var VersionHash_value = map[string]int32{
	"HASH_d41d8cd98f00b204e9800998ecf8427e": 0,
	"HASH_611b28894b117c2aaa22c12adcd81f74": 47,
	"HASH_37dea30756fed2b0c0ecbc3e7b084855": 48,
	"HASH_1304c4ec69343ced28fd3ebc85f4a3a9": 49,
	"HASH_601fa4f6a8109f39e46adf1ea3b89197": 50,
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
	// 366 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x3c, 0x90, 0x3b, 0x8b, 0xdb, 0x40,
	0x14, 0x85, 0xa5, 0x14, 0x01, 0x3b, 0x0f, 0x84, 0x48, 0x21, 0x44, 0x50, 0x97, 0x22, 0x01, 0x5b,
	0xf3, 0x92, 0x34, 0x43, 0x48, 0xe1, 0xa4, 0x71, 0x08, 0x84, 0x40, 0x42, 0xda, 0x30, 0x8f, 0x3b,
	0xb2, 0xc1, 0xf6, 0x08, 0x49, 0x0e, 0x71, 0x9b, 0xd2, 0xd5, 0x36, 0xfb, 0x9f, 0x5c, 0xba, 0xdc,
	0x72, 0xd7, 0xfe, 0x0b, 0x6b, 0xd8, 0x72, 0xb1, 0xec, 0x75, 0x75, 0x3f, 0x0e, 0xe7, 0xde, 0x73,
	0x39, 0xfd, 0x57, 0x7f, 0xa1, 0x6e, 0xa6, 0x6e, 0x31, 0xac, 0x6a, 0xd7, 0xba, 0xb0, 0x07, 0xa6,
	0x84, 0x0e, 0xe3, 0x2f, 0xe5, 0xb4, 0x9d, 0x2c, 0xd5, 0x50, 0xbb, 0x79, 0x7a, 0x54, 0xff, 0xd5,
	0xdd, 0x18, 0xe8, 0x99, 0x5b, 0x9a, 0x41, 0x35, 0x93, 0xad, 0x75, 0xf5, 0x3c, 0x6d, 0x9d, 0x9b,
	0x35, 0x69, 0xb7, 0x52, 0xc2, 0xe2, 0x02, 0xa7, 0x7b, 0xf1, 0x9b, 0xd2, 0x95, 0xae, 0xc3, 0xf4,
	0x48, 0x27, 0xf5, 0xc3, 0xf5, 0xb3, 0xfe, 0x8b, 0xdf, 0xa7, 0xdc, 0xb1, 0x6c, 0x26, 0xe1, 0xfb,
	0xfe, 0xbb, 0xf1, 0xe8, 0xe7, 0xf8, 0x8f, 0x61, 0xd8, 0x70, 0x6d, 0x04, 0xb7, 0x08, 0x29, 0x82,
	0x18, 0x08, 0x8e, 0x90, 0x10, 0x1c, 0xb4, 0xe5, 0x8c, 0x14, 0x10, 0x78, 0x17, 0x6b, 0x8e, 0xb1,
	0x22, 0x9c, 0x0b, 0xa6, 0x30, 0x2e, 0x34, 0x91, 0x52, 0x12, 0xa2, 0x31, 0x91, 0x46, 0x1b, 0x8e,
	0x6d, 0xc1, 0x82, 0x34, 0xfc, 0x74, 0xb6, 0xd2, 0xc2, 0x80, 0xa4, 0xa8, 0xc8, 0x72, 0x0b, 0x86,
	0x28, 0xa4, 0x11, 0x68, 0xa5, 0x29, 0x14, 0x0a, 0x71, 0xc6, 0xb3, 0x2c, 0x40, 0x71, 0xb8, 0x3e,
	0x44, 0xaf, 0x47, 0x55, 0xf5, 0x75, 0xd1, 0xb4, 0xdf, 0x60, 0xf5, 0x5d, 0xce, 0xe1, 0x92, 0x84,
	0x29, 0x62, 0x9a, 0x81, 0xce, 0x05, 0x65, 0x54, 0x83, 0x21, 0xdc, 0x1a, 0x0a, 0x4a, 0xf3, 0xcc,
	0x32, 0x49, 0xa5, 0x08, 0x70, 0xf8, 0xf1, 0xe9, 0x29, 0x84, 0xad, 0x64, 0x36, 0x97, 0x1c, 0x23,
	0x61, 0xa9, 0x00, 0x96, 0x4b, 0x63, 0x31, 0x48, 0xaa, 0xb8, 0xc0, 0xa2, 0x08, 0x48, 0x1c, 0xac,
	0x0f, 0xd1, 0xcb, 0x1f, 0xe7, 0xf2, 0x7e, 0xad, 0x2a, 0x88, 0x7b, 0x0f, 0xf7, 0x91, 0xff, 0xff,
	0x10, 0xf9, 0xe4, 0xf3, 0xdb, 0xcd, 0x5d, 0xe2, 0x6d, 0x76, 0x89, 0xbf, 0xdd, 0x25, 0xfe, 0xed,
	0x2e, 0xf1, 0xaf, 0xf6, 0x89, 0xb7, 0xdd, 0x27, 0xde, 0xcd, 0x3e, 0xf1, 0xd4, 0xf3, 0xae, 0x3c,
	0xfa, 0x18, 0x00, 0x00, 0xff, 0xff, 0x50, 0x5d, 0x34, 0xd2, 0xb3, 0x01, 0x00, 0x00,
}
var VersionHashStrings = []string{
	"HASH_d41d8cd98f00b204e9800998ecf8427e",
	"HASH_611b28894b117c2aaa22c12adcd81f74",
	"HASH_37dea30756fed2b0c0ecbc3e7b084855",
	"HASH_1304c4ec69343ced28fd3ebc85f4a3a9",
	"HASH_601fa4f6a8109f39e46adf1ea3b89197",
}

const (
	VersionHashHASHD41D8Cd98F00B204E9800998Ecf8427E  uint64 = 1 << 0
	VersionHashHASH_611B28894B117C2Aaa22C12Adcd81F74 uint64 = 1 << 1
	VersionHashHASH_37Dea30756Fed2B0C0Ecbc3E7B084855 uint64 = 1 << 2
	VersionHashHASH_1304C4Ec69343Ced28Fd3Ebc85F4A3A9 uint64 = 1 << 3
	VersionHashHASH_601Fa4F6A8109F39E46Adf1Ea3B89197 uint64 = 1 << 4
)

var VersionHash_CamelName = map[int32]string{
	// HASH_d41d8cd98f00b204e9800998ecf8427e -> HashD41D8Cd98F00B204E9800998Ecf8427E
	0: "HashD41D8Cd98F00B204E9800998Ecf8427E",
	// HASH_611b28894b117c2aaa22c12adcd81f74 -> Hash611B28894B117C2Aaa22C12Adcd81F74
	47: "Hash611B28894B117C2Aaa22C12Adcd81F74",
	// HASH_37dea30756fed2b0c0ecbc3e7b084855 -> Hash37Dea30756Fed2B0C0Ecbc3E7B084855
	48: "Hash37Dea30756Fed2B0C0Ecbc3E7B084855",
	// HASH_1304c4ec69343ced28fd3ebc85f4a3a9 -> Hash1304C4Ec69343Ced28Fd3Ebc85F4A3A9
	49: "Hash1304C4Ec69343Ced28Fd3Ebc85F4A3A9",
	// HASH_601fa4f6a8109f39e46adf1ea3b89197 -> Hash601Fa4F6A8109F39E46Adf1Ea3B89197
	50: "Hash601Fa4F6A8109F39E46Adf1Ea3B89197",
}
var VersionHash_CamelValue = map[string]int32{
	"HashD41D8Cd98F00B204E9800998Ecf8427E": 0,
	"Hash611B28894B117C2Aaa22C12Adcd81F74": 47,
	"Hash37Dea30756Fed2B0C0Ecbc3E7B084855": 48,
	"Hash1304C4Ec69343Ced28Fd3Ebc85F4A3A9": 49,
	"Hash601Fa4F6A8109F39E46Adf1Ea3B89197": 50,
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
// AppInstKeyV1
// AppInstRefKey
// AppKey
// CloudletKey
// CloudletPoolKey
// ClusterInstKey
// ClusterInstKeyV1
// ClusterKey
// ClusterKeyV1
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
// VirtualClusterInstKeyV1
var versionHashString = "601fa4f6a8109f39e46adf1ea3b89197"

func GetDataModelVersion() string {
	return versionHashString
}
