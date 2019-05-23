// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: version.proto

package edgeproto

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/googleapis/google/api"
import _ "github.com/mobiledgex/edge-cloud/protogen"
import _ "github.com/mobiledgex/edge-cloud/protoc-gen-cmd/protocmd"

import "errors"
import "strconv"
import "encoding/json"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Below enum lists hashes as well as corresponding versions
type VersionHash int32

const (
	VersionHash_HASH_d41d8cd98f00b204e9800998ecf8427e VersionHash = 0
	VersionHash_HASH_b35326df0fcd1550b7c0cf6460c4bca2 VersionHash = 1
	VersionHash_HASH_52e6980599cd59bbbd0de8d5f4d53d4b VersionHash = 2
	VersionHash_HASH_00bdcfa956ca4ee42be87abcd8fcaf1c VersionHash = 3
)

var VersionHash_name = map[int32]string{
	0: "HASH_d41d8cd98f00b204e9800998ecf8427e",
	1: "HASH_b35326df0fcd1550b7c0cf6460c4bca2",
	2: "HASH_52e6980599cd59bbbd0de8d5f4d53d4b",
	3: "HASH_00bdcfa956ca4ee42be87abcd8fcaf1c",
}
var VersionHash_value = map[string]int32{
	"HASH_d41d8cd98f00b204e9800998ecf8427e": 0,
	"HASH_b35326df0fcd1550b7c0cf6460c4bca2": 1,
	"HASH_52e6980599cd59bbbd0de8d5f4d53d4b": 2,
	"HASH_00bdcfa956ca4ee42be87abcd8fcaf1c": 3,
}

func (x VersionHash) String() string {
	return proto.EnumName(VersionHash_name, int32(x))
}
func (VersionHash) EnumDescriptor() ([]byte, []int) { return fileDescriptorVersion, []int{0} }

func init() {
	proto.RegisterEnum("edgeproto.VersionHash", VersionHash_name, VersionHash_value)
}

var VersionHashStrings = []string{
	"HASH_d41d8cd98f00b204e9800998ecf8427e",
	"HASH_b35326df0fcd1550b7c0cf6460c4bca2",
	"HASH_52e6980599cd59bbbd0de8d5f4d53d4b",
	"HASH_00bdcfa956ca4ee42be87abcd8fcaf1c",
}

const (
	VersionHashHASHD41D8Cd98F00B204E9800998Ecf8427E  uint64 = 1 << 0
	VersionHashHASHB35326Df0Fcd1550B7C0Cf6460C4Bca2  uint64 = 1 << 1
	VersionHashHASH_52E6980599Cd59Bbbd0De8D5F4D53D4B uint64 = 1 << 2
	VersionHashHASH_00Bdcfa956Ca4Ee42Be87Abcd8Fcaf1C uint64 = 1 << 3
)

func (e *VersionHash) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var str string
	err := unmarshal(&str)
	if err != nil {
		return err
	}
	val, ok := VersionHash_value[str]
	if !ok {
		// may be enum value instead of string
		ival, err := strconv.Atoi(str)
		val = int32(ival)
		if err == nil {
			_, ok = VersionHash_name[val]
		}
	}
	if !ok {
		return errors.New(fmt.Sprintf("No enum value for %s", str))
	}
	*e = VersionHash(val)
	return nil
}

func (e VersionHash) MarshalYAML() (interface{}, error) {
	return e.String(), nil
}

// custom JSON encoding/decoding
func (e *VersionHash) UnmarshalJSON(b []byte) error {
	var str string
	err := json.Unmarshal(b, &str)
	if err == nil {
		val, ok := VersionHash_value[str]
		if !ok {
			// may be int value instead of enum name
			ival, err := strconv.Atoi(str)
			val = int32(ival)
			if err == nil {
				_, ok = VersionHash_name[val]
			}
		}
		if !ok {
			return errors.New(fmt.Sprintf("No enum value for %s", str))
		}
		*e = VersionHash(val)
		return nil
	}
	var val int32
	err = json.Unmarshal(b, &val)
	if err == nil {
		*e = VersionHash(val)
		return nil
	}
	return fmt.Errorf("No enum value for %v", b)
}

func (e VersionHash) MarshalJSON() ([]byte, error) {
	return []byte("\"" + e.String() + "\""), nil
}

// Keys being hashed:
// AppInstKey
// AppKey
// CloudletKey
// ClusterInstKey
// ClusterKey
// ControllerKey
// DeveloperKey
// FlavorKey
// NodeKey
// OperatorKey
var versionHashString = "00bdcfa956ca4ee42be87abcd8fcaf1c"

func GetDataModelVersion() string {
	return versionHashString
}

var VersionHash_UpgradeFuncs = map[int32]VersionUpgradeFunc{
	0: nil,
	1: TestUpgradeExample,
	2: nil,
	3: AddClusterInstKeyToAppInstKey,
}
var VersionHash_UpgradeFuncNames = map[int32]string{
	0: "",
	1: "TestUpgradeExample",
	2: "",
	3: "AddClusterInstKeyToAppInstKey",
}

func init() { proto.RegisterFile("version.proto", fileDescriptorVersion) }

var fileDescriptorVersion = []byte{
	// 360 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x90, 0x41, 0xab, 0xd3, 0x40,
	0x10, 0xc7, 0x1b, 0x05, 0xd1, 0x8a, 0x10, 0x72, 0x90, 0x10, 0x34, 0xe0, 0xc1, 0x83, 0x42, 0x5f,
	0xb6, 0xc9, 0x6e, 0xba, 0x7b, 0x8c, 0x22, 0x56, 0xf4, 0xe6, 0xd3, 0xab, 0xec, 0xce, 0xcc, 0xe6,
	0x05, 0x92, 0x6c, 0x48, 0x52, 0x79, 0x5e, 0x3d, 0xbe, 0x4f, 0xd6, 0xa3, 0x1f, 0x41, 0xfb, 0x19,
	0x2c, 0x78, 0x12, 0x69, 0x1b, 0x8b, 0x47, 0x2f, 0xc3, 0x6f, 0xe0, 0xf7, 0x9f, 0x19, 0x66, 0xfe,
	0xe0, 0x33, 0xf5, 0x43, 0xe5, 0xda, 0x8b, 0xae, 0x77, 0xa3, 0x0b, 0xee, 0x11, 0x96, 0x74, 0xc4,
	0xe8, 0x51, 0xe9, 0x5c, 0x59, 0x53, 0xa2, 0xbb, 0x2a, 0xd1, 0x6d, 0xeb, 0x46, 0x3d, 0x56, 0xae,
	0x1d, 0x4e, 0x62, 0x24, 0xcb, 0x6a, 0xbc, 0xda, 0x98, 0x0b, 0x70, 0x4d, 0xd2, 0x38, 0x53, 0xd5,
	0x87, 0xe0, 0x75, 0x72, 0xa8, 0x0b, 0xa8, 0xdd, 0x06, 0x93, 0xa3, 0x57, 0x52, 0x7b, 0x86, 0x29,
	0xf9, 0xfa, 0xff, 0x92, 0xb0, 0x28, 0xa9, 0x5d, 0x40, 0xf3, 0xb7, 0xfd, 0x07, 0x4e, 0x83, 0x9e,
	0xff, 0xf6, 0xe6, 0xf7, 0x3f, 0x9e, 0xae, 0x5f, 0xeb, 0xe1, 0x2a, 0x78, 0x36, 0x7f, 0xba, 0x2e,
	0xde, 0xaf, 0x3f, 0x21, 0x5f, 0xa2, 0x04, 0x54, 0xd2, 0x32, 0x66, 0x52, 0xc6, 0x49, 0x49, 0xc6,
	0x94, 0x92, 0x04, 0x56, 0xf2, 0x74, 0x45, 0xfe, 0x2c, 0x28, 0x26, 0xd5, 0x64, 0x22, 0x4b, 0x73,
	0xb4, 0xcc, 0x02, 0x2e, 0x85, 0x60, 0x66, 0x05, 0x0c, 0x6c, 0xce, 0x73, 0x06, 0xdc, 0x80, 0x4e,
	0x7d, 0x2f, 0x7a, 0x78, 0xb3, 0x0f, 0x83, 0x4b, 0x1a, 0xc6, 0x0f, 0x5d, 0xd9, 0x6b, 0xa4, 0x57,
	0xd7, 0xba, 0xe9, 0x6a, 0x3a, 0x6f, 0x13, 0x29, 0xe5, 0x4a, 0x32, 0xa1, 0x14, 0xa0, 0x50, 0xc6,
	0x18, 0x64, 0x48, 0x12, 0x85, 0xe5, 0x28, 0x32, 0xe4, 0xc6, 0xbf, 0x15, 0xbc, 0x9b, 0x54, 0xc6,
	0x0c, 0x82, 0xd5, 0x4a, 0xe4, 0xa0, 0x39, 0x11, 0x4f, 0x0d, 0xc9, 0x95, 0x36, 0x80, 0xd2, 0x82,
	0xb6, 0x4b, 0xf0, 0x6f, 0x47, 0x4f, 0x6e, 0xf6, 0xe1, 0xe3, 0x02, 0xf1, 0x65, 0xbd, 0x19, 0x46,
	0xea, 0xdf, 0xb4, 0xc3, 0xf8, 0x96, 0xbe, 0x5c, 0xba, 0xa2, 0xeb, 0x26, 0x8e, 0xee, 0xfe, 0xfa,
	0x19, 0x7a, 0x5f, 0xf7, 0xe1, 0xec, 0x85, 0xbf, 0xfd, 0x11, 0xcf, 0xb6, 0xbb, 0xd8, 0xfb, 0xb6,
	0x8b, 0xbd, 0xef, 0xbb, 0xd8, 0x33, 0x77, 0x8e, 0x9f, 0xc9, 0xfe, 0x04, 0x00, 0x00, 0xff, 0xff,
	0x6a, 0xb5, 0xcc, 0x64, 0xd6, 0x01, 0x00, 0x00,
}