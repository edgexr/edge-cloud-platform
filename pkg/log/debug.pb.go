// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: debug.proto

package log

import (
	"encoding/json"
	fmt "fmt"
	"github.com/edgexr/edge-cloud-platform/util"
	proto "github.com/gogo/protobuf/proto"
	math "math"
	reflect "reflect"
	"strconv"
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

type DebugLevel int32

const (
	DebugLevel_etcd    DebugLevel = 0
	DebugLevel_api     DebugLevel = 1
	DebugLevel_notify  DebugLevel = 2
	DebugLevel_dmedb   DebugLevel = 3
	DebugLevel_dmereq  DebugLevel = 4
	DebugLevel_locapi  DebugLevel = 5
	DebugLevel_infra   DebugLevel = 6
	DebugLevel_metrics DebugLevel = 7
	DebugLevel_upgrade DebugLevel = 8
	DebugLevel_info    DebugLevel = 9
	DebugLevel_sampled DebugLevel = 10
	DebugLevel_events  DebugLevel = 11
	DebugLevel_fedapi  DebugLevel = 12
)

var DebugLevel_name = map[int32]string{
	0:  "etcd",
	1:  "api",
	2:  "notify",
	3:  "dmedb",
	4:  "dmereq",
	5:  "locapi",
	6:  "infra",
	7:  "metrics",
	8:  "upgrade",
	9:  "info",
	10: "sampled",
	11: "events",
	12: "fedapi",
}

var DebugLevel_value = map[string]int32{
	"etcd":    0,
	"api":     1,
	"notify":  2,
	"dmedb":   3,
	"dmereq":  4,
	"locapi":  5,
	"infra":   6,
	"metrics": 7,
	"upgrade": 8,
	"info":    9,
	"sampled": 10,
	"events":  11,
	"fedapi":  12,
}

func (x DebugLevel) String() string {
	return proto.EnumName(DebugLevel_name, int32(x))
}

func (DebugLevel) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_8d9d361be58531fb, []int{0}
}

func init() {
	proto.RegisterEnum("log.DebugLevel", DebugLevel_name, DebugLevel_value)
}

func init() { proto.RegisterFile("debug.proto", fileDescriptor_8d9d361be58531fb) }

var fileDescriptor_8d9d361be58531fb = []byte{
	// 197 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x1c, 0x8f, 0xcd, 0x4d, 0xc4, 0x30,
	0x10, 0x85, 0xd7, 0x64, 0x37, 0xd9, 0x9d, 0x70, 0x18, 0xb9, 0x00, 0x17, 0xc0, 0x81, 0x0b, 0x1d,
	0x20, 0x8e, 0x34, 0xe1, 0x64, 0xc6, 0x91, 0x25, 0xff, 0xe1, 0x78, 0x23, 0xd1, 0x0e, 0xd5, 0xe4,
	0x48, 0x09, 0x90, 0x4a, 0xd0, 0x70, 0x7b, 0xf3, 0xe9, 0xe9, 0x1b, 0x3d, 0x18, 0x89, 0xa7, 0xfb,
	0xf2, 0x5c, 0x6a, 0x6e, 0x59, 0x77, 0x21, 0x2f, 0x4f, 0x5f, 0x0a, 0xe0, 0x4d, 0xe0, 0x3b, 0x6f,
	0x1c, 0xf4, 0x15, 0xce, 0xdc, 0x66, 0xc2, 0x93, 0x1e, 0xa0, 0xb3, 0xc5, 0xa3, 0xd2, 0x00, 0x7d,
	0xca, 0xcd, 0xbb, 0x4f, 0x7c, 0xd0, 0x37, 0xb8, 0x50, 0x64, 0x9a, 0xb0, 0x13, 0x4c, 0x91, 0x2b,
	0x7f, 0xe0, 0x59, 0x72, 0xc8, 0xb3, 0xd4, 0x2f, 0x52, 0xf1, 0xc9, 0x55, 0x8b, 0xbd, 0x1e, 0x61,
	0x88, 0xdc, 0xaa, 0x9f, 0x57, 0x1c, 0xe4, 0xb8, 0x97, 0xa5, 0x5a, 0x62, 0xbc, 0xca, 0x1b, 0x9f,
	0x5c, 0xc6, 0x9b, 0xe0, 0xd5, 0xc6, 0x12, 0x98, 0x10, 0xc4, 0xc3, 0x1b, 0xa7, 0xb6, 0xe2, 0x28,
	0xd9, 0x31, 0x89, 0xf3, 0xf1, 0x15, 0xf7, 0x5f, 0x73, 0xda, 0x0f, 0xa3, 0xbe, 0x0f, 0xa3, 0x7e,
	0x0e, 0xa3, 0xa6, 0xfe, 0x7f, 0xc2, 0xcb, 0x5f, 0x00, 0x00, 0x00, 0xff, 0xff, 0x05, 0x3f, 0x7b,
	0xac, 0xd1, 0x00, 0x00, 0x00,
}
var DebugLevelStrings = []string{
	"etcd",
	"api",
	"notify",
	"dmedb",
	"dmereq",
	"locapi",
	"infra",
	"metrics",
	"upgrade",
	"info",
	"sampled",
	"events",
	"fedapi",
}

const (
	DebugLevelEtcd    uint64 = 1 << 0
	DebugLevelApi     uint64 = 1 << 1
	DebugLevelNotify  uint64 = 1 << 2
	DebugLevelDmedb   uint64 = 1 << 3
	DebugLevelDmereq  uint64 = 1 << 4
	DebugLevelLocapi  uint64 = 1 << 5
	DebugLevelInfra   uint64 = 1 << 6
	DebugLevelMetrics uint64 = 1 << 7
	DebugLevelUpgrade uint64 = 1 << 8
	DebugLevelInfo    uint64 = 1 << 9
	DebugLevelSampled uint64 = 1 << 10
	DebugLevelEvents  uint64 = 1 << 11
	DebugLevelFedapi  uint64 = 1 << 12
)

var DebugLevel_CamelName = map[int32]string{
	// etcd -> Etcd
	0: "Etcd",
	// api -> Api
	1: "Api",
	// notify -> Notify
	2: "Notify",
	// dmedb -> Dmedb
	3: "Dmedb",
	// dmereq -> Dmereq
	4: "Dmereq",
	// locapi -> Locapi
	5: "Locapi",
	// infra -> Infra
	6: "Infra",
	// metrics -> Metrics
	7: "Metrics",
	// upgrade -> Upgrade
	8: "Upgrade",
	// info -> Info
	9: "Info",
	// sampled -> Sampled
	10: "Sampled",
	// events -> Events
	11: "Events",
	// fedapi -> Fedapi
	12: "Fedapi",
}
var DebugLevel_CamelValue = map[string]int32{
	"Etcd":    0,
	"Api":     1,
	"Notify":  2,
	"Dmedb":   3,
	"Dmereq":  4,
	"Locapi":  5,
	"Infra":   6,
	"Metrics": 7,
	"Upgrade": 8,
	"Info":    9,
	"Sampled": 10,
	"Events":  11,
	"Fedapi":  12,
}

func ParseDebugLevel(data interface{}) (DebugLevel, error) {
	if val, ok := data.(DebugLevel); ok {
		return val, nil
	} else if str, ok := data.(string); ok {
		val, ok := DebugLevel_CamelValue[util.CamelCase(str)]
		if !ok {
			// may be int value instead of enum name
			ival, err := strconv.Atoi(str)
			val = int32(ival)
			if err == nil {
				_, ok = DebugLevel_CamelName[val]
			}
		}
		if !ok {
			return DebugLevel(0), fmt.Errorf("Invalid DebugLevel value %q", str)
		}
		return DebugLevel(val), nil
	} else if ival, ok := data.(int32); ok {
		if _, ok := DebugLevel_CamelName[ival]; ok {
			return DebugLevel(ival), nil
		} else {
			return DebugLevel(0), fmt.Errorf("Invalid DebugLevel value %d", ival)
		}
	}
	return DebugLevel(0), fmt.Errorf("Invalid DebugLevel value %v", data)
}

func (e *DebugLevel) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var str string
	err := unmarshal(&str)
	if err != nil {
		return err
	}
	val, err := ParseDebugLevel(str)
	if err != nil {
		return err
	}
	*e = val
	return nil
}

func (e DebugLevel) MarshalYAML() (interface{}, error) {
	str := proto.EnumName(DebugLevel_CamelName, int32(e))
	return str, nil
}

// custom JSON encoding/decoding
func (e *DebugLevel) UnmarshalJSON(b []byte) error {
	var str string
	err := json.Unmarshal(b, &str)
	if err == nil {
		val, err := ParseDebugLevel(str)
		if err != nil {
			return &json.UnmarshalTypeError{
				Value: "string " + str,
				Type:  reflect.TypeOf(DebugLevel(0)),
			}
		}
		*e = DebugLevel(val)
		return nil
	}
	var ival int32
	err = json.Unmarshal(b, &ival)
	if err == nil {
		val, err := ParseDebugLevel(ival)
		if err == nil {
			*e = val
			return nil
		}
	}
	return &json.UnmarshalTypeError{
		Value: "value " + string(b),
		Type:  reflect.TypeOf(DebugLevel(0)),
	}
}

func (e DebugLevel) MarshalJSON() ([]byte, error) {
	str := proto.EnumName(DebugLevel_CamelName, int32(e))
	return json.Marshal(str)
}

type MatchOptions struct {
	// Filter will ignore 0 or nil fields on the passed in object
	Filter bool
	// IgnoreBackend will ignore fields that were marked backend in .proto
	IgnoreBackend bool
	// Sort repeated (arrays) of Key objects so matching does not
	// fail due to order.
	SortArrayedKeys bool
}

type MatchOpt func(*MatchOptions)

func MatchFilter() MatchOpt {
	return func(opts *MatchOptions) {
		opts.Filter = true
	}
}

func MatchIgnoreBackend() MatchOpt {
	return func(opts *MatchOptions) {
		opts.IgnoreBackend = true
	}
}

func MatchSortArrayedKeys() MatchOpt {
	return func(opts *MatchOptions) {
		opts.SortArrayedKeys = true
	}
}

func applyMatchOptions(opts *MatchOptions, args ...MatchOpt) {
	for _, f := range args {
		f(opts)
	}
}

// DecodeHook for use with the mapstructure package.
// Allows decoding to handle protobuf enums that are
// represented as strings.
func EnumDecodeHook(from, to reflect.Type, data interface{}) (interface{}, error) {
	switch to {
	case reflect.TypeOf(DebugLevel(0)):
		return ParseDebugLevel(data)
	}
	return data, nil
}

// GetEnumParseHelp gets end-user specific messages for
// enum parse errors.
// It returns the enum type name, a help message with
// valid values, and a bool that indicates if a type was matched.
func GetEnumParseHelp(t reflect.Type) (string, string, bool) {
	switch t {
	case reflect.TypeOf(DebugLevel(0)):
		return "DebugLevel", ", valid values are one of Etcd, Api, Notify, Dmedb, Dmereq, Locapi, Infra, Metrics, Upgrade, Info, Sampled, Events, Fedapi, or 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12", true
	}
	return "", "", false
}

var ShowMethodNames = map[string]struct{}{}

func IsShow(cmd string) bool {
	_, found := ShowMethodNames[cmd]
	return found
}