// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: version.proto

package controller

import (
	fmt "fmt"
	_ "github.com/edgexr/edge-cloud-platform/tools/protogen"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

var VersionHash_UpgradeFuncs = map[int32]VersionUpgradeFunc{
	0:  nil,
	47: nil,
	48: nil,
	49: nil,
	50: nil,
	51: nil,
	52: nil,
	53: UpgradeCrmOnEdge,
	54: AddStaticFqdn,
	55: InstanceKeysRegionScopedName,
}
var VersionHash_UpgradeFuncNames = map[int32]string{
	0:  "",
	47: "",
	48: "",
	49: "",
	50: "",
	51: "",
	52: "",
	53: "UpgradeCrmOnEdge",
	54: "AddStaticFqdn",
	55: "InstanceKeysRegionScopedName",
}

// Auto-generated code: DO NOT EDIT
