// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: version.proto

package main

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
	48: AppInstKeyName,
}
var VersionHash_UpgradeFuncNames = map[int32]string{
	0:  "",
	47: "",
	48: "AppInstKeyName",
}

// Auto-generated code: DO NOT EDIT
