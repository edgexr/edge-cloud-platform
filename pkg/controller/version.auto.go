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

type VersionUpgrade struct {
	id          int32
	hash        string
	upgradeFunc VersionUpgradeFunc
	name        string
}

var VersionHash_UpgradeFuncs = []VersionUpgrade{
	{0, "d41d8cd98f00b204e9800998ecf8427e", nil, ""},
	{52, "c2d882033b0c14f28cece41cf4010060", nil, ""},
	{53, "14ae4c721c1bace6e8379d0061a72a77", UpgradeCrmOnEdge, "UpgradeCrmOnEdge"},
	{54, "eff9d3a6c74fd02840efce05d1984e8d", AddStaticFqdn, "AddStaticFqdn"},
	{55, "eac56710c013d954db31eeb306b514a4", InstanceKeysRegionScopedName, "InstanceKeysRegionScopedName"},
	{56, "75883d14000640b2ecf694fe8ef9192b", ZoneFeature, "ZoneFeature"},
	{57, "e65c39ec2a489834dd06e87f7239f9a8", NodePoolsFeature, "NodePoolsFeature"},
	{58, "b25b4e18e9a1dadfd3006e23fabfbf95", AppObjID, "AppObjID"},
	{59, "abec45b13db5cd29e3bcf63d3b80be29", nil, ""},
	{60, "2d0b51b0cb6eaff42225cd1795e168e7", nil, ""},
}

// Auto-generated code: DO NOT EDIT
