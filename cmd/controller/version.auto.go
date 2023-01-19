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
	9:  nil,
	10: nil,
	11: nil,
	12: nil,
	13: nil,
	14: nil,
	15: nil,
	16: nil,
	17: nil,
	18: nil,
	19: nil,
	20: CheckForHttpPorts,
	21: PrunePlatosPlatformDevices,
	22: SetTrusted,
	23: nil,
	24: CloudletResourceUpgradeFunc,
	25: nil,
	26: nil,
	27: nil,
	28: nil,
	29: nil,
	30: AppInstRefsDR,
	31: nil,
	32: nil,
	33: TrustPolicyExceptionUpgradeFunc,
	34: AddClusterRefs,
	35: nil,
	36: AddAppInstUniqueId,
	37: nil,
	38: AddDnsLabels,
	39: AddCloudletKeyToCloudletPool,
	40: AddSetupSpecificAppDNSRootForCloudlets,
	41: nil,
	42: nil,
	43: nil,
	44: AddGPUDriverStoragePaths,
	45: FixSharedRootLBFQDN,
	46: SetAppFederatedId,
}
var VersionHash_UpgradeFuncNames = map[int32]string{
	0:  "",
	9:  "",
	10: "",
	11: "",
	12: "",
	13: "",
	14: "",
	15: "",
	16: "",
	17: "",
	18: "",
	19: "",
	20: "CheckForHttpPorts",
	21: "PrunePlatosPlatformDevices",
	22: "SetTrusted",
	23: "",
	24: "CloudletResourceUpgradeFunc",
	25: "",
	26: "",
	27: "",
	28: "",
	29: "",
	30: "AppInstRefsDR",
	31: "",
	32: "",
	33: "TrustPolicyExceptionUpgradeFunc",
	34: "AddClusterRefs",
	35: "",
	36: "AddAppInstUniqueId",
	37: "",
	38: "AddDnsLabels",
	39: "AddCloudletKeyToCloudletPool",
	40: "AddSetupSpecificAppDNSRootForCloudlets",
	41: "",
	42: "",
	43: "",
	44: "AddGPUDriverStoragePaths",
	45: "FixSharedRootLBFQDN",
	46: "SetAppFederatedId",
}

// Auto-generated code: DO NOT EDIT
