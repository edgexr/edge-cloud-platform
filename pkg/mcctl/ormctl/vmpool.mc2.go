// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: vmpool.proto

package ormctl

import (
	fmt "fmt"
	edgeproto "github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	_ "github.com/edgexr/edge-cloud-platform/tools/protogen"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	_ "github.com/gogo/protobuf/types"
	math "math"
	"strings"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

var CreateVMPoolCmd = &ApiCommand{
	Name:         "CreateVMPool",
	Use:          "create",
	Short:        "Create VMPool. Creates VM pool which will have VMs defined.",
	RequiredArgs: "region " + strings.Join(CreateVMPoolRequiredArgs, " "),
	OptionalArgs: strings.Join(CreateVMPoolOptionalArgs, " "),
	AliasArgs:    strings.Join(VMPoolAliasArgs, " "),
	SpecialArgs:  &VMPoolSpecialArgs,
	Comments:     addRegionComment(VMPoolComments),
	NoConfig:     "Vms:#.GroupName,Vms:#.InternalName,Vms:#.UpdatedAt.Seconds,Vms:#.UpdatedAt.Nanos,State,Errors,Vms:#.Flavor,Vms:#.State",
	ReqData:      &ormapi.RegionVMPool{},
	ReplyData:    &edgeproto.Result{},
	Path:         "/auth/ctrl/CreateVMPool",
	ProtobufApi:  true,
}

var DeleteVMPoolCmd = &ApiCommand{
	Name:         "DeleteVMPool",
	Use:          "delete",
	Short:        "Delete VMPool. Deletes VM pool given that none of VMs part of this pool is used.",
	RequiredArgs: "region " + strings.Join(VMPoolRequiredArgs, " "),
	OptionalArgs: strings.Join(VMPoolOptionalArgs, " "),
	AliasArgs:    strings.Join(VMPoolAliasArgs, " "),
	SpecialArgs:  &VMPoolSpecialArgs,
	Comments:     addRegionComment(VMPoolComments),
	NoConfig:     "Vms:#.GroupName,Vms:#.InternalName,Vms:#.UpdatedAt.Seconds,Vms:#.UpdatedAt.Nanos,State,Errors,Vms:#.Flavor",
	ReqData:      &ormapi.RegionVMPool{},
	ReplyData:    &edgeproto.Result{},
	Path:         "/auth/ctrl/DeleteVMPool",
	ProtobufApi:  true,
}

var UpdateVMPoolCmd = &ApiCommand{
	Name:         "UpdateVMPool",
	Use:          "update",
	Short:        "Update VMPool. Updates a VM pools VMs.",
	RequiredArgs: "region " + strings.Join(VMPoolRequiredArgs, " "),
	OptionalArgs: strings.Join(VMPoolOptionalArgs, " "),
	AliasArgs:    strings.Join(VMPoolAliasArgs, " "),
	SpecialArgs:  &VMPoolSpecialArgs,
	Comments:     addRegionComment(VMPoolComments),
	NoConfig:     "Vms:#.GroupName,Vms:#.InternalName,Vms:#.UpdatedAt.Seconds,Vms:#.UpdatedAt.Nanos,State,Errors,Vms:#.Flavor",
	ReqData:      &ormapi.RegionVMPool{},
	ReplyData:    &edgeproto.Result{},
	Path:         "/auth/ctrl/UpdateVMPool",
	ProtobufApi:  true,
}

var ShowVMPoolCmd = &ApiCommand{
	Name:         "ShowVMPool",
	Use:          "show",
	Short:        "Show VMPools. Lists all the VMs part of the VM pool.",
	RequiredArgs: "region",
	OptionalArgs: strings.Join(append(VMPoolRequiredArgs, VMPoolOptionalArgs...), " "),
	AliasArgs:    strings.Join(VMPoolAliasArgs, " "),
	SpecialArgs:  &VMPoolSpecialArgs,
	Comments:     addRegionComment(VMPoolComments),
	NoConfig:     "Vms:#.GroupName,Vms:#.InternalName,Vms:#.UpdatedAt.Seconds,Vms:#.UpdatedAt.Nanos,State,Errors,Vms:#.Flavor",
	ReqData:      &ormapi.RegionVMPool{},
	ReplyData:    &edgeproto.VMPool{},
	Path:         "/auth/ctrl/ShowVMPool",
	StreamOut:    true,
	ProtobufApi:  true,
}

var AddVMPoolMemberCmd = &ApiCommand{
	Name:         "AddVMPoolMember",
	Use:          "addmember",
	Short:        "Add VMPoolMember. Adds a VM to existing VM Pool.",
	RequiredArgs: "region " + strings.Join(AddVMPoolMemberRequiredArgs, " "),
	OptionalArgs: strings.Join(AddVMPoolMemberOptionalArgs, " "),
	AliasArgs:    strings.Join(VMPoolMemberAliasArgs, " "),
	SpecialArgs:  &VMPoolMemberSpecialArgs,
	Comments:     addRegionComment(VMPoolMemberComments),
	NoConfig:     "Vm.GroupName,Vm.State,Vm.UpdatedAt.Seconds,Vm.UpdatedAt.Nanos,Vm.InternalName,Vm.Flavor",
	ReqData:      &ormapi.RegionVMPoolMember{},
	ReplyData:    &edgeproto.Result{},
	Path:         "/auth/ctrl/AddVMPoolMember",
	ProtobufApi:  true,
}

var RemoveVMPoolMemberCmd = &ApiCommand{
	Name:         "RemoveVMPoolMember",
	Use:          "removemember",
	Short:        "Remove VMPoolMember. Removes a VM from existing VM Pool.",
	RequiredArgs: "region " + strings.Join(RemoveVMPoolMemberRequiredArgs, " "),
	OptionalArgs: strings.Join(RemoveVMPoolMemberOptionalArgs, " "),
	AliasArgs:    strings.Join(VMPoolMemberAliasArgs, " "),
	SpecialArgs:  &VMPoolMemberSpecialArgs,
	Comments:     addRegionComment(VMPoolMemberComments),
	NoConfig:     "Vm.GroupName,Vm.State,Vm.UpdatedAt.Seconds,Vm.UpdatedAt.Nanos,Vm.InternalName,Vm.Flavor,Vm.NetInfo.ExternalIp,Vm.NetInfo.InternalIp,Vm.Flavor",
	ReqData:      &ormapi.RegionVMPoolMember{},
	ReplyData:    &edgeproto.Result{},
	Path:         "/auth/ctrl/RemoveVMPoolMember",
	ProtobufApi:  true,
}
var VMPoolApiCmds = []*ApiCommand{
	CreateVMPoolCmd,
	DeleteVMPoolCmd,
	UpdateVMPoolCmd,
	ShowVMPoolCmd,
	AddVMPoolMemberCmd,
	RemoveVMPoolMemberCmd,
}

const VMPoolGroup = "VMPool"

func init() {
	AllApis.AddGroup(VMPoolGroup, "Manage VMPools", VMPoolApiCmds)
}

var CreateVMPoolRequiredArgs = []string{
	"vmpoolorg",
	"vmpool",
}
var CreateVMPoolOptionalArgs = []string{
	"vms:#.name",
	"vms:#.netinfo.externalip",
	"vms:#.netinfo.internalip",
	"crmoverride",
	"deleteprepare",
}
var AddVMPoolMemberRequiredArgs = []string{
	"vmpoolorg",
	"vmpool",
	"vm.name",
	"vm.netinfo.internalip",
}
var AddVMPoolMemberOptionalArgs = []string{
	"vm.netinfo.externalip",
	"crmoverride",
}
var RemoveVMPoolMemberRequiredArgs = []string{
	"vmpoolorg",
	"vmpool",
	"vm.name",
}
var RemoveVMPoolMemberOptionalArgs = []string{
	"crmoverride",
}
var VMPoolRequiredArgs = []string{
	"vmpoolorg",
	"vmpool",
}
var VMPoolOptionalArgs = []string{
	"vms:empty",
	"vms:#.name",
	"vms:#.netinfo.externalip",
	"vms:#.netinfo.internalip",
	"vms:#.state",
	"crmoverride",
	"deleteprepare",
}
var VMPoolAliasArgs = []string{
	"fields=vmpool.fields",
	"vmpoolorg=vmpool.key.organization",
	"vmpool=vmpool.key.name",
	"vms:empty=vmpool.vms:empty",
	"vms:#.name=vmpool.vms:#.name",
	"vms:#.netinfo.externalip=vmpool.vms:#.netinfo.externalip",
	"vms:#.netinfo.internalip=vmpool.vms:#.netinfo.internalip",
	"vms:#.groupname=vmpool.vms:#.groupname",
	"vms:#.state=vmpool.vms:#.state",
	"vms:#.updatedat.seconds=vmpool.vms:#.updatedat.seconds",
	"vms:#.updatedat.nanos=vmpool.vms:#.updatedat.nanos",
	"vms:#.internalname=vmpool.vms:#.internalname",
	"vms:#.flavor.name=vmpool.vms:#.flavor.name",
	"vms:#.flavor.vcpus=vmpool.vms:#.flavor.vcpus",
	"vms:#.flavor.ram=vmpool.vms:#.flavor.ram",
	"vms:#.flavor.disk=vmpool.vms:#.flavor.disk",
	"vms:#.flavor.propmap=vmpool.vms:#.flavor.propmap",
	"state=vmpool.state",
	"errors=vmpool.errors",
	"crmoverride=vmpool.crmoverride",
	"deleteprepare=vmpool.deleteprepare",
}
var VMPoolComments = map[string]string{
	"fields":                   "Fields are used for the Update API to specify which fields to apply",
	"vmpoolorg":                "Organization of the vmpool",
	"vmpool":                   "Name of the vmpool",
	"vms:empty":                "list of VMs to be part of VM pool, specify vms:empty=true to clear",
	"vms:#.name":               "VM Name",
	"vms:#.netinfo.externalip": "External IP",
	"vms:#.netinfo.internalip": "Internal IP",
	"vms:#.groupname":          "VM Group Name",
	"vms:#.state":              "VM State, one of ForceFree",
	"vms:#.updatedat.seconds":  "Represents seconds of UTC time since Unix epoch 1970-01-01T00:00:00Z. Must be from 0001-01-01T00:00:00Z to 9999-12-31T23:59:59Z inclusive.",
	"vms:#.updatedat.nanos":    "Non-negative fractions of a second at nanosecond resolution. Negative second values with fractions must still have non-negative nanos values that count forward in time. Must be from 0 to 999,999,999 inclusive.",
	"vms:#.internalname":       "VM Internal Name",
	"vms:#.flavor.name":        "Name of the flavor on the Cloudlet",
	"vms:#.flavor.vcpus":       "Number of VCPU cores on the Cloudlet",
	"vms:#.flavor.ram":         "Ram in MB on the Cloudlet",
	"vms:#.flavor.disk":        "Amount of disk in GB on the Cloudlet",
	"vms:#.flavor.propmap":     "OS Flavor Properties, if any, specify vms:#.flavor.propmap:empty=true to clear",
	"state":                    "Current state of the VM pool, one of TrackedStateUnknown, NotPresent, CreateRequested, Creating, CreateError, Ready, UpdateRequested, Updating, UpdateError, DeleteRequested, Deleting, DeleteError, DeletePrepare, CrmInitok, CreatingDependencies, DeleteDone",
	"errors":                   "Any errors trying to add/remove VM to/from VM Pool, specify errors:empty=true to clear",
	"crmoverride":              "Override actions to CRM, one of NoOverride, IgnoreCrmErrors, IgnoreCrm, IgnoreTransientState, IgnoreCrmAndTransientState",
	"deleteprepare":            "Preparing to be deleted",
}
var VMPoolSpecialArgs = map[string]string{
	"vmpool.errors":               "StringArray",
	"vmpool.fields":               "StringArray",
	"vmpool.vms:#.flavor.propmap": "StringToString",
}
var VMPoolMemberRequiredArgs = []string{
	"vmpoolorg",
	"vmpool",
}
var VMPoolMemberOptionalArgs = []string{
	"vm.name",
	"vm.netinfo.externalip",
	"vm.netinfo.internalip",
	"crmoverride",
}
var VMPoolMemberAliasArgs = []string{
	"vmpoolorg=vmpoolmember.key.organization",
	"vmpool=vmpoolmember.key.name",
	"vm.name=vmpoolmember.vm.name",
	"vm.netinfo.externalip=vmpoolmember.vm.netinfo.externalip",
	"vm.netinfo.internalip=vmpoolmember.vm.netinfo.internalip",
	"vm.groupname=vmpoolmember.vm.groupname",
	"vm.state=vmpoolmember.vm.state",
	"vm.updatedat.seconds=vmpoolmember.vm.updatedat.seconds",
	"vm.updatedat.nanos=vmpoolmember.vm.updatedat.nanos",
	"vm.internalname=vmpoolmember.vm.internalname",
	"vm.flavor.name=vmpoolmember.vm.flavor.name",
	"vm.flavor.vcpus=vmpoolmember.vm.flavor.vcpus",
	"vm.flavor.ram=vmpoolmember.vm.flavor.ram",
	"vm.flavor.disk=vmpoolmember.vm.flavor.disk",
	"vm.flavor.propmap=vmpoolmember.vm.flavor.propmap",
	"crmoverride=vmpoolmember.crmoverride",
}
var VMPoolMemberComments = map[string]string{
	"vmpoolorg":             "Organization of the vmpool",
	"vmpool":                "Name of the vmpool",
	"vm.name":               "VM Name",
	"vm.netinfo.externalip": "External IP",
	"vm.netinfo.internalip": "Internal IP",
	"vm.groupname":          "VM Group Name",
	"vm.state":              "VM State, one of ForceFree",
	"vm.updatedat.seconds":  "Represents seconds of UTC time since Unix epoch 1970-01-01T00:00:00Z. Must be from 0001-01-01T00:00:00Z to 9999-12-31T23:59:59Z inclusive.",
	"vm.updatedat.nanos":    "Non-negative fractions of a second at nanosecond resolution. Negative second values with fractions must still have non-negative nanos values that count forward in time. Must be from 0 to 999,999,999 inclusive.",
	"vm.internalname":       "VM Internal Name",
	"vm.flavor.name":        "Name of the flavor on the Cloudlet",
	"vm.flavor.vcpus":       "Number of VCPU cores on the Cloudlet",
	"vm.flavor.ram":         "Ram in MB on the Cloudlet",
	"vm.flavor.disk":        "Amount of disk in GB on the Cloudlet",
	"vm.flavor.propmap":     "OS Flavor Properties, if any",
	"crmoverride":           "Override actions to CRM, one of NoOverride, IgnoreCrmErrors, IgnoreCrm, IgnoreTransientState, IgnoreCrmAndTransientState",
}
var VMPoolMemberSpecialArgs = map[string]string{
	"vmpoolmember.vm.flavor.propmap": "StringToString",
}
