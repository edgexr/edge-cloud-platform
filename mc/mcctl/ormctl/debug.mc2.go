// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: debug.proto

package ormctl

import (
	fmt "fmt"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	edgeproto "github.com/edgexr/edge-cloud/edgeproto"
	_ "github.com/edgexr/edge-cloud/protogen"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	math "math"
	"strings"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

var EnableDebugLevelsCmd = &ApiCommand{
	Name:         "EnableDebugLevels",
	Use:          "enabledebuglevels",
	Short:        "Enable debug log levels",
	RequiredArgs: strings.Join(EnableDebugLevelsRequiredArgs, " "),
	OptionalArgs: strings.Join(EnableDebugLevelsOptionalArgs, " "),
	AliasArgs:    strings.Join(DebugRequestAliasArgs, " "),
	SpecialArgs:  &DebugRequestSpecialArgs,
	Comments:     addRegionComment(DebugRequestComments),
	NoConfig:     "Cmd,Id",
	ReqData:      &ormapi.RegionDebugRequest{},
	ReplyData:    &edgeproto.DebugReply{},
	Path:         "/auth/ctrl/EnableDebugLevels",
	StreamOut:    true,
	ProtobufApi:  true,
}

var DisableDebugLevelsCmd = &ApiCommand{
	Name:         "DisableDebugLevels",
	Use:          "disabledebuglevels",
	Short:        "Disable debug log levels",
	RequiredArgs: strings.Join(DisableDebugLevelsRequiredArgs, " "),
	OptionalArgs: strings.Join(DisableDebugLevelsOptionalArgs, " "),
	AliasArgs:    strings.Join(DebugRequestAliasArgs, " "),
	SpecialArgs:  &DebugRequestSpecialArgs,
	Comments:     addRegionComment(DebugRequestComments),
	NoConfig:     "Cmd,Id",
	ReqData:      &ormapi.RegionDebugRequest{},
	ReplyData:    &edgeproto.DebugReply{},
	Path:         "/auth/ctrl/DisableDebugLevels",
	StreamOut:    true,
	ProtobufApi:  true,
}

var ShowDebugLevelsCmd = &ApiCommand{
	Name:         "ShowDebugLevels",
	Use:          "showdebuglevels",
	Short:        "Show debug log levels",
	RequiredArgs: strings.Join(ShowDebugLevelsRequiredArgs, " "),
	OptionalArgs: strings.Join(ShowDebugLevelsOptionalArgs, " "),
	AliasArgs:    strings.Join(DebugRequestAliasArgs, " "),
	SpecialArgs:  &DebugRequestSpecialArgs,
	Comments:     addRegionComment(DebugRequestComments),
	NoConfig:     "Levels,Cmd,Id",
	ReqData:      &ormapi.RegionDebugRequest{},
	ReplyData:    &edgeproto.DebugReply{},
	Path:         "/auth/ctrl/ShowDebugLevels",
	StreamOut:    true,
	ProtobufApi:  true,
}

var RunDebugCmd = &ApiCommand{
	Name:         "RunDebug",
	Use:          "rundebug",
	Short:        "Run debug command",
	RequiredArgs: strings.Join(RunDebugRequiredArgs, " "),
	OptionalArgs: strings.Join(RunDebugOptionalArgs, " "),
	AliasArgs:    strings.Join(DebugRequestAliasArgs, " "),
	SpecialArgs:  &DebugRequestSpecialArgs,
	Comments:     addRegionComment(DebugRequestComments),
	NoConfig:     "Levels,Id",
	ReqData:      &ormapi.RegionDebugRequest{},
	ReplyData:    &edgeproto.DebugReply{},
	Path:         "/auth/ctrl/RunDebug",
	StreamOut:    true,
	ProtobufApi:  true,
}
var DebugApiCmds = []*ApiCommand{
	EnableDebugLevelsCmd,
	DisableDebugLevelsCmd,
	ShowDebugLevelsCmd,
	RunDebugCmd,
}

const DebugGroup = "Debug"

func init() {
	AllApis.AddGroup(DebugGroup, "Manage Debugs", DebugApiCmds)
}

var EnableDebugLevelsRequiredArgs = []string{
	"levels",
}
var EnableDebugLevelsOptionalArgs = []string{
	"name",
	"type",
	"organization",
	"cloudlet",
	"node.cloudletkey.federatedorganization",
	"region",
	"pretty",
	"args",
	"timeout",
}
var DisableDebugLevelsRequiredArgs = []string{
	"levels",
}
var DisableDebugLevelsOptionalArgs = []string{
	"name",
	"type",
	"organization",
	"cloudlet",
	"node.cloudletkey.federatedorganization",
	"region",
	"pretty",
	"args",
	"timeout",
}
var ShowDebugLevelsRequiredArgs = []string{}
var ShowDebugLevelsOptionalArgs = []string{
	"name",
	"type",
	"organization",
	"cloudlet",
	"node.cloudletkey.federatedorganization",
	"region",
	"pretty",
	"args",
	"timeout",
}
var RunDebugRequiredArgs = []string{
	"cmd",
}
var RunDebugOptionalArgs = []string{
	"name",
	"type",
	"organization",
	"cloudlet",
	"node.cloudletkey.federatedorganization",
	"region",
	"pretty",
	"args",
	"timeout",
}
var DebugRequestRequiredArgs = []string{}
var DebugRequestOptionalArgs = []string{
	"name",
	"type",
	"organization",
	"cloudlet",
	"node.cloudletkey.federatedorganization",
	"region",
	"levels",
	"cmd",
	"pretty",
	"id",
	"args",
	"timeout",
}
var DebugRequestAliasArgs = []string{
	"name=debugrequest.node.name",
	"type=debugrequest.node.type",
	"organization=debugrequest.node.cloudletkey.organization",
	"cloudlet=debugrequest.node.cloudletkey.name",
	"node.cloudletkey.federatedorganization=debugrequest.node.cloudletkey.federatedorganization",
	"region=debugrequest.node.region",
	"levels=debugrequest.levels",
	"cmd=debugrequest.cmd",
	"pretty=debugrequest.pretty",
	"id=debugrequest.id",
	"args=debugrequest.args",
	"timeout=debugrequest.timeout",
}
var DebugRequestComments = map[string]string{
	"name":                                   "Name or hostname of node",
	"type":                                   "Node type",
	"organization":                           "Organization of the cloudlet site",
	"cloudlet":                               "Name of the cloudlet",
	"node.cloudletkey.federatedorganization": "Federated operator organization who shared this cloudlet",
	"region":                                 "Region the node is in",
	"levels":                                 "Comma separated list of debug level names: etcd,api,notify,dmereq,locapi,infra,metrics,upgrade,info,sampled,fedapi",
	"cmd":                                    "Debug command (use help to see available commands)",
	"pretty":                                 "if possible, make output pretty",
	"id":                                     "Id used internally",
	"args":                                   "Additional arguments for cmd",
	"timeout":                                "custom timeout (duration, defaults to 10s)",
}
var DebugRequestSpecialArgs = map[string]string{}