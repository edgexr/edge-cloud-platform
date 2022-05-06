// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: alertpolicy.proto

package ormctl

import (
	fmt "fmt"
	edgeproto "github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	_ "github.com/edgexr/edge-cloud-platform/tools/protogen"
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

var CreateAlertPolicyCmd = &ApiCommand{
	Name:         "CreateAlertPolicy",
	Use:          "create",
	Short:        "Create an Alert Policy",
	RequiredArgs: "region " + strings.Join(CreateAlertPolicyRequiredArgs, " "),
	OptionalArgs: strings.Join(CreateAlertPolicyOptionalArgs, " "),
	AliasArgs:    strings.Join(AlertPolicyAliasArgs, " "),
	SpecialArgs:  &AlertPolicySpecialArgs,
	Comments:     addRegionComment(AlertPolicyComments),
	NoConfig:     "DeletePrepare",
	ReqData:      &ormapi.RegionAlertPolicy{},
	ReplyData:    &edgeproto.Result{},
	Path:         "/auth/ctrl/CreateAlertPolicy",
	ProtobufApi:  true,
}

var DeleteAlertPolicyCmd = &ApiCommand{
	Name:         "DeleteAlertPolicy",
	Use:          "delete",
	Short:        "Delete an Alert Policy",
	RequiredArgs: "region " + strings.Join(AlertPolicyRequiredArgs, " "),
	OptionalArgs: strings.Join(AlertPolicyOptionalArgs, " "),
	AliasArgs:    strings.Join(AlertPolicyAliasArgs, " "),
	SpecialArgs:  &AlertPolicySpecialArgs,
	Comments:     addRegionComment(AlertPolicyComments),
	NoConfig:     "DeletePrepare",
	ReqData:      &ormapi.RegionAlertPolicy{},
	ReplyData:    &edgeproto.Result{},
	Path:         "/auth/ctrl/DeleteAlertPolicy",
	ProtobufApi:  true,
}

var UpdateAlertPolicyCmd = &ApiCommand{
	Name:         "UpdateAlertPolicy",
	Use:          "update",
	Short:        "Update an Alert Policy",
	RequiredArgs: "region " + strings.Join(AlertPolicyRequiredArgs, " "),
	OptionalArgs: strings.Join(AlertPolicyOptionalArgs, " "),
	AliasArgs:    strings.Join(AlertPolicyAliasArgs, " "),
	SpecialArgs:  &AlertPolicySpecialArgs,
	Comments:     addRegionComment(AlertPolicyComments),
	NoConfig:     "DeletePrepare",
	ReqData:      &ormapi.RegionAlertPolicy{},
	ReplyData:    &edgeproto.Result{},
	Path:         "/auth/ctrl/UpdateAlertPolicy",
	ProtobufApi:  true,
}

var ShowAlertPolicyCmd = &ApiCommand{
	Name:         "ShowAlertPolicy",
	Use:          "show",
	Short:        "Show Alert Policies. Any fields specified will be used to filter results.",
	RequiredArgs: "region",
	OptionalArgs: strings.Join(append(AlertPolicyRequiredArgs, AlertPolicyOptionalArgs...), " "),
	AliasArgs:    strings.Join(AlertPolicyAliasArgs, " "),
	SpecialArgs:  &AlertPolicySpecialArgs,
	Comments:     addRegionComment(AlertPolicyComments),
	NoConfig:     "DeletePrepare",
	ReqData:      &ormapi.RegionAlertPolicy{},
	ReplyData:    &edgeproto.AlertPolicy{},
	Path:         "/auth/ctrl/ShowAlertPolicy",
	StreamOut:    true,
	ProtobufApi:  true,
}
var AlertPolicyApiCmds = []*ApiCommand{
	CreateAlertPolicyCmd,
	DeleteAlertPolicyCmd,
	UpdateAlertPolicyCmd,
	ShowAlertPolicyCmd,
}

const AlertPolicyGroup = "AlertPolicy"

func init() {
	AllApis.AddGroup(AlertPolicyGroup, "Manage AlertPolicys", AlertPolicyApiCmds)
}

var CreateAlertPolicyRequiredArgs = []string{
	"alertorg",
	"name",
	"severity",
}
var CreateAlertPolicyOptionalArgs = []string{
	"cpuutilization",
	"memutilization",
	"diskutilization",
	"activeconnections",
	"triggertime",
	"labels",
	"annotations",
	"description",
}
var AlertPolicyRequiredArgs = []string{
	"alertorg",
	"name",
}
var AlertPolicyOptionalArgs = []string{
	"cpuutilization",
	"memutilization",
	"diskutilization",
	"activeconnections",
	"severity",
	"triggertime",
	"labels",
	"annotations",
	"description",
}
var AlertPolicyAliasArgs = []string{
	"fields=alertpolicy.fields",
	"alertorg=alertpolicy.key.organization",
	"name=alertpolicy.key.name",
	"cpuutilization=alertpolicy.cpuutilizationlimit",
	"memutilization=alertpolicy.memutilizationlimit",
	"diskutilization=alertpolicy.diskutilizationlimit",
	"activeconnections=alertpolicy.activeconnlimit",
	"severity=alertpolicy.severity",
	"triggertime=alertpolicy.triggertime",
	"labels=alertpolicy.labels",
	"annotations=alertpolicy.annotations",
	"description=alertpolicy.description",
	"deleteprepare=alertpolicy.deleteprepare",
}
var AlertPolicyComments = map[string]string{
	"alertorg":          "Name of the organization for the app that this alert can be applied to",
	"name":              "Alert Policy name",
	"cpuutilization":    "Container or pod CPU utilization rate(percentage) across all nodes. Valid values 1-100",
	"memutilization":    "Container or pod memory utilization rate(percentage) across all nodes. Valid values 1-100",
	"diskutilization":   "Container or pod disk utilization rate(percentage) across all nodes. Valid values 1-100",
	"activeconnections": "Active Connections alert threshold. Valid values 1-4294967295",
	"severity":          "Alert severity level - one of info, warning, error",
	"triggertime":       "Duration for which alert interval is active (max 72 hours)",
	"labels":            "Additional Labels, specify labels:empty=true to clear",
	"annotations":       "Additional Annotations for extra information about the alert, specify annotations:empty=true to clear",
	"description":       "Description of the alert policy",
	"deleteprepare":     "Preparing to be deleted",
}
var AlertPolicySpecialArgs = map[string]string{
	"alertpolicy.annotations": "StringToString",
	"alertpolicy.fields":      "StringArray",
	"alertpolicy.labels":      "StringToString",
}
