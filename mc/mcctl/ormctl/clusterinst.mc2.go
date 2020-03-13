// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: clusterinst.proto

package ormctl

import edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
import "strings"
import "github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
import "github.com/mobiledgex/edge-cloud/cli"
import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/googleapis/google/api"
import _ "github.com/mobiledgex/edge-cloud/protogen"
import _ "github.com/gogo/protobuf/gogoproto"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

var CreateClusterInstCmd = &cli.Command{
	Use:                  "CreateClusterInst",
	RequiredArgs:         "region " + strings.Join(ClusterInstRequiredArgs, " "),
	OptionalArgs:         strings.Join(ClusterInstOptionalArgs, " "),
	AliasArgs:            strings.Join(ClusterInstAliasArgs, " "),
	SpecialArgs:          &ClusterInstSpecialArgs,
	Comments:             addRegionComment(ClusterInstComments),
	ReqData:              &ormapi.RegionClusterInst{},
	ReplyData:            &edgeproto.Result{},
	Run:                  runRest("/auth/ctrl/CreateClusterInst"),
	StreamOut:            true,
	StreamOutIncremental: true,
}

var DeleteClusterInstCmd = &cli.Command{
	Use:                  "DeleteClusterInst",
	RequiredArgs:         "region " + strings.Join(ClusterInstRequiredArgs, " "),
	OptionalArgs:         strings.Join(ClusterInstOptionalArgs, " "),
	AliasArgs:            strings.Join(ClusterInstAliasArgs, " "),
	SpecialArgs:          &ClusterInstSpecialArgs,
	Comments:             addRegionComment(ClusterInstComments),
	ReqData:              &ormapi.RegionClusterInst{},
	ReplyData:            &edgeproto.Result{},
	Run:                  runRest("/auth/ctrl/DeleteClusterInst"),
	StreamOut:            true,
	StreamOutIncremental: true,
}

var UpdateClusterInstCmd = &cli.Command{
	Use:          "UpdateClusterInst",
	RequiredArgs: "region " + strings.Join(ClusterInstRequiredArgs, " "),
	OptionalArgs: strings.Join(ClusterInstOptionalArgs, " "),
	AliasArgs:    strings.Join(ClusterInstAliasArgs, " "),
	SpecialArgs:  &ClusterInstSpecialArgs,
	Comments:     addRegionComment(ClusterInstComments),
	ReqData:      &ormapi.RegionClusterInst{},
	ReplyData:    &edgeproto.Result{},
	Run: runRest("/auth/ctrl/UpdateClusterInst",
		withSetFieldsFunc(setUpdateClusterInstFields),
	),
	StreamOut:            true,
	StreamOutIncremental: true,
}

func setUpdateClusterInstFields(in map[string]interface{}) {
	// get map for edgeproto object in region struct
	obj := in[strings.ToLower("ClusterInst")]
	if obj == nil {
		return
	}
	objmap, ok := obj.(map[string]interface{})
	if !ok {
		return
	}
	objmap["fields"] = cli.GetSpecifiedFields(objmap, &edgeproto.ClusterInst{}, cli.JsonNamespace)
}

var ShowClusterInstCmd = &cli.Command{
	Use:          "ShowClusterInst",
	RequiredArgs: "region",
	OptionalArgs: strings.Join(append(ClusterInstRequiredArgs, ClusterInstOptionalArgs...), " "),
	AliasArgs:    strings.Join(ClusterInstAliasArgs, " "),
	SpecialArgs:  &ClusterInstSpecialArgs,
	Comments:     addRegionComment(ClusterInstComments),
	ReqData:      &ormapi.RegionClusterInst{},
	ReplyData:    &edgeproto.ClusterInst{},
	Run:          runRest("/auth/ctrl/ShowClusterInst"),
	StreamOut:    true,
}

var ClusterInstApiCmds = []*cli.Command{
	CreateClusterInstCmd,
	DeleteClusterInstCmd,
	UpdateClusterInstCmd,
	ShowClusterInstCmd,
}

var ClusterInstKeyRequiredArgs = []string{}
var ClusterInstKeyOptionalArgs = []string{
	"clusterkey.name",
	"cloudletkey.organization",
	"cloudletkey.name",
	"organization",
}
var ClusterInstKeyAliasArgs = []string{
	"clusterkey.name=clusterinstkey.clusterkey.name",
	"cloudletkey.organization=clusterinstkey.cloudletkey.organization",
	"cloudletkey.name=clusterinstkey.cloudletkey.name",
	"organization=clusterinstkey.organization",
}
var ClusterInstKeyComments = map[string]string{
	"clusterkey.name":          "Cluster name",
	"cloudletkey.organization": "Organization of the cloudlet site",
	"cloudletkey.name":         "Name of the cloudlet",
	"organization":             "Name of Developer organization that this cluster belongs to",
}
var ClusterInstKeySpecialArgs = map[string]string{}
var ClusterInstRequiredArgs = []string{
	"cluster",
	"cloudlet-org",
	"cloudlet",
	"cluster-org",
}
var ClusterInstOptionalArgs = []string{
	"flavor",
	"state",
	"errors",
	"crmoverride",
	"ipaccess",
	"deployment",
	"nummasters",
	"numnodes",
	"autoscalepolicy",
	"availabilityzone",
	"imagename",
	"reservable",
	"sharedvolumesize",
	"privacypolicy",
	"masternodeflavor",
}
var ClusterInstAliasArgs = []string{
	"fields=clusterinst.fields",
	"cluster=clusterinst.key.clusterkey.name",
	"cloudlet-org=clusterinst.key.cloudletkey.organization",
	"cloudlet=clusterinst.key.cloudletkey.name",
	"cluster-org=clusterinst.key.organization",
	"flavor=clusterinst.flavor.name",
	"liveness=clusterinst.liveness",
	"auto=clusterinst.auto",
	"state=clusterinst.state",
	"errors=clusterinst.errors",
	"crmoverride=clusterinst.crmoverride",
	"ipaccess=clusterinst.ipaccess",
	"allocatedip=clusterinst.allocatedip",
	"nodeflavor=clusterinst.nodeflavor",
	"deployment=clusterinst.deployment",
	"nummasters=clusterinst.nummasters",
	"numnodes=clusterinst.numnodes",
	"status.tasknumber=clusterinst.status.tasknumber",
	"status.maxtasks=clusterinst.status.maxtasks",
	"status.taskname=clusterinst.status.taskname",
	"status.stepname=clusterinst.status.stepname",
	"externalvolumesize=clusterinst.externalvolumesize",
	"autoscalepolicy=clusterinst.autoscalepolicy",
	"availabilityzone=clusterinst.availabilityzone",
	"imagename=clusterinst.imagename",
	"reservable=clusterinst.reservable",
	"reservedby=clusterinst.reservedby",
	"sharedvolumesize=clusterinst.sharedvolumesize",
	"privacypolicy=clusterinst.privacypolicy",
	"masternodeflavor=clusterinst.masternodeflavor",
}
var ClusterInstComments = map[string]string{
	"fields":             "Fields are used for the Update API to specify which fields to apply",
	"cluster":            "Cluster name",
	"cloudlet-org":       "Organization of the cloudlet site",
	"cloudlet":           "Name of the cloudlet",
	"cluster-org":        "Name of Developer organization that this cluster belongs to",
	"flavor":             "Flavor name",
	"liveness":           "Liveness of instance (see Liveness), one of LivenessUnknown, LivenessStatic, LivenessDynamic",
	"auto":               "Auto is set to true when automatically created by back-end (internal use only)",
	"state":              "State of the cluster instance, one of TrackedStateUnknown, NotPresent, CreateRequested, Creating, CreateError, Ready, UpdateRequested, Updating, UpdateError, DeleteRequested, Deleting, DeleteError, DeletePrepare, CrmInitok, CreatingDependencies",
	"errors":             "Any errors trying to create, update, or delete the ClusterInst on the Cloudlet.",
	"crmoverride":        "Override actions to CRM, one of NoOverride, IgnoreCrmErrors, IgnoreCrm, IgnoreTransientState, IgnoreCrmAndTransientState",
	"ipaccess":           "IP access type (RootLB Type), one of IpAccessUnknown, IpAccessDedicated, IpAccessShared",
	"allocatedip":        "Allocated IP for dedicated access",
	"nodeflavor":         "Cloudlet specific node flavor",
	"deployment":         "Deployment type (kubernetes or docker)",
	"nummasters":         "Number of k8s masters (In case of docker deployment, this field is not required)",
	"numnodes":           "Number of k8s nodes (In case of docker deployment, this field is not required)",
	"externalvolumesize": "Size of external volume to be attached to nodes.  This is for the root partition",
	"autoscalepolicy":    "Auto scale policy name",
	"availabilityzone":   "Optional Resource AZ if any",
	"imagename":          "Optional resource specific image to launch",
	"reservable":         "If ClusterInst is reservable",
	"reservedby":         "For reservable MobiledgeX ClusterInsts, the current developer tenant",
	"sharedvolumesize":   "Size of an optional shared volume to be mounted on the master",
	"privacypolicy":      "Optional privacy policy name",
	"masternodeflavor":   "Generic flavor for k8s master VM when worker nodes > 0",
}
var ClusterInstSpecialArgs = map[string]string{
	"clusterinst.errors": "StringArray",
	"clusterinst.fields": "StringArray",
}
var ClusterInstInfoRequiredArgs = []string{
	"key.clusterkey.name",
	"key.cloudletkey.organization",
	"key.cloudletkey.name",
	"key.organization",
}
var ClusterInstInfoOptionalArgs = []string{
	"notifyid",
	"state",
	"errors",
	"status.tasknumber",
	"status.maxtasks",
	"status.taskname",
	"status.stepname",
}
var ClusterInstInfoAliasArgs = []string{
	"fields=clusterinstinfo.fields",
	"key.clusterkey.name=clusterinstinfo.key.clusterkey.name",
	"key.cloudletkey.organization=clusterinstinfo.key.cloudletkey.organization",
	"key.cloudletkey.name=clusterinstinfo.key.cloudletkey.name",
	"key.organization=clusterinstinfo.key.organization",
	"notifyid=clusterinstinfo.notifyid",
	"state=clusterinstinfo.state",
	"errors=clusterinstinfo.errors",
	"status.tasknumber=clusterinstinfo.status.tasknumber",
	"status.maxtasks=clusterinstinfo.status.maxtasks",
	"status.taskname=clusterinstinfo.status.taskname",
	"status.stepname=clusterinstinfo.status.stepname",
}
var ClusterInstInfoComments = map[string]string{
	"fields":                       "Fields are used for the Update API to specify which fields to apply",
	"key.clusterkey.name":          "Cluster name",
	"key.cloudletkey.organization": "Organization of the cloudlet site",
	"key.cloudletkey.name":         "Name of the cloudlet",
	"key.organization":             "Name of Developer organization that this cluster belongs to",
	"notifyid":                     "Id of client assigned by server (internal use only)",
	"state":                        "State of the cluster instance, one of TrackedStateUnknown, NotPresent, CreateRequested, Creating, CreateError, Ready, UpdateRequested, Updating, UpdateError, DeleteRequested, Deleting, DeleteError, DeletePrepare, CrmInitok, CreatingDependencies",
	"errors":                       "Any errors trying to create, update, or delete the ClusterInst on the Cloudlet.",
}
var ClusterInstInfoSpecialArgs = map[string]string{
	"clusterinstinfo.errors": "StringArray",
	"clusterinstinfo.fields": "StringArray",
}
