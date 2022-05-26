// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: clusterinst.proto

package ormctl

import (
	fmt "fmt"
	_ "github.com/edgexr/edge-cloud-platform/api/dme-proto"
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

var CreateClusterInstCmd = &ApiCommand{
	Name:                 "CreateClusterInst",
	Use:                  "create",
	Short:                "Create Cluster Instance. Creates an instance of a Cluster on a Cloudlet, defined by a Cluster Key and a Cloudlet Key. ClusterInst is a collection of compute resources on a Cloudlet on which AppInsts are deployed.",
	RequiredArgs:         "region " + strings.Join(ClusterInstRequiredArgs, " "),
	OptionalArgs:         strings.Join(ClusterInstOptionalArgs, " "),
	AliasArgs:            strings.Join(ClusterInstAliasArgs, " "),
	SpecialArgs:          &ClusterInstSpecialArgs,
	Comments:             addRegionComment(ClusterInstComments),
	NoConfig:             "Liveness,Auto,MasterNodeFlavor,NodeFlavor,ExternalVolumeSize,AllocatedIp,ReservedBy,State,Errors,Resources,AvailabilityZone,CreatedAt,UpdatedAt,OptRes,ReservationEndedAt,DeletePrepare,DnsLabel,Fqdn",
	ReqData:              &ormapi.RegionClusterInst{},
	ReplyData:            &edgeproto.Result{},
	Path:                 "/auth/ctrl/CreateClusterInst",
	StreamOut:            true,
	StreamOutIncremental: true,
	ProtobufApi:          true,
}

var DeleteClusterInstCmd = &ApiCommand{
	Name:                 "DeleteClusterInst",
	Use:                  "delete",
	Short:                "Delete Cluster Instance. Deletes an instance of a Cluster deployed on a Cloudlet.",
	RequiredArgs:         "region " + strings.Join(ClusterInstRequiredArgs, " "),
	OptionalArgs:         strings.Join(ClusterInstOptionalArgs, " "),
	AliasArgs:            strings.Join(ClusterInstAliasArgs, " "),
	SpecialArgs:          &ClusterInstSpecialArgs,
	Comments:             addRegionComment(ClusterInstComments),
	NoConfig:             "Liveness,Auto,MasterNodeFlavor,NodeFlavor,ExternalVolumeSize,AllocatedIp,ReservedBy,State,Errors,Resources,AvailabilityZone,CreatedAt,UpdatedAt,OptRes,ReservationEndedAt,DeletePrepare,DnsLabel,Fqdn",
	ReqData:              &ormapi.RegionClusterInst{},
	ReplyData:            &edgeproto.Result{},
	Path:                 "/auth/ctrl/DeleteClusterInst",
	StreamOut:            true,
	StreamOutIncremental: true,
	ProtobufApi:          true,
}

var UpdateClusterInstCmd = &ApiCommand{
	Name:                 "UpdateClusterInst",
	Use:                  "update",
	Short:                "Update Cluster Instance. Updates an instance of a Cluster deployed on a Cloudlet.",
	RequiredArgs:         "region " + strings.Join(UpdateClusterInstRequiredArgs, " "),
	OptionalArgs:         strings.Join(UpdateClusterInstOptionalArgs, " "),
	AliasArgs:            strings.Join(ClusterInstAliasArgs, " "),
	SpecialArgs:          &ClusterInstSpecialArgs,
	Comments:             addRegionComment(ClusterInstComments),
	NoConfig:             "Liveness,Auto,MasterNodeFlavor,NodeFlavor,ExternalVolumeSize,AllocatedIp,ReservedBy,State,Errors,Resources,AvailabilityZone,CreatedAt,UpdatedAt,OptRes,ReservationEndedAt,DeletePrepare,DnsLabel,Fqdn,Flavor,NumMasters,AvailabilityZone,Reservable,SharedVolumeSize,IpAccess,Deployment,ImageName,Networks",
	ReqData:              &ormapi.RegionClusterInst{},
	ReplyData:            &edgeproto.Result{},
	Path:                 "/auth/ctrl/UpdateClusterInst",
	StreamOut:            true,
	StreamOutIncremental: true,
	ProtobufApi:          true,
}

var ShowClusterInstCmd = &ApiCommand{
	Name:         "ShowClusterInst",
	Use:          "show",
	Short:        "Show Cluster Instances. Lists all the cluster instances managed by Edge Controller.",
	RequiredArgs: "region",
	OptionalArgs: strings.Join(append(ClusterInstRequiredArgs, ClusterInstOptionalArgs...), " "),
	AliasArgs:    strings.Join(ClusterInstAliasArgs, " "),
	SpecialArgs:  &ClusterInstSpecialArgs,
	Comments:     addRegionComment(ClusterInstComments),
	NoConfig:     "Liveness,Auto,MasterNodeFlavor,NodeFlavor,ExternalVolumeSize,AllocatedIp,ReservedBy,State,Errors,Resources,AvailabilityZone,CreatedAt,UpdatedAt,OptRes,ReservationEndedAt,DeletePrepare,DnsLabel,Fqdn",
	ReqData:      &ormapi.RegionClusterInst{},
	ReplyData:    &edgeproto.ClusterInst{},
	Path:         "/auth/ctrl/ShowClusterInst",
	StreamOut:    true,
	ProtobufApi:  true,
}

var DeleteIdleReservableClusterInstsCmd = &ApiCommand{
	Name:         "DeleteIdleReservableClusterInsts",
	Use:          "deleteidlereservables",
	Short:        "Cleanup Reservable Cluster Instances. Deletes reservable cluster instances that are not in use.",
	RequiredArgs: "region " + strings.Join(IdleReservableClusterInstsRequiredArgs, " "),
	OptionalArgs: strings.Join(IdleReservableClusterInstsOptionalArgs, " "),
	AliasArgs:    strings.Join(IdleReservableClusterInstsAliasArgs, " "),
	SpecialArgs:  &IdleReservableClusterInstsSpecialArgs,
	Comments:     addRegionComment(IdleReservableClusterInstsComments),
	ReqData:      &ormapi.RegionIdleReservableClusterInsts{},
	ReplyData:    &edgeproto.Result{},
	Path:         "/auth/ctrl/DeleteIdleReservableClusterInsts",
	ProtobufApi:  true,
}
var ClusterInstApiCmds = []*ApiCommand{
	CreateClusterInstCmd,
	DeleteClusterInstCmd,
	UpdateClusterInstCmd,
	ShowClusterInstCmd,
	DeleteIdleReservableClusterInstsCmd,
}

const ClusterInstGroup = "ClusterInst"

func init() {
	AllApis.AddGroup(ClusterInstGroup, "Manage ClusterInsts", ClusterInstApiCmds)
}

var UpdateClusterInstRequiredArgs = []string{
	"cluster",
	"cloudletorg",
	"cloudlet",
	"clusterorg",
}
var UpdateClusterInstOptionalArgs = []string{
	"federatedorg",
	"crmoverride",
	"numnodes",
	"autoscalepolicy",
	"skipcrmcleanuponfailure",
	"multitenant",
}
var ClusterInstKeyRequiredArgs = []string{}
var ClusterInstKeyOptionalArgs = []string{
	"clusterkey.name",
	"cloudletkey.organization",
	"cloudletkey.name",
	"cloudletkey.federatedorganization",
	"organization",
}
var ClusterInstKeyAliasArgs = []string{
	"clusterkey.name=clusterinstkey.clusterkey.name",
	"cloudletkey.organization=clusterinstkey.cloudletkey.organization",
	"cloudletkey.name=clusterinstkey.cloudletkey.name",
	"cloudletkey.federatedorganization=clusterinstkey.cloudletkey.federatedorganization",
	"organization=clusterinstkey.organization",
}
var ClusterInstKeyComments = map[string]string{
	"clusterkey.name":                   "Cluster name",
	"cloudletkey.organization":          "Organization of the cloudlet site",
	"cloudletkey.name":                  "Name of the cloudlet",
	"cloudletkey.federatedorganization": "Federated operator organization who shared this cloudlet",
	"organization":                      "Name of Developer organization that this cluster belongs to",
}
var ClusterInstKeySpecialArgs = map[string]string{}
var ClusterInstRequiredArgs = []string{
	"cluster",
	"cloudletorg",
	"cloudlet",
	"clusterorg",
}
var ClusterInstOptionalArgs = []string{
	"federatedorg",
	"flavor",
	"crmoverride",
	"ipaccess",
	"deployment",
	"nummasters",
	"numnodes",
	"autoscalepolicy",
	"imagename",
	"reservable",
	"sharedvolumesize",
	"skipcrmcleanuponfailure",
	"multitenant",
	"networks",
}
var ClusterInstAliasArgs = []string{
	"fields=clusterinst.fields",
	"cluster=clusterinst.key.clusterkey.name",
	"cloudletorg=clusterinst.key.cloudletkey.organization",
	"cloudlet=clusterinst.key.cloudletkey.name",
	"federatedorg=clusterinst.key.cloudletkey.federatedorganization",
	"clusterorg=clusterinst.key.organization",
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
	"externalvolumesize=clusterinst.externalvolumesize",
	"autoscalepolicy=clusterinst.autoscalepolicy",
	"availabilityzone=clusterinst.availabilityzone",
	"imagename=clusterinst.imagename",
	"reservable=clusterinst.reservable",
	"reservedby=clusterinst.reservedby",
	"sharedvolumesize=clusterinst.sharedvolumesize",
	"masternodeflavor=clusterinst.masternodeflavor",
	"skipcrmcleanuponfailure=clusterinst.skipcrmcleanuponfailure",
	"optres=clusterinst.optres",
	"resources.vms:empty=clusterinst.resources.vms:empty",
	"resources.vms:#.name=clusterinst.resources.vms:#.name",
	"resources.vms:#.type=clusterinst.resources.vms:#.type",
	"resources.vms:#.status=clusterinst.resources.vms:#.status",
	"resources.vms:#.infraflavor=clusterinst.resources.vms:#.infraflavor",
	"resources.vms:#.ipaddresses:empty=clusterinst.resources.vms:#.ipaddresses:empty",
	"resources.vms:#.ipaddresses:#.externalip=clusterinst.resources.vms:#.ipaddresses:#.externalip",
	"resources.vms:#.ipaddresses:#.internalip=clusterinst.resources.vms:#.ipaddresses:#.internalip",
	"resources.vms:#.containers:empty=clusterinst.resources.vms:#.containers:empty",
	"resources.vms:#.containers:#.name=clusterinst.resources.vms:#.containers:#.name",
	"resources.vms:#.containers:#.type=clusterinst.resources.vms:#.containers:#.type",
	"resources.vms:#.containers:#.status=clusterinst.resources.vms:#.containers:#.status",
	"resources.vms:#.containers:#.clusterip=clusterinst.resources.vms:#.containers:#.clusterip",
	"resources.vms:#.containers:#.restarts=clusterinst.resources.vms:#.containers:#.restarts",
	"createdat=clusterinst.createdat",
	"updatedat=clusterinst.updatedat",
	"reservationendedat=clusterinst.reservationendedat",
	"multitenant=clusterinst.multitenant",
	"networks=clusterinst.networks",
	"deleteprepare=clusterinst.deleteprepare",
	"dnslabel=clusterinst.dnslabel",
	"fqdn=clusterinst.fqdn",
}
var ClusterInstComments = map[string]string{
	"fields":                            "Fields are used for the Update API to specify which fields to apply",
	"cluster":                           "Cluster name",
	"cloudletorg":                       "Organization of the cloudlet site",
	"cloudlet":                          "Name of the cloudlet",
	"federatedorg":                      "Federated operator organization who shared this cloudlet",
	"clusterorg":                        "Name of Developer organization that this cluster belongs to",
	"flavor":                            "Flavor name",
	"liveness":                          "Liveness of instance (see Liveness), one of Unknown, Static, Dynamic, Autoprov",
	"auto":                              "Auto is set to true when automatically created by back-end (internal use only)",
	"state":                             "State of the cluster instance, one of TrackedStateUnknown, NotPresent, CreateRequested, Creating, CreateError, Ready, UpdateRequested, Updating, UpdateError, DeleteRequested, Deleting, DeleteError, DeletePrepare, CrmInitok, CreatingDependencies, DeleteDone",
	"errors":                            "Any errors trying to create, update, or delete the ClusterInst on the Cloudlet., specify errors:empty=true to clear",
	"crmoverride":                       "Override actions to CRM, one of NoOverride, IgnoreCrmErrors, IgnoreCrm, IgnoreTransientState, IgnoreCrmAndTransientState",
	"ipaccess":                          "IP access type (RootLB Type), one of Unknown, Dedicated, Shared",
	"allocatedip":                       "Allocated IP for dedicated access",
	"nodeflavor":                        "Cloudlet specific node flavor",
	"deployment":                        "Deployment type (kubernetes or docker)",
	"nummasters":                        "Number of k8s masters (In case of docker deployment, this field is not required)",
	"numnodes":                          "Number of k8s nodes (In case of docker deployment, this field is not required)",
	"externalvolumesize":                "Size of external volume to be attached to nodes.  This is for the root partition",
	"autoscalepolicy":                   "Auto scale policy name",
	"availabilityzone":                  "Optional Resource AZ if any",
	"imagename":                         "Optional resource specific image to launch",
	"reservable":                        "If ClusterInst is reservable",
	"reservedby":                        "For reservable EdgeCloud ClusterInsts, the current developer tenant",
	"sharedvolumesize":                  "Size of an optional shared volume to be mounted on the master",
	"masternodeflavor":                  "Generic flavor for k8s master VM when worker nodes > 0",
	"skipcrmcleanuponfailure":           "Prevents cleanup of resources on failure within CRM, used for diagnostic purposes",
	"optres":                            "Optional Resources required by OS flavor if any",
	"resources.vms:empty":               "Virtual machine resources info, specify resources.vms:empty=true to clear",
	"resources.vms:#.name":              "Virtual machine name",
	"resources.vms:#.type":              "Type can be platformvm, platform-cluster-master, platform-cluster-primary-node, platform-cluster-secondary-node, sharedrootlb, dedicatedrootlb, cluster-master, cluster-k8s-node, cluster-docker-node, appvm",
	"resources.vms:#.status":            "Runtime status of the VM",
	"resources.vms:#.infraflavor":       "Flavor allocated within the cloudlet infrastructure, distinct from the control plane flavor",
	"resources.vms:#.ipaddresses:empty": "IP addresses allocated to the VM, specify resources.vms:#.ipaddresses:empty=true to clear",
	"resources.vms:#.ipaddresses:#.externalip": "External IP address",
	"resources.vms:#.ipaddresses:#.internalip": "Internal IP address",
	"resources.vms:#.containers:empty":         "Information about containers running in the VM, specify resources.vms:#.containers:empty=true to clear",
	"resources.vms:#.containers:#.name":        "Name of the container",
	"resources.vms:#.containers:#.type":        "Type can be docker or kubernetes",
	"resources.vms:#.containers:#.status":      "Runtime status of the container",
	"resources.vms:#.containers:#.clusterip":   "IP within the CNI and is applicable to kubernetes only",
	"resources.vms:#.containers:#.restarts":    "Restart count, applicable to kubernetes only",
	"createdat":                                "Created at time",
	"updatedat":                                "Updated at time",
	"reservationendedat":                       "For reservable ClusterInsts, when the last reservation ended",
	"multitenant":                              "Multi-tenant kubernetes cluster",
	"networks":                                 "networks to connect to, specify networks:empty=true to clear",
	"deleteprepare":                            "Preparing to be deleted",
	"dnslabel":                                 "DNS label that is unique within the cloudlet and among other AppInsts/ClusterInsts",
	"fqdn":                                     "FQDN is a globally unique DNS id for the ClusterInst",
}
var ClusterInstSpecialArgs = map[string]string{
	"clusterinst.errors":   "StringArray",
	"clusterinst.fields":   "StringArray",
	"clusterinst.networks": "StringArray",
}
var IdleReservableClusterInstsRequiredArgs = []string{}
var IdleReservableClusterInstsOptionalArgs = []string{
	"idletime",
}
var IdleReservableClusterInstsAliasArgs = []string{
	"idletime=idlereservableclusterinsts.idletime",
}
var IdleReservableClusterInstsComments = map[string]string{
	"idletime": "Idle time (duration)",
}
var IdleReservableClusterInstsSpecialArgs = map[string]string{}
