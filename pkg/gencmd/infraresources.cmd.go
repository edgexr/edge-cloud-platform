// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: infraresources.proto

package gencmd

import (
	fmt "fmt"
	_ "github.com/edgexr/edge-cloud-platform/protogen"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT
var ContainerInfoRequiredArgs = []string{}
var ContainerInfoOptionalArgs = []string{
	"name",
	"type",
	"status",
	"clusterip",
	"restarts",
}
var ContainerInfoAliasArgs = []string{}
var ContainerInfoComments = map[string]string{
	"name":      "Name of the container",
	"type":      "Type can be docker or kubernetes",
	"status":    "Runtime status of the container",
	"clusterip": "IP within the CNI and is applicable to kubernetes only",
	"restarts":  "Restart count, applicable to kubernetes only",
}
var ContainerInfoSpecialArgs = map[string]string{}
var IpAddrRequiredArgs = []string{}
var IpAddrOptionalArgs = []string{
	"externalip",
	"internalip",
}
var IpAddrAliasArgs = []string{}
var IpAddrComments = map[string]string{
	"externalip": "External IP address",
	"internalip": "Internal IP address",
}
var IpAddrSpecialArgs = map[string]string{}
var VmInfoRequiredArgs = []string{}
var VmInfoOptionalArgs = []string{
	"name",
	"type",
	"status",
	"infraflavor",
	"ipaddresses:#.externalip",
	"ipaddresses:#.internalip",
	"containers:#.name",
	"containers:#.type",
	"containers:#.status",
	"containers:#.clusterip",
	"containers:#.restarts",
}
var VmInfoAliasArgs = []string{}
var VmInfoComments = map[string]string{
	"name":                     "Virtual machine name",
	"type":                     "Type can be platformvm, platform-cluster-master, platform-cluster-primary-node, platform-cluster-secondary-node, sharedrootlb, dedicatedrootlb, cluster-master, cluster-k8s-node, cluster-docker-node, appvm",
	"status":                   "Runtime status of the VM",
	"infraflavor":              "Flavor allocated within the cloudlet infrastructure, distinct from the control plane flavor",
	"ipaddresses:#.externalip": "External IP address",
	"ipaddresses:#.internalip": "Internal IP address",
	"containers:#.name":        "Name of the container",
	"containers:#.type":        "Type can be docker or kubernetes",
	"containers:#.status":      "Runtime status of the container",
	"containers:#.clusterip":   "IP within the CNI and is applicable to kubernetes only",
	"containers:#.restarts":    "Restart count, applicable to kubernetes only",
}
var VmInfoSpecialArgs = map[string]string{}
var InfraResourceRequiredArgs = []string{}
var InfraResourceOptionalArgs = []string{
	"name",
	"value",
	"inframaxvalue",
	"quotamaxvalue",
	"description",
	"units",
	"alertthreshold",
}
var InfraResourceAliasArgs = []string{}
var InfraResourceComments = map[string]string{
	"name":           "Resource name",
	"value":          "Resource value",
	"inframaxvalue":  "Resource infra max value",
	"quotamaxvalue":  "Resource quota max value",
	"description":    "Resource description",
	"units":          "Resource units",
	"alertthreshold": "Generate alert when more than threshold percentage of resource is used",
}
var InfraResourceSpecialArgs = map[string]string{}
var NodeInfoRequiredArgs = []string{}
var NodeInfoOptionalArgs = []string{
	"name",
}
var NodeInfoAliasArgs = []string{}
var NodeInfoComments = map[string]string{
	"name": "Node name",
}
var NodeInfoSpecialArgs = map[string]string{}
var ClusterInstRefKeyRequiredArgs = []string{}
var ClusterInstRefKeyOptionalArgs = []string{
	"clusterkey.name",
	"organization",
}
var ClusterInstRefKeyAliasArgs = []string{}
var ClusterInstRefKeyComments = map[string]string{
	"clusterkey.name": "Cluster name",
	"organization":    "Name of Developer organization that this cluster belongs to",
}
var ClusterInstRefKeySpecialArgs = map[string]string{}
var AppInstRefKeyRequiredArgs = []string{}
var AppInstRefKeyOptionalArgs = []string{
	"appkey.organization",
	"appkey.name",
	"appkey.version",
	"clusterinstkey.clusterkey.name",
	"clusterinstkey.organization",
}
var AppInstRefKeyAliasArgs = []string{}
var AppInstRefKeyComments = map[string]string{
	"appkey.organization":            "App developer organization",
	"appkey.name":                    "App name",
	"appkey.version":                 "App version",
	"clusterinstkey.clusterkey.name": "Cluster name",
	"clusterinstkey.organization":    "Name of Developer organization that this cluster belongs to",
}
var AppInstRefKeySpecialArgs = map[string]string{}
var InfraResourcesRequiredArgs = []string{}
var InfraResourcesOptionalArgs = []string{
	"vms:#.name",
	"vms:#.type",
	"vms:#.status",
	"vms:#.infraflavor",
	"vms:#.ipaddresses:#.externalip",
	"vms:#.ipaddresses:#.internalip",
	"vms:#.containers:#.name",
	"vms:#.containers:#.type",
	"vms:#.containers:#.status",
	"vms:#.containers:#.clusterip",
	"vms:#.containers:#.restarts",
}
var InfraResourcesAliasArgs = []string{}
var InfraResourcesComments = map[string]string{
	"vms:#.name":                     "Virtual machine name",
	"vms:#.type":                     "Type can be platformvm, platform-cluster-master, platform-cluster-primary-node, platform-cluster-secondary-node, sharedrootlb, dedicatedrootlb, cluster-master, cluster-k8s-node, cluster-docker-node, appvm",
	"vms:#.status":                   "Runtime status of the VM",
	"vms:#.infraflavor":              "Flavor allocated within the cloudlet infrastructure, distinct from the control plane flavor",
	"vms:#.ipaddresses:#.externalip": "External IP address",
	"vms:#.ipaddresses:#.internalip": "Internal IP address",
	"vms:#.containers:#.name":        "Name of the container",
	"vms:#.containers:#.type":        "Type can be docker or kubernetes",
	"vms:#.containers:#.status":      "Runtime status of the container",
	"vms:#.containers:#.clusterip":   "IP within the CNI and is applicable to kubernetes only",
	"vms:#.containers:#.restarts":    "Restart count, applicable to kubernetes only",
}
var InfraResourcesSpecialArgs = map[string]string{}
var InfraResourcesSnapshotRequiredArgs = []string{}
var InfraResourcesSnapshotOptionalArgs = []string{
	"platformvms:#.name",
	"platformvms:#.type",
	"platformvms:#.status",
	"platformvms:#.infraflavor",
	"platformvms:#.ipaddresses:#.externalip",
	"platformvms:#.ipaddresses:#.internalip",
	"platformvms:#.containers:#.name",
	"platformvms:#.containers:#.type",
	"platformvms:#.containers:#.status",
	"platformvms:#.containers:#.clusterip",
	"platformvms:#.containers:#.restarts",
	"info:#.name",
	"info:#.value",
	"info:#.inframaxvalue",
	"info:#.quotamaxvalue",
	"info:#.description",
	"info:#.units",
	"info:#.alertthreshold",
	"clusterinsts:#.clusterkey.name",
	"clusterinsts:#.organization",
	"vmappinsts:#.appkey.organization",
	"vmappinsts:#.appkey.name",
	"vmappinsts:#.appkey.version",
	"vmappinsts:#.clusterinstkey.clusterkey.name",
	"vmappinsts:#.clusterinstkey.organization",
	"k8sappinsts:#.appkey.organization",
	"k8sappinsts:#.appkey.name",
	"k8sappinsts:#.appkey.version",
	"k8sappinsts:#.clusterinstkey.clusterkey.name",
	"k8sappinsts:#.clusterinstkey.organization",
}
var InfraResourcesSnapshotAliasArgs = []string{}
var InfraResourcesSnapshotComments = map[string]string{
	"platformvms:#.name":                           "Virtual machine name",
	"platformvms:#.type":                           "Type can be platformvm, platform-cluster-master, platform-cluster-primary-node, platform-cluster-secondary-node, sharedrootlb, dedicatedrootlb, cluster-master, cluster-k8s-node, cluster-docker-node, appvm",
	"platformvms:#.status":                         "Runtime status of the VM",
	"platformvms:#.infraflavor":                    "Flavor allocated within the cloudlet infrastructure, distinct from the control plane flavor",
	"platformvms:#.ipaddresses:#.externalip":       "External IP address",
	"platformvms:#.ipaddresses:#.internalip":       "Internal IP address",
	"platformvms:#.containers:#.name":              "Name of the container",
	"platformvms:#.containers:#.type":              "Type can be docker or kubernetes",
	"platformvms:#.containers:#.status":            "Runtime status of the container",
	"platformvms:#.containers:#.clusterip":         "IP within the CNI and is applicable to kubernetes only",
	"platformvms:#.containers:#.restarts":          "Restart count, applicable to kubernetes only",
	"info:#.name":                                  "Resource name",
	"info:#.value":                                 "Resource value",
	"info:#.inframaxvalue":                         "Resource infra max value",
	"info:#.quotamaxvalue":                         "Resource quota max value",
	"info:#.description":                           "Resource description",
	"info:#.units":                                 "Resource units",
	"info:#.alertthreshold":                        "Generate alert when more than threshold percentage of resource is used",
	"clusterinsts:#.clusterkey.name":               "Cluster name",
	"clusterinsts:#.organization":                  "Name of Developer organization that this cluster belongs to",
	"vmappinsts:#.appkey.organization":             "App developer organization",
	"vmappinsts:#.appkey.name":                     "App name",
	"vmappinsts:#.appkey.version":                  "App version",
	"vmappinsts:#.clusterinstkey.clusterkey.name":  "Cluster name",
	"vmappinsts:#.clusterinstkey.organization":     "Name of Developer organization that this cluster belongs to",
	"k8sappinsts:#.appkey.organization":            "App developer organization",
	"k8sappinsts:#.appkey.name":                    "App name",
	"k8sappinsts:#.appkey.version":                 "App version",
	"k8sappinsts:#.clusterinstkey.clusterkey.name": "Cluster name",
	"k8sappinsts:#.clusterinstkey.organization":    "Name of Developer organization that this cluster belongs to",
}
var InfraResourcesSnapshotSpecialArgs = map[string]string{}