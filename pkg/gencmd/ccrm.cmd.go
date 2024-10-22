// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: ccrm.proto

package gencmd

import (
	fmt "fmt"
	edgeproto "github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cli"
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
func CloudletExecReqHideTags(in *edgeproto.CloudletExecReq) {
	if cli.HideTags == "" {
		return
	}
	tags := make(map[string]struct{})
	for _, tag := range strings.Split(cli.HideTags, ",") {
		tags[tag] = struct{}{}
	}
	if _, found := tags["nocmp"]; found {
		in.ExecReq.Offer = ""
	}
	if _, found := tags["nocmp"]; found {
		in.ExecReq.Answer = ""
	}
	if _, found := tags["nocmp"]; found {
		in.ExecReq.Console.Url = ""
	}
}

var StreamStatusRequiredArgs = []string{}
var StreamStatusOptionalArgs = []string{
	"cacheupdatetype",
	"status",
}
var StreamStatusAliasArgs = []string{}
var StreamStatusComments = map[string]string{
	"cacheupdatetype": "Cache update type",
	"status":          "Status value",
}
var StreamStatusSpecialArgs = map[string]string{}
var InfraResourceMapRequiredArgs = []string{}
var InfraResourceMapOptionalArgs = []string{}
var InfraResourceMapAliasArgs = []string{}
var InfraResourceMapComments = map[string]string{}
var InfraResourceMapSpecialArgs = map[string]string{}
var ClusterResourcesReqRequiredArgs = []string{}
var ClusterResourcesReqOptionalArgs = []string{
	"cloudletkey.organization",
	"cloudletkey.name",
	"cloudletkey.federatedorganization",
	"vmresources:#.key.name",
	"vmresources:#.key.organization",
	"vmresources:#.vmflavor",
	"vmresources:#.type",
	"vmresources:#.count",
}
var ClusterResourcesReqAliasArgs = []string{}
var ClusterResourcesReqComments = map[string]string{
	"cloudletkey.organization":          "Organization of the cloudlet site",
	"cloudletkey.name":                  "Name of the cloudlet",
	"cloudletkey.federatedorganization": "Federated operator organization who shared this cloudlet",
	"vmresources:#.key.name":            "Cluster name",
	"vmresources:#.key.organization":    "Name of the organization that this cluster belongs to",
	"vmresources:#.vmflavor":            "Infrastructure specific flavor of the VM",
	"vmresources:#.type":                "Resource Type can be platform, rootlb, cluster-master, cluster-k8s-node, cluster-docker-node, appvm, k8s-lb-svc",
	"vmresources:#.count":               "Number of these VMs in cluster",
}
var ClusterResourcesReqSpecialArgs = map[string]string{}
var ClusterResourceMetricReqRequiredArgs = []string{}
var ClusterResourceMetricReqOptionalArgs = []string{
	"cloudletkey.organization",
	"cloudletkey.name",
	"cloudletkey.federatedorganization",
	"resmetric.name",
	"resmetric.timestamp.seconds",
	"resmetric.timestamp.nanos",
	"resmetric.tags:#.name",
	"resmetric.tags:#.val",
	"resmetric.vals:#.name",
	"vmresources:#.key.name",
	"vmresources:#.key.organization",
	"vmresources:#.vmflavor",
	"vmresources:#.type",
	"vmresources:#.count",
}
var ClusterResourceMetricReqAliasArgs = []string{}
var ClusterResourceMetricReqComments = map[string]string{
	"cloudletkey.organization":          "Organization of the cloudlet site",
	"cloudletkey.name":                  "Name of the cloudlet",
	"cloudletkey.federatedorganization": "Federated operator organization who shared this cloudlet",
	"resmetric.name":                    "Metric name",
	"resmetric.timestamp.seconds":       "Represents seconds of UTC time since Unix epoch 1970-01-01T00:00:00Z. Must be from 0001-01-01T00:00:00Z to 9999-12-31T23:59:59Z inclusive.",
	"resmetric.timestamp.nanos":         "Non-negative fractions of a second at nanosecond resolution. Negative second values with fractions must still have non-negative nanos values that count forward in time. Must be from 0 to 999,999,999 inclusive.",
	"resmetric.tags:#.name":             "Metric tag name",
	"resmetric.tags:#.val":              "Metric tag value",
	"resmetric.vals:#.name":             "Name of the value",
	"vmresources:#.key.name":            "Cluster name",
	"vmresources:#.key.organization":    "Name of the organization that this cluster belongs to",
	"vmresources:#.vmflavor":            "Infrastructure specific flavor of the VM",
	"vmresources:#.type":                "Resource Type can be platform, rootlb, cluster-master, cluster-k8s-node, cluster-docker-node, appvm, k8s-lb-svc",
	"vmresources:#.count":               "Number of these VMs in cluster",
}
var ClusterResourceMetricReqSpecialArgs = map[string]string{}
var NameSanitizeReqRequiredArgs = []string{}
var NameSanitizeReqOptionalArgs = []string{
	"cloudletkey.organization",
	"cloudletkey.name",
	"cloudletkey.federatedorganization",
	"message",
}
var NameSanitizeReqAliasArgs = []string{}
var NameSanitizeReqComments = map[string]string{
	"cloudletkey.organization":          "Organization of the cloudlet site",
	"cloudletkey.name":                  "Name of the cloudlet",
	"cloudletkey.federatedorganization": "Federated operator organization who shared this cloudlet",
	"message":                           "String value",
}
var NameSanitizeReqSpecialArgs = map[string]string{}
var CloudletExecReqRequiredArgs = []string{}
var CloudletExecReqOptionalArgs = []string{
	"cloudletkey.organization",
	"cloudletkey.name",
	"cloudletkey.federatedorganization",
	"execreq.appinstkey.name",
	"execreq.appinstkey.organization",
	"execreq.containerid",
	"execreq.offer",
	"execreq.answer",
	"execreq.err",
	"execreq.cmd.command",
	"execreq.cmd.cloudletmgmtnode.type",
	"execreq.cmd.cloudletmgmtnode.name",
	"execreq.log.since",
	"execreq.log.tail",
	"execreq.log.timestamps",
	"execreq.log.follow",
	"execreq.console.url",
	"execreq.timeout",
	"execreq.accessurl",
	"execreq.edgeturnaddr",
	"execreq.edgeturnproxyaddr",
	"execreq.cloudletkey.organization",
	"execreq.cloudletkey.name",
	"execreq.cloudletkey.federatedorganization",
}
var CloudletExecReqAliasArgs = []string{}
var CloudletExecReqComments = map[string]string{
	"cloudletkey.organization":                  "Organization of the cloudlet site",
	"cloudletkey.name":                          "Name of the cloudlet",
	"cloudletkey.federatedorganization":         "Federated operator organization who shared this cloudlet",
	"execreq.appinstkey.name":                   "App Instance name",
	"execreq.appinstkey.organization":           "App Instance organization",
	"execreq.containerid":                       "ContainerId is the name or ID of the target container, if applicable",
	"execreq.offer":                             "Offer",
	"execreq.answer":                            "Answer",
	"execreq.err":                               "Any error message",
	"execreq.cmd.command":                       "Command or Shell",
	"execreq.cmd.cloudletmgmtnode.type":         "Type of Cloudlet Mgmt Node",
	"execreq.cmd.cloudletmgmtnode.name":         "Name of Cloudlet Mgmt Node",
	"execreq.log.since":                         "Show logs since either a duration ago (5s, 2m, 3h) or a timestamp (RFC3339)",
	"execreq.log.tail":                          "Show only a recent number of lines",
	"execreq.log.timestamps":                    "Show timestamps",
	"execreq.log.follow":                        "Stream data",
	"execreq.console.url":                       "VM Console URL",
	"execreq.timeout":                           "Timeout",
	"execreq.accessurl":                         "Access URL",
	"execreq.edgeturnaddr":                      "EdgeTurn Server Address",
	"execreq.edgeturnproxyaddr":                 "EdgeTurn Proxy Address",
	"execreq.cloudletkey.organization":          "Organization of the cloudlet site",
	"execreq.cloudletkey.name":                  "Name of the cloudlet",
	"execreq.cloudletkey.federatedorganization": "Federated operator organization who shared this cloudlet",
}
var CloudletExecReqSpecialArgs = map[string]string{}
