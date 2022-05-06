// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: node.proto

package ormctl

import (
	fmt "fmt"
	edgeproto "github.com/edgexr/edge-cloud-platform/edgeproto"
	"github.com/edgexr/edge-cloud-platform/mc/ormapi"
	_ "github.com/edgexr/edge-cloud-platform/protogen"
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

var ShowNodeCmd = &ApiCommand{
	Name:         "ShowNode",
	Use:          "show",
	Short:        "Show all Nodes connected to all Controllers",
	OptionalArgs: strings.Join(append(NodeRequiredArgs, NodeOptionalArgs...), " "),
	AliasArgs:    strings.Join(NodeAliasArgs, " "),
	SpecialArgs:  &NodeSpecialArgs,
	Comments:     addRegionComment(NodeComments),
	ReqData:      &ormapi.RegionNode{},
	ReplyData:    &edgeproto.Node{},
	Path:         "/auth/ctrl/ShowNode",
	StreamOut:    true,
	ProtobufApi:  true,
}
var NodeApiCmds = []*ApiCommand{
	ShowNodeCmd,
}

const NodeGroup = "Node"

func init() {
	AllApis.AddGroup(NodeGroup, "Manage Nodes", NodeApiCmds)
}

var NodeRequiredArgs = []string{
	"name",
	"type",
	"cloudletorg",
	"cloudlet",
	"federatedorg",
	"region",
}
var NodeOptionalArgs = []string{
	"notifyid",
	"buildmaster",
	"buildhead",
	"buildauthor",
	"builddate",
	"hostname",
	"containerversion",
	"internalpki",
	"properties",
}
var NodeAliasArgs = []string{
	"fields=node.fields",
	"name=node.key.name",
	"type=node.key.type",
	"cloudletorg=node.key.cloudletkey.organization",
	"cloudlet=node.key.cloudletkey.name",
	"federatedorg=node.key.cloudletkey.federatedorganization",
	"region=node.key.region",
	"notifyid=node.notifyid",
	"buildmaster=node.buildmaster",
	"buildhead=node.buildhead",
	"buildauthor=node.buildauthor",
	"builddate=node.builddate",
	"hostname=node.hostname",
	"containerversion=node.containerversion",
	"internalpki=node.internalpki",
	"properties=node.properties",
}
var NodeComments = map[string]string{
	"fields":           "Fields are used for the Update API to specify which fields to apply",
	"name":             "Name or hostname of node",
	"type":             "Node type",
	"cloudletorg":      "Organization of the cloudlet site",
	"cloudlet":         "Name of the cloudlet",
	"federatedorg":     "Federated operator organization who shared this cloudlet",
	"region":           "Region the node is in",
	"notifyid":         "Id of client assigned by server (internal use only)",
	"buildmaster":      "Build Master Version",
	"buildhead":        "Build Head Version",
	"buildauthor":      "Build Author",
	"builddate":        "Build Date",
	"hostname":         "Hostname",
	"containerversion": "Docker edge-cloud container version which node instance use",
	"internalpki":      "Internal PKI Config",
	"properties":       "Additional properties",
}
var NodeSpecialArgs = map[string]string{
	"node.fields":     "StringArray",
	"node.properties": "StringToString",
}
