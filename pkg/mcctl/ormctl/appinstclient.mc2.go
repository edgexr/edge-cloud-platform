// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: appinstclient.proto

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

var ShowAppInstClientCmd = &ApiCommand{
	Name:                 "ShowAppInstClient",
	Use:                  "showappinstclient",
	Short:                "Show application instance clients.",
	RequiredArgs:         "region " + strings.Join(AppInstClientKeyRequiredArgs, " "),
	OptionalArgs:         strings.Join(AppInstClientKeyOptionalArgs, " "),
	AliasArgs:            strings.Join(AppInstClientKeyAliasArgs, " "),
	SpecialArgs:          &AppInstClientKeySpecialArgs,
	Comments:             addRegionComment(AppInstClientKeyComments),
	ReqData:              &ormapi.RegionAppInstClientKey{},
	ReplyData:            &edgeproto.AppInstClient{},
	Path:                 "/auth/ctrl/ShowAppInstClient",
	StreamOut:            true,
	StreamOutIncremental: true,
	ProtobufApi:          true,
}
var AppInstClientApiCmds = []*ApiCommand{
	ShowAppInstClientCmd,
}

const AppInstClientGroup = "AppInstClient"

func init() {
	AllApis.AddGroup(AppInstClientGroup, "Manage AppInstClients", AppInstClientApiCmds)
}

var AppInstClientKeyRequiredArgs = []string{
	"appinstkey.name",
	"appinstkey.organization",
	"apporg",
}
var AppInstClientKeyOptionalArgs = []string{
	"cloudletorg",
	"cloudlet",
	"federatedorg",
	"appname",
	"appvers",
	"cluster",
	"clusterorg",
	"uniqueid",
	"uniqueidtype",
}
var AppInstClientKeyAliasArgs = []string{
	"appinstkey.name=appinstclientkey.appinstkey.name",
	"appinstkey.organization=appinstclientkey.appinstkey.organization",
	"cloudletorg=appinstclientkey.appinstkey.cloudletkey.organization",
	"cloudlet=appinstclientkey.appinstkey.cloudletkey.name",
	"federatedorg=appinstclientkey.appinstkey.cloudletkey.federatedorganization",
	"apporg=appinstclientkey.appkey.organization",
	"appname=appinstclientkey.appkey.name",
	"appvers=appinstclientkey.appkey.version",
	"cluster=appinstclientkey.clusterkey.name",
	"clusterorg=appinstclientkey.clusterkey.organization",
	"uniqueid=appinstclientkey.uniqueid",
	"uniqueidtype=appinstclientkey.uniqueidtype",
}
var AppInstClientKeyComments = map[string]string{
	"appinstkey.name":         "App Instance name",
	"appinstkey.organization": "App Instance organization",
	"cloudletorg":             "Organization of the cloudlet site",
	"cloudlet":                "Name of the cloudlet",
	"federatedorg":            "Federated operator organization who shared this cloudlet",
	"apporg":                  "App developer organization",
	"appname":                 "App name",
	"appvers":                 "App version",
	"cluster":                 "Cluster name",
	"clusterorg":              "Name of the organization that this cluster belongs to",
	"uniqueid":                "AppInstClient Unique Id",
	"uniqueidtype":            "AppInstClient Unique Id Type",
}
var AppInstClientKeySpecialArgs = map[string]string{}
