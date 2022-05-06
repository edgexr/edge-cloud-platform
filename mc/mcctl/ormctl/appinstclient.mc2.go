// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: appinstclient.proto

package ormctl

import (
	fmt "fmt"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	_ "github.com/edgexr/edge-cloud/d-match-engine/dme-proto"
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
	"apporg",
}
var AppInstClientKeyOptionalArgs = []string{
	"appname",
	"appvers",
	"cluster",
	"cloudletorg",
	"cloudlet",
	"federatedorg",
	"clusterorg",
	"uniqueid",
	"uniqueidtype",
}
var AppInstClientKeyAliasArgs = []string{
	"apporg=appinstclientkey.appinstkey.appkey.organization",
	"appname=appinstclientkey.appinstkey.appkey.name",
	"appvers=appinstclientkey.appinstkey.appkey.version",
	"cluster=appinstclientkey.appinstkey.clusterinstkey.clusterkey.name",
	"cloudletorg=appinstclientkey.appinstkey.clusterinstkey.cloudletkey.organization",
	"cloudlet=appinstclientkey.appinstkey.clusterinstkey.cloudletkey.name",
	"federatedorg=appinstclientkey.appinstkey.clusterinstkey.cloudletkey.federatedorganization",
	"clusterorg=appinstclientkey.appinstkey.clusterinstkey.organization",
	"uniqueid=appinstclientkey.uniqueid",
	"uniqueidtype=appinstclientkey.uniqueidtype",
}
var AppInstClientKeyComments = map[string]string{
	"apporg":       "App developer organization",
	"appname":      "App name",
	"appvers":      "App version",
	"cluster":      "Cluster name",
	"cloudletorg":  "Organization of the cloudlet site",
	"cloudlet":     "Name of the cloudlet",
	"federatedorg": "Federated operator organization who shared this cloudlet",
	"clusterorg":   "Name of Developer organization that this cluster belongs to",
	"uniqueid":     "AppInstClient Unique Id",
	"uniqueidtype": "AppInstClient Unique Id Type",
}
var AppInstClientKeySpecialArgs = map[string]string{}
