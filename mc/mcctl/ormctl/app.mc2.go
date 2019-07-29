// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: app.proto

/*
Package ormctl is a generated protocol buffer package.

It is generated from these files:
	app.proto
	app_inst.proto
	cloudlet.proto
	cluster.proto
	clusterinst.proto
	common.proto
	controller.proto
	developer.proto
	exec.proto
	flavor.proto
	metric.proto
	node.proto
	notice.proto
	operator.proto
	refs.proto
	result.proto
	version.proto

It has these top-level messages:
	AppKey
	ConfigFile
	App
	AppInstKey
	AppInst
	AppInstRuntime
	AppInstInfo
	AppInstMetrics
	CloudletKey
	OperationTimeLimits
	CloudletInfraCommon
	AzureProperties
	GcpProperties
	OpenStackProperties
	CloudletInfraProperties
	PlatformConfig
	Cloudlet
	FlavorInfo
	CloudletInfo
	CloudletMetrics
	ClusterKey
	ClusterInstKey
	ClusterInst
	ClusterInstInfo
	StatusInfo
	ControllerKey
	Controller
	DeveloperKey
	Developer
	ExecRequest
	FlavorKey
	Flavor
	MetricTag
	MetricVal
	Metric
	NodeKey
	Node
	Notice
	OperatorKey
	Operator
	CloudletRefs
	ClusterRefs
	Result
*/
package ormctl

import edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
import "strings"
import "github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/googleapis/google/api"
import _ "github.com/mobiledgex/edge-cloud/protogen"
import _ "github.com/mobiledgex/edge-cloud/protoc-gen-cmd/protocmd"
import _ "github.com/gogo/protobuf/gogoproto"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

var CreateAppCmd = &Command{
	Use:          "CreateApp",
	RequiredArgs: strings.Join(append([]string{"region"}, AppRequiredArgs...), " "),
	OptionalArgs: strings.Join(AppOptionalArgs, " "),
	AliasArgs:    strings.Join(AppAliasArgs, " "),
	ReqData:      &ormapi.RegionApp{},
	ReplyData:    &edgeproto.Result{},
	Path:         "/auth/ctrl/CreateApp",
}

var DeleteAppCmd = &Command{
	Use:          "DeleteApp",
	RequiredArgs: strings.Join(append([]string{"region"}, AppRequiredArgs...), " "),
	OptionalArgs: strings.Join(AppOptionalArgs, " "),
	AliasArgs:    strings.Join(AppAliasArgs, " "),
	ReqData:      &ormapi.RegionApp{},
	ReplyData:    &edgeproto.Result{},
	Path:         "/auth/ctrl/DeleteApp",
}

var UpdateAppCmd = &Command{
	Use:          "UpdateApp",
	RequiredArgs: strings.Join(append([]string{"region"}, AppRequiredArgs...), " "),
	OptionalArgs: strings.Join(AppOptionalArgs, " "),
	AliasArgs:    strings.Join(AppAliasArgs, " "),
	ReqData:      &ormapi.RegionApp{},
	ReplyData:    &edgeproto.Result{},
	Path:         "/auth/ctrl/UpdateApp",
}

var ShowAppCmd = &Command{
	Use:          "ShowApp",
	RequiredArgs: "region",
	OptionalArgs: strings.Join(append(AppRequiredArgs, AppOptionalArgs...), " "),
	AliasArgs:    strings.Join(AppAliasArgs, " "),
	ReqData:      &ormapi.RegionApp{},
	ReplyData:    &edgeproto.App{},
	Path:         "/auth/ctrl/ShowApp",
	StreamOut:    true,
}
var AppApiCmds = []*Command{
	CreateAppCmd,
	DeleteAppCmd,
	UpdateAppCmd,
	ShowAppCmd,
}

var AppKeyRequiredArgs = []string{}
var AppKeyOptionalArgs = []string{
	"developerkey.name",
	"name",
	"version",
}
var AppKeyAliasArgs = []string{
	"developerkey.name=appkey.developerkey.name",
	"name=appkey.name",
	"version=appkey.version",
}
var ConfigFileRequiredArgs = []string{}
var ConfigFileOptionalArgs = []string{
	"kind",
	"config",
}
var ConfigFileAliasArgs = []string{
	"kind=configfile.kind",
	"config=configfile.config",
}
var AppRequiredArgs = []string{
	"developer",
	"appname",
	"appvers",
}
var AppOptionalArgs = []string{
	"imagepath",
	"imagetype",
	"accessports",
	"defaultflavor.name",
	"authpublickey",
	"command",
	"annotations",
	"deployment",
	"deploymentmanifest",
	"deploymentgenerator",
	"androidpackagename",
	"permitsplatformapps",
	"delopt",
	"configs.kind",
	"configs.config",
	"scalewithcluster",
	"internalports",
	"officialfqdn",
	"md5sum",
}
var AppAliasArgs = []string{
	"developer=app.key.developerkey.name",
	"appname=app.key.name",
	"appvers=app.key.version",
	"imagepath=app.imagepath",
	"imagetype=app.imagetype",
	"accessports=app.accessports",
	"defaultflavor.name=app.defaultflavor.name",
	"authpublickey=app.authpublickey",
	"command=app.command",
	"annotations=app.annotations",
	"deployment=app.deployment",
	"deploymentmanifest=app.deploymentmanifest",
	"deploymentgenerator=app.deploymentgenerator",
	"androidpackagename=app.androidpackagename",
	"permitsplatformapps=app.permitsplatformapps",
	"delopt=app.delopt",
	"configs.kind=app.configs.kind",
	"configs.config=app.configs.config",
	"scalewithcluster=app.scalewithcluster",
	"internalports=app.internalports",
	"revision=app.revision",
	"officialfqdn=app.officialfqdn",
	"md5sum=app.md5sum",
}
