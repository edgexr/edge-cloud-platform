// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: app_inst.proto

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
import _ "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
import _ "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
import _ "github.com/gogo/protobuf/gogoproto"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

var CreateAppInstCmd = &Command{
	Use:                  "CreateAppInst",
	RequiredArgs:         strings.Join(append([]string{"region"}, AppInstRequiredArgs...), " "),
	OptionalArgs:         strings.Join(AppInstOptionalArgs, " "),
	AliasArgs:            strings.Join(AppInstAliasArgs, " "),
	ReqData:              &ormapi.RegionAppInst{},
	ReplyData:            &edgeproto.Result{},
	Path:                 "/auth/ctrl/CreateAppInst",
	StreamOut:            true,
	StreamOutIncremental: true,
}

var DeleteAppInstCmd = &Command{
	Use:                  "DeleteAppInst",
	RequiredArgs:         strings.Join(append([]string{"region"}, AppInstRequiredArgs...), " "),
	OptionalArgs:         strings.Join(AppInstOptionalArgs, " "),
	AliasArgs:            strings.Join(AppInstAliasArgs, " "),
	ReqData:              &ormapi.RegionAppInst{},
	ReplyData:            &edgeproto.Result{},
	Path:                 "/auth/ctrl/DeleteAppInst",
	StreamOut:            true,
	StreamOutIncremental: true,
}

var UpdateAppInstCmd = &Command{
	Use:                  "UpdateAppInst",
	RequiredArgs:         strings.Join(append([]string{"region"}, AppInstRequiredArgs...), " "),
	OptionalArgs:         strings.Join(AppInstOptionalArgs, " "),
	AliasArgs:            strings.Join(AppInstAliasArgs, " "),
	ReqData:              &ormapi.RegionAppInst{},
	ReplyData:            &edgeproto.Result{},
	Path:                 "/auth/ctrl/UpdateAppInst",
	StreamOut:            true,
	StreamOutIncremental: true,
}

var ShowAppInstCmd = &Command{
	Use:          "ShowAppInst",
	RequiredArgs: "region",
	OptionalArgs: strings.Join(append(AppInstRequiredArgs, AppInstOptionalArgs...), " "),
	AliasArgs:    strings.Join(AppInstAliasArgs, " "),
	ReqData:      &ormapi.RegionAppInst{},
	ReplyData:    &edgeproto.AppInst{},
	Path:         "/auth/ctrl/ShowAppInst",
	StreamOut:    true,
}
var AppInstApiCmds = []*Command{
	CreateAppInstCmd,
	DeleteAppInstCmd,
	UpdateAppInstCmd,
	ShowAppInstCmd,
}

var AppInstKeyRequiredArgs = []string{}
var AppInstKeyOptionalArgs = []string{
	"appkey.developerkey.name",
	"appkey.name",
	"appkey.version",
	"clusterinstkey.clusterkey.name",
	"clusterinstkey.cloudletkey.operatorkey.name",
	"clusterinstkey.cloudletkey.name",
	"clusterinstkey.developer",
}
var AppInstKeyAliasArgs = []string{
	"appkey.developerkey.name=appinstkey.appkey.developerkey.name",
	"appkey.name=appinstkey.appkey.name",
	"appkey.version=appinstkey.appkey.version",
	"clusterinstkey.clusterkey.name=appinstkey.clusterinstkey.clusterkey.name",
	"clusterinstkey.cloudletkey.operatorkey.name=appinstkey.clusterinstkey.cloudletkey.operatorkey.name",
	"clusterinstkey.cloudletkey.name=appinstkey.clusterinstkey.cloudletkey.name",
	"clusterinstkey.developer=appinstkey.clusterinstkey.developer",
}
var AppInstRequiredArgs = []string{
	"developer",
	"appname",
	"appvers",
	"cluster",
	"operator",
	"cloudlet",
}
var AppInstOptionalArgs = []string{
	"clusterdeveloper",
	"uri",
	"flavor.name",
	"state",
	"errors",
	"crmoverride",
	"runtimeinfo.containerids",
	"runtimeinfo.consoleurl",
	"autoclusteripaccess",
	"forceupdate",
	"updatemultiple",
}
var AppInstAliasArgs = []string{
	"developer=appinst.key.appkey.developerkey.name",
	"appname=appinst.key.appkey.name",
	"appvers=appinst.key.appkey.version",
	"cluster=appinst.key.clusterinstkey.clusterkey.name",
	"operator=appinst.key.clusterinstkey.cloudletkey.operatorkey.name",
	"cloudlet=appinst.key.clusterinstkey.cloudletkey.name",
	"clusterdeveloper=appinst.key.clusterinstkey.developer",
	"cloudletloc.latitude=appinst.cloudletloc.latitude",
	"cloudletloc.longitude=appinst.cloudletloc.longitude",
	"cloudletloc.horizontalaccuracy=appinst.cloudletloc.horizontalaccuracy",
	"cloudletloc.verticalaccuracy=appinst.cloudletloc.verticalaccuracy",
	"cloudletloc.altitude=appinst.cloudletloc.altitude",
	"cloudletloc.course=appinst.cloudletloc.course",
	"cloudletloc.speed=appinst.cloudletloc.speed",
	"cloudletloc.timestamp.seconds=appinst.cloudletloc.timestamp.seconds",
	"cloudletloc.timestamp.nanos=appinst.cloudletloc.timestamp.nanos",
	"uri=appinst.uri",
	"liveness=appinst.liveness",
	"mappedports.proto=appinst.mappedports.proto",
	"mappedports.internalport=appinst.mappedports.internalport",
	"mappedports.publicport=appinst.mappedports.publicport",
	"mappedports.pathprefix=appinst.mappedports.pathprefix",
	"mappedports.fqdnprefix=appinst.mappedports.fqdnprefix",
	"flavor.name=appinst.flavor.name",
	"state=appinst.state",
	"errors=appinst.errors",
	"crmoverride=appinst.crmoverride",
	"runtimeinfo.containerids=appinst.runtimeinfo.containerids",
	"runtimeinfo.consoleurl=appinst.runtimeinfo.consoleurl",
	"createdat.seconds=appinst.createdat.seconds",
	"createdat.nanos=appinst.createdat.nanos",
	"autoclusteripaccess=appinst.autoclusteripaccess",
	"status.tasknumber=appinst.status.tasknumber",
	"status.maxtasks=appinst.status.maxtasks",
	"status.taskname=appinst.status.taskname",
	"status.stepname=appinst.status.stepname",
	"revision=appinst.revision",
	"forceupdate=appinst.forceupdate",
	"updatemultiple=appinst.updatemultiple",
}
var AppInstRuntimeRequiredArgs = []string{}
var AppInstRuntimeOptionalArgs = []string{
	"containerids",
	"consoleurl",
}
var AppInstRuntimeAliasArgs = []string{
	"containerids=appinstruntime.containerids",
	"consoleurl=appinstruntime.consoleurl",
}
var AppInstInfoRequiredArgs = []string{
	"key.appkey.developerkey.name",
	"key.appkey.name",
	"key.appkey.version",
	"key.clusterinstkey.clusterkey.name",
	"key.clusterinstkey.cloudletkey.operatorkey.name",
	"key.clusterinstkey.cloudletkey.name",
	"key.clusterinstkey.developer",
}
var AppInstInfoOptionalArgs = []string{
	"notifyid",
	"state",
	"errors",
	"runtimeinfo.containerids",
	"runtimeinfo.consoleurl",
	"status.tasknumber",
	"status.maxtasks",
	"status.taskname",
	"status.stepname",
}
var AppInstInfoAliasArgs = []string{
	"key.appkey.developerkey.name=appinstinfo.key.appkey.developerkey.name",
	"key.appkey.name=appinstinfo.key.appkey.name",
	"key.appkey.version=appinstinfo.key.appkey.version",
	"key.clusterinstkey.clusterkey.name=appinstinfo.key.clusterinstkey.clusterkey.name",
	"key.clusterinstkey.cloudletkey.operatorkey.name=appinstinfo.key.clusterinstkey.cloudletkey.operatorkey.name",
	"key.clusterinstkey.cloudletkey.name=appinstinfo.key.clusterinstkey.cloudletkey.name",
	"key.clusterinstkey.developer=appinstinfo.key.clusterinstkey.developer",
	"notifyid=appinstinfo.notifyid",
	"state=appinstinfo.state",
	"errors=appinstinfo.errors",
	"runtimeinfo.containerids=appinstinfo.runtimeinfo.containerids",
	"runtimeinfo.consoleurl=appinstinfo.runtimeinfo.consoleurl",
	"status.tasknumber=appinstinfo.status.tasknumber",
	"status.maxtasks=appinstinfo.status.maxtasks",
	"status.taskname=appinstinfo.status.taskname",
	"status.stepname=appinstinfo.status.stepname",
}
var AppInstMetricsRequiredArgs = []string{}
var AppInstMetricsOptionalArgs = []string{
	"something",
}
var AppInstMetricsAliasArgs = []string{
	"something=appinstmetrics.something",
}
