// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: settings.proto

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

var UpdateSettingsCmd = &ApiCommand{
	Name:         "UpdateSettings",
	Use:          "update",
	Short:        "Update settings",
	RequiredArgs: "region " + strings.Join(SettingsRequiredArgs, " "),
	OptionalArgs: strings.Join(SettingsOptionalArgs, " "),
	AliasArgs:    strings.Join(SettingsAliasArgs, " "),
	SpecialArgs:  &SettingsSpecialArgs,
	Comments:     addRegionComment(SettingsComments),
	ReqData:      &ormapi.RegionSettings{},
	ReplyData:    &edgeproto.Result{},
	Path:         "/auth/ctrl/UpdateSettings",
	ProtobufApi:  true,
}

var ResetSettingsCmd = &ApiCommand{
	Name:         "ResetSettings",
	Use:          "reset",
	Short:        "Reset all settings to their defaults",
	RequiredArgs: "region " + strings.Join(SettingsRequiredArgs, " "),
	OptionalArgs: strings.Join(SettingsOptionalArgs, " "),
	AliasArgs:    strings.Join(SettingsAliasArgs, " "),
	SpecialArgs:  &SettingsSpecialArgs,
	Comments:     addRegionComment(SettingsComments),
	ReqData:      &ormapi.RegionSettings{},
	ReplyData:    &edgeproto.Result{},
	Path:         "/auth/ctrl/ResetSettings",
	ProtobufApi:  true,
}

var ShowSettingsCmd = &ApiCommand{
	Name:         "ShowSettings",
	Use:          "show",
	Short:        "Show settings",
	RequiredArgs: "region " + strings.Join(SettingsRequiredArgs, " "),
	OptionalArgs: strings.Join(SettingsOptionalArgs, " "),
	AliasArgs:    strings.Join(SettingsAliasArgs, " "),
	SpecialArgs:  &SettingsSpecialArgs,
	Comments:     addRegionComment(SettingsComments),
	ReqData:      &ormapi.RegionSettings{},
	ReplyData:    &edgeproto.Settings{},
	Path:         "/auth/ctrl/ShowSettings",
	ProtobufApi:  true,
}
var SettingsApiCmds = []*ApiCommand{
	UpdateSettingsCmd,
	ResetSettingsCmd,
	ShowSettingsCmd,
}

const SettingsGroup = "Settings"

func init() {
	AllApis.AddGroup(SettingsGroup, "Manage Settings", SettingsApiCmds)
}

var SettingsRequiredArgs = []string{}
var SettingsOptionalArgs = []string{
	"shepherdmetricscollectioninterval",
	"shepherdalertevaluationinterval",
	"shepherdmetricsscrapeinterval",
	"shepherdhealthcheckretries",
	"shepherdhealthcheckinterval",
	"autodeployintervalsec",
	"autodeployoffsetsec",
	"autodeploymaxintervals",
	"createappinsttimeout",
	"updateappinsttimeout",
	"deleteappinsttimeout",
	"createclusterinsttimeout",
	"updateclusterinsttimeout",
	"deleteclusterinsttimeout",
	"masternodeflavor",
	"maxtrackeddmeclients",
	"chefclientinterval",
	"influxdbmetricsretention",
	"cloudletmaintenancetimeout",
	"updatevmpooltimeout",
	"updatetrustpolicytimeout",
	"dmeapimetricscollectioninterval",
	"edgeeventsmetricscollectioninterval",
	"cleanupreservableautoclusteridletime",
	"influxdbcloudletusagemetricsretention",
	"createcloudlettimeout",
	"updatecloudlettimeout",
	"locationtilesidelengthkm",
	"edgeeventsmetricscontinuousqueriescollectionintervals:empty",
	"edgeeventsmetricscontinuousqueriescollectionintervals:#.interval",
	"edgeeventsmetricscontinuousqueriescollectionintervals:#.retention",
	"influxdbdownsampledmetricsretention",
	"influxdbedgeeventsmetricsretention",
	"appinstclientcleanupinterval",
	"clusterautoscaleaveragingdurationsec",
	"clusterautoscaleretrydelay",
	"alertpolicymintriggertime",
	"disableratelimit",
	"ratelimitmaxtrackedips",
	"resourcesnapshotthreadinterval",
	"platformhainstancepollinterval",
	"platformhainstanceactiveexpiretime",
}
var SettingsAliasArgs = []string{
	"fields=settings.fields",
	"shepherdmetricscollectioninterval=settings.shepherdmetricscollectioninterval",
	"shepherdalertevaluationinterval=settings.shepherdalertevaluationinterval",
	"shepherdmetricsscrapeinterval=settings.shepherdmetricsscrapeinterval",
	"shepherdhealthcheckretries=settings.shepherdhealthcheckretries",
	"shepherdhealthcheckinterval=settings.shepherdhealthcheckinterval",
	"autodeployintervalsec=settings.autodeployintervalsec",
	"autodeployoffsetsec=settings.autodeployoffsetsec",
	"autodeploymaxintervals=settings.autodeploymaxintervals",
	"createappinsttimeout=settings.createappinsttimeout",
	"updateappinsttimeout=settings.updateappinsttimeout",
	"deleteappinsttimeout=settings.deleteappinsttimeout",
	"createclusterinsttimeout=settings.createclusterinsttimeout",
	"updateclusterinsttimeout=settings.updateclusterinsttimeout",
	"deleteclusterinsttimeout=settings.deleteclusterinsttimeout",
	"masternodeflavor=settings.masternodeflavor",
	"maxtrackeddmeclients=settings.maxtrackeddmeclients",
	"chefclientinterval=settings.chefclientinterval",
	"influxdbmetricsretention=settings.influxdbmetricsretention",
	"cloudletmaintenancetimeout=settings.cloudletmaintenancetimeout",
	"updatevmpooltimeout=settings.updatevmpooltimeout",
	"updatetrustpolicytimeout=settings.updatetrustpolicytimeout",
	"dmeapimetricscollectioninterval=settings.dmeapimetricscollectioninterval",
	"edgeeventsmetricscollectioninterval=settings.edgeeventsmetricscollectioninterval",
	"cleanupreservableautoclusteridletime=settings.cleanupreservableautoclusteridletime",
	"influxdbcloudletusagemetricsretention=settings.influxdbcloudletusagemetricsretention",
	"createcloudlettimeout=settings.createcloudlettimeout",
	"updatecloudlettimeout=settings.updatecloudlettimeout",
	"locationtilesidelengthkm=settings.locationtilesidelengthkm",
	"edgeeventsmetricscontinuousqueriescollectionintervals:empty=settings.edgeeventsmetricscontinuousqueriescollectionintervals:empty",
	"edgeeventsmetricscontinuousqueriescollectionintervals:#.interval=settings.edgeeventsmetricscontinuousqueriescollectionintervals:#.interval",
	"edgeeventsmetricscontinuousqueriescollectionintervals:#.retention=settings.edgeeventsmetricscontinuousqueriescollectionintervals:#.retention",
	"influxdbdownsampledmetricsretention=settings.influxdbdownsampledmetricsretention",
	"influxdbedgeeventsmetricsretention=settings.influxdbedgeeventsmetricsretention",
	"appinstclientcleanupinterval=settings.appinstclientcleanupinterval",
	"clusterautoscaleaveragingdurationsec=settings.clusterautoscaleaveragingdurationsec",
	"clusterautoscaleretrydelay=settings.clusterautoscaleretrydelay",
	"alertpolicymintriggertime=settings.alertpolicymintriggertime",
	"disableratelimit=settings.disableratelimit",
	"ratelimitmaxtrackedips=settings.ratelimitmaxtrackedips",
	"resourcesnapshotthreadinterval=settings.resourcesnapshotthreadinterval",
	"platformhainstancepollinterval=settings.platformhainstancepollinterval",
	"platformhainstanceactiveexpiretime=settings.platformhainstanceactiveexpiretime",
}
var SettingsComments = map[string]string{
	"fields":                                                      "Fields are used for the Update API to specify which fields to apply",
	"shepherdmetricscollectioninterval":                           "Shepherd metrics collection interval for k8s and docker appInstances (duration)",
	"shepherdalertevaluationinterval":                             "Shepherd alert evaluation interval for k8s and docker appInstances (duration)",
	"shepherdmetricsscrapeinterval":                               "Shepherd metrics scraping interval (how often metrics are pulled by prometheus, vs pushed to Controller by Shepherd collection)",
	"shepherdhealthcheckretries":                                  "Number of times Shepherd Health Check fails before we mark appInst down",
	"shepherdhealthcheckinterval":                                 "Health Checking probing frequency (duration)",
	"autodeployintervalsec":                                       "Auto Provisioning Stats push and analysis interval (seconds)",
	"autodeployoffsetsec":                                         "Auto Provisioning analysis offset from interval (seconds)",
	"autodeploymaxintervals":                                      "Auto Provisioning Policy max allowed intervals",
	"createappinsttimeout":                                        "Create AppInst timeout (duration)",
	"updateappinsttimeout":                                        "Update AppInst timeout (duration)",
	"deleteappinsttimeout":                                        "Delete AppInst timeout (duration)",
	"createclusterinsttimeout":                                    "Create ClusterInst timeout (duration)",
	"updateclusterinsttimeout":                                    "Update ClusterInst timeout (duration)",
	"deleteclusterinsttimeout":                                    "Delete ClusterInst timeout (duration)",
	"masternodeflavor":                                            "Default flavor for k8s master VM and > 0  workers",
	"maxtrackeddmeclients":                                        "Max DME clients to be tracked at the same time.",
	"chefclientinterval":                                          "Default chef client interval (duration)",
	"influxdbmetricsretention":                                    "Default influxDB metrics retention policy (duration)",
	"cloudletmaintenancetimeout":                                  "Default Cloudlet Maintenance timeout (used twice for AutoProv and Cloudlet)",
	"updatevmpooltimeout":                                         "Update VM pool timeout (duration)",
	"updatetrustpolicytimeout":                                    "Update Trust Policy timeout (duration)",
	"dmeapimetricscollectioninterval":                             "Metrics collection interval for DME API counts (duration)",
	"edgeeventsmetricscollectioninterval":                         "Collection interval for edgeevents metrics (latency, device, and custom)",
	"cleanupreservableautoclusteridletime":                        "Idle reservable ClusterInst clean up time",
	"influxdbcloudletusagemetricsretention":                       "Default influxDB cloudlet usage metrics retention policy (duration)",
	"createcloudlettimeout":                                       "Create Cloudlet timeout (duration)",
	"updatecloudlettimeout":                                       "Update Cloudlet timeout (duration)",
	"locationtilesidelengthkm":                                    "Length of location tiles side for latency metrics (km)",
	"edgeeventsmetricscontinuousqueriescollectionintervals:empty": "List of collection intervals for Continuous Queries for EdgeEvents metrics, specify edgeeventsmetricscontinuousqueriescollectionintervals:empty=true to clear",
	"edgeeventsmetricscontinuousqueriescollectionintervals:#.interval":  "Collection interval for Influxdb (Specifically used for continuous query intervals) (Data from old continuous queries will be inaccessible if intervals are updated)",
	"edgeeventsmetricscontinuousqueriescollectionintervals:#.retention": "Retention duration for Influxdb interval (0 uses default retention policy)",
	"influxdbdownsampledmetricsretention":                               "Default retention policy for downsampled influx db (duration)",
	"influxdbedgeeventsmetricsretention":                                "Default retention policy for edgeevents metrics influx db (duration)",
	"appinstclientcleanupinterval":                                      "AppInstClient cleanup thread run interval",
	"clusterautoscaleaveragingdurationsec":                              "Cluster auto scale averaging duration for stats to avoid spikes (seconds), avoid setting below 30s or it will not capture any measurements to average",
	"clusterautoscaleretrydelay":                                        "Cluster auto scale retry delay if scaling failed",
	"alertpolicymintriggertime":                                         "Minimmum trigger time for alert policies",
	"disableratelimit":                                                  "Disable rate limiting for APIs (default is false)",
	"ratelimitmaxtrackedips":                                            "Maximum number of IPs to track for rate limiting",
	"resourcesnapshotthreadinterval":                                    "ResourceSnapshot Refresh thread run interval",
	"platformhainstancepollinterval":                                    "Platform HA instance poll interval",
	"platformhainstanceactiveexpiretime":                                "Platform HA instance active time",
}
var SettingsSpecialArgs = map[string]string{
	"settings.fields": "StringArray",
}
