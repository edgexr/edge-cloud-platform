// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ormctl

import (
	fmt "fmt"
	"strings"

	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
)

const (
	MetricsGroup   = "Metrics"
	MetricsV2Group = "MetricsV2"
)

func init() {
	cmds := []*ApiCommand{&ApiCommand{
		Name:         "ShowAppMetrics",
		Use:          "app",
		Short:        "View App metrics",
		RequiredArgs: strings.Join(append([]string{"region"}, AppMetricRequiredArgs...), " "),
		OptionalArgs: strings.Join(append(MetricsCommonArgs, AppMetricOptionalArgs...), " "),
		AliasArgs:    strings.Join(append(AppMetricAliasArgs, MetricsCommonAliasArgs...), " "),
		Comments:     mergeMetricComments(addRegionComment(MetricCommentsCommon), AppMetricComments),
		ReqData:      &ormapi.RegionAppInstMetrics{},
		ReplyData:    &ormapi.AllMetrics{},
		Path:         "/auth/metrics/app",
	}, &ApiCommand{
		Name:         "ShowClusterMetrics",
		Use:          "cluster",
		Short:        "View ClusterInst metrics",
		RequiredArgs: strings.Join(append([]string{"region"}, ClusterMetricRequiredArgs...), " "),
		OptionalArgs: strings.Join(append(MetricsCommonArgs, ClusterMetricOptionalArgs...), " "),
		AliasArgs:    strings.Join(append(ClusterMetricAliasArgs, MetricsCommonAliasArgs...), " "),
		Comments:     mergeMetricComments(addRegionComment(MetricCommentsCommon), ClusterMetricComments),
		ReqData:      &ormapi.RegionClusterInstMetrics{},
		ReplyData:    &ormapi.AllMetrics{},
		Path:         "/auth/metrics/cluster",
	}, &ApiCommand{
		Name:         "ShowCloudletMetrics",
		Use:          "cloudlet",
		Short:        "View Cloudlet metrics",
		RequiredArgs: strings.Join(append([]string{"region"}, CloudletMetricRequiredArgs...), " "),
		OptionalArgs: strings.Join(append(MetricsCommonArgs, CloudletMetricOptionalArgs...), " "),
		AliasArgs:    strings.Join(append(CloudletMetricAliasArgs, MetricsCommonAliasArgs...), " "),
		Comments:     mergeMetricComments(addRegionComment(MetricCommentsCommon), CloudletMetricComments),
		ReqData:      &ormapi.RegionCloudletMetrics{},
		ReplyData:    &ormapi.AllMetrics{},
		Path:         "/auth/metrics/cloudlet",
	}, &ApiCommand{
		Name:         "ShowCloudletUsage",
		Use:          "cloudletusage",
		Short:        "View Cloudlet usage",
		RequiredArgs: strings.Join(append([]string{"region"}, CloudletMetricRequiredArgs...), " "),
		OptionalArgs: strings.Join(append(MetricsCommonArgs, CloudletMetricOptionalArgs...), " "),
		AliasArgs:    strings.Join(append(CloudletMetricAliasArgs, MetricsCommonAliasArgs...), " "),
		Comments:     mergeMetricComments(CloudletMetricComments, mergeMetricComments(addRegionComment(MetricCommentsCommon), CloudletUsageMetricComments)),
		ReqData:      &ormapi.RegionCloudletMetrics{},
		ReplyData:    &ormapi.AllMetrics{},
		Path:         "/auth/metrics/cloudlet/usage",
	}, &ApiCommand{
		Name:         "ShowClientApiUsageMetrics",
		Use:          "clientapiusage",
		Short:        "View client API usage",
		RequiredArgs: strings.Join(append([]string{"region"}, ClientApiUsageMetricRequiredArgs...), " "),
		OptionalArgs: strings.Join(append(MetricsCommonArgs, ClientApiUsageMetricOptionalArgs...), " "),
		AliasArgs:    strings.Join(append(ClientApiUsageMetricAliasArgs, MetricsCommonAliasArgs...), " "),
		Comments:     mergeMetricComments(addRegionComment(MetricCommentsCommon), ClientApiUsageMetricComments),
		ReqData:      &ormapi.RegionClientApiUsageMetrics{},
		ReplyData:    &ormapi.AllMetrics{},
		Path:         "/auth/metrics/clientapiusage",
	}, &ApiCommand{
		Name:         "ShowClientAppUsageMetrics",
		Use:          "clientappusage",
		Short:        "View client App usage",
		RequiredArgs: strings.Join(append([]string{"region"}, ClientAppUsageMetricRequiredArgs...), " "),
		OptionalArgs: strings.Join(append(MetricsCommonArgs, ClientAppUsageMetricOptionalArgs...), " "),
		AliasArgs:    strings.Join(append(ClientAppUsageMetricAliasArgs, MetricsCommonAliasArgs...), " "),
		Comments:     mergeMetricComments(addRegionComment(MetricCommentsCommon), getClientTypeUsageMetricComments("app")),
		ReqData:      &ormapi.RegionClientAppUsageMetrics{},
		ReplyData:    &ormapi.AllMetrics{},
		Path:         "/auth/metrics/clientappusage",
	}, &ApiCommand{
		Name:         "ShowClientCloudletUsageMetrics",
		Use:          "clientcloudletusage",
		Short:        "View client Cloudlet usage",
		RequiredArgs: strings.Join(append([]string{"region"}, ClientCloudletUsageMetricRequiredArgs...), " "),
		OptionalArgs: strings.Join(append(MetricsCommonArgs, ClientCloudletUsageMetricOptionalArgs...), " "),
		AliasArgs:    strings.Join(append(ClientCloudletUsageMetricAliasArgs, MetricsCommonAliasArgs...), " "),
		Comments:     mergeMetricComments(addRegionComment(MetricCommentsCommon), getClientTypeUsageMetricComments("cloudlet")),
		ReqData:      &ormapi.RegionClientCloudletUsageMetrics{},
		ReplyData:    &ormapi.AllMetrics{},
		Path:         "/auth/metrics/clientcloudletusage",
	}}
	AllApis.AddGroup(MetricsGroup, "View metrics", cmds)

	cmds = []*ApiCommand{&ApiCommand{
		Name:         "ShowAppV2Metrics",
		Use:          "appv2",
		Short:        "View App metrics(v2 format)",
		RequiredArgs: strings.Join(append([]string{"region"}, AppMetricV2RequiredArgs...), " "),
		OptionalArgs: strings.Join(append(MetricV2CommonArgs, AppMetricV2OptionalArgs...), " "),
		AliasArgs:    strings.Join(append(AppMetricAliasArgs, MetricsCommonAliasArgs...), " "),
		Comments:     mergeMetricComments(addRegionComment(MetricCommentsCommon), AppMetricV2Comments),
		ReqData:      &ormapi.RegionCustomAppMetrics{},
		ReplyData:    &ormapi.AllMetrics{},
		Path:         "/auth/metrics/app/v2",
	}}
	AllApis.AddGroup(MetricsV2Group, "View metrics v2 api", cmds)
}

var AppMetricV2OptionalArgs = []string{
	"appname",
	"apporg",
	"appvers",
	"cluster",
	"clusterorg",
	"cloudlet",
	"cloudletorg",
	"port",
	"aggrfunction",
}

var AppMetricV2Comments = map[string]string{
	"apporg":       "Organization or Company name of the App(Deprecated)",
	"appname":      "App name",
	"appvers":      "App version",
	"cluster":      "Cluster name",
	"cloudletorg":  "Company or Organization name of the cloudlet",
	"cloudlet":     "Name of the cloudlet",
	"clusterorg":   "Organization or Company Name that a Cluster is used by",
	"measurement":  "Measurement to view. Available measurements: \"connections\"",
	"port":         "Port for which to show the data(valid for \"connections\" measurement)",
	"aggrfunction": "Aggregate function. \"sum\" - will add all connections together across all ports",
}

var AppMetricV2RequiredArgs = []string{
	"measurement",
}

var MetricV2CommonArgs = []string{
	"numsamples",
	"starttime",
	"endtime",
	"startage",
	"endage",
}

var AppMetricRequiredArgs = []string{
	"selector",
}

var AppMetricOptionalArgs = []string{
	"appname",
	"apporg",
	"appvers",
	"cluster",
	"clusterorg",
	"cloudlet",
	"cloudletorg",
	"appinsts:#.apporg",
	"appinsts:#.appname",
	"appinsts:#.appvers",
	"appinsts:#.cluster",
	"appinsts:#.clusterorg",
	"appinsts:#.cloudletorg",
	"appinsts:#.cloudlet",
}

var AppMetricAliasArgs = []string{
	"apporg=appinst.appkey.organization",
	"appname=appinst.appkey.name",
	"appvers=appinst.appkey.version",
	"cluster=appinst.clusterinstkey.clusterkey.name",
	"clusterorg=appinst.clusterinstkey.organization",
	"cloudletorg=appinst.clusterinstkey.cloudletkey.organization",
	"cloudlet=appinst.clusterinstkey.cloudletkey.name",
	"appinsts:#.apporg=appinsts:#.appkey.organization",
	"appinsts:#.appname=appinsts:#.appkey.name",
	"appinsts:#.appvers=appinsts:.appkey.version",
	"appinsts:#.cluster=appinsts:#.clusterinstkey.clusterkey.name",
	"appinsts:#.clusterorg=appinsts:#.clusterinstkey.organization",
	"appinsts:#.cloudletorg=appinsts:#.clusterinstkey.cloudletkey.organization",
	"appinsts:#.cloudlet=appinsts:#.clusterinstkey.cloudletkey.name",
	"aggrfunction=aggrfunction",
}

var AppMetricComments = map[string]string{
	"apporg":                 "Organization or Company name of the App(Deprecated)",
	"appname":                "App name(Deprecated)",
	"appvers":                "App version(Deprecated)",
	"cluster":                "Cluster name(Deprecated)",
	"cloudletorg":            "Company or Organization name of the cloudlet(Deprecated)",
	"cloudlet":               "Name of the cloudlet(Deprecated)",
	"clusterorg":             "Organization or Company Name that a Cluster is used by(Deprecated)",
	"appinsts:#.apporg":      "Organization or Company name of the App",
	"appinsts:#.appname":     "App name",
	"appinsts:#.appvers":     "App version",
	"appinsts:#.cluster":     "Cluster name",
	"appinsts:#.clusterorg":  "Organization or Company Name that a Cluster is used by",
	"appinsts:#.cloudletorg": "Company or Organization name of the cloudlet",
	"appinsts:#.cloudlet":    "Name of the cloudlet",
	"selector":               "Comma separated list of metrics to view. Available metrics: \"" + strings.Join(ormapi.AppSelectors, "\", \"") + "\"",
}

var ClusterMetricRequiredArgs = []string{
	"selector",
}

var ClusterMetricOptionalArgs = []string{
	"cluster",
	"clusterorg",
	"cloudletorg",
	"cloudlet",
	"clusterinsts:#.cluster",
	"clusterinsts:#.clusterorg",
	"clusterinsts:#.cloudletorg",
	"clusterinsts:#.cloudlet",
}

var ClusterMetricAliasArgs = []string{
	"clusterorg=clusterinst.organization",
	"cluster=clusterinst.clusterkey.name",
	"cloudletorg=clusterinst.cloudletkey.organization",
	"cloudlet=clusterinst.cloudletkey.name",
	"clusterinsts:#.cluster=clusterinsts:#.clusterkey.name",
	"clusterinsts:#.clusterorg=clusterinsts:#.organization",
	"clusterinsts:#.cloudletorg=clusterinsts:#.cloudletkey.organization",
	"clusterinsts:#.cloudlet=clusterinsts:#.cloudletkey.name",
}

var ClusterMetricComments = map[string]string{
	"cluster":                    "Cluster name(Deprecated)",
	"cloudletorg":                "Company or Organization name of the cloudlet(Deprecated)",
	"cloudlet":                   "Name of the cloudlet(Deprecated)",
	"clusterorg":                 "Organization or Company Name that a Cluster is used by(Deprecated)",
	"clusterinsts:#.cluster":     "Cluster name",
	"clusterinsts:#.clusterorg":  "Organization or Company Name that a Cluster is used by",
	"clusterinsts:#.cloudletorg": "Company or Organization name of the cloudlet",
	"clusterinsts:#.cloudlet":    "Name of the cloudlet",
	"selector":                   "Comma separated list of metrics to view. Available metrics: \"" + strings.Join(ormapi.ClusterSelectors, "\", \"") + "\"",
}

var CloudletMetricRequiredArgs = []string{
	"selector",
}

var CloudletMetricOptionalArgs = []string{
	"cloudlet",
	"cloudletorg",
	"cloudlets:#.cloudletorg",
	"cloudlets:#.cloudlet",
}

var CloudletMetricAliasArgs = []string{
	"cloudletorg=cloudlet.organization",
	"cloudlet=cloudlet.name",
	"cloudlets:#.cloudletorg=cloudlets:#.organization",
	"cloudlets:#.cloudlet=cloudlets:#.name",
}

var CloudletMetricComments = map[string]string{
	"cloudletorg":             "Company or Organization name of the cloudlet(Deprecated)",
	"cloudlet":                "Name of the cloudlet(Deprecated)",
	"cloudlets:#.cloudletorg": "Company or Organization name of the cloudlet",
	"cloudlets:#.cloudlet":    "Name of the cloudlet",

	"selector": "Comma separated list of metrics to view. Available metrics: \"" + strings.Join(ormapi.CloudletSelectors, "\", \"") + "\"",
}

var CloudletUsageMetricComments = map[string]string{
	"selector": "Comma separated list of metrics to view. Available metrics: \"" + strings.Join(ormapi.CloudletUsageSelectors, "\", \"") + "\"",
}

var ClientApiUsageMetricRequiredArgs = []string{
	"selector",
}

var ClientApiUsageMetricOptionalArgs = []string{
	"appname",
	"appvers",
	"apporg",
	"cloudlet",
	"cloudletorg",
	"dmecloudlet",
	"dmeorg",
	"method",
}

var ClientApiUsageMetricAliasArgs = []string{
	"apporg=appinst.appkey.organization",
	"appname=appinst.appkey.name",
	"appvers=appinst.appkey.version",
	"cloudletorg=appinst.clusterinstkey.cloudletkey.organization",
	"cloudlet=appinst.clusterinstkey.cloudletkey.name",
	"dmecloudlet=dmecloudlet",
	"dmeorg=dmecloudletorg",
}

var ClientApiUsageMetricComments = map[string]string{
	"method":      "Api call method, one of: FindCloudlet, PlatformFindCloudlet, RegisterClient, VerifyLocation",
	"selector":    "Comma separated list of metrics to view. Currently only \"api\" is supported.",
	"dmecloudlet": "Cloudlet name where DME is running",
	"dmeorg":      "Operator org where DME is running",
}

var ClientAppUsageMetricRequiredArgs = []string{
	"selector",
}

var ClientAppUsageMetricOptionalArgs = []string{
	"appname",
	"appvers",
	"apporg",
	"cluster",
	"clusterorg",
	"cloudlet",
	"cloudletorg",
	"locationtile",
	"deviceos",
	"devicemodel",
	"devicecarrier",
	"datanetworktype",
}

var ClientAppUsageMetricAliasArgs = []string{
	"apporg=appinst.appkey.organization",
	"appname=appinst.appkey.name",
	"appvers=appinst.appkey.version",
	"cluster=appinst.clusterinstkey.clusterkey.name",
	"clusterorg=appinst.clusterinstkey.organization",
	"cloudletorg=appinst.clusterinstkey.cloudletkey.organization",
	"cloudlet=appinst.clusterinstkey.cloudletkey.name",
}

var ClientCloudletUsageMetricRequiredArgs = []string{
	"cloudletorg",
	"selector",
}

var ClientCloudletUsageMetricOptionalArgs = []string{
	"cloudlet",
	"locationtile",
	"deviceos",
	"devicemodel",
	"devicecarrier",
	"datanetworktype",
}

var ClientCloudletUsageMetricAliasArgs = []string{
	"cloudletorg=cloudlet.organization",
	"cloudlet=cloudlet.name",
}

var MetricsCommonArgs = []string{
	"limit",
	"numsamples",
	"starttime",
	"endtime",
	"startage",
	"endage",
}

var MetricCommentsCommon = map[string]string{
	"apporg":      "Organization or Company name of the App",
	"appname":     "App name",
	"appvers":     "App version",
	"cluster":     "Cluster name",
	"cloudletorg": "Company or Organization name of the cloudlet",
	"cloudlet":    "Name of the cloudlet",
	"clusterorg":  "Organization or Company Name that a Cluster is used by",
	"limit":       "Display the last X metrics",
	"numsamples":  "Display X samples spaced out evenly over start and end times",
	"starttime":   "Time to start displaying stats from in RFC3339 format (ex. 2002-12-31T15:00:00Z)",
	"endtime":     "Time up to which to display stats in RFC3339 format (ex. 2002-12-31T10:00:00-05:00)",
	"startage":    "Relative age from now of search range start (default 48h)",
	"endage":      "Relative age from now of search range end (default 0)",
}

var MetricsCommonAliasArgs = []string{
	"limit=metricscommon.limit",
	"numsamples=metricscommon.numsamples",
	"starttime=metricscommon.timerange.starttime",
	"endtime=metricscommon.timerange.endtime",
	"startage=metricscommon.timerange.startage",
	"endage=metricscommon.timerange.endage",
}

// merge two maps - entries in b will overwrite values in a
// resulting map is a newly allocated map
func mergeMetricComments(a, b map[string]string) map[string]string {
	res := map[string]string{}
	for k, v := range a {
		res[k] = v
	}
	for k, v := range b {
		res[k] = v
	}
	return res
}

// generates ClientAppUsage and ClientCloudletUsage comments along with which args are available for which selectors
func getClientTypeUsageMetricComments(typ string) map[string]string {
	baseSelectorPermission := "Can be used for selectors: %s."
	var locationtileSelectorPermission string
	var deviceosSelectorPermission string
	var devicemodelSelectorPermission string
	var devicecarrierSelectorPermission string
	var datanetworktypeSelectorPermission string
	var availableMetrics string

	switch typ {
	case "app":
		locationtileSelectorPermission = fmt.Sprintf(baseSelectorPermission, "latency, deviceinfo")
		deviceosSelectorPermission = fmt.Sprintf(baseSelectorPermission, "deviceinfo")
		devicemodelSelectorPermission = fmt.Sprintf(baseSelectorPermission, "deviceinfo")
		devicecarrierSelectorPermission = fmt.Sprintf(baseSelectorPermission, "deviceinfo")
		datanetworktypeSelectorPermission = fmt.Sprintf(baseSelectorPermission, "latency, deviceinfo")
		availableMetrics = strings.Join(ormapi.ClientAppUsageSelectors, "\", \"")
	case "cloudlet":
		locationtileSelectorPermission = fmt.Sprintf(baseSelectorPermission, "latency, deviceinfo")
		deviceosSelectorPermission = fmt.Sprintf(baseSelectorPermission, "deviceinfo")
		devicemodelSelectorPermission = fmt.Sprintf(baseSelectorPermission, "deviceinfo")
		devicecarrierSelectorPermission = fmt.Sprintf(baseSelectorPermission, "latency, deviceinfo")
		datanetworktypeSelectorPermission = fmt.Sprintf(baseSelectorPermission, "latency")
		availableMetrics = strings.Join(ormapi.ClientCloudletUsageSelectors, "\", \"")
	default:
		return map[string]string{}
	}

	return map[string]string{
		"locationtile":    fmt.Sprintf("Location tile. Provides the range of GPS coordinates for the location tile/square. Format is: \"LocationUnderLongitude,LocationUnderLatitude_LocationOverLongitude,LocationOverLatitude_LocationTileLength\". LocationUnder are the GPS coordinates of the corner closest to (0,0) of the location tile. LocationOver are the GPS coordinates of the corner farthest from (0,0) of the location tile. LocationTileLength is the length (in kilometers) of one side of the location tile square. %s", locationtileSelectorPermission),
		"deviceos":        fmt.Sprintf("Device operating system. %s", deviceosSelectorPermission),
		"devicemodel":     fmt.Sprintf("Device model. %s", devicemodelSelectorPermission),
		"devicecarrier":   fmt.Sprintf("Device carrier. %s", devicecarrierSelectorPermission),
		"datanetworktype": fmt.Sprintf("Data network type used by client device. %s", datanetworktypeSelectorPermission),
		"selector":        fmt.Sprintf("Comma separated list of metrics to view. Available metrics: \"%s\"", availableMetrics),
	}
}
