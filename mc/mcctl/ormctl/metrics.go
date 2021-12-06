package ormctl

import (
	fmt "fmt"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
)

const MetricsGroup = "Metrics"

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
		Comments:     mergeMetricComments(addRegionComment(MetricCommentsCommon), CloudletUsageMetricComments),
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
}

var AppMetricRequiredArgs = []string{
	"selector",
}

var AppMetricOptionalArgs = []string{
	"appname",
	"app-org",
	"appvers",
	"cluster",
	"cluster-org",
	"cloudlet",
	"cloudlet-org",
	"appinsts:#.app-org",
	"appinsts:#.appname",
	"appinsts:#.appvers",
	"appinsts:#.cluster",
	"appinsts:#.cluster-org",
	"appinsts:#.cloudlet-org",
	"appinsts:#.cloudlet",
}

var AppMetricAliasArgs = []string{
	"app-org=appinst.appkey.organization",
	"appname=appinst.appkey.name",
	"appvers=appinst.appkey.version",
	"cluster=appinst.clusterinstkey.clusterkey.name",
	"cluster-org=appinst.clusterinstkey.organization",
	"cloudlet-org=appinst.clusterinstkey.cloudletkey.organization",
	"cloudlet=appinst.clusterinstkey.cloudletkey.name",
	"appinsts:#.app-org=appinsts:#.appkey.organization",
	"appinsts:#.appname=appinsts:#.appkey.name",
	"appinsts:#.appvers=appinsts:.appkey.version",
	"appinsts:#.cluster=appinsts:#.clusterinstkey.clusterkey.name",
	"appinsts:#.cluster-org=appinsts:#.clusterinstkey.organization",
	"appinsts:#.cloudlet-org=appinsts:#.clusterinstkey.cloudletkey.organization",
	"appinsts:#.cloudlet=appinsts:#.clusterinstkey.cloudletkey.name",
}

var AppMetricComments = map[string]string{
	"app-org":                 "Organization or Company name of the App(Deprecated)",
	"appname":                 "App name(Deprecated)",
	"appvers":                 "App version(Deprecated)",
	"cluster":                 "Cluster name(Deprecated)",
	"cloudlet-org":            "Company or Organization name of the cloudlet(Deprecated)",
	"cloudlet":                "Name of the cloudlet(Deprecated)",
	"cluster-org":             "Organization or Company Name that a Cluster is used by(Deprecated)",
	"appinsts:#.app-org":      "Organization or Company name of the App",
	"appinsts:#.appname":      "App name",
	"appinsts:#.appvers":      "App version",
	"appinsts:#.cluster":      "Cluster name",
	"appinsts:#.cluster-org":  "Organization or Company Name that a Cluster is used by",
	"appinsts:#.cloudlet-org": "Company or Organization name of the cloudlet",
	"appinsts:#.cloudlet":     "Name of the cloudlet",
	"selector":                "Comma separated list of metrics to view. Available metrics: \"" + strings.Join(ormapi.AppSelectors, "\", \"") + "\"",
}

var ClusterMetricRequiredArgs = []string{
	"selector",
}

var ClusterMetricOptionalArgs = []string{
	"cluster",
	"cluster-org",
	"cloudlet-org",
	"cloudlet",
	"clusterinsts:#.cluster",
	"clusterinsts:#.cluster-org",
	"clusterinsts:#.cloudlet-org",
	"clusterinsts:#.cloudlet",
}

var ClusterMetricAliasArgs = []string{
	"cluster-org=clusterinst.organization",
	"cluster=clusterinst.clusterkey.name",
	"cloudlet-org=clusterinst.cloudletkey.organization",
	"cloudlet=clusterinst.cloudletkey.name",
	"clusterinsts:#.cluster=clusterinsts:#.clusterkey.name",
	"clusterinsts:#.cluster-org=clusterinsts:#.organization",
	"clusterinsts:#.cloudlet-org=clusterinsts:#.cloudletkey.organization",
	"clusterinsts:#.cloudlet=clusterinsts:#.cloudletkey.name",
}

var ClusterMetricComments = map[string]string{
	"cluster":                     "Cluster name(Deprecated)",
	"cloudlet-org":                "Company or Organization name of the cloudlet(Deprecated)",
	"cloudlet":                    "Name of the cloudlet(Deprecated)",
	"cluster-org":                 "Organization or Company Name that a Cluster is used by(Deprecated)",
	"clusterinsts:#.cluster":      "Cluster name",
	"clusterinsts:#.cluster-org":  "Organization or Company Name that a Cluster is used by",
	"clusterinsts:#.cloudlet-org": "Company or Organization name of the cloudlet",
	"clusterinsts:#.cloudlet":     "Name of the cloudlet",
	"selector":                    "Comma separated list of metrics to view. Available metrics: \"" + strings.Join(ormapi.ClusterSelectors, "\", \"") + "\"",
}

var CloudletMetricRequiredArgs = []string{
	"selector",
}

var CloudletMetricOptionalArgs = []string{
	"cloudlet",
	"cloudlet-org",
	"cloudlets:#.cloudlet-org",
	"cloudlets:#.cloudlet",
}

var CloudletMetricAliasArgs = []string{
	"cloudlet-org=cloudlet.organization",
	"cloudlet=cloudlet.name",
	"cloudlets:#.cloudlet-org=cloudlets:#.organization",
	"cloudlets:#.cloudlet=cloudlets:#.name",
}

var CloudletMetricComments = map[string]string{
	"cloudlet-org":             "Company or Organization name of the cloudlet(Deprecated)",
	"cloudlet":                 "Name of the cloudlet(Deprecated)",
	"cloudlets:#.cloudlet-org": "Company or Organization name of the cloudlet",
	"cloudlets:#.cloudlet":     "Name of the cloudlet",

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
	"app-org",
	"cloudlet",
	"cloudlet-org",
	"dme-cloudlet",
	"dme-org",
	"method",
}

var ClientApiUsageMetricAliasArgs = []string{
	"app-org=appinst.appkey.organization",
	"appname=appinst.appkey.name",
	"appvers=appinst.appkey.version",
	"cloudlet-org=appinst.clusterinstkey.cloudletkey.organization",
	"cloudlet=appinst.clusterinstkey.cloudletkey.name",
	"dme-cloudlet=dmecloudlet",
	"dme-org=dmecloudletorg",
}

var ClientApiUsageMetricComments = map[string]string{
	"method":       "Api call method, one of: FindCloudlet, PlatformFindCloudlet, RegisterClient, VerifyLocation",
	"selector":     "Comma separated list of metrics to view. Currently only \"api\" is supported.",
	"dme-cloudlet": "Cloudlet name where DME is running",
	"dme-org":      "Operator org where DME is running",
}

var ClientAppUsageMetricRequiredArgs = []string{
	"selector",
}

var ClientAppUsageMetricOptionalArgs = []string{
	"appname",
	"appvers",
	"app-org",
	"cluster",
	"cluster-org",
	"cloudlet",
	"cloudlet-org",
	"locationtile",
	"deviceos",
	"devicemodel",
	"devicecarrier",
	"datanetworktype",
}

var ClientAppUsageMetricAliasArgs = []string{
	"app-org=appinst.appkey.organization",
	"appname=appinst.appkey.name",
	"appvers=appinst.appkey.version",
	"cluster=appinst.clusterinstkey.clusterkey.name",
	"cluster-org=appinst.clusterinstkey.organization",
	"cloudlet-org=appinst.clusterinstkey.cloudletkey.organization",
	"cloudlet=appinst.clusterinstkey.cloudletkey.name",
}

var ClientCloudletUsageMetricRequiredArgs = []string{
	"cloudlet-org",
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
	"cloudlet-org=cloudlet.organization",
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
	"app-org":      "Organization or Company name of the App",
	"appname":      "App name",
	"appvers":      "App version",
	"cluster":      "Cluster name",
	"cloudlet-org": "Company or Organization name of the cloudlet",
	"cloudlet":     "Name of the cloudlet",
	"cluster-org":  "Organization or Company Name that a Cluster is used by",
	"limit":        "Display the last X metrics",
	"numsamples":   "Display X samples spaced out evenly over start and end times",
	"starttime":    "Time to start displaying stats from in RFC3339 format (ex. 2002-12-31T15:00:00Z)",
	"endtime":      "Time up to which to display stats in RFC3339 format (ex. 2002-12-31T10:00:00-05:00)",
	"startage":     "Relative age from now of search range start (default 48h)",
	"endage":       "Relative age from now of search range end (default 0)",
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
		locationtileSelectorPermission = fmt.Sprintf(baseSelectorPermission, "latency")
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
