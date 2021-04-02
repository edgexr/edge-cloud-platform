package ormctl

import (
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/mc/orm"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cli"
	"github.com/spf13/cobra"
)

func GetMetricsCommand() *cobra.Command {
	cmds := []*cli.Command{&cli.Command{
		Use:          "app",
		Short:        "View App metrics",
		RequiredArgs: strings.Join(append([]string{"region"}, AppMetricRequiredArgs...), " "),
		OptionalArgs: strings.Join(AppMetricOptionalArgs, " "),
		AliasArgs:    strings.Join(AppMetricAliasArgs, " "),
		Comments:     mergeMetricComments(addRegionComment(MetricCommentsCommon), AppMetricComments),
		ReqData:      &ormapi.RegionAppInstMetrics{},
		ReplyData:    &ormapi.AllMetrics{},
		Run:          runRest("/auth/metrics/app"),
	}, &cli.Command{
		Use:          "cluster",
		Short:        "View ClusterInst metrics",
		RequiredArgs: strings.Join(append([]string{"region"}, ClusterMetricRequiredArgs...), " "),
		OptionalArgs: strings.Join(ClusterMetricOptionalArgs, " "),
		AliasArgs:    strings.Join(ClusterMetricAliasArgs, " "),
		Comments:     mergeMetricComments(addRegionComment(MetricCommentsCommon), ClusterMetricComments),
		ReqData:      &ormapi.RegionClusterInstMetrics{},
		ReplyData:    &ormapi.AllMetrics{},
		Run:          runRest("/auth/metrics/cluster"),
	}, &cli.Command{
		Use:          "cloudlet",
		Short:        "View Cloudlet metrics",
		RequiredArgs: strings.Join(append([]string{"region"}, CloudletMetricRequiredArgs...), " "),
		OptionalArgs: strings.Join(CloudletMetricOptionalArgs, " "),
		AliasArgs:    strings.Join(CloudletMetricAliasArgs, " "),
		Comments:     mergeMetricComments(addRegionComment(MetricCommentsCommon), CloudletMetricComments),
		ReqData:      &ormapi.RegionCloudletMetrics{},
		ReplyData:    &ormapi.AllMetrics{},
		Run:          runRest("/auth/metrics/cloudlet"),
	}, &cli.Command{
		Use:          "cloudletusage",
		Short:        "View Cloudlet usage",
		RequiredArgs: strings.Join(append([]string{"region"}, CloudletMetricRequiredArgs...), " "),
		OptionalArgs: strings.Join(CloudletMetricOptionalArgs, " "),
		AliasArgs:    strings.Join(CloudletMetricAliasArgs, " "),
		Comments:     mergeMetricComments(addRegionComment(MetricCommentsCommon), CloudletUsageMetricComments),
		ReqData:      &ormapi.RegionCloudletMetrics{},
		ReplyData:    &ormapi.AllMetrics{},
		Run:          runRest("/auth/metrics/cloudlet/usage"),
	}, &cli.Command{
		Use:          "clientapiusage",
		Short:        "View client API usage",
		RequiredArgs: strings.Join(append([]string{"region"}, ClientApiUsageMetricRequiredArgs...), " "),
		OptionalArgs: strings.Join(ClientApiUsageMetricOptionalArgs, " "),
		AliasArgs:    strings.Join(ClientApiUsageMetricAliasArgs, " "),
		Comments:     mergeMetricComments(addRegionComment(MetricCommentsCommon), ClientApiUsageMetricComments),
		ReqData:      &ormapi.RegionClientApiUsageMetrics{},
		ReplyData:    &ormapi.AllMetrics{},
		Run:          runRest("/auth/metrics/clientapiusage"),
	}, &cli.Command{
		Use:          "clientappusage",
		Short:        "View client App usage",
		RequiredArgs: strings.Join(append([]string{"region"}, ClientAppUsageMetricRequiredArgs...), " "),
		OptionalArgs: strings.Join(ClientAppUsageMetricOptionalArgs, " "),
		AliasArgs:    strings.Join(ClientAppUsageMetricAliasArgs, " "),
		Comments:     mergeMetricComments(addRegionComment(MetricCommentsCommon), ClientAppUsageMetricComments),
		ReqData:      &ormapi.RegionClientAppUsageMetrics{},
		ReplyData:    &ormapi.AllMetrics{},
		Run:          runRest("/auth/metrics/clientappusage"),
	}, &cli.Command{
		Use:          "clientcloudletusage",
		Short:        "View client Cloudlet usage",
		RequiredArgs: strings.Join(append([]string{"region"}, ClientCloudletUsageMetricRequiredArgs...), " "),
		OptionalArgs: strings.Join(ClientCloudletUsageMetricOptionalArgs, " "),
		AliasArgs:    strings.Join(ClientCloudletUsageMetricAliasArgs, " "),
		Comments:     mergeMetricComments(addRegionComment(MetricCommentsCommon), ClientCloudletUsageMetricComments),
		ReqData:      &ormapi.RegionClientCloudletUsageMetrics{},
		ReplyData:    &ormapi.AllMetrics{},
		Run:          runRest("/auth/metrics/clientcloudletusage"),
	}}
	return cli.GenGroup("metrics", "View metrics", cmds)
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
	"last",
	"starttime",
	"endtime",
}

var AppMetricAliasArgs = []string{
	"app-org=appinst.appkey.organization",
	"appname=appinst.appkey.name",
	"appvers=appinst.appkey.version",
	"cluster=appinst.clusterinstkey.clusterkey.name",
	"cluster-org=appinst.clusterinstkey.organization",
	"cloudlet-org=appinst.clusterinstkey.cloudletkey.organization",
	"cloudlet=appinst.clusterinstkey.cloudletkey.name",
}

var AppMetricComments = map[string]string{
	"selector": "Comma separated list of metrics to view. Available metrics: \"" + strings.Join(orm.AppSelectors, "\", \"") + "\"",
}

var ClusterMetricRequiredArgs = []string{
	"selector",
}

var ClusterMetricOptionalArgs = []string{
	"cluster",
	"cluster-org",
	"cloudlet-org",
	"cloudlet",
	"last",
	"starttime",
	"endtime",
}

var ClusterMetricAliasArgs = []string{
	"cluster-org=clusterinst.organization",
	"cluster=clusterinst.clusterkey.name",
	"cloudlet-org=clusterinst.cloudletkey.organization",
	"cloudlet=clusterinst.cloudletkey.name",
}

var ClusterMetricComments = map[string]string{
	"selector": "Comma separated list of metrics to view. Available metrics: \"" + strings.Join(orm.ClusterSelectors, "\", \"") + "\"",
}

var CloudletMetricRequiredArgs = []string{
	"cloudlet-org",
	"selector",
}

var CloudletMetricOptionalArgs = []string{
	"cloudlet",
	"last",
	"starttime",
	"endtime",
}

var CloudletMetricAliasArgs = []string{
	"cloudlet-org=cloudlet.organization",
	"cloudlet=cloudlet.name",
}

var CloudletMetricComments = map[string]string{
	"selector": "Comma separated list of metrics to view. Available metrics: \"" + strings.Join(orm.CloudletSelectors, "\", \"") + "\"",
}

var CloudletUsageMetricComments = map[string]string{
	"selector": "Comma separated list of metrics to view. Available metrics: \"" + strings.Join(orm.CloudletUsageSelectors, "\", \"") + "\"",
}

var ClientApiUsageMetricRequiredArgs = []string{
	"selector",
}

var ClientApiUsageMetricOptionalArgs = []string{
	"appname",
	"appvers",
	"app-org",
	"cluster",
	"cluster-org",
	"cloudlet",
	"cloudlet-org",
	"method",
	"cellid",
	"last",
	"starttime",
	"endtime",
}

var ClientApiUsageMetricAliasArgs = []string{
	"app-org=appinst.appkey.organization",
	"appname=appinst.appkey.name",
	"appvers=appinst.appkey.version",
	"cluster=appinst.clusterinstkey.clusterkey.name",
	"cluster-org=appinst.clusterinstkey.organization",
	"cloudlet-org=appinst.clusterinstkey.cloudletkey.organization",
	"cloudlet=appinst.clusterinstkey.cloudletkey.name",
}

var ClientApiUsageMetricComments = map[string]string{
	"method":   "Api call method, one of: FindCloudlet, PlatformFindCloudlet, RegisterClient, VerifyLocation",
	"cellid":   "Cell tower Id(experimental)",
	"selector": "Comma separated list of metrics to view. Currently only \"api\" is supported.",
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
	"location",
	"device-os",
	"device-type",
	"data-network-type",
	"raw-data",
	"last",
	"starttime",
	"endtime",
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

var ClientAppUsageMetricComments = map[string]string{
	"location":          "Location tile. Use only for latency selector",
	"device-os":         "Device operating system. Use only for deviceinfo selector",
	"device-type":       "Device type. Use only for deviceinfo selector",
	"data-network-type": "Data network type used by client device. Use only for deviceinfo selector",
	"raw-data":          "Set to true for additional raw data (not downsampled)",
	"selector":          "Comma separated list of metrics to view. Available metrics: \"" + strings.Join(orm.ClientAppUsageSelectors, "\", \"") + "\"",
}

var ClientCloudletUsageMetricRequiredArgs = []string{
	"cloudlet-org",
	"selector",
}

var ClientCloudletUsageMetricOptionalArgs = []string{
	"cloudlet",
	"location",
	"device-os",
	"device-type",
	"data-network-type",
	"raw-data",
	"last",
	"starttime",
	"endtime",
}

var ClientCloudletUsageMetricAliasArgs = []string{
	"cloudlet-org=cloudlet.organization",
	"cloudlet=cloudlet.name",
}

var ClientCloudletUsageMetricComments = map[string]string{
	"location":          "Location tile. Use for either latency or deviceinfo selectors",
	"device-os":         "Device operating system. Use only for deviceinfo selector",
	"device-type":       "Device type. Use only for deviceinfo selector",
	"data-network-type": "Data network type used by client device. Use only for latency selector",
	"raw-data":          "Set to true for additional raw data (not downsampled)",
	"selector":          "Comma separated list of metrics to view. Available metrics: \"" + strings.Join(orm.ClientCloudletUsageSelectors, "\", \"") + "\"",
}

var MetricCommentsCommon = map[string]string{
	"app-org":      "Organization or Company name of the App",
	"appname":      "App name",
	"appvers":      "App version",
	"cluster":      "Cluster name",
	"cloudlet-org": "Company or Organization name of the cloudlet",
	"cloudlet":     "Name of the cloudlet",
	"cluster-org":  "Organization or Company Name that a Cluster is used by",
	"last":         "Display the last X metrics",
	"starttime":    "Time to start displaying stats from in RFC3339 format (ex. 2002-12-31T15:00:00Z)",
	"endtime":      "Time up to which to display stats in RFC3339 format (ex. 2002-12-31T10:00:00-05:00)",
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
