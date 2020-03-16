package ormctl

import (
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cli"
	"github.com/spf13/cobra"
)

func GetMetricsCommand() *cobra.Command {
	cmds := []*cli.Command{&cli.Command{
		Use:          "app",
		RequiredArgs: strings.Join(append([]string{"region"}, AppMetricRequiredArgs...), " "),
		OptionalArgs: strings.Join(AppMetricOptionalArgs, " "),
		AliasArgs:    strings.Join(AppMetricAliasArgs, " "),
		Comments:     addRegionComment(MetricComments),
		ReqData:      &ormapi.RegionAppInstMetrics{},
		ReplyData:    &ormapi.AllMetrics{},
		Run:          runRest("/auth/metrics/app"),
	}, &cli.Command{
		Use:          "cluster",
		RequiredArgs: strings.Join(append([]string{"region"}, ClusterMetricRequiredArgs...), " "),
		OptionalArgs: strings.Join(ClusterMetricOptionalArgs, " "),
		AliasArgs:    strings.Join(ClusterMetricAliasArgs, " "),
		Comments:     addRegionComment(MetricComments),
		ReqData:      &ormapi.RegionClusterInstMetrics{},
		ReplyData:    &ormapi.AllMetrics{},
		Run:          runRest("/auth/metrics/cluster"),
	}, &cli.Command{
		Use:          "cloudlet",
		RequiredArgs: strings.Join(append([]string{"region"}, CloudletMetricRequiredArgs...), " "),
		OptionalArgs: strings.Join(CloudletMetricOptionalArgs, " "),
		AliasArgs:    strings.Join(CloudletMetricAliasArgs, " "),
		Comments:     addRegionComment(MetricComments),
		ReqData:      &ormapi.RegionCloudletMetrics{},
		ReplyData:    &ormapi.AllMetrics{},
		Run:          runRest("/auth/metrics/cloudlet"),
	}}
	return cli.GenGroup("metrics", "view metrics ", cmds)
}

var AppMetricRequiredArgs = []string{
	"clusterorg",
	"selector",
}

var AppMetricOptionalArgs = []string{
	"appname",
	"appvers",
	"cluster",
	"cloudlet",
	"cloudletorg",
	"last",
	"starttime",
	"endtime",
}

var AppMetricAliasArgs = []string{
	"apporg=appinst.appkey.organization",
	"appname=appinst.appkey.name",
	"appvers=appinst.appkey.version",
	"cluster=appinst.clusterinstkey.clusterkey.name",
	"clusterorg=appinst.clusterinstkey.organization",
	"cloudletorg=appinst.clusterinstkey.cloudletkey.organization",
	"cloudlet=appinst.clusterinstkey.cloudletkey.name",
}

var ClusterMetricRequiredArgs = []string{
	"clusterorg",
	"selector",
}

var ClusterMetricOptionalArgs = []string{
	"cluster",
	"cloudletorg",
	"cloudlet",
	"last",
	"starttime",
	"endtime",
}

var ClusterMetricAliasArgs = []string{
	"clusterorg=clusterinst.organization",
	"cluster=clusterinst.clusterkey.name",
	"cloudletorg=clusterinst.cloudletkey.organization",
	"cloudlet=clusterinst.cloudletkey.name",
}

var CloudletMetricRequiredArgs = []string{
	"cloudletorg",
	"selector",
}

var CloudletMetricOptionalArgs = []string{
	"cloudlet",
	"last",
	"starttime",
	"endtime",
}

var CloudletMetricAliasArgs = []string{
	"organization=cloudlet.organization",
	"cloudlet=cloudlet.name",
}

var MetricComments = map[string]string{
	"apporg":      "Organization or Company name of the App",
	"appname":     "App name",
	"appvers":     "App version",
	"cluster":     "Cluster name",
	"cloudletorg": "Company or Organization name of the cloudlet",
	"cloudlet":    "Name of the cloudlet",
	"clusterorg":  "Organization or Company Name that a Cluster is used by",
	"selector":    "Comma separated list of metrics to view",
	"last":        "Display the last X metrics",
	"starttime":   "Time to start displaying stats from",
	"endtime":     "Time up to which to display stats",
}
