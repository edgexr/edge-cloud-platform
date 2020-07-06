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
	"app-org",
	"selector",
}

var AppMetricOptionalArgs = []string{
	"appname",
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

var ClusterMetricRequiredArgs = []string{
	"cluster-org",
	"selector",
}

var ClusterMetricOptionalArgs = []string{
	"cluster",
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

var MetricComments = map[string]string{
	"app-org":      "Organization or Company name of the App",
	"appname":      "App name",
	"appvers":      "App version",
	"cluster":      "Cluster name",
	"cloudlet-org": "Company or Organization name of the cloudlet",
	"cloudlet":     "Name of the cloudlet",
	"cluster-org":  "Organization or Company Name that a Cluster is used by",
	"selector":     "Comma separated list of metrics to view",
	"last":         "Display the last X metrics",
	"starttime":    "Time to start displaying stats from in RFC3339 format (ex. 2002-12-31T15:00:00Z)",
	"endtime":      "Time up to which to display stats in RFC3339 format (ex. 2002-12-31T10:00:00-05:00)",
}
