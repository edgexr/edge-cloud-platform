package ormctl

import (
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
)

const UsageGroup = "Usage"

func init() {
	cmds := []*ApiCommand{&ApiCommand{
		Name:         "ShowAppUsage",
		Use:          "app",
		Short:        "View App usage",
		RequiredArgs: strings.Join(append([]string{"region"}, AppUsageRequiredArgs...), " "),
		OptionalArgs: strings.Join(AppUsageOptionalArgs, " "),
		AliasArgs:    strings.Join(AppUsageAliasArgs, " "),
		Comments:     addRegionComment(AppUsageComments),
		ReqData:      &ormapi.RegionAppInstUsage{},
		ReplyData:    &ormapi.AllMetrics{},
		Path:         "/auth/usage/app",
	}, &ApiCommand{
		Name:         "ShowClusterUsage",
		Use:          "cluster",
		Short:        "View ClusterInst usage",
		RequiredArgs: strings.Join(append([]string{"region"}, ClusterUsageRequiredArgs...), " "),
		OptionalArgs: strings.Join(ClusterUsageOptionalArgs, " "),
		AliasArgs:    strings.Join(ClusterUsageAliasArgs, " "),
		Comments:     addRegionComment(ClusterUsageComments),
		ReqData:      &ormapi.RegionClusterInstUsage{},
		ReplyData:    &ormapi.AllMetrics{},
		Path:         "/auth/usage/cluster",
	}, &ApiCommand{
		Name:         "ShowCloudletPoolUsage",
		Use:          "cloudletpool",
		Short:        "View CloudletPool usage",
		RequiredArgs: strings.Join(append([]string{"region"}, CloudletPoolUsageRequiredArgs...), " "),
		OptionalArgs: "showvmappsonly",
		AliasArgs:    strings.Join(CloudletPoolUsageAliasArgs, " "),
		Comments:     addRegionComment(CloudletPoolUsageComments),
		ReqData:      &ormapi.RegionCloudletPoolUsage{},
		ReplyData:    &ormapi.AllMetrics{},
		Path:         "/auth/usage/cloudletpool",
	}}
	AllApis.AddGroup(UsageGroup, "View App, Cluster, etc usage ", cmds)
}

var AppUsageRequiredArgs = []string{
	"starttime",
	"endtime",
}

var AppUsageOptionalArgs = []string{
	"appname",
	"app-org",
	"appvers",
	"cluster",
	"cloudlet",
	"cloudlet-org",
	"vmonly",
}

var AppUsageAliasArgs = []string{
	"app-org=appinst.appkey.organization",
	"appname=appinst.appkey.name",
	"appvers=appinst.appkey.version",
	"cluster=appinst.clusterinstkey.clusterkey.name",
	"cloudlet-org=appinst.clusterinstkey.cloudletkey.organization",
	"cloudlet=appinst.clusterinstkey.cloudletkey.name",
}

var ClusterUsageRequiredArgs = []string{
	"starttime",
	"endtime",
}

var ClusterUsageOptionalArgs = []string{
	"cluster",
	"cluster-org",
	"cloudlet-org",
	"cloudlet",
}

var ClusterUsageAliasArgs = []string{
	"cluster-org=clusterinst.organization",
	"cluster=clusterinst.clusterkey.name",
	"cloudlet-org=clusterinst.cloudletkey.organization",
	"cloudlet=clusterinst.cloudletkey.name",
}

var AppUsageComments = map[string]string{
	"app-org":      "Organization or Company Name that a Developer is part of",
	"appname":      "App name",
	"appvers":      "App version",
	"cluster":      "Cluster name",
	"cloudlet-org": "Organization name owning of the cloudlet",
	"cloudlet":     "Name of the cloudlet",
	"starttime":    "Time to start displaying usage from",
	"endtime":      "Time up to which to display usage",
	"vmonly":       "Only show VM based apps",
}

var ClusterUsageComments = map[string]string{
	"cluster-org":  "Organization or Company Name that a Developer is part of",
	"cluster":      "Cluster name",
	"cloudlet-org": "Organization name owning of the cloudlet",
	"cloudlet":     "Name of the cloudlet",
	"starttime":    "Time to start displaying usage from",
	"endtime":      "Time up to which to display usage",
}

var CloudletPoolUsageRequiredArgs = []string{
	"cloudletpool",
	"cloudletpoolorg",
	"starttime",
	"endtime",
}

var CloudletPoolUsageAliasArgs = []string{
	"cloudletpool=cloudletpool.name",
	"cloudletpoolorg=cloudletpool.organization",
}

var CloudletPoolUsageComments = map[string]string{
	"cloudletpool":    "Name of the CloudletPool to pull usage from",
	"cloudletpoolorg": "Organization or Company Name that a Operator is part of",
	"starttime":       "Time to start displaying usage from",
	"endtime":         "Time up to which to display usage",
	"showvmappsonly":  "Display only vm based appinsts",
}
