package ormctl

import (
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
)

const BillingEventsGroup = "BillingEvents"

func init() {
	cmds := []*ApiCommand{&ApiCommand{
		Name:         "ShowAppEvents",
		Use:          "app",
		Short:        "View App billing events",
		RequiredArgs: strings.Join(append([]string{"region"}, AppEventRequiredArgs...), " "),
		OptionalArgs: strings.Join(AppEventOptionalArgs, " "),
		AliasArgs:    strings.Join(AppEventAliasArgs, " "),
		Comments:     addRegionComment(EventComments),
		ReqData:      &ormapi.RegionAppInstEvents{},
		ReplyData:    &ormapi.AllMetrics{},
		Path:         "/auth/events/app",
	}, &ApiCommand{
		Name:         "ShowClusterEvents",
		Use:          "cluster",
		Short:        "View ClusterInst billing events",
		RequiredArgs: strings.Join(append([]string{"region"}, ClusterEventRequiredArgs...), " "),
		OptionalArgs: strings.Join(ClusterEventOptionalArgs, " "),
		AliasArgs:    strings.Join(ClusterEventAliasArgs, " "),
		Comments:     addRegionComment(EventComments),
		ReqData:      &ormapi.RegionClusterInstEvents{},
		ReplyData:    &ormapi.AllMetrics{},
		Path:         "/auth/events/cluster",
	}, &ApiCommand{
		Name:         "ShowCloudletEvents",
		Use:          "cloudlet",
		Short:        "View Cloudlet billing events",
		RequiredArgs: strings.Join(append([]string{"region"}, CloudletEventRequiredArgs...), " "),
		OptionalArgs: strings.Join(CloudletEventOptionalArgs, " "),
		AliasArgs:    strings.Join(CloudletEventAliasArgs, " "),
		Comments:     addRegionComment(EventComments),
		ReqData:      &ormapi.RegionCloudletEvents{},
		ReplyData:    &ormapi.AllMetrics{},
		Path:         "/auth/events/cloudlet",
	}}
	AllApis.AddGroup(BillingEventsGroup, "View billing events ", cmds)
}

var AppEventRequiredArgs = []string{}

var AppEventOptionalArgs = []string{
	"appname",
	"app-org",
	"appvers",
	"cluster",
	"cloudlet",
	"cloudlet-org",
	"last",
	"starttime",
	"endtime",
}

var AppEventAliasArgs = []string{
	"app-org=appinst.appkey.organization",
	"appname=appinst.appkey.name",
	"appvers=appinst.appkey.version",
	"cluster=appinst.clusterinstkey.clusterkey.name",
	"cloudlet-org=appinst.clusterinstkey.cloudletkey.organization",
	"cloudlet=appinst.clusterinstkey.cloudletkey.name",
}

var ClusterEventRequiredArgs = []string{}

var ClusterEventOptionalArgs = []string{
	"cluster",
	"cluster-org",
	"cloudlet-org",
	"cloudlet",
	"last",
	"starttime",
	"endtime",
}

var ClusterEventAliasArgs = []string{
	"cluster-org=clusterinst.organization",
	"cluster=clusterinst.clusterkey.name",
	"cloudlet-org=clusterinst.cloudletkey.organization",
	"cloudlet=clusterinst.cloudletkey.name",
}

var CloudletEventRequiredArgs = []string{
	"cloudlet-org",
}

var CloudletEventOptionalArgs = []string{
	"cloudlet",
	"last",
	"starttime",
	"endtime",
}

var CloudletEventAliasArgs = []string{
	"cloudlet-org=cloudlet.organization",
	"cloudlet=cloudlet.name",
}

var EventComments = map[string]string{
	"app-org":      "Organization or Company Name that a Developer is part of",
	"appname":      "App name",
	"appvers":      "App version",
	"cluster":      "Cluster name",
	"cloudlet-org": "Organization name owning of the cloudlet",
	"cloudlet":     "Name of the cloudlet",
	"last":         "Display the last X Events",
	"starttime":    "Time to start displaying stats from",
	"endtime":      "Time up to which to display stats",
}
