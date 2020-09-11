package ormctl

import (
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cli"
	"github.com/spf13/cobra"
)

func GetBillingEventsCommand() *cobra.Command {
	cmds := []*cli.Command{&cli.Command{
		Use:          "app",
		RequiredArgs: strings.Join(append([]string{"region"}, AppEventRequiredArgs...), " "),
		OptionalArgs: strings.Join(AppEventOptionalArgs, " "),
		AliasArgs:    strings.Join(AppEventAliasArgs, " "),
		Comments:     addRegionComment(EventComments),
		ReqData:      &ormapi.RegionAppInstEvents{},
		ReplyData:    &ormapi.AllMetrics{},
		Run:          runRest("/auth/events/app"),
	}, &cli.Command{
		Use:          "cluster",
		RequiredArgs: strings.Join(append([]string{"region"}, ClusterEventRequiredArgs...), " "),
		OptionalArgs: strings.Join(ClusterEventOptionalArgs, " "),
		AliasArgs:    strings.Join(ClusterEventAliasArgs, " "),
		Comments:     addRegionComment(EventComments),
		ReqData:      &ormapi.RegionClusterInstEvents{},
		ReplyData:    &ormapi.AllMetrics{},
		Run:          runRest("/auth/events/cluster"),
	}, &cli.Command{
		Use:          "cloudlet",
		RequiredArgs: strings.Join(append([]string{"region"}, CloudletEventRequiredArgs...), " "),
		OptionalArgs: strings.Join(CloudletEventOptionalArgs, " "),
		AliasArgs:    strings.Join(CloudletEventAliasArgs, " "),
		Comments:     addRegionComment(EventComments),
		ReqData:      &ormapi.RegionCloudletEvents{},
		ReplyData:    &ormapi.AllMetrics{},
		Run:          runRest("/auth/events/cloudlet"),
	}}
	return cli.GenGroup("billingevents", "view billing events ", cmds)
}

var AppEventRequiredArgs = []string{
	"apporg",
}

var AppEventOptionalArgs = []string{
	"appname",
	"appvers",
	"cluster",
	"cloudlet",
	"cloudletorg",
	"last",
	"starttime",
	"endtime",
}

var AppEventAliasArgs = []string{
	"apporg=appinst.appkey.organization",
	"appname=appinst.appkey.name",
	"appvers=appinst.appkey.version",
	"cluster=appinst.clusterinstkey.clusterkey.name",
	"cloudletorg=appinst.clusterinstkey.cloudletkey.organization",
	"cloudlet=appinst.clusterinstkey.cloudletkey.name",
}

var ClusterEventRequiredArgs = []string{
	"clusterorg",
}

var ClusterEventOptionalArgs = []string{
	"cluster",
	"cloudletorg",
	"cloudlet",
	"last",
	"starttime",
	"endtime",
}

var ClusterEventAliasArgs = []string{
	"clusterorg=clusterinst.organization",
	"cluster=clusterinst.clusterkey.name",
	"cloudletorg=clusterinst.cloudletkey.organization",
	"cloudlet=clusterinst.cloudletkey.name",
}

var CloudletEventRequiredArgs = []string{
	"cloudletorg",
}

var CloudletEventOptionalArgs = []string{
	"cloudlet",
	"last",
	"starttime",
	"endtime",
}

var CloudletEventAliasArgs = []string{
	"cloudletorg=cloudlet.organization",
	"cloudlet=cloudlet.name",
}

var EventComments = map[string]string{
	"apporg":      "Organization or Company Name that a Developer is part of",
	"appname":     "App name",
	"appvers":     "App version",
	"cluster":     "Cluster name",
	"cloudletorg": "Organization name owning of the cloudlet",
	"cloudlet":    "Name of the cloudlet",
	"last":        "Display the last X Events",
	"starttime":   "Time to start displaying stats from",
	"endtime":     "Time up to which to display stats",
}
