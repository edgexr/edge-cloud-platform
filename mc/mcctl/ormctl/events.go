package ormctl

import (
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cli"
	"github.com/spf13/cobra"
)

func GetEventsCommand() *cobra.Command {
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
	return cli.GenGroup("events", "view events ", cmds)
}

var AppEventRequiredArgs = []string{
	"developer",
}

var AppEventOptionalArgs = []string{
	"appname",
	"appvers",
	"cluster",
	"cloudlet",
	"operator",
	"last",
	"starttime",
	"endtime",
}

var AppEventAliasArgs = []string{
	"developer=appinst.appkey.developerkey.name",
	"appname=appinst.appkey.name",
	"appvers=appinst.appkey.version",
	"cluster=appinst.clusterinstkey.clusterkey.name",
	"operator=appinst.clusterinstkey.cloudletkey.operatorkey.name",
	"cloudlet=appinst.clusterinstkey.cloudletkey.name",
}

var ClusterEventRequiredArgs = []string{
	"developer",
}

var ClusterEventOptionalArgs = []string{
	"cluster",
	"operator",
	"cloudlet",
	"last",
	"starttime",
	"endtime",
}

var ClusterEventAliasArgs = []string{
	"developer=clusterinst.developer",
	"cluster=clusterinst.clusterkey.name",
	"operator=clusterinst.cloudletkey.operatorkey.name",
	"cloudlet=clusterinst.cloudletkey.name",
}

var CloudletEventRequiredArgs = []string{
	"operator",
}

var CloudletEventOptionalArgs = []string{
	"cloudlet",
	"last",
	"starttime",
	"endtime",
}

var CloudletEventAliasArgs = []string{
	"operator=cloudlet.operatorkey.name",
	"cloudlet=cloudlet.name",
}

var EventComments = map[string]string{
	"developer": "Organization or Company Name that a Developer is part of",
	"appname":   "App name",
	"appvers":   "App version",
	"cluster":   "Cluster name",
	"operator":  "Company or Organization name of the operator",
	"cloudlet":  "Name of the cloudlet",
	"last":      "Display the last X Events",
	"starttime": "Time to start displaying stats from",
	"endtime":   "Time up to which to display stats",
}
