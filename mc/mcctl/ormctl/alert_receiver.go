package ormctl

import (
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cli"
	"github.com/spf13/cobra"
)

var AlertReceiverAliasArgs = []string{
	"app-org=appinst.appkey.organization",
	"appname=appinst.appkey.name",
	"appvers=appinst.appkey.version",
	"cluster=appinst.clusterinstkey.clusterkey.name",
	"cluster-org=appinst.clusterinstkey.organization",
	"app-cloudlet-org=appinst.clusterinstkey.cloudletkey.organization",
	"app-cloudlet=appinst.clusterinstkey.cloudletkey.name",
	"cloudlet-org=cloudlet.organization",
	"cloudlet=cloudlet.name",
}

func GetAlertReceiverCommand() *cobra.Command {
	cmds := []*cli.Command{&cli.Command{
		Use:          "create",
		RequiredArgs: "name type severity",
		OptionalArgs: "cloudlet appinst",
		AliasArgs:    strings.Join(AlertReceiverAliasArgs, " "),
		ReqData:      &ormapi.AlertReceiver{},
		Run:          runRest("/auth/alertreceiver/create"),
	}, &cli.Command{
		Use:          "delete",
		RequiredArgs: "name type severity",
		ReqData:      &ormapi.AlertReceiver{},
		AliasArgs:    strings.Join(AlertReceiverAliasArgs, " "),
		Run:          runRest("/auth/alertreceiver/delete"),
	}, &cli.Command{
		Use:       "show",
		ReplyData: &[]ormapi.AlertReceiver{},
		Run:       runRest("/auth/alertreceiver/show"),
	}}
	return cli.GenGroup("alertreceiver", "manage alert receivers", cmds)
}
