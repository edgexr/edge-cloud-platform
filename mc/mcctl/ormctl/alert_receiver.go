package ormctl

import (
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cli"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/spf13/cobra"
)

var AlertReceiverAliasArgs = []string{
	"slack-channel=slackchannel",
	"slack-api-url=slackwebhook",
	"pagerduty-integration-key=pagerdutyintegrationkey",
	"pagerduty-api-version=pagerdutyapiversion",
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
		Short:        "Create an alert receiver",
		RequiredArgs: strings.Join(AlertReceiverRequiredArgs, " "),
		OptionalArgs: strings.Join(AlertReceiverOptionalArgs, " "),
		AliasArgs:    strings.Join(AlertReceiverAliasArgs, " "),
		Comments:     AlertReceiverArgsComments,
		ReqData:      &ormapi.AlertReceiver{},
		Run:          runRest("/auth/alertreceiver/create"),
	}, &cli.Command{
		Use:          "delete",
		Short:        "Delete an alert receiver",
		RequiredArgs: strings.Join(AlertReceiverRequiredArgs, " "),
		OptionalArgs: strings.Join(AlertReceiverOptionalArgs, " "),
		ReqData:      &ormapi.AlertReceiver{},
		AliasArgs:    strings.Join(AlertReceiverAliasArgs, " "),
		Comments:     AlertReceiverArgsComments,
		Run:          runRest("/auth/alertreceiver/delete"),
	}, &cli.Command{
		Use:          "show",
		Short:        "Show alert receivers",
		AliasArgs:    strings.Join(AlertReceiverAliasArgs, " "),
		Comments:     AlertReceiverArgsComments,
		OptionalArgs: strings.Join(AlertReceiverOptionalArgs, " ") + " " + strings.Join(AlertReceiverRequiredArgs, " "),
		ReqData:      &ormapi.AlertReceiver{},
		ReplyData:    &[]ormapi.AlertReceiver{},
		Run:          runRest("/auth/alertreceiver/show"),
	}}
	return cli.GenGroup("alertreceiver", "Manage alert receivers", cmds)
}

var AlertReceiverRequiredArgs = []string{
	"name",
	"type",
	"severity",
}

var AlertReceiverOptionalArgs = []string{
	"region",
	"user",
	"email",
	"slack-channel",
	"slack-api-url",
	"pagerduty-integration-key",
	"pagerduty-api-version",
	"appname",
	"appvers",
	"app-org",
	"app-cloudlet",
	"app-cloudlet-org",
	"cluster",
	"cluster-org",
	"cloudlet",
	"cloudlet-org",
}

var AlertReceiverArgsComments = map[string]string{
	"region":                    "Region where alert originated",
	"user":                      "User name, if not the same as the logged in user",
	"name":                      "Unique name of this receiver",
	"type":                      "Receiver type - email or slack",
	"severity":                  "Alert severity level - one of " + cloudcommon.GetValidAlertSeverityString(),
	"email":                     "Email address receiving the alert (by default email associated with the account)",
	"slack-channel":             "Slack channel to be receiving the alert",
	"slack-api-url":             "Slack webhook url",
	"pagerduty-integration-key": "PagerDuty Integration key",
	"pagerduty-api-version":     "PagerDuty API version(\"v1\" or \"v2\"). By default \"v2\" is used",
	"app-org":                   "Organization or Company name of the App Instance",
	"appname":                   "App Instance name",
	"appvers":                   "App Instance version",
	"app-cloudlet":              "Cloudlet name where app instance is deployed",
	"app-cloudlet-org":          "Company or Organization that owns the cloudlet",
	"cluster":                   "App Instance Cluster name",
	"cluster-org":               "Company or Organization Name that a Cluster is owned by",
	"cloudlet-org":              "Company or Organization name of the cloudlet",
	"cloudlet":                  "Name of the cloudlet",
}
