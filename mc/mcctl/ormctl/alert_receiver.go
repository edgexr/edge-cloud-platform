package ormctl

import (
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
)

var AlertReceiverAliasArgs = []string{
	"slackchannel=slackchannel",
	"slackapiurl=slackwebhook",
	"pagerdutyintegrationkey=pagerdutyintegrationkey",
	"pagerdutyapiversion=pagerdutyapiversion",
	"apporg=appinst.appkey.organization",
	"appname=appinst.appkey.name",
	"appvers=appinst.appkey.version",
	"cluster=appinst.clusterinstkey.clusterkey.name",
	"clusterorg=appinst.clusterinstkey.organization",
	"appcloudletorg=appinst.clusterinstkey.cloudletkey.organization",
	"appcloudlet=appinst.clusterinstkey.cloudletkey.name",
	"cloudletorg=cloudlet.organization",
	"cloudlet=cloudlet.name",
}

const AlertReceiverGroup = "AlertReceiver"

func init() {
	cmds := []*ApiCommand{&ApiCommand{
		Name:         "CreateAlertReceiver",
		Use:          "create",
		Short:        "Create an alert receiver",
		RequiredArgs: strings.Join(AlertReceiverRequiredArgs, " "),
		OptionalArgs: strings.Join(AlertReceiverOptionalArgs, " "),
		AliasArgs:    strings.Join(AlertReceiverAliasArgs, " "),
		Comments:     AlertReceiverArgsComments,
		ReqData:      &ormapi.AlertReceiver{},
		Path:         "/auth/alertreceiver/create",
	}, &ApiCommand{
		Name:         "DeleteAlertReceiver",
		Use:          "delete",
		Short:        "Delete an alert receiver",
		RequiredArgs: strings.Join(AlertReceiverRequiredArgs, " "),
		OptionalArgs: strings.Join(AlertReceiverOptionalArgs, " "),
		ReqData:      &ormapi.AlertReceiver{},
		AliasArgs:    strings.Join(AlertReceiverAliasArgs, " "),
		Comments:     AlertReceiverArgsComments,
		Path:         "/auth/alertreceiver/delete",
	}, &ApiCommand{
		Name:         "ShowAlertReceiver",
		Use:          "show",
		Short:        "Show alert receivers",
		AliasArgs:    strings.Join(AlertReceiverAliasArgs, " "),
		Comments:     AlertReceiverArgsComments,
		OptionalArgs: strings.Join(AlertReceiverOptionalArgs, " ") + " " + strings.Join(AlertReceiverRequiredArgs, " "),
		ReqData:      &ormapi.AlertReceiver{},
		ReplyData:    &[]ormapi.AlertReceiver{},
		Path:         "/auth/alertreceiver/show",
	}}
	AllApis.AddGroup(AlertReceiverGroup, "Manage alert receivers", cmds)
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
	"slackchannel",
	"slackapiurl",
	"pagerdutyintegrationkey",
	"pagerdutyapiversion",
	"appname",
	"appvers",
	"apporg",
	"appcloudlet",
	"appcloudletorg",
	"cluster",
	"clusterorg",
	"cloudlet",
	"cloudletorg",
}

var AlertReceiverArgsComments = map[string]string{
	"region":                  "Region where alert originated",
	"user":                    "User name, if not the same as the logged in user",
	"name":                    "Unique name of this receiver",
	"type":                    "Receiver type - email, slack or pagerduty",
	"severity":                "Alert severity level - one of " + cloudcommon.GetValidAlertSeverityString(),
	"email":                   "Email address receiving the alert (by default email associated with the account)",
	"slackchannel":            "Slack channel to be receiving the alert",
	"slackapiurl":             "Slack webhook url",
	"pagerdutyintegrationkey": "PagerDuty Integration key",
	"pagerdutyapiversion":     "PagerDuty API version(\"v1\" or \"v2\"). By default \"v2\" is used",
	"apporg":                  "Organization or Company name of the App Instance",
	"appname":                 "App Instance name",
	"appvers":                 "App Instance version",
	"appcloudlet":             "Cloudlet name where app instance is deployed",
	"appcloudletorg":          "Company or Organization that owns the cloudlet",
	"cluster":                 "App Instance Cluster name",
	"clusterorg":              "Company or Organization Name that a Cluster is owned by",
	"cloudletorg":             "Company or Organization name of the cloudlet",
	"cloudlet":                "Name of the cloudlet",
}
