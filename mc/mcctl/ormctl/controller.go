package ormctl

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cli"
	"github.com/spf13/cobra"
)

func GetControllerCommand() *cobra.Command {
	cmds := []*cli.Command{&cli.Command{
		Use:          "create",
		RequiredArgs: "region address",
		OptionalArgs: "influxdb",
		ReqData:      &ormapi.Controller{},
		Run:          runRest("/auth/controller/create"),
	}, &cli.Command{
		Use:          "delete",
		RequiredArgs: "region",
		ReqData:      &ormapi.Controller{},
		Run:          runRest("/auth/controller/delete"),
	}, &cli.Command{
		Use:       "show",
		ReplyData: &[]ormapi.Controller{},
		Run:       runRest("/auth/controller/show"),
	}}
	return cli.GenGroup("controller", "register country controllers", cmds)
}

func GetRegionCommand() *cobra.Command {
	cmds := []*cli.Command{}
	cmds = append(cmds, FlavorApiCmds...)
	cmds = append(cmds, OperatorCodeApiCmds...)
	cmds = append(cmds, CloudletApiCmds...)
	cmds = append(cmds, CloudletPoolApiCmds...)
	cmds = append(cmds, CloudletInfoApiCmds...)
	cmds = append(cmds, CloudletPoolMemberApiCmds...)
	cmds = append(cmds, ClusterInstApiCmds...)
	cmds = append(cmds, AppApiCmds...)
	cmds = append(cmds, AppInstApiCmds...)
	cmds = append(cmds, NodeApiCmds...)
	cmds = append(cmds, AlertApiCmds...)
	cmds = append(cmds, AutoScalePolicyApiCmds...)
	cmds = append(cmds, AutoProvPolicyApiCmds...)
	cmds = append(cmds, PrivacyPolicyApiCmds...)
	cmds = append(cmds, SettingsApiCmds...)
	cmds = append(cmds, ResTagTableApiCmds...)
	cmds = append(cmds, AppInstClientApiCmds...)
	cmds = append(cmds, DebugApiCmds...)
	cmds = append(cmds, DeviceApiCmds...)
	cmds = append(cmds, CloudletRefsApiCmds...)
	cmds = append(cmds, ClusterRefsApiCmds...)
	cmds = append(cmds, AppInstRefsApiCmds...)
	cmds = append(cmds, VMPoolApiCmds...)
	return cli.GenGroup("region", "manage region data", cmds)
}
