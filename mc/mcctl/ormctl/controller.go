package ormctl

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/spf13/cobra"
)

func GetControllerCommand() *cobra.Command {
	cmds := []*Command{&Command{
		Use:          "create",
		RequiredArgs: "region address",
		ReqData:      &ormapi.Controller{},
		Path:         "/auth/controller/create",
	}, &Command{
		Use:          "delete",
		RequiredArgs: "region",
		ReqData:      &ormapi.Controller{},
		Path:         "/auth/controller/delete",
	}, &Command{
		Use:       "show",
		ReplyData: &[]ormapi.Controller{},
		Path:      "/auth/controller/show",
	}}
	return genGroup("controller", "register country controllers", cmds)
}

func GetRegionCommand() *cobra.Command {
	cmds := []*Command{}
	cmds = append(cmds, FlavorApiCmds...)
	cmds = append(cmds, CloudletApiCmds...)
	cmds = append(cmds, ClusterInstApiCmds...)
	cmds = append(cmds, AppApiCmds...)
	cmds = append(cmds, AppInstApiCmds...)
	cmds = append(cmds, NodeApiCmds...)
	return genGroup("region", "manage region data", cmds)
}
