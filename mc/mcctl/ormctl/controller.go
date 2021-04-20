package ormctl

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cli"
	"github.com/spf13/cobra"
)

func GetControllerCommand() *cobra.Command {
	cmds := []*cli.Command{&cli.Command{
		Use:          "create",
		Short:        "Create a new regional controller",
		RequiredArgs: "region address",
		OptionalArgs: "influxdb",
		ReqData:      &ormapi.Controller{},
		Run:          runRest("/auth/controller/create"),
	}, &cli.Command{
		Use:          "delete",
		Short:        "Delete a regional controller",
		RequiredArgs: "region",
		ReqData:      &ormapi.Controller{},
		Run:          runRest("/auth/controller/delete"),
	}, &cli.Command{
		Use:       "show",
		Short:     "Show regional controllers",
		ReplyData: &[]ormapi.Controller{},
		Run:       runRest("/auth/controller/show"),
	}}
	return cli.GenGroup("controller", "Manage regional controllers", cmds)
}
