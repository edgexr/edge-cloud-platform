package ormctl

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cli"
	"github.com/spf13/cobra"
)

func GetOrgCommand() *cobra.Command {
	cmds := []*cli.Command{&cli.Command{
		Use:          "create",
		RequiredArgs: "name type",
		OptionalArgs: "address phone publicimages",
		ReqData:      &ormapi.Organization{},
		Run:          runRest("/auth/org/create"),
	}, &cli.Command{
		Use:          "update",
		RequiredArgs: "name",
		OptionalArgs: "address phone publicimages",
		ReqData:      &ormapi.Organization{},
		Run:          runRest("/auth/org/update"),
	}, &cli.Command{
		Use:          "delete",
		RequiredArgs: "name",
		ReqData:      &ormapi.Organization{},
		Run:          runRest("/auth/org/delete"),
	}, &cli.Command{
		Use:       "show",
		ReplyData: &[]ormapi.Organization{},
		Run:       runRest("/auth/org/show"),
	}}
	return cli.GenGroup("org", "manage organizations", cmds)
}
