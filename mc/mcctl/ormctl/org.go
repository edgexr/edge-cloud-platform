package ormctl

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cli"
	"github.com/spf13/cobra"
)

func GetOrgCommand() *cobra.Command {
	cmds := []*cli.Command{&cli.Command{
		Use:          "create",
		Short:        "Create a new developer or operator organization",
		RequiredArgs: "name type",
		OptionalArgs: "address phone publicimages",
		Comments:     ormapi.OrganizationComments,
		ReqData:      &ormapi.Organization{},
		Run:          runRest("/auth/org/create"),
	}, &cli.Command{
		Use:          "update",
		Short:        "Update an organization",
		RequiredArgs: "name",
		OptionalArgs: "address phone publicimages",
		Comments:     ormapi.OrganizationComments,
		ReqData:      &ormapi.Organization{},
		Run:          runRest("/auth/org/update"),
	}, &cli.Command{
		Use:          "delete",
		Short:        "Delete an organization",
		RequiredArgs: "name",
		Comments:     ormapi.OrganizationComments,
		ReqData:      &ormapi.Organization{},
		Run:          runRest("/auth/org/delete"),
	}, &cli.Command{
		Use:       "show",
		Short:     "Show organizations",
		ReplyData: &[]ormapi.Organization{},
		Run:       runRest("/auth/org/show"),
	}}
	return cli.GenGroup("org", "Manage organizations", cmds)
}
