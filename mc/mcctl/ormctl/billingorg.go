package ormctl

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cli"
	"github.com/spf13/cobra"
)

func GetBillingOrgCommand() *cobra.Command {
	cmds := []*cli.Command{&cli.Command{
		Use:          "create",
		RequiredArgs: "name type firstname lastname email address city country state postalcode currency",
		OptionalArgs: "phone",
		ReqData:      &ormapi.BillingOrganization{},
		Run:          runRest("/auth/billingorg/create"),
	}, &cli.Command{
		Use:          "update",
		RequiredArgs: "name",
		OptionalArgs: "firstname lastname email address city country state postalcode",
		ReqData:      &ormapi.BillingOrganization{},
		Run:          runRest("/auth/billingorg/update"),
	}, &cli.Command{
		Use:          "addchild",
		RequiredArgs: "name child",
		AliasArgs:    "child=children",
		ReqData:      &ormapi.BillingOrganization{},
		Run:          runRest("/auth/billingorg/addchild"),
	}, &cli.Command{
		Use:          "removechild",
		RequiredArgs: "name child",
		AliasArgs:    "child=children",
		ReqData:      &ormapi.BillingOrganization{},
		Run:          runRest("/auth/billingorg/removechild"),
	}, &cli.Command{
		Use:          "delete",
		RequiredArgs: "name",
		ReqData:      &ormapi.BillingOrganization{},
		Run:          runRest("/auth/billingorg/delete"),
	}, &cli.Command{
		Use:       "show",
		ReplyData: &[]ormapi.BillingOrganization{},
		Run:       runRest("/auth/billingorg/show"),
	}}
	return cli.GenGroup("billingorg", "manage billing organizations", cmds)
}
