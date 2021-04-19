package ormctl

import (
	"github.com/mobiledgex/edge-cloud-infra/billing"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cli"
	"github.com/spf13/cobra"
)

func GetBillingOrgCommand() *cobra.Command {
	cmds := []*cli.Command{&cli.Command{
		Use:          "validate",
		Short:        "Set up a BillingOrganization and validate inputs",
		RequiredArgs: "name type firstname lastname email",
		OptionalArgs: "address address2 city country state postalcode phone paymenttype ccfirstname cclastname ccnumber ccexpmonth ccexpyear children",
		ReqData:      &ormapi.BillingOrganization{},
		Comments:     CreateBillingOrgComments,
		Run:          runRest("/auth/billingorg/create"),
	}, &cli.Command{
		Use:          "updateaccountinfo",
		Short:        "Commit a BillingOrganization after validating it with our payment platform",
		RequiredArgs: "orgname accountid",
		OptionalArgs: "subscriptionid",
		ReqData:      &billing.AccountInfo{},
		Comments:     ormapi.AccountInfoComments,
		Run:          runRest("/auth/billingorg/updateaccount"),
	}, &cli.Command{
		Use:          "update",
		Short:        "Update a billing organization",
		RequiredArgs: "name",
		OptionalArgs: "firstname lastname email address city country state postalcode",
		Comments:     ormapi.BillingOrganizationComments,
		ReqData:      &ormapi.BillingOrganization{},
		Run:          runRest("/auth/billingorg/update"),
	}, &cli.Command{
		Use:          "addchild",
		Short:        "Add an organization as a child of a billing organization",
		RequiredArgs: "name child",
		AliasArgs:    "child=children",
		Comments:     ormapi.BillingOrganizationComments,
		ReqData:      &ormapi.BillingOrganization{},
		Run:          runRest("/auth/billingorg/addchild"),
	}, &cli.Command{
		Use:          "removechild",
		Short:        "Remove an organization from a billing organization",
		RequiredArgs: "name child",
		AliasArgs:    "child=children",
		Comments:     ormapi.BillingOrganizationComments,
		ReqData:      &ormapi.BillingOrganization{},
		Run:          runRest("/auth/billingorg/removechild"),
	}, &cli.Command{
		Use:          "delete",
		Short:        "Delete a billing organization",
		RequiredArgs: "name",
		Comments:     ormapi.BillingOrganizationComments,
		ReqData:      &ormapi.BillingOrganization{},
		Run:          runRest("/auth/billingorg/delete"),
	}, &cli.Command{
		Use:       "show",
		Short:     "Show billing organizations",
		Comments:  ormapi.BillingOrganizationComments,
		ReplyData: &[]ormapi.BillingOrganization{},
		Run:       runRest("/auth/billingorg/show"),
	}, &cli.Command{
		Use:          "getinvoice",
		RequiredArgs: "name",
		OptionalArgs: "startdate enddate",
		ReqData:      &ormapi.InvoiceRequest{},
		Comments:     ormapi.InvoiceComments,
		ReplyData:    &[]billing.InvoiceData{},
		Run:          runRest("/auth/billingorg/invoice"),
	}}
	return cli.GenGroup("billingorg", "Manage billing organizations", cmds)
}

var CreateBillingOrgComments = map[string]string{
	"name":       "name of the billingOrg",
	"type":       "type of the billingOrg",
	"firstname":  "First name",
	"lastname":   "Last name",
	"email":      "Email address",
	"address":    "Address line 1",
	"address2":   "Address line 2",
	"city":       "City",
	"country":    "Country",
	"state":      "State",
	"postalcode": "zip code",
	"phone":      "Phone number",
}
