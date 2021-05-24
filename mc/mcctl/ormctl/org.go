package ormctl

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
)

const OrgGroup = "Org"

func init() {
	cmds := []*ApiCommand{&ApiCommand{
		Name:         "CreateOrg",
		Use:          "create",
		Short:        "Create a new developer or operator organization",
		RequiredArgs: "name type",
		OptionalArgs: "address phone publicimages",
		Comments:     ormapi.OrganizationComments,
		ReqData:      &ormapi.Organization{},
		Path:         "/auth/org/create",
	}, &ApiCommand{
		Name:         "UpdateOrg",
		Use:          "update",
		Short:        "Update an organization",
		RequiredArgs: "name",
		OptionalArgs: "address phone publicimages",
		Comments:     ormapi.OrganizationComments,
		ReqData:      &ormapi.Organization{},
		Path:         "/auth/org/update",
	}, &ApiCommand{
		Name:         "DeleteOrg",
		Use:          "delete",
		Short:        "Delete an organization",
		RequiredArgs: "name",
		Comments:     ormapi.OrganizationComments,
		ReqData:      &ormapi.Organization{},
		Path:         "/auth/org/delete",
	}, &ApiCommand{
		Name:         "ShowOrg",
		Use:          "show",
		Short:        "Show organizations",
		OptionalArgs: "name type address phone publicimages deleteinprogress edgeboxonly",
		Comments:     ormapi.OrganizationComments,
		ReqData:      &ormapi.Organization{},
		ReplyData:    &[]ormapi.Organization{},
		ShowFilter:   true,
		Path:         "/auth/org/show",
	}}
	AllApis.AddGroup(OrgGroup, "Manage organizations", cmds)

	cmd := &ApiCommand{
		Name:         "RestrictedUpdateOrg",
		Short:        "Admin-only update of org fields, requires name",
		RequiredArgs: "name",
		OptionalArgs: "edgeboxonly",
		Comments:     ormapi.OrganizationComments,
		ReqData:      &ormapi.Organization{},
		Path:         "/auth/restricted/org/update",
		IsUpdate:     true,
	}
	AllApis.AddCommand(cmd)
}
