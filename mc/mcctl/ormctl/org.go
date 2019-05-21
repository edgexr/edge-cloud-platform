package ormctl

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/spf13/cobra"
)

func GetOrgCommand() *cobra.Command {
	cmds := []*Command{&Command{
		Use:          "create",
		RequiredArgs: "name address phone type",
		ReqData:      &ormapi.Organization{},
		Path:         "/auth/org/create",
	}, &Command{
		Use:          "delete",
		RequiredArgs: "name",
		ReqData:      &ormapi.Organization{},
		Path:         "/auth/org/delete",
	}, &Command{
		Use:       "show",
		ReplyData: &[]ormapi.Organization{},
		Path:      "/auth/org/show",
	}}
	return genGroup("org", "manage organizations", cmds)
}
