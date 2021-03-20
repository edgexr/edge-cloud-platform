package ormctl

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cli"
	"github.com/spf13/cobra"
)

func GetRoleCommand() *cobra.Command {
	cmds := []*cli.Command{&cli.Command{
		Use:       "names",
		Short:     "Show role names",
		ReplyData: &[]string{},
		Run:       runRest("/auth/role/show"),
	}, &cli.Command{
		Use:          "add",
		Short:        "Add a role for the organization to the user",
		RequiredArgs: "org username role",
		Comments:     ormapi.RoleComments,
		ReqData:      &ormapi.Role{},
		Run:          runRest("/auth/role/adduser"),
	}, &cli.Command{
		Use:          "remove",
		Short:        "Remove the role for the organization from the user",
		RequiredArgs: "org username role",
		Comments:     ormapi.RoleComments,
		ReqData:      &ormapi.Role{},
		Run:          runRest("/auth/role/removeuser"),
	}, &cli.Command{
		Use:       "show",
		Short:     "Show roles for the organizations the current user can add or remove roles to",
		ReplyData: &[]ormapi.Role{},
		Run:       runRest("/auth/role/showuser"),
	}, &cli.Command{
		Use:       "assignment",
		Short:     "Show roles for the current user",
		ReplyData: &[]ormapi.Role{},
		Run:       runRest("/auth/role/assignment/show"),
	}, &cli.Command{
		Use:       "perms",
		Short:     "Show permissions associated with each role",
		ReplyData: &[]ormapi.RolePerm{},
		Run:       runRest("/auth/role/perms/show"),
	}}
	return cli.GenGroup("role", "Manage user roles and permissions", cmds)
}
