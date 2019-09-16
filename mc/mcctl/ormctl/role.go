package ormctl

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cli"
	"github.com/spf13/cobra"
)

func GetRoleCommand() *cobra.Command {
	cmds := []*cli.Command{&cli.Command{
		Use:       "names",
		ReplyData: &[]string{},
		Run:       runRest("/auth/role/show"),
	}, &cli.Command{
		Use:          "add",
		RequiredArgs: "org username role",
		ReqData:      &ormapi.Role{},
		Run:          runRest("/auth/role/adduser"),
	}, &cli.Command{
		Use:          "remove",
		RequiredArgs: "org username role",
		ReqData:      &ormapi.Role{},
		Run:          runRest("/auth/role/removeuser"),
	}, &cli.Command{
		Use:       "show",
		ReplyData: &[]ormapi.Role{},
		Run:       runRest("/auth/role/showuser"),
	}, &cli.Command{
		Use:       "assignment",
		ReplyData: &[]ormapi.Role{},
		Run:       runRest("/auth/role/assignment/show"),
	}, &cli.Command{
		Use:       "perms",
		ReplyData: &[]ormapi.RolePerm{},
		Run:       runRest("/auth/role/perms/show"),
	}}
	return cli.GenGroup("role", "manage user roles", cmds)
}
