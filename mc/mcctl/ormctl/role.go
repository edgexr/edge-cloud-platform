package ormctl

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/spf13/cobra"
)

func GetRoleCommand() *cobra.Command {
	cmds := []*Command{&Command{
		Use:       "names",
		ReplyData: &[]string{},
		Path:      "/auth/role/show",
	}, &Command{
		Use:          "add",
		RequiredArgs: "org username role",
		ReqData:      &ormapi.Role{},
		Path:         "/auth/role/adduser",
	}, &Command{
		Use:          "remove",
		RequiredArgs: "org username role",
		ReqData:      &ormapi.Role{},
		Path:         "/auth/role/removeuser",
	}, &Command{
		Use:       "show",
		ReplyData: &[]ormapi.Role{},
		Path:      "/auth/role/showuser",
	}, &Command{
		Use:       "assignment",
		ReplyData: &[]ormapi.Role{},
		Path:      "/auth/role/assignment/show",
	}, &Command{
		Use:       "perms",
		ReplyData: &[]ormapi.RolePerm{},
		Path:      "/auth/role/perms/show",
	}}
	return genGroup("role", "manage user roles", cmds)
}
