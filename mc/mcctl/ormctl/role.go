package ormctl

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
)

const RoleGroup = "Role"

func init() {
	cmds := []*ApiCommand{&ApiCommand{
		Name:      "ShowRoleNames",
		Use:       "names",
		Short:     "Show role names",
		ReplyData: &[]string{},
		Path:      "/auth/role/show",
	}, &ApiCommand{
		Name:         "AddUserRole",
		Use:          "add",
		Short:        "Add a role for the organization to the user",
		RequiredArgs: "org username role",
		Comments:     ormapi.RoleComments,
		ReqData:      &ormapi.Role{},
		Path:         "/auth/role/adduser",
	}, &ApiCommand{
		Name:         "RemoveUserRole",
		Use:          "remove",
		Short:        "Remove the role for the organization from the user",
		RequiredArgs: "org username role",
		Comments:     ormapi.RoleComments,
		ReqData:      &ormapi.Role{},
		Path:         "/auth/role/removeuser",
	}, &ApiCommand{
		Name:      "ShowUserRole",
		Use:       "show",
		Short:     "Show roles for the organizations the current user can add or remove roles to",
		ReplyData: &[]ormapi.Role{},
		Path:      "/auth/role/showuser",
	}, &ApiCommand{
		Name:      "ShowRoleAssignment",
		Use:       "assignment",
		Short:     "Show roles for the current user",
		ReplyData: &[]ormapi.Role{},
		Path:      "/auth/role/assignment/show",
	}, &ApiCommand{
		Name:      "ShowRolePerm",
		Use:       "perms",
		Short:     "Show permissions associated with each role",
		ReplyData: &[]ormapi.RolePerm{},
		Path:      "/auth/role/perms/show",
	}}
	AllApis.AddGroup(RoleGroup, "Manage user roles and permissions", cmds)
}
