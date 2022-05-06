// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ormctl

import (
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
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
		Name:         "ShowUserRole",
		Use:          "show",
		Short:        "Show roles for the organizations the current user can add or remove roles to",
		OptionalArgs: "org username role",
		Comments:     ormapi.RoleComments,
		ReqData:      &ormapi.Role{},
		ReplyData:    &[]ormapi.Role{},
		ShowFilter:   true,
		Path:         "/auth/role/showuser",
	}, &ApiCommand{
		Name:         "ShowRoleAssignment",
		Use:          "assignment",
		Short:        "Show roles for the current user",
		OptionalArgs: "org username role",
		Comments:     ormapi.RoleComments,
		ReqData:      &ormapi.Role{},
		ReplyData:    &[]ormapi.Role{},
		ShowFilter:   true,
		Path:         "/auth/role/assignment/show",
	}, &ApiCommand{
		Name:         "ShowRolePerm",
		Use:          "perms",
		Short:        "Show permissions associated with each role",
		OptionalArgs: "role resource action",
		Comments:     ormapi.RolePermComments,
		ReqData:      &ormapi.RolePerm{},
		ReplyData:    &[]ormapi.RolePerm{},
		ShowFilter:   true,
		Path:         "/auth/role/perms/show",
	}}
	AllApis.AddGroup(RoleGroup, "Manage user roles and permissions", cmds)
}
