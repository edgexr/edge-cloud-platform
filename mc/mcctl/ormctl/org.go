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
