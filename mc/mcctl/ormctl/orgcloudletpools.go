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
	edgeproto "github.com/edgexr/edge-cloud/edgeproto"
)

const (
	CloudletPoolInvitationGroup = "CloudletPoolInvitation"
	CloudletPoolResponseGroup   = "CloudletPoolResponse"
	CloudletPoolAccessGroup     = "CloudletPoolAccess"
	OrgCloudletPoolGroup        = "OrgCloudletPool"
	OrgCloudletGroup            = "OrgCloudlet"
	OrgCloudletInfoGroup        = "OrgCloudletInfo"
)

func init() {
	cmds := []*ApiCommand{{
		Name:         "CreateCloudletPoolAccessInvitation",
		Use:          "create",
		Short:        "Create a cloudletpool invitation",
		RequiredArgs: "org region cloudletpool cloudletpoolorg",
		Comments:     OrgCloudletPoolComments,
		ReqData:      &ormapi.OrgCloudletPool{},
		Path:         "/auth/cloudletpoolaccessinvitation/create",
	}, {
		Name:         "DeleteCloudletPoolAccessInvitation",
		Use:          "delete",
		Short:        "Delete a cloudletpool invitation",
		RequiredArgs: "org region cloudletpool cloudletpoolorg",
		Comments:     OrgCloudletPoolComments,
		ReqData:      &ormapi.OrgCloudletPool{},
		Path:         "/auth/cloudletpoolaccessinvitation/delete",
	}, {
		Name:         "ShowCloudletPoolAccessInvitation",
		Use:          "show",
		Short:        "Show cloudletpool invitations",
		OptionalArgs: "org region cloudletpool cloudletpoolorg",
		Comments:     OrgCloudletPoolComments,
		ReqData:      &ormapi.OrgCloudletPool{},
		ReplyData:    &[]ormapi.OrgCloudletPool{},
		ShowFilter:   true,
		Path:         "/auth/cloudletpoolaccessinvitation/show",
	}}
	AllApis.AddGroup(CloudletPoolInvitationGroup, "Manage CloudletPool invitations", cmds)
	cmds = []*ApiCommand{{
		Name:         "CreateCloudletPoolAccessResponse",
		Use:          "create",
		Short:        "Create a cloudletpool response to an invitation",
		RequiredArgs: "org region cloudletpool cloudletpoolorg decision",
		Comments:     OrgCloudletPoolComments,
		ReqData:      &ormapi.OrgCloudletPool{},
		Path:         "/auth/cloudletpoolaccessresponse/create",
	}, {
		Name:         "DeleteCloudletPoolAccessResponse",
		Use:          "delete",
		Short:        "Delete a cloudletpool response to an invitation",
		RequiredArgs: "org region cloudletpool cloudletpoolorg",
		Comments:     OrgCloudletPoolComments,
		ReqData:      &ormapi.OrgCloudletPool{},
		Path:         "/auth/cloudletpoolaccessresponse/delete",
	}, {
		Name:         "ShowCloudletPoolAccessResponse",
		Use:          "show",
		Short:        "Show cloudletpool responses",
		OptionalArgs: "org region cloudletpool cloudletpoolorg",
		Comments:     OrgCloudletPoolComments,
		ReqData:      &ormapi.OrgCloudletPool{},
		ReplyData:    &[]ormapi.OrgCloudletPool{},
		ShowFilter:   true,
		Path:         "/auth/cloudletpoolaccessresponse/show",
	}}
	AllApis.AddGroup(CloudletPoolResponseGroup, "Manage CloudletPool responses to invitations", cmds)

	cmds = []*ApiCommand{{
		Name:         "ShowCloudletPoolAccessGranted",
		Use:          "showgranted",
		Short:        "Show granted cloudletpool access",
		OptionalArgs: "org region cloudletpool cloudletpoolorg",
		Comments:     OrgCloudletPoolComments,
		ReqData:      &ormapi.OrgCloudletPool{},
		ReplyData:    &[]ormapi.OrgCloudletPool{},
		ShowFilter:   true,
		Path:         "/auth/cloudletpoolaccessgranted/show",
	}, {
		Name:         "ShowCloudletPoolAccessPending",
		Use:          "showpending",
		Short:        "Show pending cloudletpool invitations without responses",
		OptionalArgs: "org region cloudletpool cloudletpoolorg",
		Comments:     OrgCloudletPoolComments,
		ReqData:      &ormapi.OrgCloudletPool{},
		ReplyData:    &[]ormapi.OrgCloudletPool{},
		ShowFilter:   true,
		Path:         "/auth/cloudletpoolaccesspending/show",
	}}
	AllApis.AddGroup(CloudletPoolAccessGroup, "View CloudletPool access", cmds)

	cmds = []*ApiCommand{&ApiCommand{
		Name:         "ShowOrgCloudlet",
		Use:          "show",
		RequiredArgs: "region org",
		Comments:     ormapi.OrgCloudletComments,
		ReqData:      &ormapi.OrgCloudlet{},
		ReplyData:    &[]edgeproto.Cloudlet{},
		Path:         "/auth/orgcloudlet/show",
	}}
	AllApis.AddGroup(OrgCloudletGroup, "manage Org Cloudlets", cmds)

	cmds = []*ApiCommand{&ApiCommand{
		Name:         "ShowOrgCloudletInfo",
		Use:          "show",
		RequiredArgs: "region org",
		Comments:     ormapi.OrgCloudletComments,
		ReqData:      &ormapi.OrgCloudlet{},
		ReplyData:    &[]edgeproto.CloudletInfo{},
		Path:         "/auth/orgcloudletinfo/show",
	}}
	AllApis.AddGroup(OrgCloudletInfoGroup, "manage Org CloudletInfos", cmds)
}

var OrgCloudletPoolComments = map[string]string{
	"org":             "developer organization that will have access to cloudlet pool",
	"region":          "region in which cloudlet pool is defined",
	"cloudletpool":    "cloudlet pool name",
	"cloudletpoolorg": "cloudlet pool's operator organziation",
	"decision":        "accept or reject the invitation",
}
