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

const ConfigGroup = "Config"

func init() {
	cmds := []*ApiCommand{&ApiCommand{
		Name:         "UpdateConfig",
		Use:          "update",
		Short:        "Update master controller global configuration",
		OptionalArgs: "locknewaccounts notifyemailaddress skipverifyemail maxmetricsdatapoints passwordmincracktimesec adminpasswordmincracktimesec userapikeycreatelimit billingenable disableratelimit ratelimitmaxtrackedips ratelimitmaxtrackedusers failedloginlockoutthreshold1 failedloginlockouttimesec1 failedloginlockoutthreshold2 failedloginlockouttimesec2",
		Comments:     ormapi.ConfigComments,
		ReqData:      &ormapi.Config{},
		Path:         "/auth/config/update",
	}, &ApiCommand{
		Name:  "ResetConfig",
		Use:   "reset",
		Short: "Reset master controller global configuration",
		Path:  "/auth/config/reset",
	}, &ApiCommand{
		Name:      "ShowConfig",
		Use:       "show",
		Short:     "Show master controller global configuration",
		ReplyData: &ormapi.Config{},
		Path:      "/auth/config/show",
	}, &ApiCommand{
		Name:      "ShowPublicConfig",
		Use:       "public",
		Short:     "Show publicly visible master controller global configuration",
		ReplyData: &ormapi.Config{},
		Path:      "/publicconfig",
	}, &ApiCommand{
		Name:      "MCVersion",
		Use:       "version",
		Short:     "Show master controller version",
		ReplyData: &ormapi.Version{},
		Path:      "/auth/config/version",
	}}
	AllApis.AddGroup(ConfigGroup, "Manage global configuration", cmds)
}
