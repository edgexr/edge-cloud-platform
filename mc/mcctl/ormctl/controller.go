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

const ControllerGroup = "Controller"

func init() {
	cmds := []*ApiCommand{&ApiCommand{
		Name:         "CreateController",
		Use:          "create",
		Short:        "Create a new regional controller",
		RequiredArgs: "region address",
		OptionalArgs: "influxdb thanosmetrics",
		Comments:     ormapi.ControllerComments,
		ReqData:      &ormapi.Controller{},
		Path:         "/auth/controller/create",
	}, &ApiCommand{
		Name:         "UpdateController",
		Use:          "update",
		Short:        "Update region controller",
		RequiredArgs: "region",
		OptionalArgs: "address notifyaddr influxdb thanosmetrics dnsregion",
		Comments:     ormapi.ControllerComments,
		ReqData:      &ormapi.Controller{},
		Path:         "/auth/controller/update",
	}, &ApiCommand{
		Name:         "DeleteController",
		Use:          "delete",
		Short:        "Delete a regional controller",
		RequiredArgs: "region",
		Comments:     ormapi.ControllerComments,
		ReqData:      &ormapi.Controller{},
		Path:         "/auth/controller/delete",
	}, &ApiCommand{
		Name:         "ShowController",
		Use:          "show",
		Short:        "Show regional controllers",
		OptionalArgs: "region",
		Comments:     ormapi.ControllerComments,
		ReqData:      &ormapi.Controller{},
		ReplyData:    &[]ormapi.Controller{},
		ShowFilter:   true,
		Path:         "/auth/controller/show",
	}}
	AllApis.AddGroup(ControllerGroup, "Manage regional controllers", cmds)
}
