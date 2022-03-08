package ormctl

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
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
