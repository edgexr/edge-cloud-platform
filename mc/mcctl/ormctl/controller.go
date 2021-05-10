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
		OptionalArgs: "influxdb",
		ReqData:      &ormapi.Controller{},
		Path:         "/auth/controller/create",
	}, &ApiCommand{
		Name:         "DeleteController",
		Use:          "delete",
		Short:        "Delete a regional controller",
		RequiredArgs: "region",
		ReqData:      &ormapi.Controller{},
		Path:         "/auth/controller/delete",
	}, &ApiCommand{
		Name:      "ShowController",
		Use:       "show",
		Short:     "Show regional controllers",
		ReplyData: &[]ormapi.Controller{},
		Path:      "/auth/controller/show",
	}}
	AllApis.AddGroup(ControllerGroup, "Manage regional controllers", cmds)
}
