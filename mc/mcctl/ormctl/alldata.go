package ormctl

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
)

const AllDataGroup = "AllData"

func init() {
	cmds := []*ApiCommand{&ApiCommand{
		Name:         "CreateAllData",
		Use:          "create",
		DataFlagOnly: true,
		StreamOut:    true,
		ReqData:      &ormapi.AllData{},
		Path:         "/auth/data/create",
	}, &ApiCommand{
		Name:         "DeleteAllData",
		Use:          "delete",
		DataFlagOnly: true,
		StreamOut:    true,
		ReqData:      &ormapi.AllData{},
		Path:         "/auth/data/delete",
	}, &ApiCommand{
		Name:      "ShowAllData",
		Use:       "show",
		ReplyData: &ormapi.AllData{},
		Path:      "/auth/data/show",
	}}
	AllApis.AddGroup(AllDataGroup, "bulk manage data", cmds)
}
