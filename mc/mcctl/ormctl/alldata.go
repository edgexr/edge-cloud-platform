package ormctl

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/spf13/cobra"
)

func GetAllDataCommand() *cobra.Command {
	cmds := []*Command{&Command{
		Use:          "create",
		DataFlagOnly: true,
		StreamOut:    true,
		Path:         "/auth/data/create",
	}, &Command{
		Use:          "delete",
		DataFlagOnly: true,
		StreamOut:    true,
		Path:         "/auth/data/delete",
	}, &Command{
		Use:       "show",
		ReplyData: &ormapi.AllData{},
		Path:      "/auth/data/show",
	}}
	return genGroup("alldata", "bulk manage data", cmds)
}
