package ormctl

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cli"
	"github.com/spf13/cobra"
)

func GetAllDataCommand() *cobra.Command {
	cmds := []*cli.Command{&cli.Command{
		Use:          "create",
		DataFlagOnly: true,
		StreamOut:    true,
		ReqData:      &ormapi.AllData{},
		Run:          runRest("/auth/data/create"),
	}, &cli.Command{
		Use:          "delete",
		DataFlagOnly: true,
		StreamOut:    true,
		ReqData:      &ormapi.AllData{},
		Run:          runRest("/auth/data/delete"),
	}, &cli.Command{
		Use:       "show",
		ReplyData: &ormapi.AllData{},
		Run:       runRest("/auth/data/show"),
	}}
	return cli.GenGroup("alldata", "bulk manage data", cmds)
}
