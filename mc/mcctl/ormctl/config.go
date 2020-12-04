package ormctl

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cli"
	"github.com/spf13/cobra"
)

func GetConfigCommand() *cobra.Command {
	cmds := []*cli.Command{&cli.Command{
		Use:          "update",
		OptionalArgs: "locknewaccounts notifyemailaddress, skipverifyemail, maxmetricsdatapoints, passwordmincracktimesec, adminpasswordmincracktimesec",
		ReqData:      &ormapi.Config{},
		Run:          runRest("/auth/config/update"),
	}, &cli.Command{
		Use: "reset",
		Run: runRest("/auth/config/reset"),
	}, &cli.Command{
		Use:       "show",
		ReplyData: &ormapi.Config{},
		Run:       runRest("/auth/config/show"),
	}, &cli.Command{
		Use:       "public",
		ReplyData: &ormapi.Config{},
		Run:       runRest("/publicconfig"),
	}, &cli.Command{
		Use:       "version",
		ReplyData: &ormapi.Version{},
		Run:       runRest("/auth/config/version"),
	}}
	return cli.GenGroup("config", "admin config", cmds)
}
