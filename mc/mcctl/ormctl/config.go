package ormctl

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cli"
	"github.com/spf13/cobra"
)

func GetConfigCommand() *cobra.Command {
	cmds := []*cli.Command{&cli.Command{
		Use:          "update",
		Short:        "Update master controller global configuration",
		OptionalArgs: "locknewaccounts notifyemailaddress, skipverifyemail, maxmetricsdatapoints, passwordmincracktimesec, adminpasswordmincracktimesec userapikeycreatelimit billingenable",
		ReqData:      &ormapi.Config{},
		Run:          runRest("/auth/config/update"),
	}, &cli.Command{
		Use:   "reset",
		Short: "Reset master controller global configuration",
		Run:   runRest("/auth/config/reset"),
	}, &cli.Command{
		Use:       "show",
		Short:     "Show master controller global configuration",
		ReplyData: &ormapi.Config{},
		Run:       runRest("/auth/config/show"),
	}, &cli.Command{
		Use:       "public",
		Short:     "Show publicly visible master controller global configuration",
		ReplyData: &ormapi.Config{},
		Run:       runRest("/publicconfig"),
	}, &cli.Command{
		Use:       "version",
		Short:     "Show master controller version",
		ReplyData: &ormapi.Version{},
		Run:       runRest("/auth/config/version"),
	}}
	return cli.GenGroup("config", "Manage global configuration", cmds)
}
