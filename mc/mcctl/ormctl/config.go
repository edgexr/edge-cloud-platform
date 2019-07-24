package ormctl

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/spf13/cobra"
)

func GetConfigCommand() *cobra.Command {
	cmds := []*Command{&Command{
		Use:          "update",
		OptionalArgs: "locknewaccounts notifyemailaddress",
		ReqData:      &ormapi.Config{},
		Path:         "/auth/config/update",
	}, &Command{
		Use:       "show",
		ReplyData: &ormapi.Config{},
		Path:      "/auth/config/show",
	}, &Command{
		Use:       "version",
		ReplyData: &ormapi.Version{},
		Path:      "/auth/config/version",
	}}
	return genGroup("config", "admin config", cmds)
}
