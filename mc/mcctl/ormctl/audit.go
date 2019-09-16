package ormctl

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cli"
	"github.com/spf13/cobra"
)

func GetAuditCommand() *cobra.Command {
	cmds := []*cli.Command{&cli.Command{
		Use:          "showself",
		OptionalArgs: "limit",
		ReqData:      &ormapi.AuditQuery{},
		ReplyData:    &[]ormapi.AuditResponse{},
		Run:          runRest("/auth/audit/showself"),
	}, &cli.Command{
		Use:          "showorg",
		OptionalArgs: "org limit",
		ReqData:      &ormapi.AuditQuery{},
		ReplyData:    &[]ormapi.AuditResponse{},
		Run:          runRest("/auth/audit/showorg"),
	}}
	return cli.GenGroup("audit", "show audit logs", cmds)
}
