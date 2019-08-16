package ormctl

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/spf13/cobra"
)

func GetAuditCommand() *cobra.Command {
	cmds := []*Command{&Command{
		Use:          "showself",
		OptionalArgs: "limit",
		ReqData:      &ormapi.AuditQuery{},
		ReplyData:    &[]ormapi.AuditResponse{},
		Path:         "/auth/audit/showself",
	}, &Command{
		Use:          "showorg",
		OptionalArgs: "org limit",
		ReqData:      &ormapi.AuditQuery{},
		ReplyData:    &[]ormapi.AuditResponse{},
		Path:         "/auth/audit/showorg",
	}}
	return genGroup("audit", "show audit logs", cmds)
}
