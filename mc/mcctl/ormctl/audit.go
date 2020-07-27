package ormctl

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cli"
	"github.com/spf13/cobra"
)

func GetAuditCommand() *cobra.Command {
	cmds := []*cli.Command{&cli.Command{
		Use:          "showself",
		OptionalArgs: "limit starttime endtime startage endage",
		Comments:     AuditSelfComments,
		ReqData:      &ormapi.AuditQuery{},
		ReplyData:    &[]ormapi.AuditResponse{},
		Run:          runRest("/auth/audit/showself"),
	}, &cli.Command{
		Use:          "showorg",
		OptionalArgs: "org limit starttime endtime startage endage",
		Comments:     AuditOrgComments,
		ReqData:      &ormapi.AuditQuery{},
		ReplyData:    &[]ormapi.AuditResponse{},
		Run:          runRest("/auth/audit/showorg"),
	}}
	return cli.GenGroup("audit", "show audit logs", cmds)
}

var AuditOrgComments = map[string]string{
	"username":  "filter by user name",
	"org":       "filter by organization name",
	"limit":     "limit the number of returned results (default 100)",
	"starttime": "absolute time of search range start (RFC3339)",
	"endtime":   "absolute time of search range end (RFC3339)",
	"startage":  "relative age from now of search range start (default 48h)",
	"endage":    "relative age from now of search range end (default 0)",
}

var AuditSelfComments = map[string]string{
	"org":       "filter by organization name",
	"limit":     "limit the number of returned results (default 100)",
	"starttime": "absolute time of search range start",
	"endtime":   "absolute time of search range end",
	"startage":  "relative age from now of search range start (default 48h)",
	"endage":    "relative age from now of search range end (default 0)",
}
