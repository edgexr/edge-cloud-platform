package ormctl

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cli"
	edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/spf13/cobra"
)

func GetOrgCloudletPoolCommand() *cobra.Command {
	cmds := []*cli.Command{&cli.Command{
		Use:          "create",
		RequiredArgs: "org region cloudletpool cloudletpoolorg",
		ReqData:      &ormapi.OrgCloudletPool{},
		Run:          runRest("/auth/orgcloudletpool/create"),
	}, &cli.Command{
		Use:          "delete",
		RequiredArgs: "org region cloudletpool cloudletpoolorg",
		ReqData:      &ormapi.OrgCloudletPool{},
		Run:          runRest("/auth/orgcloudletpool/delete"),
	}, &cli.Command{
		Use:       "show",
		ReplyData: &[]ormapi.OrgCloudletPool{},
		Run:       runRest("/auth/orgcloudletpool/show"),
	}}
	return cli.GenGroup("orgcloudletpool", "manage Org CloudletPools", cmds)
}

func GetOrgCloudletCommand() *cobra.Command {
	cmds := []*cli.Command{&cli.Command{
		Use:          "show",
		RequiredArgs: "region org",
		ReqData:      &ormapi.OrgCloudlet{},
		ReplyData:    &[]edgeproto.Cloudlet{},
		Run:          runRest("/auth/orgcloudlet/show"),
	}}
	return cli.GenGroup("orgcloudlet", "manage Org Cloudlets", cmds)
}

func GetOrgCloudletInfoCommand() *cobra.Command {
	cmds := []*cli.Command{&cli.Command{
		Use:          "show",
		RequiredArgs: "region org",
		ReqData:      &ormapi.OrgCloudlet{},
		ReplyData:    &[]edgeproto.CloudletInfo{},
		Run:          runRest("/auth/orgcloudletinfo/show"),
	}}
	return cli.GenGroup("orgcloudletinfo", "manage Org CloudletInfos", cmds)
}
