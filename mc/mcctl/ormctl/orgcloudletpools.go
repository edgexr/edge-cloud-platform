package ormctl

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cli"
	edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/spf13/cobra"
)

func GetOrgCloudletPoolCommand() *cobra.Command {
	cmds := []*cli.Command{&cli.Command{
		Use:          "createinvitation",
		RequiredArgs: "org region cloudletpool cloudletpoolorg",
		Comments:     OrgCloudletPoolComments,
		ReqData:      &ormapi.OrgCloudletPool{},
		Run:          runRest("/auth/cloudletpoolaccessinvitation/create"),
	}, &cli.Command{
		Use:          "deleteinvitation",
		RequiredArgs: "org region cloudletpool cloudletpoolorg",
		Comments:     OrgCloudletPoolComments,
		ReqData:      &ormapi.OrgCloudletPool{},
		Run:          runRest("/auth/cloudletpoolaccessinvitation/delete"),
	}, &cli.Command{
		Use:          "showinvitation",
		OptionalArgs: "org region cloudletpool cloudletpoolorg",
		Comments:     OrgCloudletPoolComments,
		ReqData:      &ormapi.OrgCloudletPool{},
		ReplyData:    &[]ormapi.OrgCloudletPool{},
		Run:          runRest("/auth/cloudletpoolaccessinvitation/show"),
	}, &cli.Command{
		Use:          "createconfirmation",
		RequiredArgs: "org region cloudletpool cloudletpoolorg",
		Comments:     OrgCloudletPoolComments,
		ReqData:      &ormapi.OrgCloudletPool{},
		Run:          runRest("/auth/cloudletpoolaccessconfirmation/create"),
	}, &cli.Command{
		Use:          "deleteconfirmation",
		RequiredArgs: "org region cloudletpool cloudletpoolorg",
		Comments:     OrgCloudletPoolComments,
		ReqData:      &ormapi.OrgCloudletPool{},
		Run:          runRest("/auth/cloudletpoolaccessconfirmation/delete"),
	}, &cli.Command{
		Use:          "showconfirmation",
		OptionalArgs: "org region cloudletpool cloudletpoolorg",
		Comments:     OrgCloudletPoolComments,
		ReqData:      &ormapi.OrgCloudletPool{},
		ReplyData:    &[]ormapi.OrgCloudletPool{},
		Run:          runRest("/auth/cloudletpoolaccessconfirmation/show"),
	}, &cli.Command{
		Use:          "showgranted",
		OptionalArgs: "org region cloudletpool cloudletpoolorg",
		Comments:     OrgCloudletPoolComments,
		ReqData:      &ormapi.OrgCloudletPool{},
		ReplyData:    &[]ormapi.OrgCloudletPool{},
		Run:          runRest("/auth/cloudletpoolaccessgranted/show"),
	}}
	return cli.GenGroup("cloudletpoolaccess", "manage CloudletPool access", cmds)
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

var OrgCloudletPoolComments = map[string]string{
	"org":             "developer organization that will have access to cloudlet pool",
	"region":          "region in which cloudlet pool is defined",
	"cloudletpool":    "cloudlet pool name",
	"cloudletpoolorg": "cloudlet pool's operator organziation",
}
