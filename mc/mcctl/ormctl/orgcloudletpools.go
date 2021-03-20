package ormctl

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cli"
	edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/spf13/cobra"
)

func GetCloudletPoolInvitationCommand() *cobra.Command {
	cmds := []*cli.Command{{
		Use:          "create",
		RequiredArgs: "org region cloudletpool cloudletpoolorg",
		Comments:     OrgCloudletPoolComments,
		ReqData:      &ormapi.OrgCloudletPool{},
		Run:          runRest("/auth/cloudletpoolaccessinvitation/create"),
	}, {
		Use:          "delete",
		RequiredArgs: "org region cloudletpool cloudletpoolorg",
		Comments:     OrgCloudletPoolComments,
		ReqData:      &ormapi.OrgCloudletPool{},
		Run:          runRest("/auth/cloudletpoolaccessinvitation/delete"),
	}, {
		Use:          "show",
		OptionalArgs: "org region cloudletpool cloudletpoolorg",
		Comments:     OrgCloudletPoolComments,
		ReqData:      &ormapi.OrgCloudletPool{},
		ReplyData:    &[]ormapi.OrgCloudletPool{},
		Run:          runRest("/auth/cloudletpoolaccessinvitation/show"),
	}, &grantedCommand,
	}
	return cli.GenGroup("cloudletpoolinvitation", "Manage CloudletPool invitations", cmds)
}

func GetCloudletPoolConfirmationCommand() *cobra.Command {
	cmds := []*cli.Command{{
		Use:          "create",
		RequiredArgs: "org region cloudletpool cloudletpoolorg",
		Comments:     OrgCloudletPoolComments,
		ReqData:      &ormapi.OrgCloudletPool{},
		Run:          runRest("/auth/cloudletpoolaccessconfirmation/create"),
	}, {
		Use:          "delete",
		RequiredArgs: "org region cloudletpool cloudletpoolorg",
		Comments:     OrgCloudletPoolComments,
		ReqData:      &ormapi.OrgCloudletPool{},
		Run:          runRest("/auth/cloudletpoolaccessconfirmation/delete"),
	}, {
		Use:          "show",
		OptionalArgs: "org region cloudletpool cloudletpoolorg",
		Comments:     OrgCloudletPoolComments,
		ReqData:      &ormapi.OrgCloudletPool{},
		ReplyData:    &[]ormapi.OrgCloudletPool{},
		Run:          runRest("/auth/cloudletpoolaccessconfirmation/show"),
	}, &grantedCommand,
	}
	return cli.GenGroup("cloudletpoolconfirmation", "Manage CloudletPool confirmations", cmds)
}

var grantedCommand = cli.Command{
	Use:          "showgranted",
	OptionalArgs: "org region cloudletpool cloudletpoolorg",
	Comments:     OrgCloudletPoolComments,
	ReqData:      &ormapi.OrgCloudletPool{},
	ReplyData:    &[]ormapi.OrgCloudletPool{},
	Run:          runRest("/auth/cloudletpoolaccessgranted/show"),
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
