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
		Short:        "Create a cloudletpool invitation",
		RequiredArgs: "org region cloudletpool cloudletpoolorg",
		Comments:     OrgCloudletPoolComments,
		ReqData:      &ormapi.OrgCloudletPool{},
		Run:          runRest("/auth/cloudletpoolaccessinvitation/create"),
	}, {
		Use:          "delete",
		Short:        "Delete a cloudletpool invitation",
		RequiredArgs: "org region cloudletpool cloudletpoolorg",
		Comments:     OrgCloudletPoolComments,
		ReqData:      &ormapi.OrgCloudletPool{},
		Run:          runRest("/auth/cloudletpoolaccessinvitation/delete"),
	}, {
		Use:          "show",
		Short:        "Show cloudletpool invitations",
		OptionalArgs: "org region cloudletpool cloudletpoolorg",
		Comments:     OrgCloudletPoolComments,
		ReqData:      &ormapi.OrgCloudletPool{},
		ReplyData:    &[]ormapi.OrgCloudletPool{},
		Run:          runRest("/auth/cloudletpoolaccessinvitation/show"),
	}, &grantedCommand, &pendingCommand,
	}
	return cli.GenGroup("cloudletpoolinvitation", "Manage CloudletPool invitations", cmds)
}

func GetCloudletPoolResponseCommand() *cobra.Command {
	cmds := []*cli.Command{{
		Use:          "create",
		Short:        "Create a cloudletpool response to an invitation",
		RequiredArgs: "org region cloudletpool cloudletpoolorg decision",
		Comments:     OrgCloudletPoolComments,
		ReqData:      &ormapi.OrgCloudletPool{},
		Run:          runRest("/auth/cloudletpoolaccessresponse/create"),
	}, {
		Use:          "delete",
		Short:        "Delete a cloudletpool response to an invitation",
		RequiredArgs: "org region cloudletpool cloudletpoolorg",
		Comments:     OrgCloudletPoolComments,
		ReqData:      &ormapi.OrgCloudletPool{},
		Run:          runRest("/auth/cloudletpoolaccessresponse/delete"),
	}, {
		Use:          "show",
		Short:        "Show cloudletpool responses",
		OptionalArgs: "org region cloudletpool cloudletpoolorg",
		Comments:     OrgCloudletPoolComments,
		ReqData:      &ormapi.OrgCloudletPool{},
		ReplyData:    &[]ormapi.OrgCloudletPool{},
		Run:          runRest("/auth/cloudletpoolaccessresponse/show"),
	}, &grantedCommand, &pendingCommand,
	}
	return cli.GenGroup("cloudletpoolresponse", "Manage CloudletPool responses to invitations", cmds)
}

var grantedCommand = cli.Command{
	Use:          "showgranted",
	Short:        "Show granted cloudletpool access",
	OptionalArgs: "org region cloudletpool cloudletpoolorg",
	Comments:     OrgCloudletPoolComments,
	ReqData:      &ormapi.OrgCloudletPool{},
	ReplyData:    &[]ormapi.OrgCloudletPool{},
	Run:          runRest("/auth/cloudletpoolaccessgranted/show"),
}

var pendingCommand = cli.Command{
	Use:          "showpending",
	Short:        "Show pending cloudletpool invitations without responses",
	OptionalArgs: "org region cloudletpool cloudletpoolorg",
	Comments:     OrgCloudletPoolComments,
	ReqData:      &ormapi.OrgCloudletPool{},
	ReplyData:    &[]ormapi.OrgCloudletPool{},
	Run:          runRest("/auth/cloudletpoolaccesspending/show"),
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
	"decision":        "accept or reject the invitation",
}
