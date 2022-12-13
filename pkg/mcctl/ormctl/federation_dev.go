package ormctl

import (
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
)

const (
	FederationDeveloperGroup = "Federation"
)

func init() {
	cmds := []*ApiCommand{{
		Name:         "ShowFederation",
		Use:          "show",
		Short:        "Show federations for App deployment",
		SpecialArgs:  &FederationConsumerSpecialArgs,
		OptionalArgs: strings.Join(FederationConsumerShowArgs, " "),
		Comments:     ormapi.FederationConsumerComments,
		ReqData:      &ormapi.FederationConsumer{},
		ReplyData:    &[]ormapi.FederationConsumer{},
		Path:         "/auth/federation/consumer/show",
		ShowFilter:   true,
	}, {
		Name:         "CreateConsumerApp",
		Use:          "createapp",
		Short:        "Onboard App to partner federation",
		RequiredArgs: "region federationname " + strings.Join(AppRequiredArgs, " "),
		Comments:     util.AddMaps(addRegionComment(AppComments), ormapi.ConsumerAppComments),
		AliasArgs:    strings.Join(AppAliasArgs, " "),
		SpecialArgs:  &AppSpecialArgs,
		ReqData:      &ormapi.ConsumerApp{},
		ReplyData:    &ormapi.Result{},
		Path:         "/auth/federation/consumer/app/create",
	}, {
		Name:         "CreateConsumerImage",
		Use:          "createimage",
		Short:        "Create image on federation partner",
		RequiredArgs: strings.Join(ConsumerImageRequiredArgs, " "),
		OptionalArgs: strings.Join(ConsumerImageOptionalArgs, " "),
		Comments:     ormapi.ConsumerImageComments,
		ReqData:      &ormapi.ConsumerImage{},
		ReplyData:    &ormapi.Result{},
		Path:         "/auth/federation/consumer/image/create",
	}, {
		Name:         "DeleteConsumerImage",
		Use:          "deleteimage",
		Short:        "Delete image from federation partner",
		OptionalArgs: "id organization federationname name",
		Comments:     ormapi.ConsumerImageComments,
		ReqData:      &ormapi.ConsumerImage{},
		ReplyData:    &ormapi.Result{},
		Path:         "/auth/federation/consumer/image/delete",
	}, {
		Name:         "ShowConsumerImage",
		Use:          "showimages",
		Short:        "Show images on federation partner",
		OptionalArgs: strings.Join(ConsumerImageShowArgs, " "),
		Comments:     ormapi.ConsumerImageComments,
		ReqData:      &ormapi.ConsumerImage{},
		ReplyData:    &[]ormapi.ConsumerImage{},
		Path:         "/auth/federation/consumer/image/show",
		ShowFilter:   true,
	}}
	AllApis.AddGroup(FederationDeveloperGroup, "Manage Federated Images and Apps", cmds)
}

// Image Management
// ===============

var ConsumerImageRequiredArgs = []string{
	"organization",
	"federationname",
	"sourcepath",
	"type",
}

var ConsumerImageOptionalArgs = []string{
	"id",
	"name",
	"checksum",
}

var ConsumerImageShowArgs = []string{
	"id",
	"organization",
	"federationname",
	"name",
	"sourcepath",
	"type",
	"status",
}
