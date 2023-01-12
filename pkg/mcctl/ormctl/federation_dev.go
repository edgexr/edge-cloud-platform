package ormctl

import (
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/ormapi"
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
		Name:         "OnboardConsumerApp",
		Use:          "onboardapp",
		Short:        "Onboard existing App to partner federation",
		RequiredArgs: "region federationname appname apporg appvers",
		Comments:     addRegionComment(ormapi.ConsumerAppComments),
		ReqData:      &ormapi.ConsumerApp{},
		ReplyData:    &ormapi.Result{},
		Path:         "/auth/federation/consumer/app/onboard",
	}, {
		Name:         "DeboardConsumerApp",
		Use:          "deboardapp",
		Short:        "Remove App from partner federation",
		RequiredArgs: "federationname appname apporg appvers",
		Comments:     addRegionComment(ormapi.ConsumerAppComments),
		ReqData:      &ormapi.ConsumerApp{},
		ReplyData:    &ormapi.Result{},
		Path:         "/auth/federation/consumer/app/deboard",
	}, {
		Name:         "ShowConsumerApp",
		Use:          "showapps",
		Short:        "Show Apps onboarded to partner federation",
		OptionalArgs: "id region federationname appname apporg appvers artefactid status",
		Comments:     ormapi.ConsumerAppComments,
		ReqData:      &ormapi.ConsumerApp{},
		ReplyData:    &[]ormapi.ConsumerApp{},
		Path:         "/auth/federation/consumer/app/show",
		ShowFilter:   true,
	}, {
		Name:         "CreateConsumerImage",
		Use:          "createimage",
		Short:        "Create image on partner federation",
		RequiredArgs: strings.Join(ConsumerImageRequiredArgs, " "),
		OptionalArgs: strings.Join(ConsumerImageOptionalArgs, " "),
		Comments:     ormapi.ConsumerImageComments,
		ReqData:      &ormapi.ConsumerImage{},
		ReplyData:    &ormapi.Result{},
		Path:         "/auth/federation/consumer/image/create",
	}, {
		Name:         "DeleteConsumerImage",
		Use:          "deleteimage",
		Short:        "Delete image from partner federation",
		OptionalArgs: "id organization federationname name",
		Comments:     ormapi.ConsumerImageComments,
		ReqData:      &ormapi.ConsumerImage{},
		ReplyData:    &ormapi.Result{},
		Path:         "/auth/federation/consumer/image/delete",
	}, {
		Name:         "ShowConsumerImage",
		Use:          "showimages",
		Short:        "Show images on partner federation",
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
