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
		Name:                 "OnboardGuestApp",
		Use:                  "onboardapp",
		Short:                "Onboard existing App to partner federation",
		RequiredArgs:         "region federationname appname apporg appvers",
		Comments:             addRegionComment(ormapi.ConsumerAppComments),
		SpecialArgs:          &ConsumerAppSpecialArgs,
		ReqData:              &ormapi.ConsumerApp{},
		ReplyData:            &ormapi.Result{},
		Path:                 "/auth/federation/consumer/app/onboard",
		StreamOut:            true,
		StreamOutIncremental: true,
	}, {
		Name:                 "DeboardGuestApp",
		Use:                  "deboardapp",
		Short:                "Remove App from partner federation",
		RequiredArgs:         "federationname appname apporg appvers",
		Comments:             addRegionComment(ormapi.ConsumerAppComments),
		SpecialArgs:          &ConsumerAppSpecialArgs,
		QueryParams:          FederationQueryParams,
		QueryComments:        FederationQueryComments,
		ReqData:              &ormapi.ConsumerApp{},
		ReplyData:            &ormapi.Result{},
		Path:                 "/auth/federation/consumer/app/deboard",
		StreamOut:            true,
		StreamOutIncremental: true,
	}, {
		Name:         "ShowGuestApp",
		Use:          "showapps",
		Short:        "Show Apps onboarded to partner federation",
		OptionalArgs: "id region federationname appname apporg appvers status",
		SpecialArgs:  &ConsumerAppSpecialArgs,
		Comments:     ormapi.ConsumerAppComments,
		ReqData:      &ormapi.ConsumerApp{},
		ReplyData:    &[]ormapi.ConsumerApp{},
		Path:         "/auth/federation/consumer/app/show",
		ShowFilter:   true,
	}, {
		Name:         "CreateGuestImage",
		Use:          "createimage",
		Short:        "Create image on partner federation",
		RequiredArgs: strings.Join(ConsumerImageRequiredArgs, " "),
		OptionalArgs: strings.Join(ConsumerImageOptionalArgs, " "),
		Comments:     ormapi.ConsumerImageComments,
		ReqData:      &ormapi.ConsumerImage{},
		ReplyData:    &ormapi.Result{},
		Path:         "/auth/federation/consumer/image/create",
	}, {
		Name:          "DeleteGuestImage",
		Use:           "deleteimage",
		Short:         "Delete image from partner federation",
		OptionalArgs:  "id organization federationname name",
		Comments:      ormapi.ConsumerImageComments,
		QueryParams:   FederationQueryParams,
		QueryComments: FederationQueryComments,
		ReqData:       &ormapi.ConsumerImage{},
		ReplyData:     &ormapi.Result{},
		Path:          "/auth/federation/consumer/image/delete",
	}, {
		Name:         "ShowGuestImage",
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
	"version",
	"checksum",
}

var ConsumerImageShowArgs = []string{
	"id",
	"organization",
	"federationname",
	"name",
	"version",
	"sourcepath",
	"type",
	"status",
}

var ConsumerAppSpecialArgs = map[string]string{
	"imageids": "StringArray",
}
