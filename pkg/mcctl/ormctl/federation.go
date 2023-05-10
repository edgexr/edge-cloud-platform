// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ormctl

import (
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/ormapi"
)

const (
	FederationHostGroup  = "FederationHost"
	FederationGuestGroup = "FederationGuest"
)

func init() {
	cmds := []*ApiCommand{
		&ApiCommand{
			Name:         "CreateFederationHost",
			Use:          "create",
			Short:        "Create Federation Host",
			SpecialArgs:  &FederationProviderSpecialArgs,
			RequiredArgs: strings.Join(FederationProviderRequiredArgs, " "),
			OptionalArgs: strings.Join(FederationProviderOptionalArgs, " "),
			AliasArgs:    strings.Join(FederationProviderAliasArgs, " "),
			Comments:     ormapi.FederationProviderComments,
			ReqData:      &ormapi.FederationProvider{},
			ReplyData:    &ormapi.FederationProviderInfo{},
			Path:         "/auth/federation/provider/create",
		},
		&ApiCommand{
			Name:          "UpdateFederationHost",
			Use:           "update",
			Short:         "Update Federation Host",
			SpecialArgs:   &FederationProviderSpecialArgs,
			RequiredArgs:  "name operatorid",
			OptionalArgs:  strings.Join(FederationProviderOptionalArgs, " "),
			AliasArgs:     strings.Join(FederationProviderAliasArgs, " "),
			Comments:      ormapi.FederationProviderComments,
			QueryParams:   FederationQueryParams,
			QueryComments: FederationQueryComments,
			ReqData:       &ormapi.FederationProvider{},
			ReplyData:     &ormapi.Result{},
			Path:          "/auth/federation/provider/update",
		},
		&ApiCommand{
			Name:          "DeleteFederationHost",
			Use:           "delete",
			Short:         "Delete Federation Host",
			RequiredArgs:  "name",
			Comments:      ormapi.FederationProviderComments,
			QueryParams:   FederationQueryParams,
			QueryComments: FederationQueryComments,
			ReqData:       &ormapi.FederationProvider{},
			ReplyData:     &ormapi.Result{},
			Path:          "/auth/federation/provider/delete",
		},
		&ApiCommand{
			Name:         "ShowFederationHost",
			Use:          "show",
			Short:        "Show Federation Host",
			SpecialArgs:  &FederationProviderSpecialArgs,
			OptionalArgs: strings.Join(FederationProviderShowArgs, " "),
			AliasArgs:    strings.Join(FederationProviderAliasArgs, " "),
			Comments:     ormapi.FederationProviderComments,
			ReqData:      &ormapi.FederationProvider{},
			ReplyData:    &[]ormapi.FederationProvider{},
			Path:         "/auth/federation/provider/show",
			ShowFilter:   true,
		},
		&ApiCommand{
			Name:         "GenerateFederationHostAPIKey",
			Use:          "generateapikey",
			Short:        "Generate Federation Host API Key to share with Guest",
			RequiredArgs: "name operatorid",
			Comments:     ormapi.FederationProviderComments,
			ReqData:      &ormapi.FederationProvider{},
			ReplyData:    &ormapi.FederationProviderInfo{},
			Path:         "/auth/federation/provider/generateapikey",
		},
		&ApiCommand{
			Name:         "SetFederationHostNotifyKey",
			Use:          "setnotifykey",
			Short:        "Set Federation Host notify key for notify connections",
			RequiredArgs: "name operatorid partnernotifyclientid partnernotifyclientkey",
			OptionalArgs: "partnernotifytokenurl",
			Comments:     ormapi.FederationProviderComments,
			ReqData:      &ormapi.FederationProvider{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federation/provider/setnotifykey",
		},
		&ApiCommand{
			Name:         "CreateHostZoneBase",
			Use:          "createzonebase",
			Short:        "Create Host Zone Base to package cloudlets into a zone",
			SpecialArgs:  &ProviderZoneBaseSpecialArgs,
			RequiredArgs: strings.Join(ProviderZoneBaseRequiredArgs, " "),
			OptionalArgs: strings.Join(ProviderZoneBaseOptionalArgs, " "),
			Comments:     ormapi.ProviderZoneBaseComments,
			ReqData:      &ormapi.ProviderZoneBase{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federation/provider/zonebase/create",
		},
		&ApiCommand{
			Name:         "DeleteHostZoneBase",
			Use:          "deletezonebase",
			Short:        "Delete Host Zone Base",
			RequiredArgs: "zoneid operatorid",
			Comments:     ormapi.ProviderZoneBaseComments,
			ReqData:      &ormapi.ProviderZoneBase{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federation/provider/zonebase/delete",
		},
		&ApiCommand{
			Name:         "UpdateHostZoneBase",
			Use:          "updatezonebase",
			Short:        "Update Host Zone Base",
			RequiredArgs: "zoneid operatorid",
			OptionalArgs: "countrycode geolocation geographydetails",
			Comments:     ormapi.ProviderZoneBaseComments,
			ReqData:      &ormapi.ProviderZoneBase{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federation/provider/zonebase/update",
		},
		&ApiCommand{
			Name:         "ShowHostZoneBase",
			Use:          "showzonebase",
			Short:        "Show Host Zone Bases",
			OptionalArgs: "zoneid operatorid countrycode geolocation geographydetails region cloudlets",
			Comments:     ormapi.ProviderZoneBaseComments,
			ReqData:      &ormapi.ProviderZoneBase{},
			ReplyData:    &[]ormapi.ProviderZoneBase{},
			Path:         "/auth/federation/provider/zonebase/show",
			ShowFilter:   true,
		},
		&ApiCommand{
			Name:          "ShareHostZone",
			Use:           "sharezone",
			Short:         "Share Host Zone with Partner OP",
			RequiredArgs:  strings.Join(ShareZoneRequiredArgs, " "),
			SpecialArgs:   &ShareZoneSpecialArgs,
			Comments:      ormapi.FederatedZoneShareRequestComments,
			QueryParams:   FederationQueryParams,
			QueryComments: FederationQueryComments,
			ReqData:       &ormapi.FederatedZoneShareRequest{},
			ReplyData:     &ormapi.Result{},
			Path:          "/auth/federation/provider/zone/share",
		},
		&ApiCommand{
			Name:          "UnshareHostZone",
			Use:           "unsharezone",
			Short:         "Unshare Host Zone with Partner OP",
			RequiredArgs:  strings.Join(ShareZoneRequiredArgs, " "),
			SpecialArgs:   &ShareZoneSpecialArgs,
			Comments:      ormapi.FederatedZoneShareRequestComments,
			QueryParams:   FederationQueryParams,
			QueryComments: FederationQueryComments,
			ReqData:       &ormapi.FederatedZoneShareRequest{},
			ReplyData:     &ormapi.Result{},
			Path:          "/auth/federation/provider/zone/unshare",
		},
		&ApiCommand{
			Name:         "ShowHostZone",
			Use:          "showsharedzones",
			Short:        "Show Shared Host Zones",
			OptionalArgs: strings.Join(ProviderZoneShowArgs, " "),
			AliasArgs:    strings.Join(ProviderZoneAliasArgs, " "),
			Comments:     ormapi.ProviderZoneComments,
			ReqData:      &ormapi.ProviderZone{},
			ReplyData:    &[]ormapi.ProviderZone{},
			Path:         "/auth/federation/provider/zone/show",
			ShowFilter:   true,
		}, {
			Name:         "ShowHostImage",
			Use:          "showimages",
			Short:        "Show Images uploaded by partner",
			OptionalArgs: strings.Join(ProviderImageShowArgs, " "),
			Comments:     ormapi.ProviderImageComments,
			ReqData:      &ormapi.ProviderImage{},
			ReplyData:    &[]ormapi.ProviderImage{},
			Path:         "/auth/federation/provider/image/show",
			ShowFilter:   true,
		}, {
			Name:         "ShowHostArtefact",
			Use:          "showartefacts",
			Short:        "Show Artefacts created by partner",
			OptionalArgs: strings.Join(ProviderArtefactShowArgs, " "),
			Comments:     ormapi.ProviderArtefactComments,
			ReqData:      &ormapi.ProviderArtefact{},
			ReplyData:    &[]ormapi.ProviderArtefact{},
			Path:         "/auth/federation/provider/artefact/show",
			ShowFilter:   true,
		}, {
			Name:         "ShowHostApp",
			Use:          "showapps",
			Short:        "Show Apps onboarded by partner",
			OptionalArgs: strings.Join(ProviderAppShowArgs, " "),
			SpecialArgs:  &ProviderAppSpecialArgs,
			Comments:     ormapi.ProviderAppComments,
			ReqData:      &ormapi.ProviderApp{},
			ReplyData:    &[]ormapi.ProviderApp{},
			Path:         "/auth/federation/provider/app/show",
			ShowFilter:   true,
		}, {
			Name:         "ShowHostAppInst",
			Use:          "showappinsts",
			Short:        "Show AppInsts onboarded by partner",
			OptionalArgs: strings.Join(ProviderAppInstShowArgs, " "),
			Comments:     ormapi.ProviderAppInstComments,
			ReqData:      &ormapi.ProviderAppInst{},
			ReplyData:    &[]ormapi.ProviderAppInst{},
			Path:         "/auth/federation/provider/appinst/show",
			ShowFilter:   true,
		}, {
			Name:         "UnsafeDeleteHostImage",
			Use:          "unsafedeleteimage",
			Short:        "Delete Image onboarded by partner, use only if partner cannot trigger delete themselves",
			Comments:     ormapi.ProviderImageComments,
			RequiredArgs: "federationname fileid",
			ReqData:      &ormapi.ProviderImage{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federation/provider/image/unsafedelete",
		}, {
			Name:         "UnsafeDeleteHostArtefact",
			Use:          "unsafedeleteartefact",
			Short:        "Delete Artefact onboarded by partner, use only if partner cannot trigger delete themselves",
			RequiredArgs: "federationname artefactid",
			Comments:     ormapi.ProviderArtefactComments,
			ReqData:      &ormapi.ProviderArtefact{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federation/provider/artefact/unsafedelete",
		}, {
			Name:         "UnsafeDeleteHostApp",
			Use:          "unsafedeleteapp",
			Short:        "Delete App onboarded by partner, use only if partner cannot trigger delete themselves",
			RequiredArgs: "federationname appid",
			SpecialArgs:  &ProviderAppSpecialArgs,
			Comments:     ormapi.ProviderAppComments,
			ReqData:      &ormapi.ProviderApp{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federation/provider/app/unsafedelete",
		}, {
			Name:         "UnsafeDeleteHostAppInst",
			Use:          "unsafedeleteappinst",
			Short:        "Delete AppInst created by partner, use only if partner cannot trigger delete themselves",
			RequiredArgs: "federationname appinstid",
			Comments:     ormapi.ProviderAppInstComments,
			ReqData:      &ormapi.ProviderAppInst{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federation/provider/appinst/unsafedelete",
		},
	}
	AllApis.AddGroup(FederationHostGroup, "Manage Federation Host and Zones", cmds)
	cmds = []*ApiCommand{
		&ApiCommand{
			Name:         "CreateFederationGuest",
			Use:          "create",
			Short:        "Create Federation Guest",
			SpecialArgs:  &FederationConsumerSpecialArgs,
			RequiredArgs: strings.Join(FederationConsumerRequiredArgs, " "),
			OptionalArgs: strings.Join(FederationConsumerOptionalArgs, " "),
			AliasArgs:    strings.Join(FederationConsumerAliasArgs, " "),
			Comments:     ormapi.FederationConsumerComments,
			ReqData:      &ormapi.FederationConsumer{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federation/consumer/create",
		},
		&ApiCommand{
			Name:         "UpdateFederationGuest",
			Use:          "update",
			Short:        "Update Federation Guest",
			SpecialArgs:  &FederationConsumerSpecialArgs,
			RequiredArgs: "name operatorid",
			OptionalArgs: "public",
			AliasArgs:    strings.Join(FederationConsumerAliasArgs, " "),
			Comments:     ormapi.FederationConsumerComments,
			ReqData:      &ormapi.FederationConsumer{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federation/consumer/update",
		},
		&ApiCommand{
			Name:          "DeleteFederationGuest",
			Use:           "delete",
			Short:         "Delete Federation Guest",
			SpecialArgs:   &FederationConsumerSpecialArgs,
			OptionalArgs:  "id name operatorid",
			Comments:      ormapi.FederationConsumerComments,
			QueryParams:   FederationQueryParams,
			QueryComments: FederationQueryComments,
			ReqData:       &ormapi.FederationConsumer{},
			ReplyData:     &ormapi.Result{},
			Path:          "/auth/federation/consumer/delete",
		},
		&ApiCommand{
			Name:         "ShowFederationGuest",
			Use:          "show",
			Short:        "Show Federation Guest",
			SpecialArgs:  &FederationConsumerSpecialArgs,
			OptionalArgs: strings.Join(FederationConsumerShowArgs, " "),
			AliasArgs:    strings.Join(FederationConsumerAliasArgs, " "),
			Comments:     ormapi.FederationConsumerComments,
			ReqData:      &ormapi.FederationConsumer{},
			ReplyData:    &[]ormapi.FederationConsumer{},
			Path:         "/auth/federation/consumer/show",
			ShowFilter:   true,
		},
		&ApiCommand{
			Name:         "SetFederationGuestAPIKey",
			Use:          "setpartnerapikey",
			Short:        "Set Partner Federation API Key",
			RequiredArgs: "name operatorid hostclientid hostclientkey",
			SpecialArgs:  &FederationConsumerSpecialArgs,
			AliasArgs:    strings.Join(FederationConsumerAliasArgs, " "),
			Comments:     ormapi.FederationConsumerComments,
			ReqData:      &ormapi.FederationConsumer{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federation/consumer/setapikey",
		},
		&ApiCommand{
			Name:         "GenerateFederationGuestNotifyKey",
			Use:          "generatenotifykey",
			Short:        "Set Partner Federation API Key",
			RequiredArgs: "name operatorid",
			SpecialArgs:  &FederationConsumerSpecialArgs,
			AliasArgs:    strings.Join(FederationConsumerAliasArgs, " "),
			Comments:     ormapi.FederationConsumerComments,
			ReqData:      &ormapi.FederationConsumer{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federation/consumer/gennotifykey",
		},
		&ApiCommand{
			Name:         "RegisterGuestZone",
			Use:          "register",
			Short:        "Register Partner Federator Zone",
			SpecialArgs:  &RegisterZoneSpecialArgs,
			RequiredArgs: strings.Join(RegisterZoneRequiredArgs, " "),
			Comments:     ormapi.FederatedZoneRegRequestComments,
			ReqData:      &ormapi.FederatedZoneRegRequest{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federation/consumer/zone/register",
		},
		&ApiCommand{
			Name:          "DeregisterGuestZone",
			Use:           "deregister",
			Short:         "DeRegister Partner Federator Zone",
			SpecialArgs:   &RegisterZoneSpecialArgs,
			RequiredArgs:  strings.Join(DeregisterZoneRequiredArgs, " "),
			Comments:      ormapi.FederatedZoneRegRequestComments,
			QueryParams:   FederationQueryParams,
			QueryComments: FederationQueryComments,
			ReqData:       &ormapi.FederatedZoneRegRequest{},
			ReplyData:     &ormapi.Result{},
			Path:          "/auth/federation/consumer/zone/deregister",
		},
		&ApiCommand{
			Name:         "ShowGuestZone",
			Use:          "showzones",
			Short:        "Show Federated Partner Zones",
			OptionalArgs: strings.Join(ConsumerZoneShowArgs, " "),
			AliasArgs:    strings.Join(ConsumerZoneAliasArgs, " "),
			Comments:     ormapi.ConsumerZoneComments,
			ReqData:      &ormapi.ConsumerZone{},
			ReplyData:    &[]ormapi.ConsumerZone{},
			Path:         "/auth/federation/consumer/zone/show",
			ShowFilter:   true,
		}, {
			Name:         "ShowFedGuestImage",
			Use:          "showimages",
			Short:        "Show Images onboarded by developers",
			OptionalArgs: strings.Join(ConsumerImageRedactedShowArgs, " "),
			Comments:     ormapi.ConsumerImageComments,
			ReqData:      &ormapi.ConsumerImage{},
			ReplyData:    &[]ormapi.ConsumerImage{},
			Path:         "/auth/federation/consumer/image/show",
			ShowFilter:   true,
		},
	}
	AllApis.AddGroup(FederationGuestGroup, "Manage Federation Guest and Zones", cmds)
}

var FederationQueryParams = "ignorepartner"

var FederationQueryComments = map[string]string{
	"ignorepartner": "ignore partner federation and skip any API calls to them",
}

// Federation Host
// ===================

var FederationProviderRequiredArgs = []string{
	"name",
	"operatorid",
	"regions",
}

var FederationProviderOptionalArgs = []string{
	"myinfo.countrycode",
	"myinfo.mcc",
	"myinfo.mnc",
	"myinfo.fixednetworkids",
}

var FederationProviderSpecialArgs = map[string]string{
	"regions":                     "StringArray",
	"myinfo.mnc":                  "StringArray",
	"myinfo.fixednetworkids":      "StringArray",
	"partnerinfo.mnc":             "StringArray",
	"partnerinfo.fixednetworkids": "StringArray",
}

var FederationProviderAliasArgs = []string{
	"hostclientid=providerclientid",
}

var FederationProviderShowArgs = []string{
	"id",
	"name",
	"operatorid",
	"regions",
	"federationcontextid",
	"myinfo.federationid",
	"myinfo.countrycode",
	"myinfo.mcc",
	"myinfo.mnc",
	"myinfo.fixednetworkids",
	"myinfo.discoveryendpoint",
	"partnerinfo.federationid",
	"partnerinfo.countrycode",
	"partnerinfo.mcc",
	"partnerinfo.mnc",
	"partnerinfo.fixednetworkids",
	"partnerinfo.discoveryendpoint",
	"status",
	"hostclientid",
}

var ProviderZoneBaseRequiredArgs = []string{
	"zoneid",
	"operatorid",
	"region",
	"cloudlets",
}

var ProviderZoneBaseOptionalArgs = []string{
	"countrycode",
	"geolocation",
	"geographydetails",
}

var ProviderZoneBaseSpecialArgs = map[string]string{
	"cloudlets": "StringArray",
}

var ShareZoneRequiredArgs = []string{
	"fedhost",
	"zones",
}

var ProviderZoneShowArgs = []string{
	"zoneid",
	"operatorid",
	"fedhost",
	"status",
}

var ShareZoneSpecialArgs = map[string]string{
	"zones": "StringArray",
}

var ProviderZoneAliasArgs = []string{
	"fedhost=providername",
}

var ProviderArtefactShowArgs = []string{
	"federationname",
	"artefactid",
	"appname",
	"appvers",
	"appproviderid",
	"virttype",
	"desctype",
}

var ProviderAppShowArgs = []string{
	"federationname",
	"appid",
	"appname",
	"appvers",
	"appproviderid",
	"artefactids",
	"deploymentzones",
}

var ProviderAppInstShowArgs = []string{
	"federationname",
	"appinstid",
}

var ProviderAppSpecialArgs = map[string]string{
	"artefactids":     "StringArray",
	"deploymentzones": "StringArray",
}

// Federation Guest
// ===================

var FederationConsumerRequiredArgs = []string{
	"name",
	"operatorid",
	"partneraddr",
	"hostclientid",
	"hostclientkey",
}

var FederationConsumerOptionalArgs = []string{
	"public",
	"autoregisterzones",
	"autoregisterregion",
	"partnertokenurl",
	"myinfo.countrycode",
	"myinfo.mcc",
	"myinfo.mnc",
	"myinfo.fixednetworkids",
}

var FederationConsumerSpecialArgs = map[string]string{
	"myinfo.mnc":                  "StringArray",
	"myinfo.fixednetworkids":      "StringArray",
	"partnerinfo.mnc":             "StringArray",
	"partnerinfo.fixednetworkids": "StringArray",
}

var FederationConsumerShowArgs = []string{
	"id",
	"name",
	"operatorid",
	"partneraddr",
	"federationcontextid",
	"myinfo.federationid",
	"myinfo.countrycode",
	"myinfo.mcc",
	"myinfo.mnc",
	"myinfo.fixednetworkids",
	"myinfo.discoveryendpoint",
	"partnerinfo.federationid",
	"partnerinfo.countrycode",
	"partnerinfo.mcc",
	"partnerinfo.mnc",
	"partnerinfo.fixednetworkids",
	"partnerinfo.discoveryendpoint",
	"status",
	"hostclientid",
	"notifyclientid",
}

var FederationConsumerAliasArgs = []string{
	"hostclientid=providerclientid",
	"hostclientkey=providerclientkey",
}

var RegisterZoneRequiredArgs = []string{
	"fedguest",
	"region",
	"zones",
}

var DeregisterZoneRequiredArgs = []string{
	"fedguest",
	"zones",
}

var RegisterZoneSpecialArgs = map[string]string{
	"zones": "StringArray",
}

var ConsumerZoneShowArgs = []string{
	"zoneid",
	"fedguest",
	"operatorid",
	"geolocation",
	"geographydetails",
	"status",
}

var ConsumerZoneAliasArgs = []string{
	"fedguest=consumername",
}

var ProviderImageShowArgs = []string{
	"federationname",
	"fileid",
	"path",
	"name",
	"version",
	"type",
	"appproviderid",
	"status",
}

var ConsumerImageRedactedShowArgs = []string{
	"id",
	"organization",
	"federationname",
}
