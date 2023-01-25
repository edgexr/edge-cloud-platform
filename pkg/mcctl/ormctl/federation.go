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
	FederationProviderGroup = "FederationProvider"
	FederationConsumerGroup = "FederationConsumer"
)

func init() {
	cmds := []*ApiCommand{
		&ApiCommand{
			Name:         "CreateFederationProvider",
			Use:          "create",
			Short:        "Create Federation Provider",
			SpecialArgs:  &FederationProviderSpecialArgs,
			RequiredArgs: strings.Join(FederationProviderRequiredArgs, " "),
			OptionalArgs: strings.Join(FederationProviderOptionalArgs, " "),
			Comments:     ormapi.FederationProviderComments,
			ReqData:      &ormapi.FederationProvider{},
			ReplyData:    &ormapi.FederationProviderInfo{},
			Path:         "/auth/federation/provider/create",
		},
		&ApiCommand{
			Name:         "UpdateFederationProvider",
			Use:          "update",
			Short:        "Update Federation Provider",
			SpecialArgs:  &FederationProviderSpecialArgs,
			RequiredArgs: "name operatorid",
			OptionalArgs: strings.Join(FederationProviderOptionalArgs, " "),
			Comments:     ormapi.FederationProviderComments,
			ReqData:      &ormapi.FederationProvider{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federation/provider/update",
		},
		&ApiCommand{
			Name:         "DeleteFederationProvider",
			Use:          "delete",
			Short:        "Delete Federation Provider",
			RequiredArgs: "name",
			Comments:     ormapi.FederationProviderComments,
			ReqData:      &ormapi.FederationProvider{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federation/provider/delete",
		},
		&ApiCommand{
			Name:         "ShowFederationProvider",
			Use:          "show",
			Short:        "Show Federation Provider",
			SpecialArgs:  &FederationProviderSpecialArgs,
			OptionalArgs: strings.Join(FederationProviderShowArgs, " "),
			Comments:     ormapi.FederationProviderComments,
			ReqData:      &ormapi.FederationProvider{},
			ReplyData:    &[]ormapi.FederationProvider{},
			Path:         "/auth/federation/provider/show",
			ShowFilter:   true,
		},
		&ApiCommand{
			Name:         "GenerateFederationProviderAPIKey",
			Use:          "generateapikey",
			Short:        "Generate Federation Provider API Key to share with Consumer",
			RequiredArgs: "name operatorid",
			Comments:     ormapi.FederationProviderComments,
			ReqData:      &ormapi.FederationProvider{},
			ReplyData:    &ormapi.FederationProviderInfo{},
			Path:         "/auth/federation/provider/generateapikey",
		},
		&ApiCommand{
			Name:         "SetFederationProviderNotifyKey",
			Use:          "setnotifykey",
			Short:        "Set Federation Provider notify key for notify connections",
			RequiredArgs: "name operatorid partnernotifyclientid partnernotifyclientkey",
			Comments:     ormapi.FederationProviderComments,
			ReqData:      &ormapi.FederationProvider{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federation/provider/setnotifykey",
		},
		&ApiCommand{
			Name:         "CreateProviderZoneBase",
			Use:          "createzonebase",
			Short:        "Create Provider Zone Base to package cloudlets into a zone",
			SpecialArgs:  &ProviderZoneBaseSpecialArgs,
			RequiredArgs: strings.Join(ProviderZoneBaseRequiredArgs, " "),
			OptionalArgs: strings.Join(ProviderZoneBaseOptionalArgs, " "),
			Comments:     ormapi.ProviderZoneBaseComments,
			ReqData:      &ormapi.ProviderZoneBase{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federation/provider/zonebase/create",
		},
		&ApiCommand{
			Name:         "DeleteProviderZoneBase",
			Use:          "deletezonebase",
			Short:        "Delete Provider Zone Base",
			RequiredArgs: "zoneid operatorid",
			Comments:     ormapi.ProviderZoneBaseComments,
			ReqData:      &ormapi.ProviderZoneBase{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federation/provider/zonebase/delete",
		},
		&ApiCommand{
			Name:         "ShowProviderZoneBase",
			Use:          "showzonebase",
			Short:        "Show Provider Zone Bases",
			OptionalArgs: "zoneid operatorid countrycode geolocation geographydetails region cloudlets",
			Comments:     ormapi.ProviderZoneBaseComments,
			ReqData:      &ormapi.ProviderZoneBase{},
			ReplyData:    &[]ormapi.ProviderZoneBase{},
			Path:         "/auth/federation/provider/zonebase/show",
			ShowFilter:   true,
		},
		&ApiCommand{
			Name:         "ShareProviderZone",
			Use:          "sharezone",
			Short:        "Share Provider Zone with Partner OP",
			RequiredArgs: strings.Join(ShareZoneRequiredArgs, " "),
			SpecialArgs:  &ShareZoneSpecialArgs,
			Comments:     ormapi.FederatedZoneShareRequestComments,
			ReqData:      &ormapi.FederatedZoneShareRequest{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federation/provider/zone/share",
		},
		&ApiCommand{
			Name:         "UnshareProviderZone",
			Use:          "unsharezone",
			Short:        "Unshare Provider Zone with Partner OP",
			RequiredArgs: strings.Join(ShareZoneRequiredArgs, " "),
			SpecialArgs:  &ShareZoneSpecialArgs,
			Comments:     ormapi.FederatedZoneShareRequestComments,
			ReqData:      &ormapi.FederatedZoneShareRequest{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federation/provider/zone/unshare",
		},
		&ApiCommand{
			Name:         "ShowProviderZone",
			Use:          "showsharedzones",
			Short:        "Show Shared Provider Zones",
			OptionalArgs: strings.Join(ProviderZoneShowArgs, " "),
			Comments:     ormapi.ProviderZoneComments,
			ReqData:      &ormapi.ProviderZone{},
			ReplyData:    &[]ormapi.ProviderZone{},
			Path:         "/auth/federation/provider/zone/show",
			ShowFilter:   true,
		}, {
			Name:         "ShowProviderImage",
			Use:          "showimages",
			Short:        "Show Images uploaded by partner",
			OptionalArgs: strings.Join(ProviderImageShowArgs, " "),
			Comments:     ormapi.ProviderImageComments,
			ReqData:      &ormapi.ProviderImage{},
			ReplyData:    &[]ormapi.ProviderImage{},
			Path:         "/auth/federation/provider/image/show",
			ShowFilter:   true,
		}, {
			Name:         "ShowProviderArtefact",
			Use:          "showartefacts",
			Short:        "Show Artefacts created by partner",
			OptionalArgs: strings.Join(ProviderArtefactShowArgs, " "),
			Comments:     ormapi.ProviderArtefactComments,
			ReqData:      &ormapi.ProviderArtefact{},
			ReplyData:    &[]ormapi.ProviderArtefact{},
			Path:         "/auth/federation/provider/artefact/show",
			ShowFilter:   true,
		}, {
			Name:         "ShowProviderApp",
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
			Name:         "ShowProviderAppInst",
			Use:          "showappinsts",
			Short:        "Show AppInsts onboarded by partner, just for tracking unique ids",
			OptionalArgs: strings.Join(ProviderAppInstShowArgs, " "),
			Comments:     ormapi.ProviderAppInstComments,
			ReqData:      &ormapi.ProviderAppInst{},
			ReplyData:    &[]ormapi.ProviderAppInst{},
			Path:         "/auth/federation/provider/appinst/show",
			ShowFilter:   true,
		},
	}
	AllApis.AddGroup(FederationProviderGroup, "Manage Federation Provider and Zones", cmds)
	cmds = []*ApiCommand{
		&ApiCommand{
			Name:         "CreateFederationConsumer",
			Use:          "create",
			Short:        "Create Federation Consumer",
			SpecialArgs:  &FederationConsumerSpecialArgs,
			RequiredArgs: strings.Join(FederationConsumerRequiredArgs, " "),
			OptionalArgs: strings.Join(FederationConsumerOptionalArgs, " "),
			Comments:     ormapi.FederationConsumerComments,
			ReqData:      &ormapi.FederationConsumer{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federation/consumer/create",
		},
		&ApiCommand{
			Name:         "UpdateFederationConsumer",
			Use:          "update",
			Short:        "Update Federation Consumer",
			SpecialArgs:  &FederationConsumerSpecialArgs,
			RequiredArgs: "name operatorid",
			OptionalArgs: "public",
			Comments:     ormapi.FederationConsumerComments,
			ReqData:      &ormapi.FederationConsumer{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federation/consumer/update",
		},
		&ApiCommand{
			Name:         "DeleteFederationConsumer",
			Use:          "delete",
			Short:        "Delete Federation Consumer",
			SpecialArgs:  &FederationConsumerSpecialArgs,
			OptionalArgs: "id name operatorid",
			Comments:     ormapi.FederationConsumerComments,
			ReqData:      &ormapi.FederationConsumer{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federation/consumer/delete",
		},
		&ApiCommand{
			Name:         "ShowFederationConsumer",
			Use:          "show",
			Short:        "Show Federation Consumer",
			SpecialArgs:  &FederationConsumerSpecialArgs,
			OptionalArgs: strings.Join(FederationConsumerShowArgs, " "),
			Comments:     ormapi.FederationConsumerComments,
			ReqData:      &ormapi.FederationConsumer{},
			ReplyData:    &[]ormapi.FederationConsumer{},
			Path:         "/auth/federation/consumer/show",
			ShowFilter:   true,
		},
		&ApiCommand{
			Name:         "SetFederationConsumerAPIKey",
			Use:          "setpartnerapikey",
			Short:        "Set Partner Federation API Key",
			RequiredArgs: "name operatorid providerclientid providerclientkey",
			SpecialArgs:  &FederationConsumerSpecialArgs,
			Comments:     ormapi.FederationConsumerComments,
			ReqData:      &ormapi.FederationConsumer{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federation/consumer/setapikey",
		},
		&ApiCommand{
			Name:         "GenerateFederationConsumerNotifyKey",
			Use:          "generatenotifykey",
			Short:        "Set Partner Federation API Key",
			RequiredArgs: "name operatorid",
			SpecialArgs:  &FederationConsumerSpecialArgs,
			Comments:     ormapi.FederationConsumerComments,
			ReqData:      &ormapi.FederationConsumer{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federation/consumer/gennotifykey",
		},
		&ApiCommand{
			Name:         "RegisterConsumerZone",
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
			Name:         "DeregisterConsumerZone",
			Use:          "deregister",
			Short:        "DeRegister Partner Federator Zone",
			SpecialArgs:  &RegisterZoneSpecialArgs,
			RequiredArgs: strings.Join(DeregisterZoneRequiredArgs, " "),
			Comments:     ormapi.FederatedZoneRegRequestComments,
			ReqData:      &ormapi.FederatedZoneRegRequest{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federation/consumer/zone/deregister",
		},
		&ApiCommand{
			Name:         "ShowConsumerZone",
			Use:          "showzones",
			Short:        "Show Federated Partner Zones",
			OptionalArgs: strings.Join(ConsumerZoneShowArgs, " "),
			Comments:     ormapi.ConsumerZoneComments,
			ReqData:      &ormapi.ConsumerZone{},
			ReplyData:    &[]ormapi.ConsumerZone{},
			Path:         "/auth/federation/consumer/zone/show",
			ShowFilter:   true,
		}, {
			Name:         "ShowFedConsumerImage",
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
	AllApis.AddGroup(FederationConsumerGroup, "Manage Federation Consumer and Zones", cmds)
}

// Federation Provider
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
	"providerclientid",
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
	"providername",
	"zones",
}

var ProviderZoneShowArgs = []string{
	"zoneid",
	"operatorid",
	"providername",
	"status",
}

var ShareZoneSpecialArgs = map[string]string{
	"zones": "StringArray",
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

// Federation Consumer
// ===================

var FederationConsumerRequiredArgs = []string{
	"name",
	"operatorid",
	"partneraddr",
	"providerclientid",
	"providerclientkey",
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
	"providerclientid",
	"notifyclientid",
}

var RegisterZoneRequiredArgs = []string{
	"consumername",
	"region",
	"zones",
}

var DeregisterZoneRequiredArgs = []string{
	"consumername",
	"zones",
}

var RegisterZoneSpecialArgs = map[string]string{
	"zones": "StringArray",
}

var ConsumerZoneShowArgs = []string{
	"zoneid",
	"consumername",
	"operatorid",
	"geolocation",
	"geographydetails",
	"status",
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
