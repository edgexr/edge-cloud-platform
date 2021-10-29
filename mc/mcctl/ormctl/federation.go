package ormctl

import (
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
)

const (
	FederatorGroup     = "Federator"
	FederatorZoneGroup = "FederatorZone"
	FederationGroup    = "Federation"
)

func init() {
	cmds := []*ApiCommand{
		&ApiCommand{
			Name:         "CreateSelfFederator",
			Use:          "create",
			Short:        "Create Self Federator",
			SpecialArgs:  &FederatorSpecialArgs,
			RequiredArgs: strings.Join(FederatorRequiredArgs, " "),
			OptionalArgs: strings.Join(FederatorOptionalArgs, " "),
			Comments:     ormapi.FederatorComments,
			ReqData:      &ormapi.Federator{},
			ReplyData:    &ormapi.Federator{},
			Path:         "/auth/federator/self/create",
		},
		&ApiCommand{
			Name:         "UpdateSelfFederator",
			Use:          "update",
			Short:        "Update Self Federator",
			SpecialArgs:  &FederatorSpecialArgs,
			RequiredArgs: "operatorid federationid",
			OptionalArgs: "mcc mnc locatorendpoint",
			Comments:     ormapi.FederatorComments,
			ReqData:      &ormapi.Federator{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federator/self/update",
		},
		&ApiCommand{
			Name:         "DeleteSelfFederator",
			Use:          "delete",
			Short:        "Delete Self Federator",
			RequiredArgs: "operatorid federationid",
			Comments:     ormapi.FederatorComments,
			ReqData:      &ormapi.Federator{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federator/self/delete",
		},
		&ApiCommand{
			Name:         "ShowSelfFederator",
			Use:          "show",
			Short:        "Show Self Federator",
			SpecialArgs:  &FederatorSpecialArgs,
			OptionalArgs: strings.Join(append(FederatorRequiredArgs, FederatorOptionalArgs...), " "),
			Comments:     ormapi.FederatorComments,
			ReqData:      &ormapi.Federator{},
			ReplyData:    &[]ormapi.Federator{},
			Path:         "/auth/federator/self/show",
		},
	}
	AllApis.AddGroup(FederatorGroup, "Federator APIs", cmds)

	cmds = []*ApiCommand{
		&ApiCommand{
			Name:         "CreateSelfFederatorZone",
			Use:          "create",
			Short:        "Create Self Federator Zone",
			SpecialArgs:  &FederatorZoneSpecialArgs,
			RequiredArgs: strings.Join(FederatorZoneRequiredArgs, " "),
			OptionalArgs: strings.Join(FederatorZoneOptionalArgs, " "),
			Comments:     ormapi.FederatorZoneComments,
			ReqData:      &ormapi.FederatorZone{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federator/self/zone/create",
		},
		&ApiCommand{
			Name:         "DeleteSelfFederatorZone",
			Use:          "delete",
			Short:        "Delete Self Federator Zone",
			RequiredArgs: "zoneid operatorid countrycode",
			Comments:     ormapi.FederatorZoneComments,
			ReqData:      &ormapi.FederatorZone{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federator/self/zone/delete",
		},
		&ApiCommand{
			Name:         "ShowSelfFederatorZone",
			Use:          "show",
			Short:        "Show Self Federator Zone",
			OptionalArgs: "operatorid countrycode zoneid city region",
			Comments:     ormapi.FederatorZoneComments,
			ReqData:      &ormapi.FederatorZone{},
			ReplyData:    &[]ormapi.FederatorZone{},
			Path:         "/auth/federator/self/zone/show",
		},
		&ApiCommand{
			Name:         "ShareSelfFederatorZone",
			Use:          "share",
			Short:        "Share Self Federator Zone",
			RequiredArgs: strings.Join(FederatedZoneArgs, " "),
			Comments:     ormapi.FederatedSelfZoneComments,
			ReqData:      &ormapi.FederatedSelfZone{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federator/self/zone/share",
		},
		&ApiCommand{
			Name:         "UnshareSelfFederatorZone",
			Use:          "unshare",
			Short:        "Unshare Self Federator Zone",
			RequiredArgs: strings.Join(FederatedZoneArgs, " "),
			Comments:     ormapi.FederatedSelfZoneComments,
			ReqData:      &ormapi.FederatedSelfZone{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federator/self/zone/unshare",
		},
		&ApiCommand{
			Name:         "RegisterPartnerFederatorZone",
			Use:          "register",
			Short:        "Register Partner Federator Zone",
			AliasArgs:    strings.Join(FederatorZoneAliasArgs, " "),
			RequiredArgs: strings.Join(FederatedZoneArgs, " "),
			Comments:     aliasedComments(ormapi.FederatedPartnerZoneComments, FederatorZoneAliasArgs),
			ReqData:      &ormapi.FederatedPartnerZone{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federator/partner/zone/register",
		},
		&ApiCommand{
			Name:         "DeRegisterPartnerFederatorZone",
			Use:          "deregister",
			Short:        "DeRegister Partner Federator Zone",
			AliasArgs:    strings.Join(FederatorZoneAliasArgs, " "),
			RequiredArgs: strings.Join(FederatedZoneArgs, " "),
			Comments:     aliasedComments(ormapi.FederatedPartnerZoneComments, FederatorZoneAliasArgs),
			ReqData:      &ormapi.FederatedPartnerZone{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federator/partner/zone/deregister",
		},
		&ApiCommand{
			Name:         "ShowFederatedSelfZone",
			Use:          "showfederatedselfzone",
			Short:        "Show Federated Self Zones",
			OptionalArgs: strings.Join(FederatedZoneArgs, " "),
			Comments:     ormapi.FederatedSelfZoneComments,
			ReqData:      &ormapi.FederatedSelfZone{},
			ReplyData:    &[]ormapi.FederatedSelfZone{},
			Path:         "/auth/federation/self/zone/show",
		},
		&ApiCommand{
			Name:         "ShowFederatedPartnerZone",
			Use:          "showfederatedpartnerzone",
			Short:        "Show Federated Partner Zones",
			SpecialArgs:  &FederatorZoneSpecialArgs,
			AliasArgs:    strings.Join(FederatorZoneAliasArgs, " "),
			OptionalArgs: strings.Join(FederatedZoneArgs, " "),
			Comments:     aliasedComments(ormapi.FederatedPartnerZoneComments, FederatorZoneAliasArgs),
			ReqData:      &ormapi.FederatedPartnerZone{},
			ReplyData:    &[]ormapi.FederatedPartnerZone{},
			Path:         "/auth/federation/partner/zone/show",
		},
	}
	AllApis.AddGroup(FederatorZoneGroup, "Federator Zone APIs", cmds)

	cmds = []*ApiCommand{
		&ApiCommand{
			Name:         "CreateFederation",
			Use:          "create",
			Short:        "Create Federation",
			SpecialArgs:  &FederatorSpecialArgs,
			AliasArgs:    strings.Join(FederationAliasArgs, " "),
			RequiredArgs: strings.Join(append(SelfFederatorArgs, FederationRequiredArgs...), " "),
			Comments:     aliasedComments(ormapi.FederationComments, FederationAliasArgs),
			ReqData:      &ormapi.Federation{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federation/create",
		},
		&ApiCommand{
			Name:         "DeleteFederation",
			Use:          "delete",
			Short:        "Delete Federation",
			AliasArgs:    strings.Join(FederationAliasArgs, " "),
			RequiredArgs: strings.Join(FederationArgs, " "),
			Comments:     aliasedComments(ormapi.FederationComments, FederationAliasArgs),
			ReqData:      &ormapi.Federation{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federation/delete",
		},
		&ApiCommand{
			Name:         "RegisterFederation",
			Use:          "register",
			Short:        "Register Federation",
			AliasArgs:    strings.Join(FederationAliasArgs, " "),
			RequiredArgs: strings.Join(FederationArgs, " "),
			Comments:     aliasedComments(ormapi.FederationComments, FederationAliasArgs),
			ReqData:      &ormapi.Federation{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federation/register",
		},
		&ApiCommand{
			Name:         "DeregisterFederation",
			Use:          "deregister",
			Short:        "Deregister Federation",
			AliasArgs:    strings.Join(FederationAliasArgs, " "),
			RequiredArgs: strings.Join(FederationArgs, " "),
			Comments:     aliasedComments(ormapi.FederationComments, FederationAliasArgs),
			ReqData:      &ormapi.Federation{},
			ReplyData:    &ormapi.Result{},
			Path:         "/auth/federation/deregister",
		},
		&ApiCommand{
			Name:         "ShowFederation",
			Use:          "show",
			Short:        "Show Federation",
			SpecialArgs:  &FederatorSpecialArgs,
			AliasArgs:    strings.Join(FederationAliasArgs, " "),
			OptionalArgs: strings.Join(append(SelfFederatorArgs, FederationRequiredArgs...), " "),
			Comments:     aliasedComments(ormapi.FederationComments, FederationAliasArgs),
			ReqData:      &ormapi.Federation{},
			ReplyData:    &[]ormapi.Federation{},
			Path:         "/auth/federation/show",
		},
	}
	AllApis.AddGroup(FederationGroup, "Federation APIs", cmds)
}

var SelfFederatorArgs = []string{
	"selfoperatorid",
	"selffederationid",
}

var FederatorRequiredArgs = []string{
	"operatorid",
	"countrycode",
	"region",
	"mcc",
	"mnc",
}

var FederatorOptionalArgs = []string{
	"federationid",
	"locatorendpoint",
}

var FederationRequiredArgs = []string{
	"name",
	"operatorid",
	"countrycode",
	"federationid",
	"federationaddr",
}

var FederationArgs = []string{
	"selfoperatorid",
	"name",
}

var FederationAliasArgs = []string{
	"operatorid=federator.operatorid",
	"countrycode=federator.countrycode",
	"federationid=federator.federationid",
	"federationaddr=federator.federationaddr",
	"mcc=federator.mcc",
	"mnc=federator.mnc",
	"locatorendpoint=federator.locatorendpoint",
}

var FederatorSpecialArgs = map[string]string{
	"federator.mnc": "StringArray",
}
var FederatorZoneSpecialArgs = map[string]string{
	"federatorzone.cloudlets": "StringArray",
}

var FederatorZoneRequiredArgs = []string{
	"zoneid",
	"operatorid",
	"countrycode",
	"cloudlets",
	"geolocation",
}

var FederatorZoneOptionalArgs = []string{
	"city",
	"state",
	"locality",
}

var FederatorZoneAliasArgs = []string{
	"operatorid=federatorzone.operatorid",
	"countrycode=federatorzone.countrycode",
	"zoneid=federatorzone.zoneid",
	"geolocation=federatorzone.geolocation",
	"city=federatorzone.city",
	"state=federatorzone.state",
	"locality=federatorzone.locality",
	"region=federatorzone.locality",
	"cloudlets=federatorzone.cloudlets",
}

var FederatedZoneArgs = []string{
	"zoneid",
	"selfoperatorid",
	"federationname",
}
