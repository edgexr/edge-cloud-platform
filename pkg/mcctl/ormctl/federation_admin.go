package ormctl

import (
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/fedewapi"
)

const FederationDirectGroup = "FederationDirect"

func init() {
	cmds := []*ApiCommand{{
		Name:         "GetFederationPartner",
		Use:          "getpartner",
		Short:        "Direct get partner EWBI API",
		RequiredArgs: "name",
		Comments:     ormapi.FederationConsumerComments,
		ReqData:      &ormapi.FederationConsumer{},
		ReplyData:    &fedewapi.GetFederationDetails200Response{},
		Path:         "/auth/federation/direct/partner/get",
	}, {
		Name:         "GetFederationZone",
		Use:          "getzone",
		Short:        "Direct get zone EWBI API",
		RequiredArgs: "consumername zoneid",
		AliasArgs:    strings.Join(ConsumerZoneAliasArgs, " "),
		Comments:     ormapi.ConsumerZoneComments,
		ReqData:      &ormapi.ConsumerZone{},
		ReplyData:    &fedewapi.ZoneRegisteredData{},
		Path:         "/auth/federation/direct/zone/get",
	}, {
		Name:         "GetFederationArtefact",
		Use:          "getartefact",
		Short:        "Direct get artefact EWBI API",
		RequiredArgs: "federationname id",
		Comments:     ormapi.ConsumerAppComments,
		ReqData:      &ormapi.ConsumerApp{},
		ReplyData:    &fedewapi.GetArtefact200Response{},
		Path:         "/auth/federation/direct/artefact/get",
	}, {
		Name:         "GetFederationFile",
		Use:          "getfile",
		Short:        "Direct get file EWBI API",
		RequiredArgs: "federationname id",
		Comments:     ormapi.ConsumerImageComments,
		ReqData:      &ormapi.ConsumerImage{},
		ReplyData:    &fedewapi.ViewFile200Response{},
		Path:         "/auth/federation/direct/file/get",
	}, {
		Name:         "GetFederationApp",
		Use:          "getapp",
		Short:        "Direct get app EWBI API",
		RequiredArgs: "federationname id",
		Comments:     ormapi.ConsumerAppComments,
		ReqData:      &ormapi.ConsumerApp{},
		ReplyData:    &fedewapi.ViewApplication200Response{},
		Path:         "/auth/federation/direct/app/get",
	}, {
		Name:         "GetFederationAppInsts",
		Use:          "getappinst",
		Short:        "Direct get appinst EWBI API",
		RequiredArgs: "region",
		OptionalArgs: strings.Join(append(AppInstRequiredArgs, AppInstOptionalArgs...), " "),
		AliasArgs:    strings.Join(AppInstAliasArgs, " "),
		SpecialArgs:  &AppInstSpecialArgs,
		Comments:     addRegionComment(AppInstComments),
		NoConfig:     "CloudletLoc,Uri,MappedPorts,Liveness,CreatedAt,Revision,Errors,RuntimeInfo,VmFlavor,ExternalVolumeSize,AvailabilityZone,State,UpdatedAt,OptRes,SharedVolumeSize,AutoClusterIpAccess,InternalPortToLbIp,UniqueId,DnsLabel,FedKey",
		ReqData:      &ormapi.RegionAppInst{},
		ReplyData:    &[]fedewapi.GetAppInstanceDetails200Response{},
		Path:         "/auth/federation/direct/appinst/get",
	}}
	AllApis.AddGroup(FederationDirectGroup, "Direct Federation APIs", cmds)
}
