/*
Federation Management Service

# Introduction --- RESTful APIs that allow an OP to share the edge cloud resources and capabilities securely to other partner OPs over E/WBI.   --- # API Scope  --- APIs defined in this version of the specification can be categorized into the following areas: * __FederationManagement__ - Create and manage directed federation relationship with a partner OP * __AvailabilityZoneInfoSynchronization__ - Management of resources of partner OP zones and status updates  * __ArtefactManagement__ - Upload, remove, retrieve and update application descriptors, charts and packages over E/WBI towards a partner OP * __FileManagement__ - Upload, remove, retrieve and update  application binaries over E/WBI towards a partner OP * __ApplicationOnboardingManagement__ - Register, retrieve, update and remove applications over E/WBI towards a partner OP * __ApplicationDeploymentManagement__ - Create, update, retrieve and terminate application instances over E/WBI towards a partner OP * __AppProviderResourceManagement__ -  Static resource reservation for an application provider over E/WBI for partner OP zones * __EdgeNodeSharing__ - Edge discovery procedures towards partner OP over E/WBI. * __LBORoamingAuthentication__ -  Validation of user client authentication from home OP  --- # Definitions --- This section provides definitions of terminologies commonly referred to throughout the API descriptions.  * __Accepted Zones__  - List of partner OP zones, which the originating OP has confirmed to use for its edge applications * __Anchoring__ - Partner OP capability to serve application clients (still in their home location) from application instances running on partner zones.  * __Application Provider__ - An application developer, onboarding his/her edge application on a partner operator platform (MEC).         * __Artefact__ - Descriptor, charts or any other package associated with the application. * __Availability Zone__ - Zones that partner OP can offer to share with originating OP. * __Device__ - Refers to user equipment like mobile phone, tablet, IOT kit, AR/VR device etc. In context of MEC users use these devices to access edge applications * __Directed Federation__ - A Federation between two OP instances A and B, in which edge compute resources are shared by B to A, but not from A to B. * __Edge Application__ - Application designed to run on MEC edge cloud   * __Edge Discovery Service__ - Partner OP service responsible to select most optimal edge( within partner OP) for edge application instantiation. Edge discovery service is defined as HTTP based API endpoint identified by a well-defined FQDN or IP. * __E/WBI__ - East west bound interface. * __Federation__ - Relationship among member OPs who agrees to offer  services and capabilities to the application providers and end users of member OPs   * __FederationContextId__ - Partner OP defined string identifier representing a certain federation relationship. * __Federation Identifier__ - Identify an operator platform in federation context. * __FileId__ - An OP defined string identifier representing a certain application image uploaded by an application provider * __Flavour__ - A group of compute, network and storage resources that can be requested or granted as a single unit * __FlavourIdentifier__ - An OP defined string identifier representing a set of compute, storage  and networking resources * __Home OP__ - Used in federation context to identify the OP with which the application developers or user clients are registered. * __Home Routing__ - Partner OP capability to direct roaming user client traffic towards application instances running on home OP zones.  * __Instance__ - Application process running on an edge * __LCM Service__ -  Partner OP service responsible for life cycle management of edge applications. LCM service is defined as HTTP based API endpoint identified by a well-defined FQDN or IP. * __Offered Zones__ - Zones that partner OP offer to share  to the Originating OP based on the prior agreement and local configuration.    * __Onboarding__ - Submitting an application to MEC platform  * __OP__ - Operator platform. * __OperatorIdentfier__ - String identifier representing the owner of MEC platform. Owner could  be an enterprise, a TSP or some other organization * __Originating OP__ - The OP when initiating the federation creation request towards the partner OP is defined as the Originating OP * __Partner OP__ - Operator Platform which offers its Edge Cloud capabilities to the other Operator Platforms via E/WBI.      * __Resource__ - Compute, networking and storage resources. * __Resource Pool__ -  A group of  compute, networking and storage resources. Application provider  pre-reserve resources on partner OP zone, these resources are reserved in terms of flavours.  * __ZoneIdentifier__ - An OP defined string identifier representing a certain geographical or logical area where edge resources and services are provided * __Zone Confirmation__ - Procedure via which originating OP acknowledges partner OP about the partner zones it wishes to use. * __User Clients__ -  Lightweight client applications used to access edge applications. Application users run these clients on their devices (UE, IOT device, AR/VR device etc)    --- # API Operations ---    __FederationManagement__ * __CreateFederation__  Creates a directed federation relationship with a partner OP * __GetFederationDetails__  Retrieves details about the federation relationship with the partner OP. The response shall provide info about the zones offered by the partner, partner OP network codes, information about edge discovery and LCM service etc. * __DeleteFederationDetails__  Remove existing federation with the partner OP * __NotifyFederationUpdates__ Call back notification used by partner OP to update originating OP about any change in existing federation relationship. * __UpdateFederation__ API used by the Originating OP towards the partner OP, to update the parameters associated to the existing federation  __AvailabilityZoneInfoSynchronization__ * __ZoneSubscribe__  Informs partner OP that originating OP is willing to access the specified zones  and partner OP shall reserve compute and network resources for these zones. * __ZoneUnsubscribe__  Informs partner OP that originating OP will no longer access the specified partner OP zone. * __GetZoneData__  Retrieves details about the computation and network resources that partner OP has reserved for an partner OP  zone. * __Notify Zone Information__ Call back notification used by partner OP to update originating OP about changes in the resources reserved on a partner zone.  __ArtefactManagement__ * __UploadArtefact__  Uploads application artefact  on partner operator platform. * __RemoveArtefact__  Removes an artefact from partner operator platform. * __GetArtefact__  Retrieves details about an artefact from partner operator platform. * __UploadFile__ Upload application binaries to partner operator platform * __RemoveFile__  Removes application binaries from partner operator platform * __ViewFile__  Retrieves details about binaries assosiated with an application from partner operator platform  __ApplicationOnboardingManagement__ * __OnboardApplication__ - Submits an application details to a partner OP. Based on the details provided,  partner OP shall do bookkeeping, resource validation and other pre-deployment operations * __UpdateApplication__ - Updates partner OP about changes in  application compute resource requirements, QOS Profile, associated descriptor or change in assosiated components * __DeboardApplication__ - Removes an application from partner OP * __ViewApplication__ - Retrieves application details from partner OP * __OnboardExistingAppNewZones__ - Make an application available on new additional zones * __LockUnlockApplicationZone__ - Forbid or permit instantiation of application on a zone  __Application Instance Lifecycle Management__ * __InstallApp__ - Instantiates an application on a partner OP zone. * __GetAppInstanceDetails__ - Retrieves an application instance details from partner OP. * __RemoveApp__ - Terminate an application instance on a partner OP zone. * __GetAllAppInstances__ - Retrieves details about all instances of the application running on partner OP zones.   __AppProviderResourceManagement__ * __CreateResourcePools__  Reserves resources (compute, network and storage)  on a partner OP zone. ISVs registered with home OP reserves resurces on a partner OP zone. * __UpdateISVResPool__  Updates resources reserved for a pool by an ISV * __ViewISVResPool__  Retrieves the resource pool reserved by an ISV * __RemoveISVResPool__ Deletes the resource pool reserved by an ISV   __EdgeNodeSharing__ *__GetCandidateZones__ Edge discovery procedures towards partner OP over E/WBI. Originating OP request partner OP to provide a list of candidate zones where an application instance can be created.    __LBORoamingAuthentication__ *__AuthenticateDevice__ Validates the authenticity of a roaming user from home OP   © 2022 GSM Association. All rights reserved. 

API version: 1.0.0
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package fedewapi

import (
	"encoding/json"
)

// checks if the FederationContextIdZonesPostRequest type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &FederationContextIdZonesPostRequest{}

// FederationContextIdZonesPostRequest struct for FederationContextIdZonesPostRequest
type FederationContextIdZonesPostRequest struct {
	ZoneResUpdInfo []FederationContextIdZonesPostRequestZoneResUpdInfoInner `json:"zoneResUpdInfo"`
}

// NewFederationContextIdZonesPostRequest instantiates a new FederationContextIdZonesPostRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewFederationContextIdZonesPostRequest(zoneResUpdInfo []FederationContextIdZonesPostRequestZoneResUpdInfoInner) *FederationContextIdZonesPostRequest {
	this := FederationContextIdZonesPostRequest{}
	this.ZoneResUpdInfo = zoneResUpdInfo
	return &this
}

// NewFederationContextIdZonesPostRequestWithDefaults instantiates a new FederationContextIdZonesPostRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewFederationContextIdZonesPostRequestWithDefaults() *FederationContextIdZonesPostRequest {
	this := FederationContextIdZonesPostRequest{}
	return &this
}

// GetZoneResUpdInfo returns the ZoneResUpdInfo field value
func (o *FederationContextIdZonesPostRequest) GetZoneResUpdInfo() []FederationContextIdZonesPostRequestZoneResUpdInfoInner {
	if o == nil {
		var ret []FederationContextIdZonesPostRequestZoneResUpdInfoInner
		return ret
	}

	return o.ZoneResUpdInfo
}

// GetZoneResUpdInfoOk returns a tuple with the ZoneResUpdInfo field value
// and a boolean to check if the value has been set.
func (o *FederationContextIdZonesPostRequest) GetZoneResUpdInfoOk() ([]FederationContextIdZonesPostRequestZoneResUpdInfoInner, bool) {
	if o == nil {
		return nil, false
	}
	return o.ZoneResUpdInfo, true
}

// SetZoneResUpdInfo sets field value
func (o *FederationContextIdZonesPostRequest) SetZoneResUpdInfo(v []FederationContextIdZonesPostRequestZoneResUpdInfoInner) {
	o.ZoneResUpdInfo = v
}

func (o FederationContextIdZonesPostRequest) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o FederationContextIdZonesPostRequest) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["zoneResUpdInfo"] = o.ZoneResUpdInfo
	return toSerialize, nil
}

type NullableFederationContextIdZonesPostRequest struct {
	value *FederationContextIdZonesPostRequest
	isSet bool
}

func (v NullableFederationContextIdZonesPostRequest) Get() *FederationContextIdZonesPostRequest {
	return v.value
}

func (v *NullableFederationContextIdZonesPostRequest) Set(val *FederationContextIdZonesPostRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableFederationContextIdZonesPostRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableFederationContextIdZonesPostRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableFederationContextIdZonesPostRequest(val *FederationContextIdZonesPostRequest) *NullableFederationContextIdZonesPostRequest {
	return &NullableFederationContextIdZonesPostRequest{value: val, isSet: true}
}

func (v NullableFederationContextIdZonesPostRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableFederationContextIdZonesPostRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


