/*
Federation Management Service

# Introduction --- RESTful APIs that allow an OP to share the edge cloud resources and capabilities securely to other partner OPs over E/WBI.   --- # API Scope  --- APIs defined in this version of the specification can be categorized into the following areas: * __FederationManagement__ - Create and manage directed federation relationship with a partner OP * __AvailabilityZoneInfoSynchronization__ - Management of resources of partner OP zones and status updates  * __ArtifactManagement__ - Upload, remove, retrieve and update application descriptors, charts and packages over E/WBI towards a partner OP * __FileManagement__ - Upload, remove, retrieve and update  application binaries over E/WBI towards a partner OP * __ApplicationOnboardingManagement__ - Register, retrieve, update and remove applications over E/WBI towards a partner OP * __ApplicationDeploymentManagement__ - Create, update, retrieve and terminate application instances over E/WBI towards a partner OP * __AppProviderResourceManagement__ -  Static resource reservation for an application provider over E/WBI for partner OP zones * __EdgeNodeSharing__ - Edge discovery procedures towards partner OP over E/WBI. * __LBORoamingAuthentication__ -  Validation of user client authentication from home OP  --- # Definitions --- This section provides definitions of terminologies commonly referred to throughout the API descriptions.  * __Accepted Zones__  - List of partner OP zones, which the originating OP has confirmed to use for its edge applications * __Anchoring__ - Partner OP capability to serve application clients (still in their home location) from application instances running on partner zones.  * __Application Provider__ - An application developer, onboarding his/her edge application on a partner operator platform (MEC).         * __Artefact__ - Descriptor, charts or any other package associated with the application. * __Availability Zone__ - Zones that partner OP can offer to share with originating OP. * __Device__ - Refers to user equipment like mobile phone, tablet, IOT kit, AR/VR device etc. In context of MEC users use these devices to access edge applications * __Directed Federation__ - A Federation between two OP instances A and B, in which edge compute resources are shared by B to A, but not from A to B. * __Edge Application__ - Application designed to run on MEC edge cloud   * __Edge Discovery Service__ - Partner OP service responsible to select most optimal edge( within partner OP) for edge application instantiation. Edge discovery service is defined as HTTP based API endpoint identified by a well-defined FQDN or IP. * __E/WBI__ - East west bound interface. * __Federation__ - Relationship among member OPs who agrees to offer  services and capabilities to the application providers and end users of member OPs   * __FederationContextId__ - Partner OP defined string identifier representing a certain federation relationship. * __Federation Identifier__ - Identify an operator platform in federation context. * __FileId__ - An OP defined string identifier representing a certain application image uploaded by an application provider * __Flavour__ - A group of compute, network and storage resources that can be requested or granted as a single unit * __FlavourIdentifier__ - An OP defined string identifier representing a set of compute, storage  and networking resources * __Home OP__ - Used in federation context to identify the OP with which the application developers or user clients are registered. * __Home Routing__ - Partner OP capability to direct roaming user client traffic towards application instances running on home OP zones.  * __Instance__ - Application process running on an edge * __LCM Service__ -  Partner OP service responsible for life cycle management of edge applications. LCM service is defined as HTTP based API endpoint identified by a well-defined FQDN or IP. * __Offered Zones__ - Zones that partner OP offer to share  to the Originating OP based on the prior agreement and local configuration.    * __Onboarding__ - Submitting an application to MEC platform  * __OP__ - Operator platform. * __OperatorIdentfier__ - String identifier representing the owner of MEC platform. Owner could  be an enterprise, a TSP or some other organization * __Originating OP__ - The OP when initiating the federation creation request towards the partner OP is defined as the Originating OP * __Partner OP__ - Operator Platform which offers its Edge Cloud capabilities to the other Operator Platforms via E/WBI.      * __Resource__ - Compute, networking and storage resources. * __Resource Pool__ -  A group of  compute, networking and storage resources. Application provider  pre-reserve resources on partner OP zone, these resources are reserved in terms of flavours.  * __ZoneIdentifier__ - An OP defined string identifier representing a certain geographical or logical area where edge resources and services are provided * __Zone Confirmation__ - Procedure via which originating OP acknowledges partner OP about the partner zones it wishes to use. * __User Clients__ -  Lightweight client applications used to access edge applications. Application users run these clients on their devices (UE, IOT device, AR/VR device etc)    --- # API Operations ---    __FederationManagement__ * __CreateFederation__  Creates a directed federation relationship with a partner OP * __GetFederationDetails__  Retrieves details about the federation relationship with the partner OP. The response shall provide info about the zones offered by the partner, partner OP network codes, information about edge discovery and LCM service etc. * __DeleteFederationDetails__  Remove existing federation with the partner OP * __NotifyFederationUpdates__ Call back notification used by partner OP to update originating OP about any change in existing federation relationship. * __UpdateFederation__ API used by the Originating OP towards the partner OP, to update the parameters associated to the existing federation  __AvailabilityZoneInfoSynchronization__ * __ZoneSubscribe__  Informs partner OP that originating OP is willing to access the specified zones  and partner OP shall reserve compute and network resources for these zones. * __ZoneUnsubscribe__  Informs partner OP that originating OP will no longer access the specified partner OP zone. * __GetZoneData__  Retrieves details about the computation and network resources that partner OP has reserved for an partner OP  zone. * __Notify Zone Information__ Call back notification used by partner OP to update originating OP about changes in the resources reserved on a partner zone.  __ArtefactManagement__ * __UploadArtefact__  Uploads application artefact  on partner operator platform. * __RemoveArtefact__  Removes an artefact from partner operator platform. * __GetArtefact__  Retrieves details about an artefact from partner operator platform. * __UploadFile__ Upload application binaries to partner operator platform * __RemoveFile__  Removes application binaries from partner operator platform * __ViewFile__  Retrieves details about binaries assosiated with an application from partner operator platform  __ApplicationOnboardingManagement__ * __OnboardApplication__ - Submits an application details to a partner OP. Based on the details provided,  partner OP shall do bookkeeping, resource validation and other pre-deployment operations * __UpdateApplication__ - Updates partner OP about changes in  application compute resource requirements, QOS Profile, associated descriptor or change in assosiated components * __DeboardApplication__ - Removes an application from partner OP * __ViewApplication__ - Retrieves application details from partner OP * __OnboardExistingAppNewZones__ - Make an application available on new additional zones * __LockUnlockApplicationZone__ - Forbid or permit instantiation of application on a zone  __Application Instance Lifecycle Management__ * __InstallApp__ - Instantiates an application on a partner OP zone. * __GetAppInstanceDetails__ - Retrieves an application instance details from partner OP. * __RemoveApp__ - Terminate an application instance on a partner OP zone. * __GetAllAppInstances__ - Retrieves details about all instances of the application running on partner OP zones.   __AppProviderResourceManagement__ * __CreateResourcePools__  Reserves resources (compute, network and storage)  on a partner OP zone. ISVs registered with home OP reserves resurces on a partner OP zone. * __UpdateISVResPool__  Updates resources reserved for a pool by an ISV * __ViewISVResPool__  Retrieves the resource pool reserved by an ISV * __RemoveISVResPool__ Deletes the resource pool reserved by an ISV   __EdgeNodeSharing__ *__GetCandidateZones__ Edge discovery procedures towards partner OP over E/WBI. Originating OP request partner OP to provide a list of candidate zones where an application instance can be created.    __LBORoamingAuthentication__ *__AuthenticateDevice__ Validates the authenticity of a roaming user from home OP   © 2022 GSM Association. All rights reserved. 

API version: 1.0.0
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package fedewapi

import (
	"encoding/json"
)

// FederationResponseData struct for FederationResponseData
type FederationResponseData struct {
	// Globally unique Identifier allocated to an operator platform. This is valid and used only in context of  MEC federation interface.
	PartnerOPFederationId string `json:"partnerOPFederationId"`
	// ISO 3166-1 Alpha-2 code for the country of Partner operator
	PartnerOPCountryCode string `json:"partnerOPCountryCode"`
	// This key shall be provided by the partner OP on successful verification and validation of the federation create request and is used by partner op to identify this newly created federation context. Originating OP shall provide this key in any subsequent request towards the partner op.
	FederationContextId string `json:"federationContextId"`
	EdgeDiscoveryServiceEndPoint ServiceEndpoint `json:"edgeDiscoveryServiceEndPoint"`
	LcmServiceEndPoint ServiceEndpoint `json:"lcmServiceEndPoint"`
	PartnerOPMobileNetworkCodes *MobileNetworkIds `json:"partnerOPMobileNetworkCodes,omitempty"`
	// List of network identifier associated with the fixed line network of the operator platform.
	PartnerOPFixedNetworkCodes []string `json:"partnerOPFixedNetworkCodes,omitempty"`
	// List of zones, which the operator platform wishes to make available to developers/ISVs of  requesting operator platform.
	OfferedAvailabilityZones []ZoneDetails `json:"offeredAvailabilityZones"`
	PlatformCaps []string `json:"platformCaps,omitempty"`
}

// NewFederationResponseData instantiates a new FederationResponseData object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewFederationResponseData(partnerOPFederationId string, partnerOPCountryCode string, federationContextId string, edgeDiscoveryServiceEndPoint ServiceEndpoint, lcmServiceEndPoint ServiceEndpoint, offeredAvailabilityZones []ZoneDetails) *FederationResponseData {
	this := FederationResponseData{}
	this.PartnerOPFederationId = partnerOPFederationId
	this.PartnerOPCountryCode = partnerOPCountryCode
	this.FederationContextId = federationContextId
	this.EdgeDiscoveryServiceEndPoint = edgeDiscoveryServiceEndPoint
	this.LcmServiceEndPoint = lcmServiceEndPoint
	this.OfferedAvailabilityZones = offeredAvailabilityZones
	return &this
}

// NewFederationResponseDataWithDefaults instantiates a new FederationResponseData object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewFederationResponseDataWithDefaults() *FederationResponseData {
	this := FederationResponseData{}
	return &this
}

// GetPartnerOPFederationId returns the PartnerOPFederationId field value
func (o *FederationResponseData) GetPartnerOPFederationId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.PartnerOPFederationId
}

// GetPartnerOPFederationIdOk returns a tuple with the PartnerOPFederationId field value
// and a boolean to check if the value has been set.
func (o *FederationResponseData) GetPartnerOPFederationIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.PartnerOPFederationId, true
}

// SetPartnerOPFederationId sets field value
func (o *FederationResponseData) SetPartnerOPFederationId(v string) {
	o.PartnerOPFederationId = v
}

// GetPartnerOPCountryCode returns the PartnerOPCountryCode field value
func (o *FederationResponseData) GetPartnerOPCountryCode() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.PartnerOPCountryCode
}

// GetPartnerOPCountryCodeOk returns a tuple with the PartnerOPCountryCode field value
// and a boolean to check if the value has been set.
func (o *FederationResponseData) GetPartnerOPCountryCodeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.PartnerOPCountryCode, true
}

// SetPartnerOPCountryCode sets field value
func (o *FederationResponseData) SetPartnerOPCountryCode(v string) {
	o.PartnerOPCountryCode = v
}

// GetFederationContextId returns the FederationContextId field value
func (o *FederationResponseData) GetFederationContextId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.FederationContextId
}

// GetFederationContextIdOk returns a tuple with the FederationContextId field value
// and a boolean to check if the value has been set.
func (o *FederationResponseData) GetFederationContextIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.FederationContextId, true
}

// SetFederationContextId sets field value
func (o *FederationResponseData) SetFederationContextId(v string) {
	o.FederationContextId = v
}

// GetEdgeDiscoveryServiceEndPoint returns the EdgeDiscoveryServiceEndPoint field value
func (o *FederationResponseData) GetEdgeDiscoveryServiceEndPoint() ServiceEndpoint {
	if o == nil {
		var ret ServiceEndpoint
		return ret
	}

	return o.EdgeDiscoveryServiceEndPoint
}

// GetEdgeDiscoveryServiceEndPointOk returns a tuple with the EdgeDiscoveryServiceEndPoint field value
// and a boolean to check if the value has been set.
func (o *FederationResponseData) GetEdgeDiscoveryServiceEndPointOk() (*ServiceEndpoint, bool) {
	if o == nil {
		return nil, false
	}
	return &o.EdgeDiscoveryServiceEndPoint, true
}

// SetEdgeDiscoveryServiceEndPoint sets field value
func (o *FederationResponseData) SetEdgeDiscoveryServiceEndPoint(v ServiceEndpoint) {
	o.EdgeDiscoveryServiceEndPoint = v
}

// GetLcmServiceEndPoint returns the LcmServiceEndPoint field value
func (o *FederationResponseData) GetLcmServiceEndPoint() ServiceEndpoint {
	if o == nil {
		var ret ServiceEndpoint
		return ret
	}

	return o.LcmServiceEndPoint
}

// GetLcmServiceEndPointOk returns a tuple with the LcmServiceEndPoint field value
// and a boolean to check if the value has been set.
func (o *FederationResponseData) GetLcmServiceEndPointOk() (*ServiceEndpoint, bool) {
	if o == nil {
		return nil, false
	}
	return &o.LcmServiceEndPoint, true
}

// SetLcmServiceEndPoint sets field value
func (o *FederationResponseData) SetLcmServiceEndPoint(v ServiceEndpoint) {
	o.LcmServiceEndPoint = v
}

// GetPartnerOPMobileNetworkCodes returns the PartnerOPMobileNetworkCodes field value if set, zero value otherwise.
func (o *FederationResponseData) GetPartnerOPMobileNetworkCodes() MobileNetworkIds {
	if o == nil || o.PartnerOPMobileNetworkCodes == nil {
		var ret MobileNetworkIds
		return ret
	}
	return *o.PartnerOPMobileNetworkCodes
}

// GetPartnerOPMobileNetworkCodesOk returns a tuple with the PartnerOPMobileNetworkCodes field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FederationResponseData) GetPartnerOPMobileNetworkCodesOk() (*MobileNetworkIds, bool) {
	if o == nil || o.PartnerOPMobileNetworkCodes == nil {
		return nil, false
	}
	return o.PartnerOPMobileNetworkCodes, true
}

// HasPartnerOPMobileNetworkCodes returns a boolean if a field has been set.
func (o *FederationResponseData) HasPartnerOPMobileNetworkCodes() bool {
	if o != nil && o.PartnerOPMobileNetworkCodes != nil {
		return true
	}

	return false
}

// SetPartnerOPMobileNetworkCodes gets a reference to the given MobileNetworkIds and assigns it to the PartnerOPMobileNetworkCodes field.
func (o *FederationResponseData) SetPartnerOPMobileNetworkCodes(v MobileNetworkIds) {
	o.PartnerOPMobileNetworkCodes = &v
}

// GetPartnerOPFixedNetworkCodes returns the PartnerOPFixedNetworkCodes field value if set, zero value otherwise.
func (o *FederationResponseData) GetPartnerOPFixedNetworkCodes() []string {
	if o == nil || o.PartnerOPFixedNetworkCodes == nil {
		var ret []string
		return ret
	}
	return o.PartnerOPFixedNetworkCodes
}

// GetPartnerOPFixedNetworkCodesOk returns a tuple with the PartnerOPFixedNetworkCodes field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FederationResponseData) GetPartnerOPFixedNetworkCodesOk() ([]string, bool) {
	if o == nil || o.PartnerOPFixedNetworkCodes == nil {
		return nil, false
	}
	return o.PartnerOPFixedNetworkCodes, true
}

// HasPartnerOPFixedNetworkCodes returns a boolean if a field has been set.
func (o *FederationResponseData) HasPartnerOPFixedNetworkCodes() bool {
	if o != nil && o.PartnerOPFixedNetworkCodes != nil {
		return true
	}

	return false
}

// SetPartnerOPFixedNetworkCodes gets a reference to the given []string and assigns it to the PartnerOPFixedNetworkCodes field.
func (o *FederationResponseData) SetPartnerOPFixedNetworkCodes(v []string) {
	o.PartnerOPFixedNetworkCodes = v
}

// GetOfferedAvailabilityZones returns the OfferedAvailabilityZones field value
func (o *FederationResponseData) GetOfferedAvailabilityZones() []ZoneDetails {
	if o == nil {
		var ret []ZoneDetails
		return ret
	}

	return o.OfferedAvailabilityZones
}

// GetOfferedAvailabilityZonesOk returns a tuple with the OfferedAvailabilityZones field value
// and a boolean to check if the value has been set.
func (o *FederationResponseData) GetOfferedAvailabilityZonesOk() ([]ZoneDetails, bool) {
	if o == nil {
		return nil, false
	}
	return o.OfferedAvailabilityZones, true
}

// SetOfferedAvailabilityZones sets field value
func (o *FederationResponseData) SetOfferedAvailabilityZones(v []ZoneDetails) {
	o.OfferedAvailabilityZones = v
}

// GetPlatformCaps returns the PlatformCaps field value if set, zero value otherwise.
func (o *FederationResponseData) GetPlatformCaps() []string {
	if o == nil || o.PlatformCaps == nil {
		var ret []string
		return ret
	}
	return o.PlatformCaps
}

// GetPlatformCapsOk returns a tuple with the PlatformCaps field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FederationResponseData) GetPlatformCapsOk() ([]string, bool) {
	if o == nil || o.PlatformCaps == nil {
		return nil, false
	}
	return o.PlatformCaps, true
}

// HasPlatformCaps returns a boolean if a field has been set.
func (o *FederationResponseData) HasPlatformCaps() bool {
	if o != nil && o.PlatformCaps != nil {
		return true
	}

	return false
}

// SetPlatformCaps gets a reference to the given []string and assigns it to the PlatformCaps field.
func (o *FederationResponseData) SetPlatformCaps(v []string) {
	o.PlatformCaps = v
}

func (o FederationResponseData) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if true {
		toSerialize["partnerOPFederationId"] = o.PartnerOPFederationId
	}
	if true {
		toSerialize["partnerOPCountryCode"] = o.PartnerOPCountryCode
	}
	if true {
		toSerialize["federationContextId"] = o.FederationContextId
	}
	if true {
		toSerialize["edgeDiscoveryServiceEndPoint"] = o.EdgeDiscoveryServiceEndPoint
	}
	if true {
		toSerialize["lcmServiceEndPoint"] = o.LcmServiceEndPoint
	}
	if o.PartnerOPMobileNetworkCodes != nil {
		toSerialize["partnerOPMobileNetworkCodes"] = o.PartnerOPMobileNetworkCodes
	}
	if o.PartnerOPFixedNetworkCodes != nil {
		toSerialize["partnerOPFixedNetworkCodes"] = o.PartnerOPFixedNetworkCodes
	}
	if true {
		toSerialize["offeredAvailabilityZones"] = o.OfferedAvailabilityZones
	}
	if o.PlatformCaps != nil {
		toSerialize["platformCaps"] = o.PlatformCaps
	}
	return json.Marshal(toSerialize)
}

type NullableFederationResponseData struct {
	value *FederationResponseData
	isSet bool
}

func (v NullableFederationResponseData) Get() *FederationResponseData {
	return v.value
}

func (v *NullableFederationResponseData) Set(val *FederationResponseData) {
	v.value = val
	v.isSet = true
}

func (v NullableFederationResponseData) IsSet() bool {
	return v.isSet
}

func (v *NullableFederationResponseData) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableFederationResponseData(val *FederationResponseData) *NullableFederationResponseData {
	return &NullableFederationResponseData{value: val, isSet: true}
}

func (v NullableFederationResponseData) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableFederationResponseData) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


