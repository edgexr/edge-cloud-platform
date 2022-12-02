/*
Federation Management Service

# Introduction --- RESTful APIs that allow an OP to share the edge cloud resources and capabilities securely to other partner OPs over E/WBI.   --- # API Scope  --- APIs defined in this version of the specification can be categorized into the following areas: * __FederationManagement__ - Create and manage directed federation relationship with a partner OP * __AvailabilityZoneInfoSynchronization__ - Management of resources of partner OP zones and status updates  * __ArtifactManagement__ - Upload, remove, retrieve and update application descriptors, charts and packages over E/WBI towards a partner OP * __FileManagement__ - Upload, remove, retrieve and update  application binaries over E/WBI towards a partner OP * __ApplicationOnboardingManagement__ - Register, retrieve, update and remove applications over E/WBI towards a partner OP * __ApplicationDeploymentManagement__ - Create, update, retrieve and terminate application instances over E/WBI towards a partner OP * __AppProviderResourceManagement__ -  Static resource reservation for an application provider over E/WBI for partner OP zones * __EdgeNodeSharing__ - Edge discovery procedures towards partner OP over E/WBI. * __LBORoamingAuthentication__ -  Validation of user client authentication from home OP  --- # Definitions --- This section provides definitions of terminologies commonly referred to throughout the API descriptions.  * __Accepted Zones__  - List of partner OP zones, which the originating OP has confirmed to use for its edge applications * __Anchoring__ - Partner OP capability to serve application clients (still in their home location) from application instances running on partner zones.  * __Application Provider__ - An application developer, onboarding his/her edge application on a partner operator platform (MEC).         * __Artefact__ - Descriptor, charts or any other package associated with the application. * __Availability Zone__ - Zones that partner OP can offer to share with originating OP. * __Device__ - Refers to user equipment like mobile phone, tablet, IOT kit, AR/VR device etc. In context of MEC users use these devices to access edge applications * __Directed Federation__ - A Federation between two OP instances A and B, in which edge compute resources are shared by B to A, but not from A to B. * __Edge Application__ - Application designed to run on MEC edge cloud   * __Edge Discovery Service__ - Partner OP service responsible to select most optimal edge( within partner OP) for edge application instantiation. Edge discovery service is defined as HTTP based API endpoint identified by a well-defined FQDN or IP. * __E/WBI__ - East west bound interface. * __Federation__ - Relationship among member OPs who agrees to offer  services and capabilities to the application providers and end users of member OPs   * __FederationContextId__ - Partner OP defined string identifier representing a certain federation relationship. * __Federation Identifier__ - Identify an operator platform in federation context. * __FileId__ - An OP defined string identifier representing a certain application image uploaded by an application provider * __Flavour__ - A group of compute, network and storage resources that can be requested or granted as a single unit * __FlavourIdentifier__ - An OP defined string identifier representing a set of compute, storage  and networking resources * __Home OP__ - Used in federation context to identify the OP with which the application developers or user clients are registered. * __Home Routing__ - Partner OP capability to direct roaming user client traffic towards application instances running on home OP zones.  * __Instance__ - Application process running on an edge * __LCM Service__ -  Partner OP service responsible for life cycle management of edge applications. LCM service is defined as HTTP based API endpoint identified by a well-defined FQDN or IP. * __Offered Zones__ - Zones that partner OP offer to share  to the Originating OP based on the prior agreement and local configuration.    * __Onboarding__ - Submitting an application to MEC platform  * __OP__ - Operator platform. * __OperatorIdentfier__ - String identifier representing the owner of MEC platform. Owner could  be an enterprise, a TSP or some other organization * __Originating OP__ - The OP when initiating the federation creation request towards the partner OP is defined as the Originating OP * __Partner OP__ - Operator Platform which offers its Edge Cloud capabilities to the other Operator Platforms via E/WBI.      * __Resource__ - Compute, networking and storage resources. * __Resource Pool__ -  A group of  compute, networking and storage resources. Application provider  pre-reserve resources on partner OP zone, these resources are reserved in terms of flavours.  * __ZoneIdentifier__ - An OP defined string identifier representing a certain geographical or logical area where edge resources and services are provided * __Zone Confirmation__ - Procedure via which originating OP acknowledges partner OP about the partner zones it wishes to use. * __User Clients__ -  Lightweight client applications used to access edge applications. Application users run these clients on their devices (UE, IOT device, AR/VR device etc)    --- # API Operations ---    __FederationManagement__ * __CreateFederation__  Creates a directed federation relationship with a partner OP * __GetFederationDetails__  Retrieves details about the federation relationship with the partner OP. The response shall provide info about the zones offered by the partner, partner OP network codes, information about edge discovery and LCM service etc. * __DeleteFederationDetails__  Remove existing federation with the partner OP * __NotifyFederationUpdates__ Call back notification used by partner OP to update originating OP about any change in existing federation relationship. * __UpdateFederation__ API used by the Originating OP towards the partner OP, to update the parameters associated to the existing federation  __AvailabilityZoneInfoSynchronization__ * __ZoneSubscribe__  Informs partner OP that originating OP is willing to access the specified zones  and partner OP shall reserve compute and network resources for these zones. * __ZoneUnsubscribe__  Informs partner OP that originating OP will no longer access the specified partner OP zone. * __GetZoneData__  Retrieves details about the computation and network resources that partner OP has reserved for an partner OP  zone. * __Notify Zone Information__ Call back notification used by partner OP to update originating OP about changes in the resources reserved on a partner zone.  __ArtefactManagement__ * __UploadArtefact__  Uploads application artefact  on partner operator platform. * __RemoveArtefact__  Removes an artefact from partner operator platform. * __GetArtefact__  Retrieves details about an artefact from partner operator platform. * __UploadFile__ Upload application binaries to partner operator platform * __RemoveFile__  Removes application binaries from partner operator platform * __ViewFile__  Retrieves details about binaries assosiated with an application from partner operator platform  __ApplicationOnboardingManagement__ * __OnboardApplication__ - Submits an application details to a partner OP. Based on the details provided,  partner OP shall do bookkeeping, resource validation and other pre-deployment operations * __UpdateApplication__ - Updates partner OP about changes in  application compute resource requirements, QOS Profile, associated descriptor or change in assosiated components * __DeboardApplication__ - Removes an application from partner OP * __ViewApplication__ - Retrieves application details from partner OP * __OnboardExistingAppNewZones__ - Make an application available on new additional zones * __LockUnlockApplicationZone__ - Forbid or permit instantiation of application on a zone  __Application Instance Lifecycle Management__ * __InstallApp__ - Instantiates an application on a partner OP zone. * __GetAppInstanceDetails__ - Retrieves an application instance details from partner OP. * __RemoveApp__ - Terminate an application instance on a partner OP zone. * __GetAllAppInstances__ - Retrieves details about all instances of the application running on partner OP zones.   __AppProviderResourceManagement__ * __CreateResourcePools__  Reserves resources (compute, network and storage)  on a partner OP zone. ISVs registered with home OP reserves resurces on a partner OP zone. * __UpdateISVResPool__  Updates resources reserved for a pool by an ISV * __ViewISVResPool__  Retrieves the resource pool reserved by an ISV * __RemoveISVResPool__ Deletes the resource pool reserved by an ISV   __EdgeNodeSharing__ *__GetCandidateZones__ Edge discovery procedures towards partner OP over E/WBI. Originating OP request partner OP to provide a list of candidate zones where an application instance can be created.    __LBORoamingAuthentication__ *__AuthenticateDevice__ Validates the authenticity of a roaming user from home OP   © 2022 GSM Association. All rights reserved. 

API version: 1.0.0
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package fedewapi

import (
	"encoding/json"
	"time"
)

// checks if the FederationRequestData type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &FederationRequestData{}

// FederationRequestData struct for FederationRequestData
type FederationRequestData struct {
	// Globally unique Identifier allocated to an operator platform. This is valid and used only in context of  MEC federation interface.
	OrigOPFederationId string `json:"origOPFederationId"`
	// ISO 3166-1 Alpha-2 code for the country of Partner operator
	OrigOPCountryCode *string `json:"origOPCountryCode,omitempty"`
	OrigOPMobileNetworkCodes *MobileNetworkIds `json:"origOPMobileNetworkCodes,omitempty"`
	// List of network identifier associated with the fixed line network of the operator platform.
	OrigOPFixedNetworkCodes []string `json:"origOPFixedNetworkCodes,omitempty"`
	// Time zone info of the federation initiated by the originating OP
	InitialDate time.Time `json:"initialDate"`
	FederationNotificationDest string `json:"federationNotificationDest"`
}

// NewFederationRequestData instantiates a new FederationRequestData object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewFederationRequestData(origOPFederationId string, initialDate time.Time, federationNotificationDest string) *FederationRequestData {
	this := FederationRequestData{}
	this.OrigOPFederationId = origOPFederationId
	this.InitialDate = initialDate
	this.FederationNotificationDest = federationNotificationDest
	return &this
}

// NewFederationRequestDataWithDefaults instantiates a new FederationRequestData object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewFederationRequestDataWithDefaults() *FederationRequestData {
	this := FederationRequestData{}
	return &this
}

// GetOrigOPFederationId returns the OrigOPFederationId field value
func (o *FederationRequestData) GetOrigOPFederationId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.OrigOPFederationId
}

// GetOrigOPFederationIdOk returns a tuple with the OrigOPFederationId field value
// and a boolean to check if the value has been set.
func (o *FederationRequestData) GetOrigOPFederationIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.OrigOPFederationId, true
}

// SetOrigOPFederationId sets field value
func (o *FederationRequestData) SetOrigOPFederationId(v string) {
	o.OrigOPFederationId = v
}

// GetOrigOPCountryCode returns the OrigOPCountryCode field value if set, zero value otherwise.
func (o *FederationRequestData) GetOrigOPCountryCode() string {
	if o == nil || isNil(o.OrigOPCountryCode) {
		var ret string
		return ret
	}
	return *o.OrigOPCountryCode
}

// GetOrigOPCountryCodeOk returns a tuple with the OrigOPCountryCode field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FederationRequestData) GetOrigOPCountryCodeOk() (*string, bool) {
	if o == nil || isNil(o.OrigOPCountryCode) {
		return nil, false
	}
	return o.OrigOPCountryCode, true
}

// HasOrigOPCountryCode returns a boolean if a field has been set.
func (o *FederationRequestData) HasOrigOPCountryCode() bool {
	if o != nil && !isNil(o.OrigOPCountryCode) {
		return true
	}

	return false
}

// SetOrigOPCountryCode gets a reference to the given string and assigns it to the OrigOPCountryCode field.
func (o *FederationRequestData) SetOrigOPCountryCode(v string) {
	o.OrigOPCountryCode = &v
}

// GetOrigOPMobileNetworkCodes returns the OrigOPMobileNetworkCodes field value if set, zero value otherwise.
func (o *FederationRequestData) GetOrigOPMobileNetworkCodes() MobileNetworkIds {
	if o == nil || isNil(o.OrigOPMobileNetworkCodes) {
		var ret MobileNetworkIds
		return ret
	}
	return *o.OrigOPMobileNetworkCodes
}

// GetOrigOPMobileNetworkCodesOk returns a tuple with the OrigOPMobileNetworkCodes field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FederationRequestData) GetOrigOPMobileNetworkCodesOk() (*MobileNetworkIds, bool) {
	if o == nil || isNil(o.OrigOPMobileNetworkCodes) {
		return nil, false
	}
	return o.OrigOPMobileNetworkCodes, true
}

// HasOrigOPMobileNetworkCodes returns a boolean if a field has been set.
func (o *FederationRequestData) HasOrigOPMobileNetworkCodes() bool {
	if o != nil && !isNil(o.OrigOPMobileNetworkCodes) {
		return true
	}

	return false
}

// SetOrigOPMobileNetworkCodes gets a reference to the given MobileNetworkIds and assigns it to the OrigOPMobileNetworkCodes field.
func (o *FederationRequestData) SetOrigOPMobileNetworkCodes(v MobileNetworkIds) {
	o.OrigOPMobileNetworkCodes = &v
}

// GetOrigOPFixedNetworkCodes returns the OrigOPFixedNetworkCodes field value if set, zero value otherwise.
func (o *FederationRequestData) GetOrigOPFixedNetworkCodes() []string {
	if o == nil || isNil(o.OrigOPFixedNetworkCodes) {
		var ret []string
		return ret
	}
	return o.OrigOPFixedNetworkCodes
}

// GetOrigOPFixedNetworkCodesOk returns a tuple with the OrigOPFixedNetworkCodes field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FederationRequestData) GetOrigOPFixedNetworkCodesOk() ([]string, bool) {
	if o == nil || isNil(o.OrigOPFixedNetworkCodes) {
		return nil, false
	}
	return o.OrigOPFixedNetworkCodes, true
}

// HasOrigOPFixedNetworkCodes returns a boolean if a field has been set.
func (o *FederationRequestData) HasOrigOPFixedNetworkCodes() bool {
	if o != nil && !isNil(o.OrigOPFixedNetworkCodes) {
		return true
	}

	return false
}

// SetOrigOPFixedNetworkCodes gets a reference to the given []string and assigns it to the OrigOPFixedNetworkCodes field.
func (o *FederationRequestData) SetOrigOPFixedNetworkCodes(v []string) {
	o.OrigOPFixedNetworkCodes = v
}

// GetInitialDate returns the InitialDate field value
func (o *FederationRequestData) GetInitialDate() time.Time {
	if o == nil {
		var ret time.Time
		return ret
	}

	return o.InitialDate
}

// GetInitialDateOk returns a tuple with the InitialDate field value
// and a boolean to check if the value has been set.
func (o *FederationRequestData) GetInitialDateOk() (*time.Time, bool) {
	if o == nil {
		return nil, false
	}
	return &o.InitialDate, true
}

// SetInitialDate sets field value
func (o *FederationRequestData) SetInitialDate(v time.Time) {
	o.InitialDate = v
}

// GetFederationNotificationDest returns the FederationNotificationDest field value
func (o *FederationRequestData) GetFederationNotificationDest() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.FederationNotificationDest
}

// GetFederationNotificationDestOk returns a tuple with the FederationNotificationDest field value
// and a boolean to check if the value has been set.
func (o *FederationRequestData) GetFederationNotificationDestOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.FederationNotificationDest, true
}

// SetFederationNotificationDest sets field value
func (o *FederationRequestData) SetFederationNotificationDest(v string) {
	o.FederationNotificationDest = v
}

func (o FederationRequestData) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o FederationRequestData) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["origOPFederationId"] = o.OrigOPFederationId
	if !isNil(o.OrigOPCountryCode) {
		toSerialize["origOPCountryCode"] = o.OrigOPCountryCode
	}
	if !isNil(o.OrigOPMobileNetworkCodes) {
		toSerialize["origOPMobileNetworkCodes"] = o.OrigOPMobileNetworkCodes
	}
	if !isNil(o.OrigOPFixedNetworkCodes) {
		toSerialize["origOPFixedNetworkCodes"] = o.OrigOPFixedNetworkCodes
	}
	toSerialize["initialDate"] = o.InitialDate
	toSerialize["federationNotificationDest"] = o.FederationNotificationDest
	return toSerialize, nil
}

type NullableFederationRequestData struct {
	value *FederationRequestData
	isSet bool
}

func (v NullableFederationRequestData) Get() *FederationRequestData {
	return v.value
}

func (v *NullableFederationRequestData) Set(val *FederationRequestData) {
	v.value = val
	v.isSet = true
}

func (v NullableFederationRequestData) IsSet() bool {
	return v.isSet
}

func (v *NullableFederationRequestData) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableFederationRequestData(val *FederationRequestData) *NullableFederationRequestData {
	return &NullableFederationRequestData{value: val, isSet: true}
}

func (v NullableFederationRequestData) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableFederationRequestData) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


