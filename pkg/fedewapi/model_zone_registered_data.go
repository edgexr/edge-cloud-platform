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

// ZoneRegisteredData struct for ZoneRegisteredData
type ZoneRegisteredData struct {
	// Human readable name of the zone.
	ZoneId string `json:"zoneId"`
	// Resources exclusively reserved for the originator OP.
	ReservedComputeResources []ComputeResourceInfo `json:"reservedComputeResources,omitempty"`
	// Max quota on resources partner OP allows over reserved resources.
	ComputeResourceQuotaLimits []ComputeResourceInfo `json:"computeResourceQuotaLimits,omitempty"`
	FlavoursSupported []Flavour `json:"flavoursSupported"`
	NetworkResources *ZoneRegisteredDataNetworkResources `json:"networkResources,omitempty"`
}

// NewZoneRegisteredData instantiates a new ZoneRegisteredData object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewZoneRegisteredData(zoneId string, flavoursSupported []Flavour) *ZoneRegisteredData {
	this := ZoneRegisteredData{}
	this.ZoneId = zoneId
	this.FlavoursSupported = flavoursSupported
	return &this
}

// NewZoneRegisteredDataWithDefaults instantiates a new ZoneRegisteredData object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewZoneRegisteredDataWithDefaults() *ZoneRegisteredData {
	this := ZoneRegisteredData{}
	return &this
}

// GetZoneId returns the ZoneId field value
func (o *ZoneRegisteredData) GetZoneId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.ZoneId
}

// GetZoneIdOk returns a tuple with the ZoneId field value
// and a boolean to check if the value has been set.
func (o *ZoneRegisteredData) GetZoneIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.ZoneId, true
}

// SetZoneId sets field value
func (o *ZoneRegisteredData) SetZoneId(v string) {
	o.ZoneId = v
}

// GetReservedComputeResources returns the ReservedComputeResources field value if set, zero value otherwise.
func (o *ZoneRegisteredData) GetReservedComputeResources() []ComputeResourceInfo {
	if o == nil || o.ReservedComputeResources == nil {
		var ret []ComputeResourceInfo
		return ret
	}
	return o.ReservedComputeResources
}

// GetReservedComputeResourcesOk returns a tuple with the ReservedComputeResources field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ZoneRegisteredData) GetReservedComputeResourcesOk() ([]ComputeResourceInfo, bool) {
	if o == nil || o.ReservedComputeResources == nil {
		return nil, false
	}
	return o.ReservedComputeResources, true
}

// HasReservedComputeResources returns a boolean if a field has been set.
func (o *ZoneRegisteredData) HasReservedComputeResources() bool {
	if o != nil && o.ReservedComputeResources != nil {
		return true
	}

	return false
}

// SetReservedComputeResources gets a reference to the given []ComputeResourceInfo and assigns it to the ReservedComputeResources field.
func (o *ZoneRegisteredData) SetReservedComputeResources(v []ComputeResourceInfo) {
	o.ReservedComputeResources = v
}

// GetComputeResourceQuotaLimits returns the ComputeResourceQuotaLimits field value if set, zero value otherwise.
func (o *ZoneRegisteredData) GetComputeResourceQuotaLimits() []ComputeResourceInfo {
	if o == nil || o.ComputeResourceQuotaLimits == nil {
		var ret []ComputeResourceInfo
		return ret
	}
	return o.ComputeResourceQuotaLimits
}

// GetComputeResourceQuotaLimitsOk returns a tuple with the ComputeResourceQuotaLimits field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ZoneRegisteredData) GetComputeResourceQuotaLimitsOk() ([]ComputeResourceInfo, bool) {
	if o == nil || o.ComputeResourceQuotaLimits == nil {
		return nil, false
	}
	return o.ComputeResourceQuotaLimits, true
}

// HasComputeResourceQuotaLimits returns a boolean if a field has been set.
func (o *ZoneRegisteredData) HasComputeResourceQuotaLimits() bool {
	if o != nil && o.ComputeResourceQuotaLimits != nil {
		return true
	}

	return false
}

// SetComputeResourceQuotaLimits gets a reference to the given []ComputeResourceInfo and assigns it to the ComputeResourceQuotaLimits field.
func (o *ZoneRegisteredData) SetComputeResourceQuotaLimits(v []ComputeResourceInfo) {
	o.ComputeResourceQuotaLimits = v
}

// GetFlavoursSupported returns the FlavoursSupported field value
func (o *ZoneRegisteredData) GetFlavoursSupported() []Flavour {
	if o == nil {
		var ret []Flavour
		return ret
	}

	return o.FlavoursSupported
}

// GetFlavoursSupportedOk returns a tuple with the FlavoursSupported field value
// and a boolean to check if the value has been set.
func (o *ZoneRegisteredData) GetFlavoursSupportedOk() ([]Flavour, bool) {
	if o == nil {
		return nil, false
	}
	return o.FlavoursSupported, true
}

// SetFlavoursSupported sets field value
func (o *ZoneRegisteredData) SetFlavoursSupported(v []Flavour) {
	o.FlavoursSupported = v
}

// GetNetworkResources returns the NetworkResources field value if set, zero value otherwise.
func (o *ZoneRegisteredData) GetNetworkResources() ZoneRegisteredDataNetworkResources {
	if o == nil || o.NetworkResources == nil {
		var ret ZoneRegisteredDataNetworkResources
		return ret
	}
	return *o.NetworkResources
}

// GetNetworkResourcesOk returns a tuple with the NetworkResources field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ZoneRegisteredData) GetNetworkResourcesOk() (*ZoneRegisteredDataNetworkResources, bool) {
	if o == nil || o.NetworkResources == nil {
		return nil, false
	}
	return o.NetworkResources, true
}

// HasNetworkResources returns a boolean if a field has been set.
func (o *ZoneRegisteredData) HasNetworkResources() bool {
	if o != nil && o.NetworkResources != nil {
		return true
	}

	return false
}

// SetNetworkResources gets a reference to the given ZoneRegisteredDataNetworkResources and assigns it to the NetworkResources field.
func (o *ZoneRegisteredData) SetNetworkResources(v ZoneRegisteredDataNetworkResources) {
	o.NetworkResources = &v
}

func (o ZoneRegisteredData) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if true {
		toSerialize["zoneId"] = o.ZoneId
	}
	if o.ReservedComputeResources != nil {
		toSerialize["reservedComputeResources"] = o.ReservedComputeResources
	}
	if o.ComputeResourceQuotaLimits != nil {
		toSerialize["computeResourceQuotaLimits"] = o.ComputeResourceQuotaLimits
	}
	if true {
		toSerialize["flavoursSupported"] = o.FlavoursSupported
	}
	if o.NetworkResources != nil {
		toSerialize["networkResources"] = o.NetworkResources
	}
	return json.Marshal(toSerialize)
}

type NullableZoneRegisteredData struct {
	value *ZoneRegisteredData
	isSet bool
}

func (v NullableZoneRegisteredData) Get() *ZoneRegisteredData {
	return v.value
}

func (v *NullableZoneRegisteredData) Set(val *ZoneRegisteredData) {
	v.value = val
	v.isSet = true
}

func (v NullableZoneRegisteredData) IsSet() bool {
	return v.isSet
}

func (v *NullableZoneRegisteredData) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableZoneRegisteredData(val *ZoneRegisteredData) *NullableZoneRegisteredData {
	return &NullableZoneRegisteredData{value: val, isSet: true}
}

func (v NullableZoneRegisteredData) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableZoneRegisteredData) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


