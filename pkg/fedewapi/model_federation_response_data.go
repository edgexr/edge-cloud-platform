/*
Federation Management Service

# Introduction --- RESTful APIs that allow an OP to share the edge cloud resources and capabilities securely to other partner OPs over E/WBI.  --- # API Scope  --- APIs defined in this version of the specification can be categorized into the following areas: * __FederationManagement__ - Create and manage directed federation relationship with a partner OP * __AvailabilityZoneInfoSynchronization__ - Management of resources of partner OP zones and status updates * __ArtefactManagement__ - Upload, remove, retrieve and update application descriptors, charts and packages over E/WBI towards a partner OP * __FileManagement__ - Upload, remove, retrieve and update application binaries over E/WBI towards a partner OP * __ApplicationOnboardingManagement__ - Register, retrieve, update and remove applications over E/WBI towards a partner OP * __ApplicationDeploymentManagement__ - Create, update, retrieve and terminate application instances over E/WBI towards a partner OP * __AppProviderResourceManagement__ - Static resource reservation for an application provider over E/WBI for partner OP zones * __EdgeNodeSharing__ - Edge discovery procedures towards partner OP over E/WBI. * __LBORoamingAuthentication__ - Validation of user client authentication from home OP  --- # Definitions --- This section provides definitions of terminologies commonly referred to throughout the API descriptions.  * __Accepted Zones__ - List of partner OP zones, which the originating OP has confirmed to use for its edge applications * __Anchoring__ - Partner OP capability to serve application clients (still in their home location) from application instances running on partner zones. * __Application Provider__ - An application developer, onboarding his/her edge application on a partner operator platform (MEC). * __Artefact__ - Descriptor, charts or any other package associated with the application. * __Availability Zone__ - Zones that partner OP can offer to share with originating OP. * __Device__ - Refers to user equipment like mobile phone, tablet, IOT kit, AR/VR device etc. In context of MEC users use these devices to access edge applications * __Directed Federation__ - A Federation between two OP instances A and B, in which edge compute resources are shared by B to A, but not from A to B. * __Edge Application__ - Application designed to run on MEC edge cloud * __Edge Discovery Service__ - Partner OP service responsible to select most optimal edge( within partner OP) for edge application instantiation. Edge discovery service is defined as HTTP based API endpoint identified by a well-defined FQDN or IP. * __E/WBI__ - East west bound interface. * __Federation__ - Relationship among member OPs who agrees to offer services and capabilities to the application providers and end users of member OPs * __FederationContextId__ - Partner OP defined string identifier representing a certain federation relationship. * __Federation Identifier__ - Identify an operator platform in federation context. * __FileId__ - An OP defined string identifier representing a certain application image uploaded by an application provider * __Flavour__ - A group of compute, network and storage resources that can be requested or granted as a single unit * __FlavourIdentifier__ - An OP defined string identifier representing a set of compute, storage and networking resources * __Home OP__ - Used in federation context to identify the OP with which the application developers or user clients are registered. * __Home Routing__ - Partner OP capability to direct roaming user client traffic towards application instances running on home OP zones. * __Instance__ - Application process running on an edge * __LCM Service__ - Partner OP service responsible for life cycle management of edge applications. LCM service is defined as HTTP based API endpoint identified by a well-defined FQDN or IP. * __Offered Zones__ - Zones that partner OP offer to share to the Originating OP based on the prior agreement and local configuration. * __Onboarding__ - Submitting an application to MEC platform * __OP__ - Operator platform. * __OperatorIdentifier__ - String identifier representing the owner of MEC platform. Owner could be an enterprise, a TSP or some other organization * __Originating OP__ - The OP when initiating the federation creation request towards the partner OP is defined as the Originating OP * __Partner OP__ - Operator Platform which offers its Edge Cloud capabilities to the other Operator Platforms via E/WBI. * __Resource__ - Compute, networking and storage resources. * __Resource Pool__ - A group of compute, networking and storage resources. Application provider pre-reserve resources on partner OP zone, these resources are reserved in terms of flavours. * __ZoneIdentifier__ - An OP defined string identifier representing a certain geographical or logical area where edge resources and services are provided * __Zone Confirmation__ - Procedure via which originating OP acknowledges partner OP about the partner zones it wishes to use. * __User Clients__ - Lightweight client applications used to access edge applications. Application users run these clients on their devices (UE, IOT device, AR/VR device etc)   --- # API Operations ---  __FederationManagement__ * __CreateFederation__ - Creates a directed federation relationship with a partner OP * __GetFederationDetails__ - Retrieves details about the federation relationship with the partner OP. The response shall provide info about the zones offered by the partner, partner OP network codes, information about edge discovery and LCM service etc. * __DeleteFederationDetails__ - Remove existing federation with the partner OP * __NotifyFederationUpdates__ - Call back notification used by partner OP to update originating OP about any change in existing federation relationship. * __UpdateFederation__ - API used by the Originating OP towards the partner OP, to update the parameters associated to the existing federation  __AvailabilityZoneInfoSynchronization__ * __ZoneSubscribe__ - Informs partner OP that originating OP is willing to access the specified zones and partner OP shall reserve compute and network resources for these zones. * __ZoneUnsubscribe__ - Informs partner OP that originating OP will no longer access the specified partner OP zone. * __GetZoneData__ - Retrieves details about the computation and network resources that partner OP has reserved for an partner OP zone. * __Notify Zone Information__ - Call back notification used by partner OP to update originating OP about changes in the resources reserved on a partner zone.  __ArtefactManagement__ * __UploadArtefact__ - Uploads application artefact on partner operator platform. * __RemoveArtefact__ - Removes an artefact from partner operator platform. * __GetArtefact__ - Retrieves details about an artefact from partner operator platform. * __UploadFile__ Upload application binaries to partner operator platform * __RemoveFile__ - Removes application binaries from partner operator platform * __ViewFile__ - Retrieves details about binaries associated with an application from partner operator platform  __ApplicationOnboardingManagement__ * __OnboardApplication__ - Submits an application details to a partner OP. Based on the details provided,  partner OP shall do bookkeeping, resource validation and other pre-deployment operations * __UpdateApplication__ - Updates partner OP about changes in application compute resource requirements, QOS Profile, associated descriptor or change in associated components * __DeboardApplication__ - Removes an application from partner OP * __ViewApplication__ - Retrieves application details from partner OP * __OnboardExistingAppNewZones__ - Make an application available on new additional zones * __LockUnlockApplicationZone__ - Forbid or permit instantiation of application on a zone  __Application Instance Lifecycle Management__ * __InstallApp__ - Instantiates an application on a partner OP zone. * __GetAppInstanceDetails__ - Retrieves an application instance details from partner OP. * __RemoveApp__ - Terminate an application instance on a partner OP zone. * __GetAllAppInstances__ - Retrieves details about all instances of the application running on partner OP zones.   __AppProviderResourceManagement__ * __CreateResourcePools__ - Reserves resources (compute, network and storage)  on a partner OP zone. ISVs registered with home OP reserves resources on a partner OP zone. * __UpdateISVResPool__ - Updates resources reserved for a pool by an ISV * __ViewISVResPool__ - Retrieves the resource pool reserved by an ISV * __RemoveISVResPool__ - Deletes the resource pool reserved by an ISV   __EdgeNodeSharing__ *__GetCandidateZones__ - Edge discovery procedures towards partner OP over E/WBI. Originating OP request partner OP to provide a list of candidate zones where an application instance can be created.   __LBORoamingAuthentication__ *__AuthenticateDevice__ - Validates the authenticity of a roaming user from home OP   © 2022 GSM Association. All rights reserved.

API version: 1.0.0
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package fedewapi

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

// checks if the FederationResponseData type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &FederationResponseData{}

// FederationResponseData struct for FederationResponseData
type FederationResponseData struct {
	// Globally unique identifier allocated to an operator platform. This is valid and used only in context of MEC federation interface.
	PartnerOPFederationId string `json:"partnerOPFederationId"`
	// ISO 3166-1 Alpha-2 code for the country of Partner operator
	PartnerOPCountryCode *string `json:"partnerOPCountryCode,omitempty"`
	// This identifier shall be provided by the partner OP on successful verification and validation of the federation create request and is used by partner op to identify this newly created federation context. Originating OP shall provide this identifier in any subsequent request towards the partner op.
	FederationContextId          string            `json:"federationContextId"`
	EdgeDiscoveryServiceEndPoint *ServiceEndpoint  `json:"edgeDiscoveryServiceEndPoint,omitempty"`
	LcmServiceEndPoint           *ServiceEndpoint  `json:"lcmServiceEndPoint,omitempty"`
	PartnerOPMobileNetworkCodes  *MobileNetworkIds `json:"partnerOPMobileNetworkCodes,omitempty"`
	// List of network identifier associated with the fixed line network of the operator platform.
	PartnerOPFixedNetworkCodes []string `json:"partnerOPFixedNetworkCodes,omitempty"`
	// List of zones, which the operator platform wishes to make available to developers/ISVs of requesting operator platform.
	OfferedAvailabilityZones []ZoneDetails `json:"offeredAvailabilityZones,omitempty"`
	PlatformCaps             []string      `json:"platformCaps"`
}

var FederationResponseDataPartnerOPFederationIdPattern = strings.TrimPrefix(strings.TrimSuffix("/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/", "/"), "/")
var FederationResponseDataPartnerOPFederationIdRE = regexp.MustCompile(FederationResponseDataPartnerOPFederationIdPattern)
var FederationResponseDataPartnerOPCountryCodePattern = strings.TrimPrefix(strings.TrimSuffix("/^[A-Z]{2}$/", "/"), "/")
var FederationResponseDataPartnerOPCountryCodeRE = regexp.MustCompile(FederationResponseDataPartnerOPCountryCodePattern)
var FederationResponseDataFederationContextIdPattern = strings.TrimPrefix(strings.TrimSuffix("/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/", "/"), "/")
var FederationResponseDataFederationContextIdRE = regexp.MustCompile(FederationResponseDataFederationContextIdPattern)

func (s *FederationResponseData) Validate() error {
	if s.PartnerOPFederationId == "" {
		return errors.New("partnerOPFederationId is required")
	}
	if !FederationResponseDataPartnerOPFederationIdRE.MatchString(s.PartnerOPFederationId) {
		return errors.New("partnerOPFederationId " + s.PartnerOPFederationId + " does not match format " + FederationResponseDataPartnerOPFederationIdPattern)
	}
	if s.PartnerOPCountryCode != nil && !FederationResponseDataPartnerOPCountryCodeRE.MatchString(*s.PartnerOPCountryCode) {
		return errors.New("partnerOPCountryCode " + *s.PartnerOPCountryCode + " does not match format " + FederationResponseDataPartnerOPCountryCodePattern)
	}
	if s.FederationContextId == "" {
		return errors.New("federationContextId is required")
	}
	if !FederationResponseDataFederationContextIdRE.MatchString(s.FederationContextId) {
		return errors.New("federationContextId " + s.FederationContextId + " does not match format " + FederationResponseDataFederationContextIdPattern)
	}
	if s.EdgeDiscoveryServiceEndPoint != nil {
		if err := s.EdgeDiscoveryServiceEndPoint.Validate(); err != nil {
			return err
		}
	}
	if s.LcmServiceEndPoint != nil {
		if err := s.LcmServiceEndPoint.Validate(); err != nil {
			return err
		}
	}
	if s.PartnerOPMobileNetworkCodes != nil {
		if err := s.PartnerOPMobileNetworkCodes.Validate(); err != nil {
			return err
		}
	}
	for ii := range s.OfferedAvailabilityZones {
		if err := s.OfferedAvailabilityZones[ii].Validate(); err != nil {
			return err
		}
	}
	return nil
}

// NewFederationResponseData instantiates a new FederationResponseData object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewFederationResponseData(partnerOPFederationId string, federationContextId string, platformCaps []string) *FederationResponseData {
	this := FederationResponseData{}
	this.PartnerOPFederationId = partnerOPFederationId
	this.FederationContextId = federationContextId
	this.PlatformCaps = platformCaps
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

// GetPartnerOPCountryCode returns the PartnerOPCountryCode field value if set, zero value otherwise.
func (o *FederationResponseData) GetPartnerOPCountryCode() string {
	if o == nil || isNil(o.PartnerOPCountryCode) {
		var ret string
		return ret
	}
	return *o.PartnerOPCountryCode
}

// GetPartnerOPCountryCodeOk returns a tuple with the PartnerOPCountryCode field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FederationResponseData) GetPartnerOPCountryCodeOk() (*string, bool) {
	if o == nil || isNil(o.PartnerOPCountryCode) {
		return nil, false
	}
	return o.PartnerOPCountryCode, true
}

// HasPartnerOPCountryCode returns a boolean if a field has been set.
func (o *FederationResponseData) HasPartnerOPCountryCode() bool {
	if o != nil && !isNil(o.PartnerOPCountryCode) {
		return true
	}

	return false
}

// SetPartnerOPCountryCode gets a reference to the given string and assigns it to the PartnerOPCountryCode field.
func (o *FederationResponseData) SetPartnerOPCountryCode(v string) {
	o.PartnerOPCountryCode = &v
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

// GetEdgeDiscoveryServiceEndPoint returns the EdgeDiscoveryServiceEndPoint field value if set, zero value otherwise.
func (o *FederationResponseData) GetEdgeDiscoveryServiceEndPoint() ServiceEndpoint {
	if o == nil || isNil(o.EdgeDiscoveryServiceEndPoint) {
		var ret ServiceEndpoint
		return ret
	}
	return *o.EdgeDiscoveryServiceEndPoint
}

// GetEdgeDiscoveryServiceEndPointOk returns a tuple with the EdgeDiscoveryServiceEndPoint field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FederationResponseData) GetEdgeDiscoveryServiceEndPointOk() (*ServiceEndpoint, bool) {
	if o == nil || isNil(o.EdgeDiscoveryServiceEndPoint) {
		return nil, false
	}
	return o.EdgeDiscoveryServiceEndPoint, true
}

// HasEdgeDiscoveryServiceEndPoint returns a boolean if a field has been set.
func (o *FederationResponseData) HasEdgeDiscoveryServiceEndPoint() bool {
	if o != nil && !isNil(o.EdgeDiscoveryServiceEndPoint) {
		return true
	}

	return false
}

// SetEdgeDiscoveryServiceEndPoint gets a reference to the given ServiceEndpoint and assigns it to the EdgeDiscoveryServiceEndPoint field.
func (o *FederationResponseData) SetEdgeDiscoveryServiceEndPoint(v ServiceEndpoint) {
	o.EdgeDiscoveryServiceEndPoint = &v
}

// GetLcmServiceEndPoint returns the LcmServiceEndPoint field value if set, zero value otherwise.
func (o *FederationResponseData) GetLcmServiceEndPoint() ServiceEndpoint {
	if o == nil || isNil(o.LcmServiceEndPoint) {
		var ret ServiceEndpoint
		return ret
	}
	return *o.LcmServiceEndPoint
}

// GetLcmServiceEndPointOk returns a tuple with the LcmServiceEndPoint field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FederationResponseData) GetLcmServiceEndPointOk() (*ServiceEndpoint, bool) {
	if o == nil || isNil(o.LcmServiceEndPoint) {
		return nil, false
	}
	return o.LcmServiceEndPoint, true
}

// HasLcmServiceEndPoint returns a boolean if a field has been set.
func (o *FederationResponseData) HasLcmServiceEndPoint() bool {
	if o != nil && !isNil(o.LcmServiceEndPoint) {
		return true
	}

	return false
}

// SetLcmServiceEndPoint gets a reference to the given ServiceEndpoint and assigns it to the LcmServiceEndPoint field.
func (o *FederationResponseData) SetLcmServiceEndPoint(v ServiceEndpoint) {
	o.LcmServiceEndPoint = &v
}

// GetPartnerOPMobileNetworkCodes returns the PartnerOPMobileNetworkCodes field value if set, zero value otherwise.
func (o *FederationResponseData) GetPartnerOPMobileNetworkCodes() MobileNetworkIds {
	if o == nil || isNil(o.PartnerOPMobileNetworkCodes) {
		var ret MobileNetworkIds
		return ret
	}
	return *o.PartnerOPMobileNetworkCodes
}

// GetPartnerOPMobileNetworkCodesOk returns a tuple with the PartnerOPMobileNetworkCodes field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FederationResponseData) GetPartnerOPMobileNetworkCodesOk() (*MobileNetworkIds, bool) {
	if o == nil || isNil(o.PartnerOPMobileNetworkCodes) {
		return nil, false
	}
	return o.PartnerOPMobileNetworkCodes, true
}

// HasPartnerOPMobileNetworkCodes returns a boolean if a field has been set.
func (o *FederationResponseData) HasPartnerOPMobileNetworkCodes() bool {
	if o != nil && !isNil(o.PartnerOPMobileNetworkCodes) {
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
	if o == nil || isNil(o.PartnerOPFixedNetworkCodes) {
		var ret []string
		return ret
	}
	return o.PartnerOPFixedNetworkCodes
}

// GetPartnerOPFixedNetworkCodesOk returns a tuple with the PartnerOPFixedNetworkCodes field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FederationResponseData) GetPartnerOPFixedNetworkCodesOk() ([]string, bool) {
	if o == nil || isNil(o.PartnerOPFixedNetworkCodes) {
		return nil, false
	}
	return o.PartnerOPFixedNetworkCodes, true
}

// HasPartnerOPFixedNetworkCodes returns a boolean if a field has been set.
func (o *FederationResponseData) HasPartnerOPFixedNetworkCodes() bool {
	if o != nil && !isNil(o.PartnerOPFixedNetworkCodes) {
		return true
	}

	return false
}

// SetPartnerOPFixedNetworkCodes gets a reference to the given []string and assigns it to the PartnerOPFixedNetworkCodes field.
func (o *FederationResponseData) SetPartnerOPFixedNetworkCodes(v []string) {
	o.PartnerOPFixedNetworkCodes = v
}

// GetOfferedAvailabilityZones returns the OfferedAvailabilityZones field value if set, zero value otherwise.
func (o *FederationResponseData) GetOfferedAvailabilityZones() []ZoneDetails {
	if o == nil || isNil(o.OfferedAvailabilityZones) {
		var ret []ZoneDetails
		return ret
	}
	return o.OfferedAvailabilityZones
}

// GetOfferedAvailabilityZonesOk returns a tuple with the OfferedAvailabilityZones field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *FederationResponseData) GetOfferedAvailabilityZonesOk() ([]ZoneDetails, bool) {
	if o == nil || isNil(o.OfferedAvailabilityZones) {
		return nil, false
	}
	return o.OfferedAvailabilityZones, true
}

// HasOfferedAvailabilityZones returns a boolean if a field has been set.
func (o *FederationResponseData) HasOfferedAvailabilityZones() bool {
	if o != nil && !isNil(o.OfferedAvailabilityZones) {
		return true
	}

	return false
}

// SetOfferedAvailabilityZones gets a reference to the given []ZoneDetails and assigns it to the OfferedAvailabilityZones field.
func (o *FederationResponseData) SetOfferedAvailabilityZones(v []ZoneDetails) {
	o.OfferedAvailabilityZones = v
}

// GetPlatformCaps returns the PlatformCaps field value
func (o *FederationResponseData) GetPlatformCaps() []string {
	if o == nil {
		var ret []string
		return ret
	}

	return o.PlatformCaps
}

// GetPlatformCapsOk returns a tuple with the PlatformCaps field value
// and a boolean to check if the value has been set.
func (o *FederationResponseData) GetPlatformCapsOk() ([]string, bool) {
	if o == nil {
		return nil, false
	}
	return o.PlatformCaps, true
}

// SetPlatformCaps sets field value
func (o *FederationResponseData) SetPlatformCaps(v []string) {
	o.PlatformCaps = v
}

func (o FederationResponseData) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o FederationResponseData) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["partnerOPFederationId"] = o.PartnerOPFederationId
	if !isNil(o.PartnerOPCountryCode) {
		toSerialize["partnerOPCountryCode"] = o.PartnerOPCountryCode
	}
	toSerialize["federationContextId"] = o.FederationContextId
	if !isNil(o.EdgeDiscoveryServiceEndPoint) {
		toSerialize["edgeDiscoveryServiceEndPoint"] = o.EdgeDiscoveryServiceEndPoint
	}
	if !isNil(o.LcmServiceEndPoint) {
		toSerialize["lcmServiceEndPoint"] = o.LcmServiceEndPoint
	}
	if !isNil(o.PartnerOPMobileNetworkCodes) {
		toSerialize["partnerOPMobileNetworkCodes"] = o.PartnerOPMobileNetworkCodes
	}
	if !isNil(o.PartnerOPFixedNetworkCodes) {
		toSerialize["partnerOPFixedNetworkCodes"] = o.PartnerOPFixedNetworkCodes
	}
	if !isNil(o.OfferedAvailabilityZones) {
		toSerialize["offeredAvailabilityZones"] = o.OfferedAvailabilityZones
	}
	toSerialize["platformCaps"] = o.PlatformCaps
	return toSerialize, nil
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
