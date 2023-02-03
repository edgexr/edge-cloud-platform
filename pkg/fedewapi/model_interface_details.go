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

// checks if the InterfaceDetails type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &InterfaceDetails{}

// InterfaceDetails struct for InterfaceDetails
type InterfaceDetails struct {
	// Each Port and corresponding traffic protocol exposed by the component is identified by a name. Application client on user device requires this to uniquely identify the interface.
	InterfaceId string `json:"interfaceId"`
	// Defines the IP transport communication protocol i.e., TCP, UDP or HTTP
	CommProtocol string `json:"commProtocol"`
	// Port number exposed by the component. OP may generate a dynamic port towards the UCs corresponding to this internal port and forward the client traffic from dynamic port to container Port.
	CommPort int32 `json:"commPort"`
	// Defines whether the interface is exposed to outer world or not i.e., external, or internal. If this is set to \"external\", then it is exposed to external applications otherwise it is exposed internally to edge application components within edge cloud. When exposed to external world, an external dynamic port is assigned for UC traffic and mapped to the internal container Port
	VisibilityType string `json:"visibilityType"`
	// Name of the network. In case the application has to be associated with more than 1 network then app provider must define the name of the network on which this interface has to be exposed. This parameter is required only if the port has to be exposed on a specific network other than default.
	Network *string `json:"network,omitempty"`
	// Interface Name. Required only if application has to be attached to a network other than default.
	InterfaceName *string `json:"InterfaceName,omitempty"`
}

var InterfaceDetailsInterfaceIdPattern = strings.TrimPrefix(strings.TrimSuffix("/^[a-z0-9]([-a-z0-9]{0,62}[a-z0-9])?$/", "/"), "/")
var InterfaceDetailsInterfaceIdRE = regexp.MustCompile(InterfaceDetailsInterfaceIdPattern)
var InterfaceDetailsNetworkPattern = strings.TrimPrefix(strings.TrimSuffix("/^[a-z0-9]([-a-z0-9]{0,62}[a-z0-9])?$/", "/"), "/")
var InterfaceDetailsNetworkRE = regexp.MustCompile(InterfaceDetailsNetworkPattern)
var InterfaceDetailsInterfaceNamePattern = strings.TrimPrefix(strings.TrimSuffix("/^[a-z][a-z0-9_-]{0,32}$/", "/"), "/")
var InterfaceDetailsInterfaceNameRE = regexp.MustCompile(InterfaceDetailsInterfaceNamePattern)

func (s *InterfaceDetails) Validate() error {
	if s.InterfaceId == "" {
		return errors.New("interfaceId is required")
	}
	if !InterfaceDetailsInterfaceIdRE.MatchString(s.InterfaceId) {
		return errors.New("interfaceId " + s.InterfaceId + " does not match format " + InterfaceDetailsInterfaceIdPattern)
	}
	if s.CommProtocol == "" {
		return errors.New("commProtocol is required")
	}
	if s.VisibilityType == "" {
		return errors.New("visibilityType is required")
	}
	if s.Network != nil && !InterfaceDetailsNetworkRE.MatchString(*s.Network) {
		return errors.New("network " + *s.Network + " does not match format " + InterfaceDetailsNetworkPattern)
	}
	if s.InterfaceName != nil && !InterfaceDetailsInterfaceNameRE.MatchString(*s.InterfaceName) {
		return errors.New("InterfaceName " + *s.InterfaceName + " does not match format " + InterfaceDetailsInterfaceNamePattern)
	}
	return nil
}

// NewInterfaceDetails instantiates a new InterfaceDetails object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewInterfaceDetails(interfaceId string, commProtocol string, commPort int32, visibilityType string) *InterfaceDetails {
	this := InterfaceDetails{}
	this.InterfaceId = interfaceId
	this.CommProtocol = commProtocol
	this.CommPort = commPort
	this.VisibilityType = visibilityType
	return &this
}

// NewInterfaceDetailsWithDefaults instantiates a new InterfaceDetails object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewInterfaceDetailsWithDefaults() *InterfaceDetails {
	this := InterfaceDetails{}
	return &this
}

// GetInterfaceId returns the InterfaceId field value
func (o *InterfaceDetails) GetInterfaceId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.InterfaceId
}

// GetInterfaceIdOk returns a tuple with the InterfaceId field value
// and a boolean to check if the value has been set.
func (o *InterfaceDetails) GetInterfaceIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.InterfaceId, true
}

// SetInterfaceId sets field value
func (o *InterfaceDetails) SetInterfaceId(v string) {
	o.InterfaceId = v
}

// GetCommProtocol returns the CommProtocol field value
func (o *InterfaceDetails) GetCommProtocol() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.CommProtocol
}

// GetCommProtocolOk returns a tuple with the CommProtocol field value
// and a boolean to check if the value has been set.
func (o *InterfaceDetails) GetCommProtocolOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.CommProtocol, true
}

// SetCommProtocol sets field value
func (o *InterfaceDetails) SetCommProtocol(v string) {
	o.CommProtocol = v
}

// GetCommPort returns the CommPort field value
func (o *InterfaceDetails) GetCommPort() int32 {
	if o == nil {
		var ret int32
		return ret
	}

	return o.CommPort
}

// GetCommPortOk returns a tuple with the CommPort field value
// and a boolean to check if the value has been set.
func (o *InterfaceDetails) GetCommPortOk() (*int32, bool) {
	if o == nil {
		return nil, false
	}
	return &o.CommPort, true
}

// SetCommPort sets field value
func (o *InterfaceDetails) SetCommPort(v int32) {
	o.CommPort = v
}

// GetVisibilityType returns the VisibilityType field value
func (o *InterfaceDetails) GetVisibilityType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.VisibilityType
}

// GetVisibilityTypeOk returns a tuple with the VisibilityType field value
// and a boolean to check if the value has been set.
func (o *InterfaceDetails) GetVisibilityTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.VisibilityType, true
}

// SetVisibilityType sets field value
func (o *InterfaceDetails) SetVisibilityType(v string) {
	o.VisibilityType = v
}

// GetNetwork returns the Network field value if set, zero value otherwise.
func (o *InterfaceDetails) GetNetwork() string {
	if o == nil || isNil(o.Network) {
		var ret string
		return ret
	}
	return *o.Network
}

// GetNetworkOk returns a tuple with the Network field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *InterfaceDetails) GetNetworkOk() (*string, bool) {
	if o == nil || isNil(o.Network) {
		return nil, false
	}
	return o.Network, true
}

// HasNetwork returns a boolean if a field has been set.
func (o *InterfaceDetails) HasNetwork() bool {
	if o != nil && !isNil(o.Network) {
		return true
	}

	return false
}

// SetNetwork gets a reference to the given string and assigns it to the Network field.
func (o *InterfaceDetails) SetNetwork(v string) {
	o.Network = &v
}

// GetInterfaceName returns the InterfaceName field value if set, zero value otherwise.
func (o *InterfaceDetails) GetInterfaceName() string {
	if o == nil || isNil(o.InterfaceName) {
		var ret string
		return ret
	}
	return *o.InterfaceName
}

// GetInterfaceNameOk returns a tuple with the InterfaceName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *InterfaceDetails) GetInterfaceNameOk() (*string, bool) {
	if o == nil || isNil(o.InterfaceName) {
		return nil, false
	}
	return o.InterfaceName, true
}

// HasInterfaceName returns a boolean if a field has been set.
func (o *InterfaceDetails) HasInterfaceName() bool {
	if o != nil && !isNil(o.InterfaceName) {
		return true
	}

	return false
}

// SetInterfaceName gets a reference to the given string and assigns it to the InterfaceName field.
func (o *InterfaceDetails) SetInterfaceName(v string) {
	o.InterfaceName = &v
}

func (o InterfaceDetails) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o InterfaceDetails) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["interfaceId"] = o.InterfaceId
	toSerialize["commProtocol"] = o.CommProtocol
	toSerialize["commPort"] = o.CommPort
	toSerialize["visibilityType"] = o.VisibilityType
	if !isNil(o.Network) {
		toSerialize["network"] = o.Network
	}
	if !isNil(o.InterfaceName) {
		toSerialize["InterfaceName"] = o.InterfaceName
	}
	return toSerialize, nil
}

type NullableInterfaceDetails struct {
	value *InterfaceDetails
	isSet bool
}

func (v NullableInterfaceDetails) Get() *InterfaceDetails {
	return v.value
}

func (v *NullableInterfaceDetails) Set(val *InterfaceDetails) {
	v.value = val
	v.isSet = true
}

func (v NullableInterfaceDetails) IsSet() bool {
	return v.isSet
}

func (v *NullableInterfaceDetails) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableInterfaceDetails(val *InterfaceDetails) *NullableInterfaceDetails {
	return &NullableInterfaceDetails{value: val, isSet: true}
}

func (v NullableInterfaceDetails) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableInterfaceDetails) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
