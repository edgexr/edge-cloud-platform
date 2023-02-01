/*
Federation Management Service

# Introduction --- RESTful APIs that allow an OP to share the edge cloud resources and capabilities securely to other partner OPs over E/WBI.  --- # API Scope  --- APIs defined in this version of the specification can be categorized into the following areas: * __FederationManagement__ - Create and manage directed federation relationship with a partner OP * __AvailabilityZoneInfoSynchronization__ - Management of resources of partner OP zones and status updates * __ArtefactManagement__ - Upload, remove, retrieve and update application descriptors, charts and packages over E/WBI towards a partner OP * __FileManagement__ - Upload, remove, retrieve and update application binaries over E/WBI towards a partner OP * __ApplicationOnboardingManagement__ - Register, retrieve, update and remove applications over E/WBI towards a partner OP * __ApplicationDeploymentManagement__ - Create, update, retrieve and terminate application instances over E/WBI towards a partner OP * __AppProviderResourceManagement__ - Static resource reservation for an application provider over E/WBI for partner OP zones * __EdgeNodeSharing__ - Edge discovery procedures towards partner OP over E/WBI. * __LBORoamingAuthentication__ - Validation of user client authentication from home OP  --- # Definitions --- This section provides definitions of terminologies commonly referred to throughout the API descriptions.  * __Accepted Zones__ - List of partner OP zones, which the originating OP has confirmed to use for its edge applications * __Anchoring__ - Partner OP capability to serve application clients (still in their home location) from application instances running on partner zones. * __Application Provider__ - An application developer, onboarding his/her edge application on a partner operator platform (MEC). * __Artefact__ - Descriptor, charts or any other package associated with the application. * __Availability Zone__ - Zones that partner OP can offer to share with originating OP. * __Device__ - Refers to user equipment like mobile phone, tablet, IOT kit, AR/VR device etc. In context of MEC users use these devices to access edge applications * __Directed Federation__ - A Federation between two OP instances A and B, in which edge compute resources are shared by B to A, but not from A to B. * __Edge Application__ - Application designed to run on MEC edge cloud * __Edge Discovery Service__ - Partner OP service responsible to select most optimal edge( within partner OP) for edge application instantiation. Edge discovery service is defined as HTTP based API endpoint identified by a well-defined FQDN or IP. * __E/WBI__ - East west bound interface. * __Federation__ - Relationship among member OPs who agrees to offer services and capabilities to the application providers and end users of member OPs * __FederationContextId__ - Partner OP defined string identifier representing a certain federation relationship. * __Federation Identifier__ - Identify an operator platform in federation context. * __FileId__ - An OP defined string identifier representing a certain application image uploaded by an application provider * __Flavour__ - A group of compute, network and storage resources that can be requested or granted as a single unit * __FlavourIdentifier__ - An OP defined string identifier representing a set of compute, storage and networking resources * __Home OP__ - Used in federation context to identify the OP with which the application developers or user clients are registered. * __Home Routing__ - Partner OP capability to direct roaming user client traffic towards application instances running on home OP zones. * __Instance__ - Application process running on an edge * __LCM Service__ - Partner OP service responsible for life cycle management of edge applications. LCM service is defined as HTTP based API endpoint identified by a well-defined FQDN or IP. * __Offered Zones__ - Zones that partner OP offer to share to the Originating OP based on the prior agreement and local configuration. * __Onboarding__ - Submitting an application to MEC platform * __OP__ - Operator platform. * __OperatorIdentifier__ - String identifier representing the owner of MEC platform. Owner could be an enterprise, a TSP or some other organization * __Originating OP__ - The OP when initiating the federation creation request towards the partner OP is defined as the Originating OP * __Partner OP__ - Operator Platform which offers its Edge Cloud capabilities to the other Operator Platforms via E/WBI. * __Resource__ - Compute, networking and storage resources. * __Resource Pool__ - A group of compute, networking and storage resources. Application provider pre-reserve resources on partner OP zone, these resources are reserved in terms of flavours. * __ZoneIdentifier__ - An OP defined string identifier representing a certain geographical or logical area where edge resources and services are provided * __Zone Confirmation__ - Procedure via which originating OP acknowledges partner OP about the partner zones it wishes to use. * __User Clients__ - Lightweight client applications used to access edge applications. Application users run these clients on their devices (UE, IOT device, AR/VR device etc)   --- # API Operations ---  __FederationManagement__ * __CreateFederation__ - Creates a directed federation relationship with a partner OP * __GetFederationDetails__ - Retrieves details about the federation relationship with the partner OP. The response shall provide info about the zones offered by the partner, partner OP network codes, information about edge discovery and LCM service etc. * __DeleteFederationDetails__ - Remove existing federation with the partner OP * __NotifyFederationUpdates__ - Call back notification used by partner OP to update originating OP about any change in existing federation relationship. * __UpdateFederation__ - API used by the Originating OP towards the partner OP, to update the parameters associated to the existing federation  __AvailabilityZoneInfoSynchronization__ * __ZoneSubscribe__ - Informs partner OP that originating OP is willing to access the specified zones and partner OP shall reserve compute and network resources for these zones. * __ZoneUnsubscribe__ - Informs partner OP that originating OP will no longer access the specified partner OP zone. * __GetZoneData__ - Retrieves details about the computation and network resources that partner OP has reserved for an partner OP zone. * __Notify Zone Information__ - Call back notification used by partner OP to update originating OP about changes in the resources reserved on a partner zone.  __ArtefactManagement__ * __UploadArtefact__ - Uploads application artefact on partner operator platform. * __RemoveArtefact__ - Removes an artefact from partner operator platform. * __GetArtefact__ - Retrieves details about an artefact from partner operator platform. * __UploadFile__ Upload application binaries to partner operator platform * __RemoveFile__ - Removes application binaries from partner operator platform * __ViewFile__ - Retrieves details about binaries associated with an application from partner operator platform  __ApplicationOnboardingManagement__ * __OnboardApplication__ - Submits an application details to a partner OP. Based on the details provided,  partner OP shall do bookkeeping, resource validation and other pre-deployment operations * __UpdateApplication__ - Updates partner OP about changes in application compute resource requirements, QOS Profile, associated descriptor or change in associated components * __DeboardApplication__ - Removes an application from partner OP * __ViewApplication__ - Retrieves application details from partner OP * __OnboardExistingAppNewZones__ - Make an application available on new additional zones * __LockUnlockApplicationZone__ - Forbid or permit instantiation of application on a zone  __Application Instance Lifecycle Management__ * __InstallApp__ - Instantiates an application on a partner OP zone. * __GetAppInstanceDetails__ - Retrieves an application instance details from partner OP. * __RemoveApp__ - Terminate an application instance on a partner OP zone. * __GetAllAppInstances__ - Retrieves details about all instances of the application running on partner OP zones.   __AppProviderResourceManagement__ * __CreateResourcePools__ - Reserves resources (compute, network and storage)  on a partner OP zone. ISVs registered with home OP reserves resources on a partner OP zone. * __UpdateISVResPool__ - Updates resources reserved for a pool by an ISV * __ViewISVResPool__ - Retrieves the resource pool reserved by an ISV * __RemoveISVResPool__ - Deletes the resource pool reserved by an ISV   __EdgeNodeSharing__ *__GetCandidateZones__ - Edge discovery procedures towards partner OP over E/WBI. Originating OP request partner OP to provide a list of candidate zones where an application instance can be created.   __LBORoamingAuthentication__ *__AuthenticateDevice__ - Validates the authenticity of a roaming user from home OP   © 2022 GSM Association. All rights reserved. 

API version: 1.0.0
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package fedewapi

import (
	"encoding/json"
)

// checks if the UpdateApplicationRequestAppComponentSpecsInner type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &UpdateApplicationRequestAppComponentSpecsInner{}

// UpdateApplicationRequestAppComponentSpecsInner struct for UpdateApplicationRequestAppComponentSpecsInner
type UpdateApplicationRequestAppComponentSpecsInner struct {
	// Must be a valid RFC 1035 label name. This defines the DNS name via which the component can be accessed over NBI. Access via serviceNameNB is restricted on specific ports. Platform shall expose component access externally via this DNS name
	ServiceNameNB *string `json:"serviceNameNB,omitempty"`
	// Must be a valid RFC 1035 label name. This defines the DNS name via which the component can be accessed via peer components. Access via serviceNameEW is open on all ports. Platform shall not expose serviceNameEW externally outside edge.
	ServiceNameEW *string `json:"serviceNameEW,omitempty"`
	// Must be a valid RFC 1035 label name. Component name must be unique with an application
	ComponentName string `json:"componentName"`
	// A globally unique identifier associated with the artefact. Originating OP generates this identifier when artefact is submitted over NBI.
	ArtefactId *string `json:"artefactId,omitempty"`
}

// NewUpdateApplicationRequestAppComponentSpecsInner instantiates a new UpdateApplicationRequestAppComponentSpecsInner object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewUpdateApplicationRequestAppComponentSpecsInner(componentName string) *UpdateApplicationRequestAppComponentSpecsInner {
	this := UpdateApplicationRequestAppComponentSpecsInner{}
	this.ComponentName = componentName
	return &this
}

// NewUpdateApplicationRequestAppComponentSpecsInnerWithDefaults instantiates a new UpdateApplicationRequestAppComponentSpecsInner object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewUpdateApplicationRequestAppComponentSpecsInnerWithDefaults() *UpdateApplicationRequestAppComponentSpecsInner {
	this := UpdateApplicationRequestAppComponentSpecsInner{}
	return &this
}

// GetServiceNameNB returns the ServiceNameNB field value if set, zero value otherwise.
func (o *UpdateApplicationRequestAppComponentSpecsInner) GetServiceNameNB() string {
	if o == nil || isNil(o.ServiceNameNB) {
		var ret string
		return ret
	}
	return *o.ServiceNameNB
}

// GetServiceNameNBOk returns a tuple with the ServiceNameNB field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *UpdateApplicationRequestAppComponentSpecsInner) GetServiceNameNBOk() (*string, bool) {
	if o == nil || isNil(o.ServiceNameNB) {
		return nil, false
	}
	return o.ServiceNameNB, true
}

// HasServiceNameNB returns a boolean if a field has been set.
func (o *UpdateApplicationRequestAppComponentSpecsInner) HasServiceNameNB() bool {
	if o != nil && !isNil(o.ServiceNameNB) {
		return true
	}

	return false
}

// SetServiceNameNB gets a reference to the given string and assigns it to the ServiceNameNB field.
func (o *UpdateApplicationRequestAppComponentSpecsInner) SetServiceNameNB(v string) {
	o.ServiceNameNB = &v
}

// GetServiceNameEW returns the ServiceNameEW field value if set, zero value otherwise.
func (o *UpdateApplicationRequestAppComponentSpecsInner) GetServiceNameEW() string {
	if o == nil || isNil(o.ServiceNameEW) {
		var ret string
		return ret
	}
	return *o.ServiceNameEW
}

// GetServiceNameEWOk returns a tuple with the ServiceNameEW field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *UpdateApplicationRequestAppComponentSpecsInner) GetServiceNameEWOk() (*string, bool) {
	if o == nil || isNil(o.ServiceNameEW) {
		return nil, false
	}
	return o.ServiceNameEW, true
}

// HasServiceNameEW returns a boolean if a field has been set.
func (o *UpdateApplicationRequestAppComponentSpecsInner) HasServiceNameEW() bool {
	if o != nil && !isNil(o.ServiceNameEW) {
		return true
	}

	return false
}

// SetServiceNameEW gets a reference to the given string and assigns it to the ServiceNameEW field.
func (o *UpdateApplicationRequestAppComponentSpecsInner) SetServiceNameEW(v string) {
	o.ServiceNameEW = &v
}

// GetComponentName returns the ComponentName field value
func (o *UpdateApplicationRequestAppComponentSpecsInner) GetComponentName() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.ComponentName
}

// GetComponentNameOk returns a tuple with the ComponentName field value
// and a boolean to check if the value has been set.
func (o *UpdateApplicationRequestAppComponentSpecsInner) GetComponentNameOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.ComponentName, true
}

// SetComponentName sets field value
func (o *UpdateApplicationRequestAppComponentSpecsInner) SetComponentName(v string) {
	o.ComponentName = v
}

// GetArtefactId returns the ArtefactId field value if set, zero value otherwise.
func (o *UpdateApplicationRequestAppComponentSpecsInner) GetArtefactId() string {
	if o == nil || isNil(o.ArtefactId) {
		var ret string
		return ret
	}
	return *o.ArtefactId
}

// GetArtefactIdOk returns a tuple with the ArtefactId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *UpdateApplicationRequestAppComponentSpecsInner) GetArtefactIdOk() (*string, bool) {
	if o == nil || isNil(o.ArtefactId) {
		return nil, false
	}
	return o.ArtefactId, true
}

// HasArtefactId returns a boolean if a field has been set.
func (o *UpdateApplicationRequestAppComponentSpecsInner) HasArtefactId() bool {
	if o != nil && !isNil(o.ArtefactId) {
		return true
	}

	return false
}

// SetArtefactId gets a reference to the given string and assigns it to the ArtefactId field.
func (o *UpdateApplicationRequestAppComponentSpecsInner) SetArtefactId(v string) {
	o.ArtefactId = &v
}

func (o UpdateApplicationRequestAppComponentSpecsInner) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o UpdateApplicationRequestAppComponentSpecsInner) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !isNil(o.ServiceNameNB) {
		toSerialize["serviceNameNB"] = o.ServiceNameNB
	}
	if !isNil(o.ServiceNameEW) {
		toSerialize["serviceNameEW"] = o.ServiceNameEW
	}
	toSerialize["componentName"] = o.ComponentName
	if !isNil(o.ArtefactId) {
		toSerialize["artefactId"] = o.ArtefactId
	}
	return toSerialize, nil
}

type NullableUpdateApplicationRequestAppComponentSpecsInner struct {
	value *UpdateApplicationRequestAppComponentSpecsInner
	isSet bool
}

func (v NullableUpdateApplicationRequestAppComponentSpecsInner) Get() *UpdateApplicationRequestAppComponentSpecsInner {
	return v.value
}

func (v *NullableUpdateApplicationRequestAppComponentSpecsInner) Set(val *UpdateApplicationRequestAppComponentSpecsInner) {
	v.value = val
	v.isSet = true
}

func (v NullableUpdateApplicationRequestAppComponentSpecsInner) IsSet() bool {
	return v.isSet
}

func (v *NullableUpdateApplicationRequestAppComponentSpecsInner) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableUpdateApplicationRequestAppComponentSpecsInner(val *UpdateApplicationRequestAppComponentSpecsInner) *NullableUpdateApplicationRequestAppComponentSpecsInner {
	return &NullableUpdateApplicationRequestAppComponentSpecsInner{value: val, isSet: true}
}

func (v NullableUpdateApplicationRequestAppComponentSpecsInner) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableUpdateApplicationRequestAppComponentSpecsInner) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


