/*
Federation Management Service

# Introduction --- RESTful APIs that allow an OP to share the edge cloud resources and capabilities securely to other partner OPs over E/WBI.  --- # API Scope  --- APIs defined in this version of the specification can be categorized into the following areas: * __FederationManagement__ - Create and manage directed federation relationship with a partner OP * __AvailabilityZoneInfoSynchronization__ - Management of resources of partner OP zones and status updates * __ArtefactManagement__ - Upload, remove, retrieve and update application descriptors, charts and packages over E/WBI towards a partner OP * __FileManagement__ - Upload, remove, retrieve and update application binaries over E/WBI towards a partner OP * __ApplicationOnboardingManagement__ - Register, retrieve, update and remove applications over E/WBI towards a partner OP * __ApplicationDeploymentManagement__ - Create, update, retrieve and terminate application instances over E/WBI towards a partner OP * __AppProviderResourceManagement__ - Static resource reservation for an application provider over E/WBI for partner OP zones * __EdgeNodeSharing__ - Edge discovery procedures towards partner OP over E/WBI. * __LBORoamingAuthentication__ - Validation of user client authentication from home OP  --- # Definitions --- This section provides definitions of terminologies commonly referred to throughout the API descriptions.  * __Accepted Zones__ - List of partner OP zones, which the originating OP has confirmed to use for its edge applications * __Anchoring__ - Partner OP capability to serve application clients (still in their home location) from application instances running on partner zones. * __Application Provider__ - An application developer, onboarding his/her edge application on a partner operator platform (MEC). * __Artefact__ - Descriptor, charts or any other package associated with the application. * __Availability Zone__ - Zones that partner OP can offer to share with originating OP. * __Device__ - Refers to user equipment like mobile phone, tablet, IOT kit, AR/VR device etc. In context of MEC users use these devices to access edge applications * __Directed Federation__ - A Federation between two OP instances A and B, in which edge compute resources are shared by B to A, but not from A to B. * __Edge Application__ - Application designed to run on MEC edge cloud * __Edge Discovery Service__ - Partner OP service responsible to select most optimal edge( within partner OP) for edge application instantiation. Edge discovery service is defined as HTTP based API endpoint identified by a well-defined FQDN or IP. * __E/WBI__ - East west bound interface. * __Federation__ - Relationship among member OPs who agrees to offer services and capabilities to the application providers and end users of member OPs * __FederationContextId__ - Partner OP defined string identifier representing a certain federation relationship. * __Federation Identifier__ - Identify an operator platform in federation context. * __FileId__ - An OP defined string identifier representing a certain application image uploaded by an application provider * __Flavour__ - A group of compute, network and storage resources that can be requested or granted as a single unit * __FlavourIdentifier__ - An OP defined string identifier representing a set of compute, storage and networking resources * __Home OP__ - Used in federation context to identify the OP with which the application developers or user clients are registered. * __Home Routing__ - Partner OP capability to direct roaming user client traffic towards application instances running on home OP zones. * __Instance__ - Application process running on an edge * __LCM Service__ - Partner OP service responsible for life cycle management of edge applications. LCM service is defined as HTTP based API endpoint identified by a well-defined FQDN or IP. * __Offered Zones__ - Zones that partner OP offer to share to the Originating OP based on the prior agreement and local configuration. * __Onboarding__ - Submitting an application to MEC platform * __OP__ - Operator platform. * __OperatorIdentifier__ - String identifier representing the owner of MEC platform. Owner could be an enterprise, a TSP or some other organization * __Originating OP__ - The OP when initiating the federation creation request towards the partner OP is defined as the Originating OP * __Partner OP__ - Operator Platform which offers its Edge Cloud capabilities to the other Operator Platforms via E/WBI. * __Resource__ - Compute, networking and storage resources. * __Resource Pool__ - A group of compute, networking and storage resources. Application provider pre-reserve resources on partner OP zone, these resources are reserved in terms of flavours. * __ZoneIdentifier__ - An OP defined string identifier representing a certain geographical or logical area where edge resources and services are provided * __Zone Confirmation__ - Procedure via which originating OP acknowledges partner OP about the partner zones it wishes to use. * __User Clients__ - Lightweight client applications used to access edge applications. Application users run these clients on their devices (UE, IOT device, AR/VR device etc)   --- # API Operations ---  __FederationManagement__ * __CreateFederation__ - Creates a directed federation relationship with a partner OP * __GetFederationDetails__ - Retrieves details about the federation relationship with the partner OP. The response shall provide info about the zones offered by the partner, partner OP network codes, information about edge discovery and LCM service etc. * __DeleteFederationDetails__ - Remove existing federation with the partner OP * __NotifyFederationUpdates__ - Call back notification used by partner OP to update originating OP about any change in existing federation relationship. * __UpdateFederation__ - API used by the Originating OP towards the partner OP, to update the parameters associated to the existing federation  __AvailabilityZoneInfoSynchronization__ * __ZoneSubscribe__ - Informs partner OP that originating OP is willing to access the specified zones and partner OP shall reserve compute and network resources for these zones. * __ZoneUnsubscribe__ - Informs partner OP that originating OP will no longer access the specified partner OP zone. * __GetZoneData__ - Retrieves details about the computation and network resources that partner OP has reserved for an partner OP zone. * __Notify Zone Information__ - Call back notification used by partner OP to update originating OP about changes in the resources reserved on a partner zone.  __ArtefactManagement__ * __UploadArtefact__ - Uploads application artefact on partner operator platform. * __RemoveArtefact__ - Removes an artefact from partner operator platform. * __GetArtefact__ - Retrieves details about an artefact from partner operator platform. * __UploadFile__ Upload application binaries to partner operator platform * __RemoveFile__ - Removes application binaries from partner operator platform * __ViewFile__ - Retrieves details about binaries associated with an application from partner operator platform  __ApplicationOnboardingManagement__ * __OnboardApplication__ - Submits an application details to a partner OP. Based on the details provided,  partner OP shall do bookkeeping, resource validation and other pre-deployment operations * __UpdateApplication__ - Updates partner OP about changes in application compute resource requirements, QOS Profile, associated descriptor or change in associated components * __DeboardApplication__ - Removes an application from partner OP * __ViewApplication__ - Retrieves application details from partner OP * __OnboardExistingAppNewZones__ - Make an application available on new additional zones * __LockUnlockApplicationZone__ - Forbid or permit instantiation of application on a zone  __Application Instance Lifecycle Management__ * __InstallApp__ - Instantiates an application on a partner OP zone. * __GetAppInstanceDetails__ - Retrieves an application instance details from partner OP. * __RemoveApp__ - Terminate an application instance on a partner OP zone. * __GetAllAppInstances__ - Retrieves details about all instances of the application running on partner OP zones.   __AppProviderResourceManagement__ * __CreateResourcePools__ - Reserves resources (compute, network and storage)  on a partner OP zone. ISVs registered with home OP reserves resources on a partner OP zone. * __UpdateISVResPool__ - Updates resources reserved for a pool by an ISV * __ViewISVResPool__ - Retrieves the resource pool reserved by an ISV * __RemoveISVResPool__ - Deletes the resource pool reserved by an ISV   __EdgeNodeSharing__ *__GetCandidateZones__ - Edge discovery procedures towards partner OP over E/WBI. Originating OP request partner OP to provide a list of candidate zones where an application instance can be created.   __LBORoamingAuthentication__ *__AuthenticateDevice__ - Validates the authenticity of a roaming user from home OP   © 2022 GSM Association. All rights reserved. 

API version: 1.0.0
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package fedewapi

import (
	"encoding/json"
	"time"
)

// checks if the UpdateFederationRequest type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &UpdateFederationRequest{}

// UpdateFederationRequest struct for UpdateFederationRequest
type UpdateFederationRequest struct {
	ObjectType string `json:"objectType"`
	OperationType string `json:"operationType"`
	AddMobileNetworkIds *MobileNetworkIds `json:"addMobileNetworkIds,omitempty"`
	RemoveMobileNetworkIds *MobileNetworkIds `json:"removeMobileNetworkIds,omitempty"`
	// List of network identifier associated with the fixed line network of the operator platform.
	AddFixedNetworkIds []string `json:"addFixedNetworkIds,omitempty"`
	// List of network identifier associated with the fixed line network of the operator platform.
	RemoveFixedNetworkIds []string `json:"removeFixedNetworkIds,omitempty"`
	// Date and time of the federation modification by the originating partner OP
	ModificationDate time.Time `json:"modificationDate"`
}

// NewUpdateFederationRequest instantiates a new UpdateFederationRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewUpdateFederationRequest(objectType string, operationType string, modificationDate time.Time) *UpdateFederationRequest {
	this := UpdateFederationRequest{}
	this.ObjectType = objectType
	this.OperationType = operationType
	this.ModificationDate = modificationDate
	return &this
}

// NewUpdateFederationRequestWithDefaults instantiates a new UpdateFederationRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewUpdateFederationRequestWithDefaults() *UpdateFederationRequest {
	this := UpdateFederationRequest{}
	return &this
}

// GetObjectType returns the ObjectType field value
func (o *UpdateFederationRequest) GetObjectType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.ObjectType
}

// GetObjectTypeOk returns a tuple with the ObjectType field value
// and a boolean to check if the value has been set.
func (o *UpdateFederationRequest) GetObjectTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.ObjectType, true
}

// SetObjectType sets field value
func (o *UpdateFederationRequest) SetObjectType(v string) {
	o.ObjectType = v
}

// GetOperationType returns the OperationType field value
func (o *UpdateFederationRequest) GetOperationType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.OperationType
}

// GetOperationTypeOk returns a tuple with the OperationType field value
// and a boolean to check if the value has been set.
func (o *UpdateFederationRequest) GetOperationTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.OperationType, true
}

// SetOperationType sets field value
func (o *UpdateFederationRequest) SetOperationType(v string) {
	o.OperationType = v
}

// GetAddMobileNetworkIds returns the AddMobileNetworkIds field value if set, zero value otherwise.
func (o *UpdateFederationRequest) GetAddMobileNetworkIds() MobileNetworkIds {
	if o == nil || isNil(o.AddMobileNetworkIds) {
		var ret MobileNetworkIds
		return ret
	}
	return *o.AddMobileNetworkIds
}

// GetAddMobileNetworkIdsOk returns a tuple with the AddMobileNetworkIds field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *UpdateFederationRequest) GetAddMobileNetworkIdsOk() (*MobileNetworkIds, bool) {
	if o == nil || isNil(o.AddMobileNetworkIds) {
		return nil, false
	}
	return o.AddMobileNetworkIds, true
}

// HasAddMobileNetworkIds returns a boolean if a field has been set.
func (o *UpdateFederationRequest) HasAddMobileNetworkIds() bool {
	if o != nil && !isNil(o.AddMobileNetworkIds) {
		return true
	}

	return false
}

// SetAddMobileNetworkIds gets a reference to the given MobileNetworkIds and assigns it to the AddMobileNetworkIds field.
func (o *UpdateFederationRequest) SetAddMobileNetworkIds(v MobileNetworkIds) {
	o.AddMobileNetworkIds = &v
}

// GetRemoveMobileNetworkIds returns the RemoveMobileNetworkIds field value if set, zero value otherwise.
func (o *UpdateFederationRequest) GetRemoveMobileNetworkIds() MobileNetworkIds {
	if o == nil || isNil(o.RemoveMobileNetworkIds) {
		var ret MobileNetworkIds
		return ret
	}
	return *o.RemoveMobileNetworkIds
}

// GetRemoveMobileNetworkIdsOk returns a tuple with the RemoveMobileNetworkIds field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *UpdateFederationRequest) GetRemoveMobileNetworkIdsOk() (*MobileNetworkIds, bool) {
	if o == nil || isNil(o.RemoveMobileNetworkIds) {
		return nil, false
	}
	return o.RemoveMobileNetworkIds, true
}

// HasRemoveMobileNetworkIds returns a boolean if a field has been set.
func (o *UpdateFederationRequest) HasRemoveMobileNetworkIds() bool {
	if o != nil && !isNil(o.RemoveMobileNetworkIds) {
		return true
	}

	return false
}

// SetRemoveMobileNetworkIds gets a reference to the given MobileNetworkIds and assigns it to the RemoveMobileNetworkIds field.
func (o *UpdateFederationRequest) SetRemoveMobileNetworkIds(v MobileNetworkIds) {
	o.RemoveMobileNetworkIds = &v
}

// GetAddFixedNetworkIds returns the AddFixedNetworkIds field value if set, zero value otherwise.
func (o *UpdateFederationRequest) GetAddFixedNetworkIds() []string {
	if o == nil || isNil(o.AddFixedNetworkIds) {
		var ret []string
		return ret
	}
	return o.AddFixedNetworkIds
}

// GetAddFixedNetworkIdsOk returns a tuple with the AddFixedNetworkIds field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *UpdateFederationRequest) GetAddFixedNetworkIdsOk() ([]string, bool) {
	if o == nil || isNil(o.AddFixedNetworkIds) {
		return nil, false
	}
	return o.AddFixedNetworkIds, true
}

// HasAddFixedNetworkIds returns a boolean if a field has been set.
func (o *UpdateFederationRequest) HasAddFixedNetworkIds() bool {
	if o != nil && !isNil(o.AddFixedNetworkIds) {
		return true
	}

	return false
}

// SetAddFixedNetworkIds gets a reference to the given []string and assigns it to the AddFixedNetworkIds field.
func (o *UpdateFederationRequest) SetAddFixedNetworkIds(v []string) {
	o.AddFixedNetworkIds = v
}

// GetRemoveFixedNetworkIds returns the RemoveFixedNetworkIds field value if set, zero value otherwise.
func (o *UpdateFederationRequest) GetRemoveFixedNetworkIds() []string {
	if o == nil || isNil(o.RemoveFixedNetworkIds) {
		var ret []string
		return ret
	}
	return o.RemoveFixedNetworkIds
}

// GetRemoveFixedNetworkIdsOk returns a tuple with the RemoveFixedNetworkIds field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *UpdateFederationRequest) GetRemoveFixedNetworkIdsOk() ([]string, bool) {
	if o == nil || isNil(o.RemoveFixedNetworkIds) {
		return nil, false
	}
	return o.RemoveFixedNetworkIds, true
}

// HasRemoveFixedNetworkIds returns a boolean if a field has been set.
func (o *UpdateFederationRequest) HasRemoveFixedNetworkIds() bool {
	if o != nil && !isNil(o.RemoveFixedNetworkIds) {
		return true
	}

	return false
}

// SetRemoveFixedNetworkIds gets a reference to the given []string and assigns it to the RemoveFixedNetworkIds field.
func (o *UpdateFederationRequest) SetRemoveFixedNetworkIds(v []string) {
	o.RemoveFixedNetworkIds = v
}

// GetModificationDate returns the ModificationDate field value
func (o *UpdateFederationRequest) GetModificationDate() time.Time {
	if o == nil {
		var ret time.Time
		return ret
	}

	return o.ModificationDate
}

// GetModificationDateOk returns a tuple with the ModificationDate field value
// and a boolean to check if the value has been set.
func (o *UpdateFederationRequest) GetModificationDateOk() (*time.Time, bool) {
	if o == nil {
		return nil, false
	}
	return &o.ModificationDate, true
}

// SetModificationDate sets field value
func (o *UpdateFederationRequest) SetModificationDate(v time.Time) {
	o.ModificationDate = v
}

func (o UpdateFederationRequest) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o UpdateFederationRequest) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["objectType"] = o.ObjectType
	toSerialize["operationType"] = o.OperationType
	if !isNil(o.AddMobileNetworkIds) {
		toSerialize["addMobileNetworkIds"] = o.AddMobileNetworkIds
	}
	if !isNil(o.RemoveMobileNetworkIds) {
		toSerialize["removeMobileNetworkIds"] = o.RemoveMobileNetworkIds
	}
	if !isNil(o.AddFixedNetworkIds) {
		toSerialize["addFixedNetworkIds"] = o.AddFixedNetworkIds
	}
	if !isNil(o.RemoveFixedNetworkIds) {
		toSerialize["removeFixedNetworkIds"] = o.RemoveFixedNetworkIds
	}
	toSerialize["modificationDate"] = o.ModificationDate
	return toSerialize, nil
}

type NullableUpdateFederationRequest struct {
	value *UpdateFederationRequest
	isSet bool
}

func (v NullableUpdateFederationRequest) Get() *UpdateFederationRequest {
	return v.value
}

func (v *NullableUpdateFederationRequest) Set(val *UpdateFederationRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableUpdateFederationRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableUpdateFederationRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableUpdateFederationRequest(val *UpdateFederationRequest) *NullableUpdateFederationRequest {
	return &NullableUpdateFederationRequest{value: val, isSet: true}
}

func (v NullableUpdateFederationRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableUpdateFederationRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


