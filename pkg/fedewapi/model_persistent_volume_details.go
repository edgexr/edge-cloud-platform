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
)

// checks if the PersistentVolumeDetails type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &PersistentVolumeDetails{}

// PersistentVolumeDetails struct for PersistentVolumeDetails
type PersistentVolumeDetails struct {
	// size of the volume given by user (10GB, 20GB, 50 GB or 100GB)
	VolumeSize string `json:"volumeSize"`
	// Defines the mount path of the volume
	VolumeMountPath string `json:"volumeMountPath"`
	// Human readable name for the volume
	VolumeName string `json:"volumeName"`
	// It indicates the ephemeral storage on the node and contents are not preserved if containers restarts
	EphemeralType *bool `json:"ephemeralType,omitempty"`
	// Values are RW (read/write) and RO (read-only)l
	AccessMode *string `json:"accessMode,omitempty"`
	// Exclusive or Shared. If shared, then in case of multiple containers same volume will be shared across the containers.
	SharingPolicy *string `json:"sharingPolicy,omitempty"`
}

func (s *PersistentVolumeDetails) Validate() error {
	if s.VolumeSize == "" {
		return errors.New("volumeSize is required")
	}
	VolumeSizeEnumVals := map[string]struct{}{
		"10Gi":  {},
		"20Gi":  {},
		"50Gi":  {},
		"100Gi": {},
	}
	if _, found := VolumeSizeEnumVals[s.VolumeSize]; !found {
		return errors.New("PersistentVolumeDetails volumeSize value \"" + s.VolumeSize + "\" is not a valid enum value")
	}
	if s.VolumeMountPath == "" {
		return errors.New("volumeMountPath is required")
	}
	if s.VolumeName == "" {
		return errors.New("volumeName is required")
	}
	return nil
}

// NewPersistentVolumeDetails instantiates a new PersistentVolumeDetails object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewPersistentVolumeDetails(volumeSize string, volumeMountPath string, volumeName string) *PersistentVolumeDetails {
	this := PersistentVolumeDetails{}
	this.VolumeSize = volumeSize
	this.VolumeMountPath = volumeMountPath
	this.VolumeName = volumeName
	var ephemeralType bool = false
	this.EphemeralType = &ephemeralType
	var accessMode string = "RW"
	this.AccessMode = &accessMode
	var sharingPolicy string = "EXCLUSIVE"
	this.SharingPolicy = &sharingPolicy
	return &this
}

// NewPersistentVolumeDetailsWithDefaults instantiates a new PersistentVolumeDetails object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewPersistentVolumeDetailsWithDefaults() *PersistentVolumeDetails {
	this := PersistentVolumeDetails{}
	var ephemeralType bool = false
	this.EphemeralType = &ephemeralType
	var accessMode string = "RW"
	this.AccessMode = &accessMode
	var sharingPolicy string = "EXCLUSIVE"
	this.SharingPolicy = &sharingPolicy
	return &this
}

// GetVolumeSize returns the VolumeSize field value
func (o *PersistentVolumeDetails) GetVolumeSize() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.VolumeSize
}

// GetVolumeSizeOk returns a tuple with the VolumeSize field value
// and a boolean to check if the value has been set.
func (o *PersistentVolumeDetails) GetVolumeSizeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.VolumeSize, true
}

// SetVolumeSize sets field value
func (o *PersistentVolumeDetails) SetVolumeSize(v string) {
	o.VolumeSize = v
}

// GetVolumeMountPath returns the VolumeMountPath field value
func (o *PersistentVolumeDetails) GetVolumeMountPath() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.VolumeMountPath
}

// GetVolumeMountPathOk returns a tuple with the VolumeMountPath field value
// and a boolean to check if the value has been set.
func (o *PersistentVolumeDetails) GetVolumeMountPathOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.VolumeMountPath, true
}

// SetVolumeMountPath sets field value
func (o *PersistentVolumeDetails) SetVolumeMountPath(v string) {
	o.VolumeMountPath = v
}

// GetVolumeName returns the VolumeName field value
func (o *PersistentVolumeDetails) GetVolumeName() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.VolumeName
}

// GetVolumeNameOk returns a tuple with the VolumeName field value
// and a boolean to check if the value has been set.
func (o *PersistentVolumeDetails) GetVolumeNameOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.VolumeName, true
}

// SetVolumeName sets field value
func (o *PersistentVolumeDetails) SetVolumeName(v string) {
	o.VolumeName = v
}

// GetEphemeralType returns the EphemeralType field value if set, zero value otherwise.
func (o *PersistentVolumeDetails) GetEphemeralType() bool {
	if o == nil || isNil(o.EphemeralType) {
		var ret bool
		return ret
	}
	return *o.EphemeralType
}

// GetEphemeralTypeOk returns a tuple with the EphemeralType field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *PersistentVolumeDetails) GetEphemeralTypeOk() (*bool, bool) {
	if o == nil || isNil(o.EphemeralType) {
		return nil, false
	}
	return o.EphemeralType, true
}

// HasEphemeralType returns a boolean if a field has been set.
func (o *PersistentVolumeDetails) HasEphemeralType() bool {
	if o != nil && !isNil(o.EphemeralType) {
		return true
	}

	return false
}

// SetEphemeralType gets a reference to the given bool and assigns it to the EphemeralType field.
func (o *PersistentVolumeDetails) SetEphemeralType(v bool) {
	o.EphemeralType = &v
}

// GetAccessMode returns the AccessMode field value if set, zero value otherwise.
func (o *PersistentVolumeDetails) GetAccessMode() string {
	if o == nil || isNil(o.AccessMode) {
		var ret string
		return ret
	}
	return *o.AccessMode
}

// GetAccessModeOk returns a tuple with the AccessMode field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *PersistentVolumeDetails) GetAccessModeOk() (*string, bool) {
	if o == nil || isNil(o.AccessMode) {
		return nil, false
	}
	return o.AccessMode, true
}

// HasAccessMode returns a boolean if a field has been set.
func (o *PersistentVolumeDetails) HasAccessMode() bool {
	if o != nil && !isNil(o.AccessMode) {
		return true
	}

	return false
}

// SetAccessMode gets a reference to the given string and assigns it to the AccessMode field.
func (o *PersistentVolumeDetails) SetAccessMode(v string) {
	o.AccessMode = &v
}

// GetSharingPolicy returns the SharingPolicy field value if set, zero value otherwise.
func (o *PersistentVolumeDetails) GetSharingPolicy() string {
	if o == nil || isNil(o.SharingPolicy) {
		var ret string
		return ret
	}
	return *o.SharingPolicy
}

// GetSharingPolicyOk returns a tuple with the SharingPolicy field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *PersistentVolumeDetails) GetSharingPolicyOk() (*string, bool) {
	if o == nil || isNil(o.SharingPolicy) {
		return nil, false
	}
	return o.SharingPolicy, true
}

// HasSharingPolicy returns a boolean if a field has been set.
func (o *PersistentVolumeDetails) HasSharingPolicy() bool {
	if o != nil && !isNil(o.SharingPolicy) {
		return true
	}

	return false
}

// SetSharingPolicy gets a reference to the given string and assigns it to the SharingPolicy field.
func (o *PersistentVolumeDetails) SetSharingPolicy(v string) {
	o.SharingPolicy = &v
}

func (o PersistentVolumeDetails) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o PersistentVolumeDetails) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["volumeSize"] = o.VolumeSize
	toSerialize["volumeMountPath"] = o.VolumeMountPath
	toSerialize["volumeName"] = o.VolumeName
	if !isNil(o.EphemeralType) {
		toSerialize["ephemeralType"] = o.EphemeralType
	}
	if !isNil(o.AccessMode) {
		toSerialize["accessMode"] = o.AccessMode
	}
	if !isNil(o.SharingPolicy) {
		toSerialize["sharingPolicy"] = o.SharingPolicy
	}
	return toSerialize, nil
}

type NullablePersistentVolumeDetails struct {
	value *PersistentVolumeDetails
	isSet bool
}

func (v NullablePersistentVolumeDetails) Get() *PersistentVolumeDetails {
	return v.value
}

func (v *NullablePersistentVolumeDetails) Set(val *PersistentVolumeDetails) {
	v.value = val
	v.isSet = true
}

func (v NullablePersistentVolumeDetails) IsSet() bool {
	return v.isSet
}

func (v *NullablePersistentVolumeDetails) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullablePersistentVolumeDetails(val *PersistentVolumeDetails) *NullablePersistentVolumeDetails {
	return &NullablePersistentVolumeDetails{value: val, isSet: true}
}

func (v NullablePersistentVolumeDetails) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullablePersistentVolumeDetails) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
