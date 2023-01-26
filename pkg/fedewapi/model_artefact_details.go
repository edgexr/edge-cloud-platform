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

// checks if the ArtefactDetails type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &ArtefactDetails{}

// ArtefactDetails Artefact details.
type ArtefactDetails struct {
	// A globally unique identifier associated with the artefact. Originating OP generates this identifier when artefact is submitted over NBI.
	ArtefactId string `json:"artefactId"`
	// UserId of the app provider.  Identifier is relevant only in context of this federation.
	AppProviderId string `json:"appProviderId"`
	// Name of the artefact.
	ArtefactName string `json:"artefactName"`
	// Brief description of the artefact by the application provider
	ArtefactDescription *string `json:"artefactDescription,omitempty"`
	// Artefact version information
	ArtefactVersionInfo string `json:"artefactVersionInfo"`
	ArtefactVirtType string `json:"artefactVirtType"`
	// Name of the file.
	ArtefactFileName *string `json:"artefactFileName,omitempty"`
	// Artefacts like Helm charts or Terraform scripts may need compressed format.
	ArtefactFileFormat *string `json:"artefactFileFormat,omitempty"`
	// Type of descriptor present in the artefact.  App provider can either define either a Helm chart or a Terraform script or container spec.
	ArtefactDescriptorType string `json:"artefactDescriptorType"`
	// Artefact or file repository location. PUBLICREPO is used of public URLs like GitHub, Helm repo, docker registry etc., PRIVATEREPO is used for private repo managed by the application developer, UPLOAD is for the case when artefact/file is uploaded from MEC web portal.  OP should pull the image from ‘repoUrl' immediately after receiving the request and then send back the response. In case the repoURL corresponds to a docker registry, use docker v2 http api to do the pull.
	RepoType *string `json:"repoType,omitempty"`
	ArtefactRepoLocation *ObjectRepoLocation `json:"artefactRepoLocation,omitempty"`
}

// NewArtefactDetails instantiates a new ArtefactDetails object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewArtefactDetails(artefactId string, appProviderId string, artefactName string, artefactVersionInfo string, artefactVirtType string, artefactDescriptorType string) *ArtefactDetails {
	this := ArtefactDetails{}
	this.ArtefactId = artefactId
	this.AppProviderId = appProviderId
	this.ArtefactName = artefactName
	this.ArtefactVersionInfo = artefactVersionInfo
	this.ArtefactVirtType = artefactVirtType
	this.ArtefactDescriptorType = artefactDescriptorType
	return &this
}

// NewArtefactDetailsWithDefaults instantiates a new ArtefactDetails object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewArtefactDetailsWithDefaults() *ArtefactDetails {
	this := ArtefactDetails{}
	return &this
}

// GetArtefactId returns the ArtefactId field value
func (o *ArtefactDetails) GetArtefactId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.ArtefactId
}

// GetArtefactIdOk returns a tuple with the ArtefactId field value
// and a boolean to check if the value has been set.
func (o *ArtefactDetails) GetArtefactIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.ArtefactId, true
}

// SetArtefactId sets field value
func (o *ArtefactDetails) SetArtefactId(v string) {
	o.ArtefactId = v
}

// GetAppProviderId returns the AppProviderId field value
func (o *ArtefactDetails) GetAppProviderId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.AppProviderId
}

// GetAppProviderIdOk returns a tuple with the AppProviderId field value
// and a boolean to check if the value has been set.
func (o *ArtefactDetails) GetAppProviderIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.AppProviderId, true
}

// SetAppProviderId sets field value
func (o *ArtefactDetails) SetAppProviderId(v string) {
	o.AppProviderId = v
}

// GetArtefactName returns the ArtefactName field value
func (o *ArtefactDetails) GetArtefactName() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.ArtefactName
}

// GetArtefactNameOk returns a tuple with the ArtefactName field value
// and a boolean to check if the value has been set.
func (o *ArtefactDetails) GetArtefactNameOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.ArtefactName, true
}

// SetArtefactName sets field value
func (o *ArtefactDetails) SetArtefactName(v string) {
	o.ArtefactName = v
}

// GetArtefactDescription returns the ArtefactDescription field value if set, zero value otherwise.
func (o *ArtefactDetails) GetArtefactDescription() string {
	if o == nil || isNil(o.ArtefactDescription) {
		var ret string
		return ret
	}
	return *o.ArtefactDescription
}

// GetArtefactDescriptionOk returns a tuple with the ArtefactDescription field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ArtefactDetails) GetArtefactDescriptionOk() (*string, bool) {
	if o == nil || isNil(o.ArtefactDescription) {
		return nil, false
	}
	return o.ArtefactDescription, true
}

// HasArtefactDescription returns a boolean if a field has been set.
func (o *ArtefactDetails) HasArtefactDescription() bool {
	if o != nil && !isNil(o.ArtefactDescription) {
		return true
	}

	return false
}

// SetArtefactDescription gets a reference to the given string and assigns it to the ArtefactDescription field.
func (o *ArtefactDetails) SetArtefactDescription(v string) {
	o.ArtefactDescription = &v
}

// GetArtefactVersionInfo returns the ArtefactVersionInfo field value
func (o *ArtefactDetails) GetArtefactVersionInfo() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.ArtefactVersionInfo
}

// GetArtefactVersionInfoOk returns a tuple with the ArtefactVersionInfo field value
// and a boolean to check if the value has been set.
func (o *ArtefactDetails) GetArtefactVersionInfoOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.ArtefactVersionInfo, true
}

// SetArtefactVersionInfo sets field value
func (o *ArtefactDetails) SetArtefactVersionInfo(v string) {
	o.ArtefactVersionInfo = v
}

// GetArtefactVirtType returns the ArtefactVirtType field value
func (o *ArtefactDetails) GetArtefactVirtType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.ArtefactVirtType
}

// GetArtefactVirtTypeOk returns a tuple with the ArtefactVirtType field value
// and a boolean to check if the value has been set.
func (o *ArtefactDetails) GetArtefactVirtTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.ArtefactVirtType, true
}

// SetArtefactVirtType sets field value
func (o *ArtefactDetails) SetArtefactVirtType(v string) {
	o.ArtefactVirtType = v
}

// GetArtefactFileName returns the ArtefactFileName field value if set, zero value otherwise.
func (o *ArtefactDetails) GetArtefactFileName() string {
	if o == nil || isNil(o.ArtefactFileName) {
		var ret string
		return ret
	}
	return *o.ArtefactFileName
}

// GetArtefactFileNameOk returns a tuple with the ArtefactFileName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ArtefactDetails) GetArtefactFileNameOk() (*string, bool) {
	if o == nil || isNil(o.ArtefactFileName) {
		return nil, false
	}
	return o.ArtefactFileName, true
}

// HasArtefactFileName returns a boolean if a field has been set.
func (o *ArtefactDetails) HasArtefactFileName() bool {
	if o != nil && !isNil(o.ArtefactFileName) {
		return true
	}

	return false
}

// SetArtefactFileName gets a reference to the given string and assigns it to the ArtefactFileName field.
func (o *ArtefactDetails) SetArtefactFileName(v string) {
	o.ArtefactFileName = &v
}

// GetArtefactFileFormat returns the ArtefactFileFormat field value if set, zero value otherwise.
func (o *ArtefactDetails) GetArtefactFileFormat() string {
	if o == nil || isNil(o.ArtefactFileFormat) {
		var ret string
		return ret
	}
	return *o.ArtefactFileFormat
}

// GetArtefactFileFormatOk returns a tuple with the ArtefactFileFormat field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ArtefactDetails) GetArtefactFileFormatOk() (*string, bool) {
	if o == nil || isNil(o.ArtefactFileFormat) {
		return nil, false
	}
	return o.ArtefactFileFormat, true
}

// HasArtefactFileFormat returns a boolean if a field has been set.
func (o *ArtefactDetails) HasArtefactFileFormat() bool {
	if o != nil && !isNil(o.ArtefactFileFormat) {
		return true
	}

	return false
}

// SetArtefactFileFormat gets a reference to the given string and assigns it to the ArtefactFileFormat field.
func (o *ArtefactDetails) SetArtefactFileFormat(v string) {
	o.ArtefactFileFormat = &v
}

// GetArtefactDescriptorType returns the ArtefactDescriptorType field value
func (o *ArtefactDetails) GetArtefactDescriptorType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.ArtefactDescriptorType
}

// GetArtefactDescriptorTypeOk returns a tuple with the ArtefactDescriptorType field value
// and a boolean to check if the value has been set.
func (o *ArtefactDetails) GetArtefactDescriptorTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.ArtefactDescriptorType, true
}

// SetArtefactDescriptorType sets field value
func (o *ArtefactDetails) SetArtefactDescriptorType(v string) {
	o.ArtefactDescriptorType = v
}

// GetRepoType returns the RepoType field value if set, zero value otherwise.
func (o *ArtefactDetails) GetRepoType() string {
	if o == nil || isNil(o.RepoType) {
		var ret string
		return ret
	}
	return *o.RepoType
}

// GetRepoTypeOk returns a tuple with the RepoType field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ArtefactDetails) GetRepoTypeOk() (*string, bool) {
	if o == nil || isNil(o.RepoType) {
		return nil, false
	}
	return o.RepoType, true
}

// HasRepoType returns a boolean if a field has been set.
func (o *ArtefactDetails) HasRepoType() bool {
	if o != nil && !isNil(o.RepoType) {
		return true
	}

	return false
}

// SetRepoType gets a reference to the given string and assigns it to the RepoType field.
func (o *ArtefactDetails) SetRepoType(v string) {
	o.RepoType = &v
}

// GetArtefactRepoLocation returns the ArtefactRepoLocation field value if set, zero value otherwise.
func (o *ArtefactDetails) GetArtefactRepoLocation() ObjectRepoLocation {
	if o == nil || isNil(o.ArtefactRepoLocation) {
		var ret ObjectRepoLocation
		return ret
	}
	return *o.ArtefactRepoLocation
}

// GetArtefactRepoLocationOk returns a tuple with the ArtefactRepoLocation field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ArtefactDetails) GetArtefactRepoLocationOk() (*ObjectRepoLocation, bool) {
	if o == nil || isNil(o.ArtefactRepoLocation) {
		return nil, false
	}
	return o.ArtefactRepoLocation, true
}

// HasArtefactRepoLocation returns a boolean if a field has been set.
func (o *ArtefactDetails) HasArtefactRepoLocation() bool {
	if o != nil && !isNil(o.ArtefactRepoLocation) {
		return true
	}

	return false
}

// SetArtefactRepoLocation gets a reference to the given ObjectRepoLocation and assigns it to the ArtefactRepoLocation field.
func (o *ArtefactDetails) SetArtefactRepoLocation(v ObjectRepoLocation) {
	o.ArtefactRepoLocation = &v
}

func (o ArtefactDetails) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o ArtefactDetails) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["artefactId"] = o.ArtefactId
	toSerialize["appProviderId"] = o.AppProviderId
	toSerialize["artefactName"] = o.ArtefactName
	if !isNil(o.ArtefactDescription) {
		toSerialize["artefactDescription"] = o.ArtefactDescription
	}
	toSerialize["artefactVersionInfo"] = o.ArtefactVersionInfo
	toSerialize["artefactVirtType"] = o.ArtefactVirtType
	if !isNil(o.ArtefactFileName) {
		toSerialize["artefactFileName"] = o.ArtefactFileName
	}
	if !isNil(o.ArtefactFileFormat) {
		toSerialize["artefactFileFormat"] = o.ArtefactFileFormat
	}
	toSerialize["artefactDescriptorType"] = o.ArtefactDescriptorType
	if !isNil(o.RepoType) {
		toSerialize["repoType"] = o.RepoType
	}
	if !isNil(o.ArtefactRepoLocation) {
		toSerialize["artefactRepoLocation"] = o.ArtefactRepoLocation
	}
	return toSerialize, nil
}

type NullableArtefactDetails struct {
	value *ArtefactDetails
	isSet bool
}

func (v NullableArtefactDetails) Get() *ArtefactDetails {
	return v.value
}

func (v *NullableArtefactDetails) Set(val *ArtefactDetails) {
	v.value = val
	v.isSet = true
}

func (v NullableArtefactDetails) IsSet() bool {
	return v.isSet
}

func (v *NullableArtefactDetails) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableArtefactDetails(val *ArtefactDetails) *NullableArtefactDetails {
	return &NullableArtefactDetails{value: val, isSet: true}
}

func (v NullableArtefactDetails) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableArtefactDetails) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


