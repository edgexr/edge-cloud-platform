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

// checks if the ViewApplication200Response type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &ViewApplication200Response{}

// ViewApplication200Response struct for ViewApplication200Response
type ViewApplication200Response struct {
	// Identifier used to refer to an application.
	AppId string `json:"appId"`
	// UserId of the app provider.  Identifier is relevant only in context of this federation.
	AppProviderId string `json:"appProviderId"`
	// Details about partner OP zones where the application should be made available;  This field when specified will instruct the OP to restrict application instantiation only on the listed zones.
	AppDeploymentZones []OnboardApplicationRequestAppDeploymentZonesInner `json:"appDeploymentZones"`
	AppMetaData AppMetaData `json:"appMetaData"`
	AppQoSProfile AppQoSProfile `json:"appQoSProfile"`
	// An application may consist of more than one component. Each component is associated with a descriptor and may exposes its services externally or internally.  App providers are required to provide details about all these components, their associated descriptors and their DNS names.
	AppComponentSpecs []AppComponentSpecsInner `json:"appComponentSpecs"`
}

// NewViewApplication200Response instantiates a new ViewApplication200Response object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewViewApplication200Response(appId string, appProviderId string, appDeploymentZones []OnboardApplicationRequestAppDeploymentZonesInner, appMetaData AppMetaData, appQoSProfile AppQoSProfile, appComponentSpecs []AppComponentSpecsInner) *ViewApplication200Response {
	this := ViewApplication200Response{}
	this.AppId = appId
	this.AppProviderId = appProviderId
	this.AppDeploymentZones = appDeploymentZones
	this.AppMetaData = appMetaData
	this.AppQoSProfile = appQoSProfile
	this.AppComponentSpecs = appComponentSpecs
	return &this
}

// NewViewApplication200ResponseWithDefaults instantiates a new ViewApplication200Response object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewViewApplication200ResponseWithDefaults() *ViewApplication200Response {
	this := ViewApplication200Response{}
	return &this
}

// GetAppId returns the AppId field value
func (o *ViewApplication200Response) GetAppId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.AppId
}

// GetAppIdOk returns a tuple with the AppId field value
// and a boolean to check if the value has been set.
func (o *ViewApplication200Response) GetAppIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.AppId, true
}

// SetAppId sets field value
func (o *ViewApplication200Response) SetAppId(v string) {
	o.AppId = v
}

// GetAppProviderId returns the AppProviderId field value
func (o *ViewApplication200Response) GetAppProviderId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.AppProviderId
}

// GetAppProviderIdOk returns a tuple with the AppProviderId field value
// and a boolean to check if the value has been set.
func (o *ViewApplication200Response) GetAppProviderIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.AppProviderId, true
}

// SetAppProviderId sets field value
func (o *ViewApplication200Response) SetAppProviderId(v string) {
	o.AppProviderId = v
}

// GetAppDeploymentZones returns the AppDeploymentZones field value
func (o *ViewApplication200Response) GetAppDeploymentZones() []OnboardApplicationRequestAppDeploymentZonesInner {
	if o == nil {
		var ret []OnboardApplicationRequestAppDeploymentZonesInner
		return ret
	}

	return o.AppDeploymentZones
}

// GetAppDeploymentZonesOk returns a tuple with the AppDeploymentZones field value
// and a boolean to check if the value has been set.
func (o *ViewApplication200Response) GetAppDeploymentZonesOk() ([]OnboardApplicationRequestAppDeploymentZonesInner, bool) {
	if o == nil {
		return nil, false
	}
	return o.AppDeploymentZones, true
}

// SetAppDeploymentZones sets field value
func (o *ViewApplication200Response) SetAppDeploymentZones(v []OnboardApplicationRequestAppDeploymentZonesInner) {
	o.AppDeploymentZones = v
}

// GetAppMetaData returns the AppMetaData field value
func (o *ViewApplication200Response) GetAppMetaData() AppMetaData {
	if o == nil {
		var ret AppMetaData
		return ret
	}

	return o.AppMetaData
}

// GetAppMetaDataOk returns a tuple with the AppMetaData field value
// and a boolean to check if the value has been set.
func (o *ViewApplication200Response) GetAppMetaDataOk() (*AppMetaData, bool) {
	if o == nil {
		return nil, false
	}
	return &o.AppMetaData, true
}

// SetAppMetaData sets field value
func (o *ViewApplication200Response) SetAppMetaData(v AppMetaData) {
	o.AppMetaData = v
}

// GetAppQoSProfile returns the AppQoSProfile field value
func (o *ViewApplication200Response) GetAppQoSProfile() AppQoSProfile {
	if o == nil {
		var ret AppQoSProfile
		return ret
	}

	return o.AppQoSProfile
}

// GetAppQoSProfileOk returns a tuple with the AppQoSProfile field value
// and a boolean to check if the value has been set.
func (o *ViewApplication200Response) GetAppQoSProfileOk() (*AppQoSProfile, bool) {
	if o == nil {
		return nil, false
	}
	return &o.AppQoSProfile, true
}

// SetAppQoSProfile sets field value
func (o *ViewApplication200Response) SetAppQoSProfile(v AppQoSProfile) {
	o.AppQoSProfile = v
}

// GetAppComponentSpecs returns the AppComponentSpecs field value
func (o *ViewApplication200Response) GetAppComponentSpecs() []AppComponentSpecsInner {
	if o == nil {
		var ret []AppComponentSpecsInner
		return ret
	}

	return o.AppComponentSpecs
}

// GetAppComponentSpecsOk returns a tuple with the AppComponentSpecs field value
// and a boolean to check if the value has been set.
func (o *ViewApplication200Response) GetAppComponentSpecsOk() ([]AppComponentSpecsInner, bool) {
	if o == nil {
		return nil, false
	}
	return o.AppComponentSpecs, true
}

// SetAppComponentSpecs sets field value
func (o *ViewApplication200Response) SetAppComponentSpecs(v []AppComponentSpecsInner) {
	o.AppComponentSpecs = v
}

func (o ViewApplication200Response) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o ViewApplication200Response) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["appId"] = o.AppId
	toSerialize["appProviderId"] = o.AppProviderId
	toSerialize["appDeploymentZones"] = o.AppDeploymentZones
	toSerialize["appMetaData"] = o.AppMetaData
	toSerialize["appQoSProfile"] = o.AppQoSProfile
	toSerialize["appComponentSpecs"] = o.AppComponentSpecs
	return toSerialize, nil
}

type NullableViewApplication200Response struct {
	value *ViewApplication200Response
	isSet bool
}

func (v NullableViewApplication200Response) Get() *ViewApplication200Response {
	return v.value
}

func (v *NullableViewApplication200Response) Set(val *ViewApplication200Response) {
	v.value = val
	v.isSet = true
}

func (v NullableViewApplication200Response) IsSet() bool {
	return v.isSet
}

func (v *NullableViewApplication200Response) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableViewApplication200Response(val *ViewApplication200Response) *NullableViewApplication200Response {
	return &NullableViewApplication200Response{value: val, isSet: true}
}

func (v NullableViewApplication200Response) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableViewApplication200Response) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


