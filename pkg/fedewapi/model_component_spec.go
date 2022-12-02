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

// checks if the ComponentSpec type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &ComponentSpec{}

// ComponentSpec Details about compute, networking and storage requirements for each component of the application. App provider should  define all information needed to instantiate the component. If artefact is being defined at component level  this section should have information just about the component. In case the artefact is being defined at application level  the section should provide details about all the components.
type ComponentSpec struct {
	// Must be a valid RFC 1035 label name.  Component name must be unique with an application
	ComponentName string `json:"componentName"`
	OsType OSType `json:"osType"`
	InstSetArch CPUArchType `json:"InstSetArch"`
	// List of all images associated with the component. Images are uploaded or specified using Upload File apis
	ImagesPath []string `json:"imagesPath,omitempty"`
	// Number of component instances to be launched.
	NumOfInstances int32 `json:"numOfInstances"`
	// How the platform shall handle component failure
	RestartPolicy string `json:"restartPolicy"`
	CommandLineParams *CommandLineParams `json:"commandLineParams,omitempty"`
	// Each application component exposes some ports either for external users or for inter component communication. Application provider is required to specify which ports are to be exposed and the type of traffic that will flow through these ports.
	ExposedInterfaces []InterfaceDetails `json:"exposedInterfaces,omitempty"`
	ComputeResourceProfile ComputeResourceInfo `json:"computeResourceProfile"`
	CompEnvParams []CompEnvParams `json:"compEnvParams,omitempty"`
	// The ephemeral volume a container process may need to temporary store internal data
	PersistentVolumes []PersistentVolumeDetails `json:"persistentVolumes,omitempty"`
}

// NewComponentSpec instantiates a new ComponentSpec object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewComponentSpec(componentName string, osType OSType, instSetArch CPUArchType, numOfInstances int32, restartPolicy string, computeResourceProfile ComputeResourceInfo) *ComponentSpec {
	this := ComponentSpec{}
	this.ComponentName = componentName
	this.OsType = osType
	this.InstSetArch = instSetArch
	this.NumOfInstances = numOfInstances
	this.RestartPolicy = restartPolicy
	this.ComputeResourceProfile = computeResourceProfile
	return &this
}

// NewComponentSpecWithDefaults instantiates a new ComponentSpec object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewComponentSpecWithDefaults() *ComponentSpec {
	this := ComponentSpec{}
	return &this
}

// GetComponentName returns the ComponentName field value
func (o *ComponentSpec) GetComponentName() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.ComponentName
}

// GetComponentNameOk returns a tuple with the ComponentName field value
// and a boolean to check if the value has been set.
func (o *ComponentSpec) GetComponentNameOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.ComponentName, true
}

// SetComponentName sets field value
func (o *ComponentSpec) SetComponentName(v string) {
	o.ComponentName = v
}

// GetOsType returns the OsType field value
func (o *ComponentSpec) GetOsType() OSType {
	if o == nil {
		var ret OSType
		return ret
	}

	return o.OsType
}

// GetOsTypeOk returns a tuple with the OsType field value
// and a boolean to check if the value has been set.
func (o *ComponentSpec) GetOsTypeOk() (*OSType, bool) {
	if o == nil {
		return nil, false
	}
	return &o.OsType, true
}

// SetOsType sets field value
func (o *ComponentSpec) SetOsType(v OSType) {
	o.OsType = v
}

// GetInstSetArch returns the InstSetArch field value
func (o *ComponentSpec) GetInstSetArch() CPUArchType {
	if o == nil {
		var ret CPUArchType
		return ret
	}

	return o.InstSetArch
}

// GetInstSetArchOk returns a tuple with the InstSetArch field value
// and a boolean to check if the value has been set.
func (o *ComponentSpec) GetInstSetArchOk() (*CPUArchType, bool) {
	if o == nil {
		return nil, false
	}
	return &o.InstSetArch, true
}

// SetInstSetArch sets field value
func (o *ComponentSpec) SetInstSetArch(v CPUArchType) {
	o.InstSetArch = v
}

// GetImagesPath returns the ImagesPath field value if set, zero value otherwise.
func (o *ComponentSpec) GetImagesPath() []string {
	if o == nil || isNil(o.ImagesPath) {
		var ret []string
		return ret
	}
	return o.ImagesPath
}

// GetImagesPathOk returns a tuple with the ImagesPath field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ComponentSpec) GetImagesPathOk() ([]string, bool) {
	if o == nil || isNil(o.ImagesPath) {
		return nil, false
	}
	return o.ImagesPath, true
}

// HasImagesPath returns a boolean if a field has been set.
func (o *ComponentSpec) HasImagesPath() bool {
	if o != nil && !isNil(o.ImagesPath) {
		return true
	}

	return false
}

// SetImagesPath gets a reference to the given []string and assigns it to the ImagesPath field.
func (o *ComponentSpec) SetImagesPath(v []string) {
	o.ImagesPath = v
}

// GetNumOfInstances returns the NumOfInstances field value
func (o *ComponentSpec) GetNumOfInstances() int32 {
	if o == nil {
		var ret int32
		return ret
	}

	return o.NumOfInstances
}

// GetNumOfInstancesOk returns a tuple with the NumOfInstances field value
// and a boolean to check if the value has been set.
func (o *ComponentSpec) GetNumOfInstancesOk() (*int32, bool) {
	if o == nil {
		return nil, false
	}
	return &o.NumOfInstances, true
}

// SetNumOfInstances sets field value
func (o *ComponentSpec) SetNumOfInstances(v int32) {
	o.NumOfInstances = v
}

// GetRestartPolicy returns the RestartPolicy field value
func (o *ComponentSpec) GetRestartPolicy() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.RestartPolicy
}

// GetRestartPolicyOk returns a tuple with the RestartPolicy field value
// and a boolean to check if the value has been set.
func (o *ComponentSpec) GetRestartPolicyOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.RestartPolicy, true
}

// SetRestartPolicy sets field value
func (o *ComponentSpec) SetRestartPolicy(v string) {
	o.RestartPolicy = v
}

// GetCommandLineParams returns the CommandLineParams field value if set, zero value otherwise.
func (o *ComponentSpec) GetCommandLineParams() CommandLineParams {
	if o == nil || isNil(o.CommandLineParams) {
		var ret CommandLineParams
		return ret
	}
	return *o.CommandLineParams
}

// GetCommandLineParamsOk returns a tuple with the CommandLineParams field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ComponentSpec) GetCommandLineParamsOk() (*CommandLineParams, bool) {
	if o == nil || isNil(o.CommandLineParams) {
		return nil, false
	}
	return o.CommandLineParams, true
}

// HasCommandLineParams returns a boolean if a field has been set.
func (o *ComponentSpec) HasCommandLineParams() bool {
	if o != nil && !isNil(o.CommandLineParams) {
		return true
	}

	return false
}

// SetCommandLineParams gets a reference to the given CommandLineParams and assigns it to the CommandLineParams field.
func (o *ComponentSpec) SetCommandLineParams(v CommandLineParams) {
	o.CommandLineParams = &v
}

// GetExposedInterfaces returns the ExposedInterfaces field value if set, zero value otherwise.
func (o *ComponentSpec) GetExposedInterfaces() []InterfaceDetails {
	if o == nil || isNil(o.ExposedInterfaces) {
		var ret []InterfaceDetails
		return ret
	}
	return o.ExposedInterfaces
}

// GetExposedInterfacesOk returns a tuple with the ExposedInterfaces field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ComponentSpec) GetExposedInterfacesOk() ([]InterfaceDetails, bool) {
	if o == nil || isNil(o.ExposedInterfaces) {
		return nil, false
	}
	return o.ExposedInterfaces, true
}

// HasExposedInterfaces returns a boolean if a field has been set.
func (o *ComponentSpec) HasExposedInterfaces() bool {
	if o != nil && !isNil(o.ExposedInterfaces) {
		return true
	}

	return false
}

// SetExposedInterfaces gets a reference to the given []InterfaceDetails and assigns it to the ExposedInterfaces field.
func (o *ComponentSpec) SetExposedInterfaces(v []InterfaceDetails) {
	o.ExposedInterfaces = v
}

// GetComputeResourceProfile returns the ComputeResourceProfile field value
func (o *ComponentSpec) GetComputeResourceProfile() ComputeResourceInfo {
	if o == nil {
		var ret ComputeResourceInfo
		return ret
	}

	return o.ComputeResourceProfile
}

// GetComputeResourceProfileOk returns a tuple with the ComputeResourceProfile field value
// and a boolean to check if the value has been set.
func (o *ComponentSpec) GetComputeResourceProfileOk() (*ComputeResourceInfo, bool) {
	if o == nil {
		return nil, false
	}
	return &o.ComputeResourceProfile, true
}

// SetComputeResourceProfile sets field value
func (o *ComponentSpec) SetComputeResourceProfile(v ComputeResourceInfo) {
	o.ComputeResourceProfile = v
}

// GetCompEnvParams returns the CompEnvParams field value if set, zero value otherwise.
func (o *ComponentSpec) GetCompEnvParams() []CompEnvParams {
	if o == nil || isNil(o.CompEnvParams) {
		var ret []CompEnvParams
		return ret
	}
	return o.CompEnvParams
}

// GetCompEnvParamsOk returns a tuple with the CompEnvParams field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ComponentSpec) GetCompEnvParamsOk() ([]CompEnvParams, bool) {
	if o == nil || isNil(o.CompEnvParams) {
		return nil, false
	}
	return o.CompEnvParams, true
}

// HasCompEnvParams returns a boolean if a field has been set.
func (o *ComponentSpec) HasCompEnvParams() bool {
	if o != nil && !isNil(o.CompEnvParams) {
		return true
	}

	return false
}

// SetCompEnvParams gets a reference to the given []CompEnvParams and assigns it to the CompEnvParams field.
func (o *ComponentSpec) SetCompEnvParams(v []CompEnvParams) {
	o.CompEnvParams = v
}

// GetPersistentVolumes returns the PersistentVolumes field value if set, zero value otherwise.
func (o *ComponentSpec) GetPersistentVolumes() []PersistentVolumeDetails {
	if o == nil || isNil(o.PersistentVolumes) {
		var ret []PersistentVolumeDetails
		return ret
	}
	return o.PersistentVolumes
}

// GetPersistentVolumesOk returns a tuple with the PersistentVolumes field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ComponentSpec) GetPersistentVolumesOk() ([]PersistentVolumeDetails, bool) {
	if o == nil || isNil(o.PersistentVolumes) {
		return nil, false
	}
	return o.PersistentVolumes, true
}

// HasPersistentVolumes returns a boolean if a field has been set.
func (o *ComponentSpec) HasPersistentVolumes() bool {
	if o != nil && !isNil(o.PersistentVolumes) {
		return true
	}

	return false
}

// SetPersistentVolumes gets a reference to the given []PersistentVolumeDetails and assigns it to the PersistentVolumes field.
func (o *ComponentSpec) SetPersistentVolumes(v []PersistentVolumeDetails) {
	o.PersistentVolumes = v
}

func (o ComponentSpec) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o ComponentSpec) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["componentName"] = o.ComponentName
	toSerialize["osType"] = o.OsType
	toSerialize["InstSetArch"] = o.InstSetArch
	if !isNil(o.ImagesPath) {
		toSerialize["imagesPath"] = o.ImagesPath
	}
	toSerialize["numOfInstances"] = o.NumOfInstances
	toSerialize["restartPolicy"] = o.RestartPolicy
	if !isNil(o.CommandLineParams) {
		toSerialize["commandLineParams"] = o.CommandLineParams
	}
	if !isNil(o.ExposedInterfaces) {
		toSerialize["exposedInterfaces"] = o.ExposedInterfaces
	}
	toSerialize["computeResourceProfile"] = o.ComputeResourceProfile
	if !isNil(o.CompEnvParams) {
		toSerialize["compEnvParams"] = o.CompEnvParams
	}
	if !isNil(o.PersistentVolumes) {
		toSerialize["persistentVolumes"] = o.PersistentVolumes
	}
	return toSerialize, nil
}

type NullableComponentSpec struct {
	value *ComponentSpec
	isSet bool
}

func (v NullableComponentSpec) Get() *ComponentSpec {
	return v.value
}

func (v *NullableComponentSpec) Set(val *ComponentSpec) {
	v.value = val
	v.isSet = true
}

func (v NullableComponentSpec) IsSet() bool {
	return v.isSet
}

func (v *NullableComponentSpec) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableComponentSpec(val *ComponentSpec) *NullableComponentSpec {
	return &NullableComponentSpec{value: val, isSet: true}
}

func (v NullableComponentSpec) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableComponentSpec) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


