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

// checks if the ComputeResourceInfo type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &ComputeResourceInfo{}

// ComputeResourceInfo struct for ComputeResourceInfo
type ComputeResourceInfo struct {
	// CPU Instruction Set Architecture (ISA) E.g., Intel, Arm etc.
	CpuArchType string `json:"cpuArchType"`
	// Number of vcpus in whole, decimal up to millivcpu, or millivcpu format.
	NumCPU string `json:"numCPU"`
	// Amount of RAM in Mbytes
	Memory int64 `json:"memory"`
	// Amount of disk storage in Gbytes for a given ISA type
	DiskStorage *int32    `json:"diskStorage,omitempty"`
	Gpu         []GpuInfo `json:"gpu,omitempty"`
	// Number of Intel VPUs available for a given ISA type
	Vpu *int32 `json:"vpu,omitempty"`
	// Number of FPGAs available for a given ISA type
	Fpga      *int32     `json:"fpga,omitempty"`
	Hugepages []HugePage `json:"hugepages,omitempty"`
	// Support for exclusive CPUs
	CpuExclusivity *bool `json:"cpuExclusivity,omitempty"`
}

var ComputeResourceInfoNumCPUPattern = strings.TrimPrefix(strings.TrimSuffix("/^\\d+((\\.\\d{1,3})|(m))?$/", "/"), "/")
var ComputeResourceInfoNumCPURE = regexp.MustCompile(ComputeResourceInfoNumCPUPattern)

func (s *ComputeResourceInfo) Validate() error {
	if s.CpuArchType == "" {
		return errors.New("cpuArchType is required")
	}
	CpuArchTypeEnumVals := map[string]struct{}{
		"ISA_X86_64": {},
		"ISA_ARM_64": {},
	}
	if _, found := CpuArchTypeEnumVals[s.CpuArchType]; !found {
		return errors.New("ComputeResourceInfo cpuArchType value \"" + s.CpuArchType + "\" is not a valid enum value")
	}
	if s.NumCPU == "" {
		return errors.New("numCPU is required")
	}
	if !ComputeResourceInfoNumCPURE.MatchString(s.NumCPU) {
		return errors.New("numCPU " + s.NumCPU + " does not match format " + ComputeResourceInfoNumCPUPattern)
	}
	for ii := range s.Gpu {
		if err := s.Gpu[ii].Validate(); err != nil {
			return err
		}
	}
	for ii := range s.Hugepages {
		if err := s.Hugepages[ii].Validate(); err != nil {
			return err
		}
	}
	return nil
}

// NewComputeResourceInfo instantiates a new ComputeResourceInfo object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewComputeResourceInfo(cpuArchType string, numCPU string, memory int64) *ComputeResourceInfo {
	this := ComputeResourceInfo{}
	this.CpuArchType = cpuArchType
	this.NumCPU = numCPU
	this.Memory = memory
	return &this
}

// NewComputeResourceInfoWithDefaults instantiates a new ComputeResourceInfo object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewComputeResourceInfoWithDefaults() *ComputeResourceInfo {
	this := ComputeResourceInfo{}
	return &this
}

// GetCpuArchType returns the CpuArchType field value
func (o *ComputeResourceInfo) GetCpuArchType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.CpuArchType
}

// GetCpuArchTypeOk returns a tuple with the CpuArchType field value
// and a boolean to check if the value has been set.
func (o *ComputeResourceInfo) GetCpuArchTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.CpuArchType, true
}

// SetCpuArchType sets field value
func (o *ComputeResourceInfo) SetCpuArchType(v string) {
	o.CpuArchType = v
}

// GetNumCPU returns the NumCPU field value
func (o *ComputeResourceInfo) GetNumCPU() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.NumCPU
}

// GetNumCPUOk returns a tuple with the NumCPU field value
// and a boolean to check if the value has been set.
func (o *ComputeResourceInfo) GetNumCPUOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.NumCPU, true
}

// SetNumCPU sets field value
func (o *ComputeResourceInfo) SetNumCPU(v string) {
	o.NumCPU = v
}

// GetMemory returns the Memory field value
func (o *ComputeResourceInfo) GetMemory() int64 {
	if o == nil {
		var ret int64
		return ret
	}

	return o.Memory
}

// GetMemoryOk returns a tuple with the Memory field value
// and a boolean to check if the value has been set.
func (o *ComputeResourceInfo) GetMemoryOk() (*int64, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Memory, true
}

// SetMemory sets field value
func (o *ComputeResourceInfo) SetMemory(v int64) {
	o.Memory = v
}

// GetDiskStorage returns the DiskStorage field value if set, zero value otherwise.
func (o *ComputeResourceInfo) GetDiskStorage() int32 {
	if o == nil || isNil(o.DiskStorage) {
		var ret int32
		return ret
	}
	return *o.DiskStorage
}

// GetDiskStorageOk returns a tuple with the DiskStorage field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ComputeResourceInfo) GetDiskStorageOk() (*int32, bool) {
	if o == nil || isNil(o.DiskStorage) {
		return nil, false
	}
	return o.DiskStorage, true
}

// HasDiskStorage returns a boolean if a field has been set.
func (o *ComputeResourceInfo) HasDiskStorage() bool {
	if o != nil && !isNil(o.DiskStorage) {
		return true
	}

	return false
}

// SetDiskStorage gets a reference to the given int32 and assigns it to the DiskStorage field.
func (o *ComputeResourceInfo) SetDiskStorage(v int32) {
	o.DiskStorage = &v
}

// GetGpu returns the Gpu field value if set, zero value otherwise.
func (o *ComputeResourceInfo) GetGpu() []GpuInfo {
	if o == nil || isNil(o.Gpu) {
		var ret []GpuInfo
		return ret
	}
	return o.Gpu
}

// GetGpuOk returns a tuple with the Gpu field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ComputeResourceInfo) GetGpuOk() ([]GpuInfo, bool) {
	if o == nil || isNil(o.Gpu) {
		return nil, false
	}
	return o.Gpu, true
}

// HasGpu returns a boolean if a field has been set.
func (o *ComputeResourceInfo) HasGpu() bool {
	if o != nil && !isNil(o.Gpu) {
		return true
	}

	return false
}

// SetGpu gets a reference to the given []GpuInfo and assigns it to the Gpu field.
func (o *ComputeResourceInfo) SetGpu(v []GpuInfo) {
	o.Gpu = v
}

// GetVpu returns the Vpu field value if set, zero value otherwise.
func (o *ComputeResourceInfo) GetVpu() int32 {
	if o == nil || isNil(o.Vpu) {
		var ret int32
		return ret
	}
	return *o.Vpu
}

// GetVpuOk returns a tuple with the Vpu field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ComputeResourceInfo) GetVpuOk() (*int32, bool) {
	if o == nil || isNil(o.Vpu) {
		return nil, false
	}
	return o.Vpu, true
}

// HasVpu returns a boolean if a field has been set.
func (o *ComputeResourceInfo) HasVpu() bool {
	if o != nil && !isNil(o.Vpu) {
		return true
	}

	return false
}

// SetVpu gets a reference to the given int32 and assigns it to the Vpu field.
func (o *ComputeResourceInfo) SetVpu(v int32) {
	o.Vpu = &v
}

// GetFpga returns the Fpga field value if set, zero value otherwise.
func (o *ComputeResourceInfo) GetFpga() int32 {
	if o == nil || isNil(o.Fpga) {
		var ret int32
		return ret
	}
	return *o.Fpga
}

// GetFpgaOk returns a tuple with the Fpga field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ComputeResourceInfo) GetFpgaOk() (*int32, bool) {
	if o == nil || isNil(o.Fpga) {
		return nil, false
	}
	return o.Fpga, true
}

// HasFpga returns a boolean if a field has been set.
func (o *ComputeResourceInfo) HasFpga() bool {
	if o != nil && !isNil(o.Fpga) {
		return true
	}

	return false
}

// SetFpga gets a reference to the given int32 and assigns it to the Fpga field.
func (o *ComputeResourceInfo) SetFpga(v int32) {
	o.Fpga = &v
}

// GetHugepages returns the Hugepages field value if set, zero value otherwise.
func (o *ComputeResourceInfo) GetHugepages() []HugePage {
	if o == nil || isNil(o.Hugepages) {
		var ret []HugePage
		return ret
	}
	return o.Hugepages
}

// GetHugepagesOk returns a tuple with the Hugepages field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ComputeResourceInfo) GetHugepagesOk() ([]HugePage, bool) {
	if o == nil || isNil(o.Hugepages) {
		return nil, false
	}
	return o.Hugepages, true
}

// HasHugepages returns a boolean if a field has been set.
func (o *ComputeResourceInfo) HasHugepages() bool {
	if o != nil && !isNil(o.Hugepages) {
		return true
	}

	return false
}

// SetHugepages gets a reference to the given []HugePage and assigns it to the Hugepages field.
func (o *ComputeResourceInfo) SetHugepages(v []HugePage) {
	o.Hugepages = v
}

// GetCpuExclusivity returns the CpuExclusivity field value if set, zero value otherwise.
func (o *ComputeResourceInfo) GetCpuExclusivity() bool {
	if o == nil || isNil(o.CpuExclusivity) {
		var ret bool
		return ret
	}
	return *o.CpuExclusivity
}

// GetCpuExclusivityOk returns a tuple with the CpuExclusivity field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ComputeResourceInfo) GetCpuExclusivityOk() (*bool, bool) {
	if o == nil || isNil(o.CpuExclusivity) {
		return nil, false
	}
	return o.CpuExclusivity, true
}

// HasCpuExclusivity returns a boolean if a field has been set.
func (o *ComputeResourceInfo) HasCpuExclusivity() bool {
	if o != nil && !isNil(o.CpuExclusivity) {
		return true
	}

	return false
}

// SetCpuExclusivity gets a reference to the given bool and assigns it to the CpuExclusivity field.
func (o *ComputeResourceInfo) SetCpuExclusivity(v bool) {
	o.CpuExclusivity = &v
}

func (o ComputeResourceInfo) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o ComputeResourceInfo) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["cpuArchType"] = o.CpuArchType
	toSerialize["numCPU"] = o.NumCPU
	toSerialize["memory"] = o.Memory
	if !isNil(o.DiskStorage) {
		toSerialize["diskStorage"] = o.DiskStorage
	}
	if !isNil(o.Gpu) {
		toSerialize["gpu"] = o.Gpu
	}
	if !isNil(o.Vpu) {
		toSerialize["vpu"] = o.Vpu
	}
	if !isNil(o.Fpga) {
		toSerialize["fpga"] = o.Fpga
	}
	if !isNil(o.Hugepages) {
		toSerialize["hugepages"] = o.Hugepages
	}
	if !isNil(o.CpuExclusivity) {
		toSerialize["cpuExclusivity"] = o.CpuExclusivity
	}
	return toSerialize, nil
}

type NullableComputeResourceInfo struct {
	value *ComputeResourceInfo
	isSet bool
}

func (v NullableComputeResourceInfo) Get() *ComputeResourceInfo {
	return v.value
}

func (v *NullableComputeResourceInfo) Set(val *ComputeResourceInfo) {
	v.value = val
	v.isSet = true
}

func (v NullableComputeResourceInfo) IsSet() bool {
	return v.isSet
}

func (v *NullableComputeResourceInfo) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableComputeResourceInfo(val *ComputeResourceInfo) *NullableComputeResourceInfo {
	return &NullableComputeResourceInfo{value: val, isSet: true}
}

func (v NullableComputeResourceInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableComputeResourceInfo) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
