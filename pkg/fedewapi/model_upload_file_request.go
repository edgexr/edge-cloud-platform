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
	"os"
	"regexp"
	"strings"
)

// checks if the UploadFileRequest type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &UploadFileRequest{}

// UploadFileRequest struct for UploadFileRequest
type UploadFileRequest struct {
	// A globally unique identifier associated with the image file. Originating OP generates this identifier when file is uploaded over NBI.
	FileId string `json:"fileId"`
	// UserId of the app provider. Identifier is relevant only in context of this federation.
	AppProviderId string `json:"appProviderId"`
	// Name of the image file.
	FileName string `json:"fileName"`
	// Brief description about the image file.
	FileDescription *string `json:"fileDescription,omitempty"`
	// File version information
	FileVersionInfo string        `json:"fileVersionInfo"`
	FileType        VirtImageType `json:"fileType"`
	// MD5 checksum for VM and file-based images, sha256 digest for containers
	Checksum      *string     `json:"checksum,omitempty"`
	ImgOSType     OSType      `json:"imgOSType"`
	ImgInsSetArch CPUArchType `json:"imgInsSetArch"`
	// Artefact or file repository location. PUBLICREPO is used of public URLs like GitHub, Helm repo, docker registry etc., PRIVATEREPO is used for private repo managed by the application developer, UPLOAD is for the case when artefact/file is uploaded from MEC web portal. OP should pull the image from ‘repoUrl' immediately after receiving the request and then send back the response. In case the repoURL corresponds to a docker registry, use docker v2 http api to do the pull.
	RepoType         *string             `json:"repoType,omitempty"`
	FileRepoLocation *ObjectRepoLocation `json:"fileRepoLocation,omitempty"`
	// Binary image associated with an application component.
	File **os.File `json:"file,omitempty"`
}

var UploadFileRequestAppProviderIdPattern = strings.TrimPrefix(strings.TrimSuffix("/^[a-z0-9]([-a-z0-9]{0,62}[a-z0-9])?$/", "/"), "/")
var UploadFileRequestAppProviderIdRE = regexp.MustCompile(UploadFileRequestAppProviderIdPattern)
var UploadFileRequestFileNamePattern = strings.TrimPrefix(strings.TrimSuffix("/^[A-Za-z0-9_][A-Za-z0-9_\\.-]{0,127}$/", "/"), "/")
var UploadFileRequestFileNameRE = regexp.MustCompile(UploadFileRequestFileNamePattern)

func (s *UploadFileRequest) Validate() error {
	if s.FileId == "" {
		return errors.New("fileId is required")
	}
	if s.AppProviderId == "" {
		return errors.New("appProviderId is required")
	}
	if !UploadFileRequestAppProviderIdRE.MatchString(s.AppProviderId) {
		return errors.New("appProviderId " + s.AppProviderId + " does not match format " + UploadFileRequestAppProviderIdPattern)
	}
	if s.FileName == "" {
		return errors.New("fileName is required")
	}
	if !UploadFileRequestFileNameRE.MatchString(s.FileName) {
		return errors.New("fileName " + s.FileName + " does not match format " + UploadFileRequestFileNamePattern)
	}
	if s.FileVersionInfo == "" {
		return errors.New("fileVersionInfo is required")
	}
	if err := s.ImgOSType.Validate(); err != nil {
		return err
	}
	if s.FileRepoLocation != nil {
		if err := s.FileRepoLocation.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// NewUploadFileRequest instantiates a new UploadFileRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewUploadFileRequest(fileId string, appProviderId string, fileName string, fileVersionInfo string, fileType VirtImageType, imgOSType OSType, imgInsSetArch CPUArchType) *UploadFileRequest {
	this := UploadFileRequest{}
	this.FileId = fileId
	this.AppProviderId = appProviderId
	this.FileName = fileName
	this.FileVersionInfo = fileVersionInfo
	this.FileType = fileType
	this.ImgOSType = imgOSType
	this.ImgInsSetArch = imgInsSetArch
	return &this
}

// NewUploadFileRequestWithDefaults instantiates a new UploadFileRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewUploadFileRequestWithDefaults() *UploadFileRequest {
	this := UploadFileRequest{}
	return &this
}

// GetFileId returns the FileId field value
func (o *UploadFileRequest) GetFileId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.FileId
}

// GetFileIdOk returns a tuple with the FileId field value
// and a boolean to check if the value has been set.
func (o *UploadFileRequest) GetFileIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.FileId, true
}

// SetFileId sets field value
func (o *UploadFileRequest) SetFileId(v string) {
	o.FileId = v
}

// GetAppProviderId returns the AppProviderId field value
func (o *UploadFileRequest) GetAppProviderId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.AppProviderId
}

// GetAppProviderIdOk returns a tuple with the AppProviderId field value
// and a boolean to check if the value has been set.
func (o *UploadFileRequest) GetAppProviderIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.AppProviderId, true
}

// SetAppProviderId sets field value
func (o *UploadFileRequest) SetAppProviderId(v string) {
	o.AppProviderId = v
}

// GetFileName returns the FileName field value
func (o *UploadFileRequest) GetFileName() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.FileName
}

// GetFileNameOk returns a tuple with the FileName field value
// and a boolean to check if the value has been set.
func (o *UploadFileRequest) GetFileNameOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.FileName, true
}

// SetFileName sets field value
func (o *UploadFileRequest) SetFileName(v string) {
	o.FileName = v
}

// GetFileDescription returns the FileDescription field value if set, zero value otherwise.
func (o *UploadFileRequest) GetFileDescription() string {
	if o == nil || isNil(o.FileDescription) {
		var ret string
		return ret
	}
	return *o.FileDescription
}

// GetFileDescriptionOk returns a tuple with the FileDescription field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *UploadFileRequest) GetFileDescriptionOk() (*string, bool) {
	if o == nil || isNil(o.FileDescription) {
		return nil, false
	}
	return o.FileDescription, true
}

// HasFileDescription returns a boolean if a field has been set.
func (o *UploadFileRequest) HasFileDescription() bool {
	if o != nil && !isNil(o.FileDescription) {
		return true
	}

	return false
}

// SetFileDescription gets a reference to the given string and assigns it to the FileDescription field.
func (o *UploadFileRequest) SetFileDescription(v string) {
	o.FileDescription = &v
}

// GetFileVersionInfo returns the FileVersionInfo field value
func (o *UploadFileRequest) GetFileVersionInfo() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.FileVersionInfo
}

// GetFileVersionInfoOk returns a tuple with the FileVersionInfo field value
// and a boolean to check if the value has been set.
func (o *UploadFileRequest) GetFileVersionInfoOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.FileVersionInfo, true
}

// SetFileVersionInfo sets field value
func (o *UploadFileRequest) SetFileVersionInfo(v string) {
	o.FileVersionInfo = v
}

// GetFileType returns the FileType field value
func (o *UploadFileRequest) GetFileType() VirtImageType {
	if o == nil {
		var ret VirtImageType
		return ret
	}

	return o.FileType
}

// GetFileTypeOk returns a tuple with the FileType field value
// and a boolean to check if the value has been set.
func (o *UploadFileRequest) GetFileTypeOk() (*VirtImageType, bool) {
	if o == nil {
		return nil, false
	}
	return &o.FileType, true
}

// SetFileType sets field value
func (o *UploadFileRequest) SetFileType(v VirtImageType) {
	o.FileType = v
}

// GetChecksum returns the Checksum field value if set, zero value otherwise.
func (o *UploadFileRequest) GetChecksum() string {
	if o == nil || isNil(o.Checksum) {
		var ret string
		return ret
	}
	return *o.Checksum
}

// GetChecksumOk returns a tuple with the Checksum field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *UploadFileRequest) GetChecksumOk() (*string, bool) {
	if o == nil || isNil(o.Checksum) {
		return nil, false
	}
	return o.Checksum, true
}

// HasChecksum returns a boolean if a field has been set.
func (o *UploadFileRequest) HasChecksum() bool {
	if o != nil && !isNil(o.Checksum) {
		return true
	}

	return false
}

// SetChecksum gets a reference to the given string and assigns it to the Checksum field.
func (o *UploadFileRequest) SetChecksum(v string) {
	o.Checksum = &v
}

// GetImgOSType returns the ImgOSType field value
func (o *UploadFileRequest) GetImgOSType() OSType {
	if o == nil {
		var ret OSType
		return ret
	}

	return o.ImgOSType
}

// GetImgOSTypeOk returns a tuple with the ImgOSType field value
// and a boolean to check if the value has been set.
func (o *UploadFileRequest) GetImgOSTypeOk() (*OSType, bool) {
	if o == nil {
		return nil, false
	}
	return &o.ImgOSType, true
}

// SetImgOSType sets field value
func (o *UploadFileRequest) SetImgOSType(v OSType) {
	o.ImgOSType = v
}

// GetImgInsSetArch returns the ImgInsSetArch field value
func (o *UploadFileRequest) GetImgInsSetArch() CPUArchType {
	if o == nil {
		var ret CPUArchType
		return ret
	}

	return o.ImgInsSetArch
}

// GetImgInsSetArchOk returns a tuple with the ImgInsSetArch field value
// and a boolean to check if the value has been set.
func (o *UploadFileRequest) GetImgInsSetArchOk() (*CPUArchType, bool) {
	if o == nil {
		return nil, false
	}
	return &o.ImgInsSetArch, true
}

// SetImgInsSetArch sets field value
func (o *UploadFileRequest) SetImgInsSetArch(v CPUArchType) {
	o.ImgInsSetArch = v
}

// GetRepoType returns the RepoType field value if set, zero value otherwise.
func (o *UploadFileRequest) GetRepoType() string {
	if o == nil || isNil(o.RepoType) {
		var ret string
		return ret
	}
	return *o.RepoType
}

// GetRepoTypeOk returns a tuple with the RepoType field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *UploadFileRequest) GetRepoTypeOk() (*string, bool) {
	if o == nil || isNil(o.RepoType) {
		return nil, false
	}
	return o.RepoType, true
}

// HasRepoType returns a boolean if a field has been set.
func (o *UploadFileRequest) HasRepoType() bool {
	if o != nil && !isNil(o.RepoType) {
		return true
	}

	return false
}

// SetRepoType gets a reference to the given string and assigns it to the RepoType field.
func (o *UploadFileRequest) SetRepoType(v string) {
	o.RepoType = &v
}

// GetFileRepoLocation returns the FileRepoLocation field value if set, zero value otherwise.
func (o *UploadFileRequest) GetFileRepoLocation() ObjectRepoLocation {
	if o == nil || isNil(o.FileRepoLocation) {
		var ret ObjectRepoLocation
		return ret
	}
	return *o.FileRepoLocation
}

// GetFileRepoLocationOk returns a tuple with the FileRepoLocation field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *UploadFileRequest) GetFileRepoLocationOk() (*ObjectRepoLocation, bool) {
	if o == nil || isNil(o.FileRepoLocation) {
		return nil, false
	}
	return o.FileRepoLocation, true
}

// HasFileRepoLocation returns a boolean if a field has been set.
func (o *UploadFileRequest) HasFileRepoLocation() bool {
	if o != nil && !isNil(o.FileRepoLocation) {
		return true
	}

	return false
}

// SetFileRepoLocation gets a reference to the given ObjectRepoLocation and assigns it to the FileRepoLocation field.
func (o *UploadFileRequest) SetFileRepoLocation(v ObjectRepoLocation) {
	o.FileRepoLocation = &v
}

// GetFile returns the File field value if set, zero value otherwise.
func (o *UploadFileRequest) GetFile() *os.File {
	if o == nil || isNil(o.File) {
		var ret *os.File
		return ret
	}
	return *o.File
}

// GetFileOk returns a tuple with the File field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *UploadFileRequest) GetFileOk() (**os.File, bool) {
	if o == nil || isNil(o.File) {
		return nil, false
	}
	return o.File, true
}

// HasFile returns a boolean if a field has been set.
func (o *UploadFileRequest) HasFile() bool {
	if o != nil && !isNil(o.File) {
		return true
	}

	return false
}

// SetFile gets a reference to the given *os.File and assigns it to the File field.
func (o *UploadFileRequest) SetFile(v *os.File) {
	o.File = &v
}

func (o UploadFileRequest) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o UploadFileRequest) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["fileId"] = o.FileId
	toSerialize["appProviderId"] = o.AppProviderId
	toSerialize["fileName"] = o.FileName
	if !isNil(o.FileDescription) {
		toSerialize["fileDescription"] = o.FileDescription
	}
	toSerialize["fileVersionInfo"] = o.FileVersionInfo
	toSerialize["fileType"] = o.FileType
	if !isNil(o.Checksum) {
		toSerialize["checksum"] = o.Checksum
	}
	toSerialize["imgOSType"] = o.ImgOSType
	toSerialize["imgInsSetArch"] = o.ImgInsSetArch
	if !isNil(o.RepoType) {
		toSerialize["repoType"] = o.RepoType
	}
	if !isNil(o.FileRepoLocation) {
		toSerialize["fileRepoLocation"] = o.FileRepoLocation
	}
	if !isNil(o.File) {
		toSerialize["file"] = o.File
	}
	return toSerialize, nil
}

type NullableUploadFileRequest struct {
	value *UploadFileRequest
	isSet bool
}

func (v NullableUploadFileRequest) Get() *UploadFileRequest {
	return v.value
}

func (v *NullableUploadFileRequest) Set(val *UploadFileRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableUploadFileRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableUploadFileRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableUploadFileRequest(val *UploadFileRequest) *NullableUploadFileRequest {
	return &NullableUploadFileRequest{value: val, isSet: true}
}

func (v NullableUploadFileRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableUploadFileRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
