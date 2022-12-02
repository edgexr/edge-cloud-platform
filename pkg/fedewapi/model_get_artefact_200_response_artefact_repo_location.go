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

// checks if the GetArtefact200ResponseArtefactRepoLocation type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &GetArtefact200ResponseArtefactRepoLocation{}

// GetArtefact200ResponseArtefactRepoLocation struct for GetArtefact200ResponseArtefactRepoLocation
type GetArtefact200ResponseArtefactRepoLocation struct {
	// Artefact repository location. PUBLICREPO is used of public URLs like GitHub, Helm repo etc, PRIVATEREPO  is used for private repo managed by the application developer, UPLOAD is for the case when artefact is uploaded from MEC web portal.
	Repotype *string `json:"repotype,omitempty"`
	RepoURL string `json:"repoURL"`
	// Username to access the artefact repository
	UserName *string `json:"userName,omitempty"`
	// Password to access the artefact repository
	Password *string `json:"password,omitempty"`
	// Authorization token to access the artefact repository
	Token *string `json:"token,omitempty"`
}

// NewGetArtefact200ResponseArtefactRepoLocation instantiates a new GetArtefact200ResponseArtefactRepoLocation object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewGetArtefact200ResponseArtefactRepoLocation(repoURL string) *GetArtefact200ResponseArtefactRepoLocation {
	this := GetArtefact200ResponseArtefactRepoLocation{}
	this.RepoURL = repoURL
	return &this
}

// NewGetArtefact200ResponseArtefactRepoLocationWithDefaults instantiates a new GetArtefact200ResponseArtefactRepoLocation object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewGetArtefact200ResponseArtefactRepoLocationWithDefaults() *GetArtefact200ResponseArtefactRepoLocation {
	this := GetArtefact200ResponseArtefactRepoLocation{}
	return &this
}

// GetRepotype returns the Repotype field value if set, zero value otherwise.
func (o *GetArtefact200ResponseArtefactRepoLocation) GetRepotype() string {
	if o == nil || isNil(o.Repotype) {
		var ret string
		return ret
	}
	return *o.Repotype
}

// GetRepotypeOk returns a tuple with the Repotype field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetArtefact200ResponseArtefactRepoLocation) GetRepotypeOk() (*string, bool) {
	if o == nil || isNil(o.Repotype) {
		return nil, false
	}
	return o.Repotype, true
}

// HasRepotype returns a boolean if a field has been set.
func (o *GetArtefact200ResponseArtefactRepoLocation) HasRepotype() bool {
	if o != nil && !isNil(o.Repotype) {
		return true
	}

	return false
}

// SetRepotype gets a reference to the given string and assigns it to the Repotype field.
func (o *GetArtefact200ResponseArtefactRepoLocation) SetRepotype(v string) {
	o.Repotype = &v
}

// GetRepoURL returns the RepoURL field value
func (o *GetArtefact200ResponseArtefactRepoLocation) GetRepoURL() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.RepoURL
}

// GetRepoURLOk returns a tuple with the RepoURL field value
// and a boolean to check if the value has been set.
func (o *GetArtefact200ResponseArtefactRepoLocation) GetRepoURLOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.RepoURL, true
}

// SetRepoURL sets field value
func (o *GetArtefact200ResponseArtefactRepoLocation) SetRepoURL(v string) {
	o.RepoURL = v
}

// GetUserName returns the UserName field value if set, zero value otherwise.
func (o *GetArtefact200ResponseArtefactRepoLocation) GetUserName() string {
	if o == nil || isNil(o.UserName) {
		var ret string
		return ret
	}
	return *o.UserName
}

// GetUserNameOk returns a tuple with the UserName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetArtefact200ResponseArtefactRepoLocation) GetUserNameOk() (*string, bool) {
	if o == nil || isNil(o.UserName) {
		return nil, false
	}
	return o.UserName, true
}

// HasUserName returns a boolean if a field has been set.
func (o *GetArtefact200ResponseArtefactRepoLocation) HasUserName() bool {
	if o != nil && !isNil(o.UserName) {
		return true
	}

	return false
}

// SetUserName gets a reference to the given string and assigns it to the UserName field.
func (o *GetArtefact200ResponseArtefactRepoLocation) SetUserName(v string) {
	o.UserName = &v
}

// GetPassword returns the Password field value if set, zero value otherwise.
func (o *GetArtefact200ResponseArtefactRepoLocation) GetPassword() string {
	if o == nil || isNil(o.Password) {
		var ret string
		return ret
	}
	return *o.Password
}

// GetPasswordOk returns a tuple with the Password field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetArtefact200ResponseArtefactRepoLocation) GetPasswordOk() (*string, bool) {
	if o == nil || isNil(o.Password) {
		return nil, false
	}
	return o.Password, true
}

// HasPassword returns a boolean if a field has been set.
func (o *GetArtefact200ResponseArtefactRepoLocation) HasPassword() bool {
	if o != nil && !isNil(o.Password) {
		return true
	}

	return false
}

// SetPassword gets a reference to the given string and assigns it to the Password field.
func (o *GetArtefact200ResponseArtefactRepoLocation) SetPassword(v string) {
	o.Password = &v
}

// GetToken returns the Token field value if set, zero value otherwise.
func (o *GetArtefact200ResponseArtefactRepoLocation) GetToken() string {
	if o == nil || isNil(o.Token) {
		var ret string
		return ret
	}
	return *o.Token
}

// GetTokenOk returns a tuple with the Token field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GetArtefact200ResponseArtefactRepoLocation) GetTokenOk() (*string, bool) {
	if o == nil || isNil(o.Token) {
		return nil, false
	}
	return o.Token, true
}

// HasToken returns a boolean if a field has been set.
func (o *GetArtefact200ResponseArtefactRepoLocation) HasToken() bool {
	if o != nil && !isNil(o.Token) {
		return true
	}

	return false
}

// SetToken gets a reference to the given string and assigns it to the Token field.
func (o *GetArtefact200ResponseArtefactRepoLocation) SetToken(v string) {
	o.Token = &v
}

func (o GetArtefact200ResponseArtefactRepoLocation) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o GetArtefact200ResponseArtefactRepoLocation) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !isNil(o.Repotype) {
		toSerialize["repotype"] = o.Repotype
	}
	toSerialize["repoURL"] = o.RepoURL
	if !isNil(o.UserName) {
		toSerialize["userName"] = o.UserName
	}
	if !isNil(o.Password) {
		toSerialize["password"] = o.Password
	}
	if !isNil(o.Token) {
		toSerialize["token"] = o.Token
	}
	return toSerialize, nil
}

type NullableGetArtefact200ResponseArtefactRepoLocation struct {
	value *GetArtefact200ResponseArtefactRepoLocation
	isSet bool
}

func (v NullableGetArtefact200ResponseArtefactRepoLocation) Get() *GetArtefact200ResponseArtefactRepoLocation {
	return v.value
}

func (v *NullableGetArtefact200ResponseArtefactRepoLocation) Set(val *GetArtefact200ResponseArtefactRepoLocation) {
	v.value = val
	v.isSet = true
}

func (v NullableGetArtefact200ResponseArtefactRepoLocation) IsSet() bool {
	return v.isSet
}

func (v *NullableGetArtefact200ResponseArtefactRepoLocation) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableGetArtefact200ResponseArtefactRepoLocation(val *GetArtefact200ResponseArtefactRepoLocation) *NullableGetArtefact200ResponseArtefactRepoLocation {
	return &NullableGetArtefact200ResponseArtefactRepoLocation{value: val, isSet: true}
}

func (v NullableGetArtefact200ResponseArtefactRepoLocation) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableGetArtefact200ResponseArtefactRepoLocation) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


