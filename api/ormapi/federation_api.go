// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ormapi

import (
	"time"

	edgeproto "github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/lib/pq"
)

// Federation provider is a Federation where I provide my resources
// to the partner OP, and allow them to deploy their applications on
// my infrastructure. This relationship is initiated by the partner OP.
type FederationProvider struct {
	// Unique ID
	ID uint `gorm:"primary_key"`
	// Unique name of this federation Host, will be used as a developer org name for Guest OP's images and apps
	Name string `gorm:"type:citext REFERENCES organizations(name);unique;not null"`
	// Operator Organization that provides the resources
	OperatorId string `gorm:"type:citext REFERENCES organizations(name);not null"`
	// Regions from which to provide resources
	Regions pq.StringArray `gorm:"type:text[]"`
	// The federation context id we generated for this federation
	FederationContextId string `gorm:"unique;not null"`
	// My federation info provided to the partner
	MyInfo Federator `gorm:"embedded;embedded_prefix:my_"`
	// Partner federation info
	PartnerInfo Federator `gorm:"embedded;embedded_prefix:partner_"`
	// Partner notification URI
	PartnerNotifyDest string
	// Partner Oauth token URI
	PartnerNotifyTokenUrl string
	// Partner notification client id
	PartnerNotifyClientId string
	// Partner notification client key (saved in secret storage)
	PartnerNotifyClientKey string
	// Default container deployment type (either docker or kubernetes)
	DefaultContainerDeployment string
	// Status
	// read only: true
	Status string
	// Host client ID for inbound connections
	ProviderClientId string
	// Time created
	// read only: true
	CreatedAt time.Time `json:",omitempty"`
	// Time updated
	// read only: true
	UpdatedAt time.Time `json:",omitempty"`
}

// Returned from creating a FederationHost, give this to partner Operator.
type FederationProviderInfo struct {
	// Client ID for Oauth
	ClientId string
	// Client Key for Oauth. Save this, as it the system cannot retrieve it.
	ClientKey string
	// Target Address for EWBI create
	TargetAddr string
	// Oauth2 token URL
	TokenUrl string
}

// Federation Guest is a Federation where I use resources
// given by the partner OP, and I can deploy my applications on
// their infrastructure. This relationship is initiated by me.
type FederationConsumer struct {
	// Unique ID
	ID uint `gorm:"primary_key"`
	// Unique name of this Federation Guest, will be used as an operator org for host's zones
	Name string `gorm:"type:citext REFERENCES organizations(name);unique;not null"`
	// Operator Organization that establishes the federation with a Host OP
	OperatorId string `gorm:"type:citext REFERENCES organizations(name);not null"`
	// Public means any developer will be able to use the cloudlets, otherwise (TODO) allowed developers will need to be added explicitly
	Public bool
	// Partner Address
	PartnerAddr string `gorm:"not null"`
	// Partner token URL
	PartnerTokenUrl string
	// Federation context id returned by partner
	FederationContextId string
	// My federation info provided to partner
	MyInfo Federator `gorm:"embedded;embedded_prefix:my_"`
	// Partner federation info
	PartnerInfo Federator `gorm:"embedded;embedded_prefix:partner_"`
	// Automatically register any zone shared with me
	AutoRegisterZones bool
	// Region used for automatically registered zones
	AutoRegisterRegion string
	// Status
	// read only: true
	Status string
	// Auth ClientId for connecting to the Host OP
	ProviderClientId string
	// Auth ClientKey for connection to the Host OP (stored in secret storage)
	ProviderClientKey string
	// Auth ClientId for notify callbacks to this Guest OP
	NotifyClientId string
	// Time created
	// read only: true
	CreatedAt time.Time `json:",omitempty"`
	// Time updated
	// read only: true
	UpdatedAt time.Time `json:",omitempty"`
}

// Federation Guest auth credentials for callbacks. Give these to the Host OP.
type FederationConsumerAuth struct {
	// Client ID for Oauth
	ClientId string
	// Client Key for Oauth
	ClientKey string
}

// Federator contains operator properties. It is never saved
// to the db standalone, but only as part of a federation.
type Federator struct {
	// Globally unique string used to indentify a federation operator
	FederationId string
	// ISO 3166-1 Alpha-2 code for the country where operator platform is located
	CountryCode string
	// Mobile country code of operator sending the request
	MCC string
	// List of mobile network codes of operator sending the request
	MNC pq.StringArray `gorm:"type:text[]"`
	// Fixed link network ids
	FixedNetworkIds pq.StringArray `gorm:"type:text[]"`
	// IP and Port of discovery service URL of operator platform
	DiscoveryEndPoint string
	// Initial create time to denote time zone
	InitialDate time.Time
}

// Base definition of zone owned by an Operator. MC defines
// a zone as a group of cloudlets, but currently it is
// restricted to one cloudlet.
type ProviderZoneBase struct {
	// Unique name for zone
	ZoneId string `gorm:"primary_key"`
	// Operator organization
	OperatorId string `gorm:"primary_key;type:citext REFERENCES organizations(name)"`
	// ISO 3166-1 Alpha-2 code for the country where operator platform is located
	CountryCode string
	// GPS co-ordinates associated with the zone (in decimal format)
	GeoLocation string
	// Geography details
	GeographyDetails string
	// Region in which cloudlets reside
	Region string
	// List of cloudlets part of this zone
	Cloudlets pq.StringArray `gorm:"type:text[]"`
}

// Local Zone shared via FederationHost
type ProviderZone struct {
	// Globally unique identifier of the federator zone
	ZoneId string `gorm:"primary_key"`
	// Name of the Federation Host OP
	ProviderName string `gorm:"primary_key;type:citext"`
	// Host operator organization
	OperatorId string `gorm:"type:citext"`
	// Zone status
	// read only: true
	Status string
	// Partner notify zone URI
	PartnerNotifyZoneURI string
}

// Remote zone shared with us via FederationGuest
type ConsumerZone struct {
	// Zone unique name
	ZoneId string `gorm:"primary_key"`
	// Name of the Federation Guest
	ConsumerName string `gorm:"primary_key;type:citext"`
	// Guest operator organization
	OperatorId string `gorm:"type:citext REFERENCES organizations(name)"`
	// Region in which zone is instantiated
	Region string
	// GPS co-ordinates associated with the zone (in decimal format)
	GeoLocation string
	// Geography details
	GeographyDetails string
	// Zone status
	// read only: true
	Status string
}

// Register/Deregister partner zones shared as part of federation
type FederatedZoneRegRequest struct {
	// Federation Guest name
	FedGuest string
	// Region to create local cloudlet versions of Host zones
	Region string
	// Partner federator zones to be registered/deregistered
	Zones []string
}

// Share/Unshare self zones shared as part of federation
type FederatedZoneShareRequest struct {
	// Federation Host name
	FedHost string
	// Self federator zones to be shared/unshared
	Zones []string
}

// Guest images are local images copied to a Host operator
type ConsumerImage struct {
	// ID
	ID string `gorm:"primary_key"`
	// Developer organization that owns the image
	Organization string `gorm:"unique_index:consumerimageindex;type:citext;not null"`
	// Federation the image is copied to (FederationGuest)
	FederationName string `gorm:"unique_index:consumerimageindex;type:citext;not null"`
	// Image name
	Name string `gorm:"unique_index:consumerimageindex;type:text;not null"`
	// Image version
	Version string
	// Full path to source image as used in App, i.e. https://vm-registry.domain/org/image.img
	SourcePath string
	// Image type (DOCKER, HELM, QCOW2, or OVA)
	Type string
	// MD5 checksum for VM and file-based image types, sha256 digest for containers and Helm charts
	Checksum string
	// Image status
	// read only: true
	Status string
}

// Host images are images copied from the Guest
type ProviderImage struct {
	// Host federation name
	FederationName string `gorm:"primary_key;type:citext;not null"`
	// File ID sent by partner
	FileID string `gorm:"primary_key;type:citext;not null"`
	// Image path
	Path string
	// Image name
	Name string
	// Image description
	Description string
	// Image version
	Version string
	// Image type (DOCKER, HELM, QCOW2, or OVA)
	Type string
	// Partner app provider organization
	AppProviderId string
	// MD5 checksum for VM and file-based image types, sha256 digest for containers and Helm charts
	Checksum string
	// Image status
	Status string
}

// GuestApp tracks an App that has been onboarded to the partner.
// The same App in different regions must be onboarded per region.
type ConsumerApp struct {
	// Unique ID, acts as both the App and Artefact IDs
	ID string `gorm:"primary_key"`
	// Target Guest Federation name
	FederationName string `gorm:"primary_key;type:citext;not null"`
	// Region name
	// required: true
	Region string
	// App name in region
	AppName string
	// App org in region
	AppOrg string
	// App version in region
	AppVers string
	// Image IDs belonging to artefacts
	ImageIds pq.StringArray `gorm:"type:text[]"`
	// Status
	// read only: true
	Status string
}

// Tracks an App created in the Host OP's regions for an Artefact
type ProviderArtefact struct {
	// Host Federation name
	FederationName string `gorm:"primary_key;type:citext;not null"`
	// Artefact ID send by partner
	ArtefactID string `gorm:"primary_key;type:text;not null"`
	// Artefact name
	ArtefactName string
	// Artefact version
	ArtefactVersion string
	// App name in region
	AppName string
	// App version in region
	AppVers string
	// App provider ID
	AppProviderId string
	// Virtualization Type
	VirtType string
	// Descriptor Type
	DescType string
	// File IDs used by Artefact
	FileIds pq.StringArray `gorm:"type:text[]"`
}

type ProviderApp struct {
	// Host Federation name
	FederationName string `gorm:"primary_key;type:citext;not null"`
	// App ID send by partner
	AppID string `gorm:"primary_key;type:text;not null"`
	// App name of federation app (not region app)
	AppName string
	// App version  of federation app (not region app)
	AppVers string
	// App provider ID
	AppProviderId string
	// Artefact IDs
	ArtefactIds pq.StringArray `gorm:"type:text[]"`
	// Onboarding Zones
	DeploymentZones pq.StringArray `gorm:"type:text[]"`
	// App status callback link
	AppStatusCallbackLink string
}

// Track AppInst created on behalf of Federation Guest
type ProviderAppInst struct {
	// Host Federation name
	FederationName string `gorm:"primary_key;type:citext;not null"`
	// AppInst unique ID
	AppInstID string `gorm:"primary_key;type:text;not null"`
	// AppInst organization
	AppInstOrg string
	// AppID for ProviderApp
	AppID string
	// Region for AppInst
	Region string
	// App name for AppInstKey
	AppName string
	// App version for AppInstKey
	AppVers string
	// Cloudlet name for AppInstKey
	Cloudlet string
	// Cloudlet org for AppInstKey
	CloudletOrg string
	// Cloudlet federation org for AppInstKey (this should always be blank)
	CloudletFedOrg string
	// Error message if create failed
	Error string
	// AppInst callback link
	AppInstCallbackLink string
}

func (f *FederationProvider) GetSortString() string {
	return f.OperatorId + "-" + f.Name
}

func (f *FederationConsumer) GetSortString() string {
	return f.OperatorId + "-" + f.Name
}

func (f *ProviderZoneBase) GetSortString() string {
	return f.OperatorId + "-" + f.ZoneId
}

func (f *ProviderZone) GetSortString() string {
	return f.OperatorId + "-" + f.ProviderName + "-" + f.ZoneId
}

func (f *ConsumerZone) GetSortString() string {
	return f.OperatorId + "-" + f.ConsumerName + "-" + f.ZoneId
}

func (f *FederationProvider) GetTags() map[string]string {
	tags := make(map[string]string)
	tags["org"] = f.OperatorId
	tags["hostfederationname"] = f.Name
	return tags
}

func (f *FederationConsumer) GetTags() map[string]string {
	tags := make(map[string]string)
	tags["org"] = f.OperatorId
	tags["guestfederationname"] = f.Name
	return tags
}

func (f *ProviderZoneBase) GetTags() map[string]string {
	tags := make(map[string]string)
	tags["org"] = f.OperatorId
	tags["region"] = f.Region
	tags["zoneid"] = f.ZoneId
	return tags
}

func (f *ProviderZone) GetTags() map[string]string {
	tags := make(map[string]string)
	tags["org"] = f.OperatorId
	tags["federationname"] = f.ProviderName
	tags["zoneid"] = f.ZoneId
	return tags
}

func (f *ConsumerZone) GetTags() map[string]string {
	tags := make(map[string]string)
	tags["org"] = f.OperatorId
	tags["federationname"] = f.ConsumerName
	tags["zoneid"] = f.ZoneId
	return tags
}

func (s *ProviderArtefact) GetAppKey() edgeproto.AppKey {
	return edgeproto.AppKey{
		Name:         s.AppName,
		Version:      s.AppVers,
		Organization: s.FederationName,
	}
}

func (s *ProviderArtefact) SetAppKey(key *edgeproto.AppKey) {
	s.AppName = key.Name
	s.AppVers = key.Version
	s.FederationName = key.Organization
}

func (s *ProviderAppInst) GetAppInstKey() edgeproto.AppInstKey {
	return edgeproto.AppInstKey{
		Name:         s.AppInstID,
		Organization: s.FederationName,
	}
}

func (s *ProviderAppInst) SetAppInstKey(key *edgeproto.AppInstKey) {
	s.AppInstID = key.Name
	s.FederationName = key.Organization
}
