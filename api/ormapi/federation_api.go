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

	"github.com/lib/pq"
)

// Federation provider is a Federation where I provide my resources
// to the partner OP, and allow them to deploy their applications on
// my infrastructure. This relationship is initiated by the partner OP.
type FederationProvider struct {
	// Unique ID
	ID uint `gorm:"primary_key"`
	// Name to describe this provider
	Name string `gorm:"unique_index:fedprovindex;type:text;not null"`
	// Operator Organization
	OperatorId string `gorm:"unique_index:fedprovindex;type:citext REFERENCES organizations(name);not null"`
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
	// Status
	// read only: true
	Status string
	// Provider client ID for inbound connections
	ProviderClientId string
	// Time created
	// read only: true
	CreatedAt time.Time `json:",omitempty"`
	// Time updated
	// read only: true
	UpdatedAt time.Time `json:",omitempty"`
}

// Returned from creating a FederationProvider, give this to partner Operator.
type FederationProviderInfo struct {
	// Client ID for Oauth
	ClientId string
	// Client Key for Oauth. Save this, as it the system cannot retreive it.
	ClientKey string
	// Target Address for EWBI create
	TargetAddr string
	// Oauth2 token URL
	TokenUrl string
}

// Federation consumer is a Federation where I consume resources
// given by the partner OP, and I can deploy my applications on
// their infrastructure. This relationship is initiated by me.
type FederationConsumer struct {
	// Unique ID
	ID uint `gorm:"primary_key"`
	// Name to describe this consumer
	Name string `gorm:"unique_index:fedconsindex;type:text;not null"`
	// Operator Organization
	OperatorId string `gorm:"unique_index:fedconsindex;type:citext REFERENCES organizations(name);not null"`
	// Partner Address
	PartnerAddr string `gorm:"not null"`
	// Partner token URL
	PartnerTokenUrl string
	// Region in which partner zones will be created as cloudlets and whose apps will be mirrored to federation partner
	Region string `gorm:"not null"`
	// Federation context id returned by partner
	FederationContextId string
	// My federation info provided to partner
	MyInfo Federator `gorm:"embedded;embedded_prefix:my_"`
	// Partner federation info
	PartnerInfo Federator `gorm:"embedded;embedded_prefix:partner_"`
	// Automatically register any zone shared with me
	AutoRegisterZones bool
	// Status
	// read only: true
	Status string
	// Auth ClientId for connecting to provider
	ProviderClientId string
	// Auth ClientKey for connection to provider (stored in secret storage)
	ProviderClientKey string
	// Auth ClientId for notify callbacks to this consumer
	NotifyClientId string
	// Time created
	// read only: true
	CreatedAt time.Time `json:",omitempty"`
	// Time updated
	// read only: true
	UpdatedAt time.Time `json:",omitempty"`
}

// Federation Consumer auth credentials for callbacks. Give these to the provider.
type FederationConsumerAuth struct {
	// Client ID for Oauth
	ClientId string
	// Client Key for Oauth
	ClientKey string
}

// Federator contains operator properties. It is never saved
// to the db standalone, but only as part of a federation.
type Federator struct {
	// Globally unique string used to indentify a federation with partner federation
	FederationId string
	// ISO 3166-1 Alpha-2 code for the country where operator platform is located
	CountryCode string
	// Mobile country code of operator sending the request
	MCC string
	// List of mobile network codes of operator sending the request
	MNC pq.StringArray `gorm:"type:text[]"`
	// Fixed linke network ids
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

// Local Zone shared via FederationProvider
type ProviderZone struct {
	// Globally unique identifier of the federator zone
	ZoneId string `gorm:"primary_key"`
	// Name of the Federation Provider
	ProviderName string `gorm:"primary_key"`
	// Provider operator organization
	OperatorId string `gorm:"primary_key;type:citext"`
	// Zone status
	// read only: true
	Status string
	// Partner notify zone URI
	PartnerNotifyZoneURI string
}

// Remote zone shared with us via FederationConsumer
type ConsumerZone struct {
	// Zone unique name
	ZoneId string `gorm:"primary_key"`
	// Name of the Federation consumer
	ConsumerName string `gorm:"primary_key"`
	// Consumer operator organization
	OperatorId string `gorm:"primary_key;type:citext"`
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
	// Operator organization
	OperatorId string
	// Federation consumer name
	ConsumerName string
	// Partner federator zones to be registered/deregistered
	Zones []string
}

// Share/Unshare self zones shared as part of federation
type FederatedZoneShareRequest struct {
	// Operator organization
	OperatorId string
	// Federation provider name
	ProviderName string
	// Self federator zones to be shared/unshared
	Zones []string
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
	tags["federationprovidername"] = f.Name
	return tags
}

func (f *FederationConsumer) GetTags() map[string]string {
	tags := make(map[string]string)
	tags["org"] = f.OperatorId
	tags["federationconsumername"] = f.Name
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
