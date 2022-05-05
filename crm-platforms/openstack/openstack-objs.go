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

package openstack

import (
	"github.com/edgexr/edge-cloud/util"
)

type OSLimit struct {
	Name  string
	Value int
}

type OSServer struct {
	Status, Name, Image, ID, Flavor, Networks string
}

type OSFlavorDetail struct {
	Name        string                     `json:"name"`
	ID          string                     `json:"id"`
	RAM         int                        `json:"ram"`
	Ephemeral   int                        `json:"OS-FLV-EXT-DATA:ephemeral"`
	VCPUs       int                        `json:"vcpus"`
	Disk        int                        `json:"disk"`
	Public      bool                       `json:"os-flavor-access:is_public"`
	Properties  string                     `json:"properties"`
	Swap        util.EmptyStringJsonNumber `json:"swap"`
	RXTX_Factor util.EmptyStringJsonNumber `json:"rxtx factor"`
}

type OSAZone struct {
	Name   string `json:"zone_name"`
	Status string `json:"zone_status"`
}

type OSFloatingIP struct {
	ID                string `json:"ID"`
	Project           string `json:"Project"`
	FixedIPAddress    string `json:"Fixed IP Address"`
	Port              string `json:"Port"`
	FloatingNetwork   string `json:"Floating Network"`
	FloatingIPAddress string `json:"Floating IP Address"`
}

type OSProject struct {
	ID   string `json:"ID"`
	Name string `json:"Name"`
}

type OSSecurityGroup struct {
	ID      string `json:"ID"`
	Project string `json:"Project"`
	Name    string `json:"Name"`
}

type OSSecurityGroupRule struct {
	ID        string `json:"ID"`
	IPRange   string `json:"IP Range"`
	PortRange string `json:"Port Range"`
	Protocol  string `json:"IP Protocol"`
}

type OSServerOpt struct {
	AvailabilityZone    string //XXX not used yet
	Name, Image, Flavor string
	UserData            string
	NetIDs              []string
	Properties          []string
}

type OSServerDetail struct {
	TaskState        string `json:"OS-EXT-STS:task_state"`
	Addresses        string `json:"addresses"`
	Image            string `json:"image"`
	VMState          string `json:"OS-EXT-STS:vm_state"`
	LaunchedAt       string `json:"OS-SRV-USG:launched_at"`
	Flavor           string `json:"flavor"`
	ID               string `json:"id"`
	SecurityGroups   string `json:"security_groups"`
	VolumesAttached  string `json:"volumes_attached"`
	UserID           string `json:"user_id"`
	DiskConfig       string `json:"OS-DCF:diskConfig"`
	AccessIPv4       string `json:"accessIPv4"`
	AccessIPv6       string `json:"accessIPv6"`
	Progress         int    `json:"progress"`
	PowerState       string `json:"OS-EXT-STS:power_state"`
	ProjectID        string `json:"project_id"`
	ConfigDrive      string `json:"config_drive"`
	Status           string `json:"status"`
	Updated          string `json:"updated"`
	HostID           string `json:"hostId"`
	TerminatedAt     string `json:"OS-SRV-USG:terminated_at"`
	KeyName          string `json:"key_name"`
	AvailabilityZone string `json:"OS-EXT-AZ:availability_zone"`
	Name             string `json:"name"`
	Created          string `json:"created"`
	Properties       string `json:"properties"`
}

type OSPort struct {
	ID         string `json:"ID"`
	Name       string `json:"Name"`
	Status     string `json:"Status"`
	MACAddress string `json:"MAC Address"`
	FixedIPs   string `json:"Fixed IP Addresses"`
}

type OSPortDetail struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	DeviceID   string `json:"device_id"`
	Status     string `json:"status"`
	MACAddress string `json:"mac_address"`
	FixedIPs   string `json:"fixed_ips"`
}

type OSImage struct {
	Status, ID, Name string
}

type OSImageDetail struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	ID         string `json:"id"`
	UpdatedAt  string `json:"updated_at"`
	Checksum   string `json:"checksum"`
	Tags       string `json:"tags"`
	Properties string `json:"propereties"`
	DiskFormat string `json:"disk_format"`
}

type OSNetwork struct {
	Subnets, ID, Name string
}

type OSNetworkDetail struct {
	ID                      string `json:"id"`
	Name                    string `json:"name"`
	ProviderPhysicalNetwork string `json:"provider:physical_network"`
	IPv6AddressScope        string `json:"ipv6_address_scope"`
	DNSDomain               string `json:"dns_domain"`
	IsVLANTransparent       bool   `json:"is_vlan_transparent"`
	ProviderNetworkType     string `json:"provider:network_type"`
	External                string `json:"router:external"`
	AvailabilityZoneHints   string `json:"availability_zone_hints"`
	AvailabilityZones       string `json:"availability_zones"`
	Segments                string `json:"segments"`
	IPv4AddressScope        string `json:"ipv4_address_scope"`
	ProjectID               string `json:"project_id"`
	Status                  string `json:"status"`
	Subnets                 string `json:"subnets"`
	Description             string `json:"description"`
	Tags                    string `json:"tags"`
	UpdatedAt               string `json:"updated_at"`
	ProviderSegmentationID  int    `json:"provider:segmentation_id"`
	QOSPolicyID             string `json:"qos_policy_id"`
	AdminStateUp            string `json:"admin_state_up"`
	CreatedAt               string `json:"created_at"`
	RevisionNumber          int    `json:"revision_number"`
	MTU                     int    `json:"mtu"`
	PortSecurityEnabled     bool   `json:"port_security_enabled"`
	Shared                  bool   `json:"shared"`
	IsDefault               bool   `json:"is_default"`
}

type OSFlavor struct {
	Name, ID                    string
	RAM, Ephemeral, VCPUs, Disk int
}

type OSSubnet struct {
	Name, ID, Network, Subnet string
}

type OSSubnetDetail struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	ServiceTypes    string `json:"service_types"`
	Description     string `json:"description"`
	EnableDHCP      bool   `json:"enable_dhcp"`
	SegmentID       string `json:"segment_id"`
	NetworkID       string `json:"network_id"`
	CreatedAt       string `json:"created_at"`
	Tags            string `json:"tags"`
	DNSNameServers  string `json:"dns_nameservers"`
	UpdatedAt       string `json:"updated_at"`
	IPv6RAMode      string `json:"ipv6_ra_mode"`
	AllocationPools string `json:"allocation_pools"`
	GatewayIP       string `json:"gateway_ip"`
	RevisionNumber  int    `json:"revision_number"`
	IPv6AddressMode string `json:"ipv6_address_mode"`
	IPVersion       int    `json:"ip_version"`
	HostRoutes      string `json:"host_routes"`
	CIDR            string `json:"cidr"`
	ProjectID       string `json:"project_id"`
	SubnetPoolID    string `json:"subnetpool_id"`
}

type OSRouter struct {
	Name, ID, Status, State, Project string
	HA, Distributed                  bool
}

type OSRouterDetail struct {
	ID                    string `json:"id"`
	Name                  string `json:"name"`
	ExternalGatewayInfo   string `json:"external_gateway_info"`
	Status                string `json:"status"`
	AvailabilityZoneHints string `json:"availability_zone_hints"`
	AvailabilityZones     string `json:"availability_zones"`
	Description           string `json:"description"`
	AdminStateUp          string `json:"admin_state_up"`
	CreatedAt             string `json:"created_at"`
	Tags                  string `json:"tags"`
	UpdatedAt             string `json:"updated_at"`
	InterfacesInfo        string `json:"interfaces_info"`
	ProjectID             string `json:"project_id"`
	FlavorID              string `json:"flavor_id"`
	Routes                string `json:"routes"`
	Distributed           bool   `json:"distributed"`
	HA                    bool   `json:"ha"`
	RevisionNumber        int    `json:"revision_number"`
}

type OSExternalGateway struct {
	NetworkID        string              `json:"network_id"` //subnet of external net
	EnableSNAT       bool                `json:"enable_snat"`
	ExternalFixedIPs []OSExternalFixedIP `json:"external_fixed_ips"` //gateway between extnet and privnet
}

type OSExternalFixedIP struct {
	SubnetID  string `json:"subnet_id"`
	IPAddress string `json:"ip_address"`
}

type OSRouterInterface struct {
	SubnetID  string `json:"subnet_id"`  //attached privnet
	IPAddress string `json:"ip_address"` //router for the privnet side on the subnet CIDR, usually X.X.X.1  but should really confirm by reading this
	PortID    string `json:"port_id"`
}

type NeutronErrorDetail struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Detail  string `json:"detail"`
}

type NeutronErrorType struct {
	NeutronError NeutronErrorDetail
}

type OSHeatStackDetail struct {
	ID                string            `json:"id"`
	Parent            string            `json:"parent"`
	Description       string            `json:"description"`
	Parameters        map[string]string `json:"parameters"`
	StackStatusReason string            `json:"stack_status_reason"`
	StackName         string            `json:"stack_name"`
	StackStatus       string            `json:"stack_status"`
}

type OSStackResource struct {
	Type       string                 `json:"type" yaml:"type"`
	Properties map[string]interface{} `json:"properties" yaml:"properties"`
}

type OSHeatStackTemplate struct {
	Resources map[string]OSStackResource `json:"resources" yaml:"resources"`
}

type OSConsoleUrl struct {
	Url string `json:"url"`
}

// instance_network_interface details
type OSMetricResource struct {
	StartedAt          string `json:"started_at"`
	UserID             string `json:"user_id"`
	RevisionEnd        string `json:"revision_end"`
	Creator            string `json:"creator"`
	RevisionStart      string `json:"revision_start"`
	InstanceId         string `json:"instance_id"`
	OriginalResourceId string `json:"original_resource_id"`
	EndedAt            string `json:"ended_at"`
	ProjectId          string `json:"project_id"`
	Type               string `json:"type"`
	Id                 string `json:"id"`
	Name               string `json:"name"`
}

// Ceilometer-based tsdb measurements
type OSMetricMeasurement struct {
	Timestamp   string  `json:"timestamp"`
	Value       float64 `json:"value"`
	Granularity float64 `json:"granularity"`
}
