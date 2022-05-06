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

package vmlayer

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/go-chef/chef"
	"github.com/edgexr/edge-cloud-infra/chefmgmt"
	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
)

type VMProperties struct {
	CommonPf                          infracommon.CommonPlatform
	SharedRootLBName                  string
	Domain                            VMDomain
	PlatformSecgrpName                string
	CloudletSecgrpName                string
	IptablesBasedFirewall             bool
	Upgrade                           bool
	UseSecgrpForInternalSubnet        bool
	RequiresWhitelistOwnIp            bool
	RunLbDhcpServerForVmApps          bool
	AppendFlavorToVmAppImage          bool
	ValidateExternalIPMapping         bool
	CloudletAccessToken               string
	NumCleanupRetries                 int
	UsesCommonSharedInternalLBNetwork bool
	PlatformExternalNetwork           string
}

const MEX_ROOTLB_FLAVOR_NAME = "mex-rootlb-flavor"
const MINIMUM_DISK_SIZE uint64 = 20
const MINIMUM_RAM_SIZE uint64 = 2048
const MINIMUM_VCPUS uint64 = 2

// note that qcow2 must be understood by vsphere and vmdk must
// be known by openstack so they can be converted back and forth
var ImageFormatQcow2 = "qcow2"
var ImageFormatVmdk = "vmdk"

var MEXInfraVersion = "4.10.0"
var ImageNamePrefix = "mobiledgex-v"
var DefaultOSImageName = ImageNamePrefix + MEXInfraVersion

// NoSubnetDNS means that DNS servers are not specified when creating the subnet
var NoSubnetDNS = "NONE"

// NoConfigExternalRouter is used for the case in which we don't manage the external
// router and don't add ports to it ourself, as happens with Contrail.  The router does exist in
// this case and we use it to route from the LB to the pods
var NoConfigExternalRouter = "NOCONFIG"

// NoExternalRouter means there is no router at all and we connect the LB to the k8s pods on the same subnet
// this may eventually be the default and possibly only option
var NoExternalRouter = "NONE"

var DefaultCloudletVMImagePath = "https://artifactory.mobiledgex.net/artifactory/baseimages/"

// properties common to all VM providers
var VMProviderProps = map[string]*edgeproto.PropertyInfo{
	"MEX_EXT_NETWORK": {
		Name:        "Infra External Network Name",
		Description: "Name of the external network to be used to reach developer apps",
		Value:       "external-network-shared",
	},
	"MEX_NETWORK": {
		Name:        "Infra Internal Network Name",
		Description: "Name of the internal network which will be created to be used for cluster communication",
		Value:       "mex-k8s-net-1",
	},
	// note OS_IMAGE refers to Operating System
	"MEX_OS_IMAGE": {
		Name:        "Cloudlet Image Name",
		Description: "Name of the VM base image to be used for bring up Cloudlet VMs",
		Value:       DefaultOSImageName,
	},
	"MEX_SECURITY_GROUP": {
		Name:        "Security Group Name",
		Description: "Name of the security group to which cloudlet VMs will be part of",
	},
	"MEX_SHARED_ROOTLB_RAM": {
		Name:        "Security Group Name",
		Description: "Size of RAM (MB) required to bring up shared RootLB",
		Value:       "4096",
	},
	"MEX_SHARED_ROOTLB_VCPUS": {
		Name:        "RootLB vCPUs",
		Description: "Number of vCPUs required to bring up shared RootLB",
		Value:       "2",
	},
	"MEX_SHARED_ROOTLB_DISK": {
		Name:        "RootLB Disk",
		Description: "Size of disk (GB) required to bring up shared RootLB",
		Value:       "40",
	},
	"MEX_NETWORK_SCHEME": {
		Name:        "Internal Network Scheme",
		Description: GetSupportedSchemesStr(),
		Value:       "cidr=10.101.X.0/24",
	},
	"MEX_COMPUTE_AVAILABILITY_ZONE": {
		Name:        "Compute Availability Zone",
		Description: "Compute Availability Zone",
	},
	"MEX_NETWORK_AVAILABILITY_ZONE": {
		Name:        "Network Availability Zone",
		Description: "Network Availability Zone",
	},
	"MEX_VOLUME_AVAILABILITY_ZONE": {
		Name:        "Volume Availability Zone",
		Description: "Volume Availability Zone",
	},
	"MEX_IMAGE_DISK_FORMAT": {
		Name:        "VM Image Disk Format",
		Description: "Name of the disk format required to upload VM image to infra datastore",
		Value:       ImageFormatQcow2,
	},
	"MEX_ROUTER": {
		Name:        "External Router Type",
		Description: GetSupportedRouterTypes(),
		Value:       NoExternalRouter,
	},
	"MEX_SUBNET_DNS": {
		Name:        "DNS Override for Subnet",
		Description: "Set to NONE to use no DNS entry for new subnets.  Otherwise subnet DNS is set to MEX_DNS",
	},
	"MEX_DNS": {
		Name:        "DNS Server(s)",
		Description: "Override DNS server IP(s), e.g. \"8.8.8.8\" or \"1.1.1.1,8.8.8.8\"",
		Value:       "1.1.1.1,1.0.0.1",
	},
	"MEX_CLOUDLET_FIREWALL_WHITELIST_EGRESS": {
		Name:        "Cloudlet Firewall Whitelist Egress",
		Description: "Firewall rule to whitelist egress traffic",
		Value:       "protocol=tcp,portrange=1:65535,remotecidr=0.0.0.0/0;protocol=udp,portrange=1:65535,remotecidr=0.0.0.0/0;protocol=icmp,remotecidr=0.0.0.0/0",
	},
	"MEX_CLOUDLET_FIREWALL_WHITELIST_INGRESS": {
		Name:        "Cloudlet Firewall Whitelist Ingress",
		Description: "Firewall rule to whitelist ingress traffic",
	},
	"MEX_ADDITIONAL_PLATFORM_NETWORKS": {
		Name:        "Additional Platform Networks",
		Description: "Optional comma separated list of networks to add to platform VM",
	},
	"MEX_ADDITIONAL_ROOTLB_NETWORKS": {
		Name:        "Additional RootLB Networks",
		Description: "Optional comma separated list of networks to add to rootLB VMs",
	},
	"MEX_NTP_SERVERS": {
		Name:        "NTP Servers",
		Description: "Optional comma separated list of NTP servers to override default of ntp.ubuntu.com",
	},
	"MEX_VM_APP_SUBNET_DHCP_ENABLED": {
		Name:        "VM App subnet enable DHCP",
		Description: "Enable DHCP for the subnet created for VM based applications (yes or no)",
		Value:       "yes",
	},
	"MEX_VM_APP_IMAGE_CLEANUP_ON_DELETE": {
		Name:        "VM App image cleanup on delete",
		Description: "Delete image files when VM apps are deleted (yes or no)",
		Value:       "yes",
	},
	"MEX_VM_APP_METRICS_COLLECT_INTERVAL": {
		Name:        "VM App Metrics collect interval, in minutes",
		Description: "Determines how often VM metrics are collected",
		Value:       "5",
	},
	"MEX_METALLB_OCTET3_RANGE": {
		Name:        "MetalLB IP third octet range",
		Description: "Start and end value of MetalLB IP range third octet, (start-end). Set to NONE to disable MetalLB",
		Value:       "200-250",
	},
	"MEX_ENABLE_ANTI_AFFINITY": {
		Name:        "Enable Anti-Affinity Rules",
		Description: "Enable Anti-Affinity rules where applicable for H/A (yes or no). Set to \"no\" for environments with limited hosts",
		Value:       "yes",
	},
}

func GetSupportedRouterTypes() string {
	return fmt.Sprintf("Supported types: %s, %s", NoExternalRouter, NoConfigExternalRouter)
}

func GetVaultCloudletCommonPath(filePath string) string {
	// TODO this path really should not be openstack
	return fmt.Sprintf("/secret/data/cloudlet/openstack/%s", filePath)
}

func GetCloudletVMImageName(imgVersion string) string {
	if imgVersion == "" {
		imgVersion = MEXInfraVersion
	}
	return ImageNamePrefix + imgVersion
}

func GetCertFilePath(key *edgeproto.CloudletKey) string {
	return fmt.Sprintf("/tmp/%s.%s.cert", key.Name, key.Organization)
}

func GetCloudletVMImagePath(imgPath, imgVersion string, imgSuffix string) string {
	vmRegistryPath := DefaultCloudletVMImagePath
	if imgPath != "" {
		vmRegistryPath = imgPath
	}
	if !strings.HasSuffix(vmRegistryPath, "/") {
		vmRegistryPath = vmRegistryPath + "/"
	}
	return vmRegistryPath + GetCloudletVMImageName(imgVersion) + imgSuffix
}

// GetCloudletSecurityGroupName overrides cloudlet wide security group if set in
// envvars, but normally is derived from the cloudlet name.  It is not exported
// as providers should use VMProperties.CloudletSecgrpName
func (v *VMPlatform) getCloudletSecurityGroupName() string {
	value, _ := v.VMProperties.CommonPf.Properties.GetValue("MEX_SECURITY_GROUP")
	if value != "" {
		return value
	}
	return v.GetSanitizedCloudletName(v.VMProperties.CommonPf.PlatformConfig.CloudletKey) + "-cloudlet-sg"
}

func (vp *VMProperties) GetCloudletExternalNetwork() string {
	value, _ := vp.CommonPf.Properties.GetValue("MEX_EXT_NETWORK")
	return value
}

func (vp *VMProperties) SetCloudletExternalNetwork(name string) {
	vp.CommonPf.Properties.SetValue("MEX_EXT_NETWORK", name)
}

// GetCloudletNetwork returns default MEX network, internal and prepped
func (vp *VMProperties) GetCloudletMexNetwork() string {
	value, _ := vp.CommonPf.Properties.GetValue("MEX_NETWORK")
	return value
}

func (vp *VMProperties) GetCloudletAdditionalPlatformNetworks() []string {
	value, _ := vp.CommonPf.Properties.GetValue("MEX_ADDITIONAL_PLATFORM_NETWORKS")
	if value == "" {
		return []string{}
	}
	return strings.Split(value, ",")
}

func (vp *VMProperties) GetCloudletAdditionalRootLbNetworks() []string {
	value, _ := vp.CommonPf.Properties.GetValue("MEX_ADDITIONAL_ROOTLB_NETWORKS")
	if value == "" {
		return []string{}
	}
	return strings.Split(value, ",")
}

// GetNetworksByType returns a map of networkName -> Type
func (vp *VMProperties) GetNetworksByType(ctx context.Context, netTypes []NetworkType) map[string]NetworkType {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetNetworksByType", "netTypes", netTypes)
	nets := make(map[string]NetworkType)

	// look for additional net based on netType.
	for _, netType := range netTypes {
		switch netType {
		case NetworkTypeExternalPrimary:
			nets[vp.GetCloudletExternalNetwork()] = NetworkTypeExternalPrimary
		case NetworkTypeExternalAdditionalRootLb:
			for _, n := range vp.GetCloudletAdditionalRootLbNetworks() {
				nets[n] = NetworkTypeExternalAdditionalRootLb
			}
		case NetworkTypeExternalAdditionalPlatform:
			for _, n := range vp.GetCloudletAdditionalPlatformNetworks() {
				nets[n] = NetworkTypeExternalAdditionalPlatform
			}
			if vp.PlatformExternalNetwork != "" {
				nets[vp.PlatformExternalNetwork] = NetworkTypeExternalAdditionalPlatform
			}
		case NetworkTypeInternalPrivate:
			fallthrough
		case NetworkTypeInternalSharedLb:
			nets[vp.GetCloudletMexNetwork()] = netType
		}
	}
	return nets
}

func (vp *VMProperties) GetNtpServers() []string {
	value, _ := vp.CommonPf.Properties.GetValue("MEX_NTP_SERVERS")
	if value == "" {
		return []string{}
	}
	return strings.Split(value, ",")
}

func (vp *VMProperties) GetCloudletNetworkScheme() string {
	value, _ := vp.CommonPf.Properties.GetValue("MEX_NETWORK_SCHEME")
	return value
}

func (vp *VMProperties) GetCloudletVolumeAvailabilityZone() string {
	value, _ := vp.CommonPf.Properties.GetValue("MEX_VOLUME_AVAILABILITY_ZONE")
	return value
}

func (vp *VMProperties) GetCloudletComputeAvailabilityZone() string {
	value, _ := vp.CommonPf.Properties.GetValue("MEX_COMPUTE_AVAILABILITY_ZONE")
	return value
}

func (vp *VMProperties) GetCloudletNetworkAvailabilityZone() string {
	value, _ := vp.CommonPf.Properties.GetValue("MEX_NETWORK_AVAILABILITY_ZONE")
	return value
}

func (vp *VMProperties) GetCloudletImageDiskFormat() string {
	value, _ := vp.CommonPf.Properties.GetValue("MEX_IMAGE_DISK_FORMAT")
	return value
}

func (vp *VMProperties) GetCloudletOSImage() string {
	value, _ := vp.CommonPf.Properties.GetValue("MEX_OS_IMAGE")
	return value
}

func (vp *VMProperties) GetCloudletFlavorMatchPattern() string {
	value, _ := vp.CommonPf.Properties.GetValue("FLAVOR_MATCH_PATTERN")
	return value
}

func (vp *VMProperties) GetSkipInstallResourceTracker() bool {
	value, _ := vp.CommonPf.Properties.GetValue("SKIP_INSTALL_RESOURCE_TRACKER")
	return strings.ToLower(value) == "true"
}

func (vp *VMProperties) GetCloudletExternalRouter() string {
	value, _ := vp.CommonPf.Properties.GetValue("MEX_ROUTER")
	return value
}

func (vp *VMProperties) GetCloudletDNS() string {
	value, _ := vp.CommonPf.Properties.GetValue("MEX_DNS")
	return value
}

func (vp *VMProperties) GetSubnetDNS() string {
	value, _ := vp.CommonPf.Properties.GetValue("MEX_SUBNET_DNS")
	return value
}

func (vp *VMProperties) GetRootLBNameForCluster(ctx context.Context, clusterInst *edgeproto.ClusterInst) string {
	lbName := vp.SharedRootLBName
	if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		lbName = clusterInst.Fqdn
	}
	return lbName
}

func (vp *VMProperties) GetVMAppSubnetDHCPEnabled() string {
	value, _ := vp.CommonPf.Properties.GetValue("MEX_VM_APP_SUBNET_DHCP_ENABLED")
	return value
}

func (vp *VMProperties) GetVMAppCleanupImageOnDelete() bool {
	value, _ := vp.CommonPf.Properties.GetValue("MEX_VM_APP_IMAGE_CLEANUP_ON_DELETE")
	return value == "yes"
}

func (vp *VMProperties) GetVmAppMetricsCollectInterval() (uint64, error) {
	value, _ := vp.CommonPf.Properties.GetValue("MEX_VM_APP_METRICS_COLLECT_INTERVAL")
	val, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("Unable to parse value MEX_VM_APP_METRICS_COLLECT_INTERVAL value: %s as integer", value)
	}
	return val, nil
}

func (vp *VMProperties) GetChefClient() *chef.Client {
	return vp.CommonPf.ChefClient
}

func (vp *VMProperties) GetChefServerPath() string {
	if vp.CommonPf.ChefServerPath == "" {
		return chefmgmt.DefaultChefServerPath
	}
	return vp.CommonPf.ChefServerPath
}

func (vp *VMProperties) GetRegion() string {
	return vp.CommonPf.PlatformConfig.Region
}

func (vp *VMProperties) GetDeploymentTag() string {
	return vp.CommonPf.DeploymentTag
}

func (vp *VMProperties) GetUsesMetalLb() bool {
	value, _ := vp.CommonPf.Properties.GetValue("MEX_METALLB_OCTET3_RANGE")
	return value != "" && value != "NONE"
}

func (vp *VMProperties) GetMetalLBIp3rdOctetRange() (uint64, uint64, error) {
	value, _ := vp.CommonPf.Properties.GetValue("MEX_METALLB_OCTET3_RANGE")
	if value == "" {
		// should not happen as GetUsesMetalLb should be called first
		return 0, 0, fmt.Errorf("No MetalLB range defined in MEX_METALLB_OCTET3_RANGE")
	}
	vals := strings.Split(value, "-")
	if len(vals) != 2 {
		return 0, 0, fmt.Errorf("MetalLB range not properly defined (start-end) in MEX_METALLB_OCTET3_RANGE")
	}
	start, err := strconv.ParseUint(vals[0], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("Failed to parse MetalLB start-end %v", err)
	}
	end, err := strconv.ParseUint(vals[1], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("Failed to parse MetalLB start-end %v", err)
	}
	if start == 0 || start > 255 || end > 255 || start > end {
		return 0, 0, fmt.Errorf("Invalid MetalLB range in MEX_METALLB_OCTET3_RANGE")
	}
	return start, end, nil
}

func (vp *VMProperties) GetEnableAntiAffinity() bool {
	value, _ := vp.CommonPf.Properties.GetValue("MEX_ENABLE_ANTI_AFFINITY")
	return value == "yes"
}

// GetMetalLBIp3rdOctetRangeFromMasterIp gives an IP range on the same subnet as the master IP
func (vp *VMProperties) GetMetalLBIp3rdOctetRangeFromMasterIp(ctx context.Context, masterIP string) ([]string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetMetalLBIp3rdOctetRangeFromMasterIp", "masterIP", masterIP)
	mip := net.ParseIP(masterIP)
	if mip == nil {
		return nil, fmt.Errorf("unable to parse master ip %s", masterIP)
	}
	start, end, err := vp.GetMetalLBIp3rdOctetRange()
	if err != nil {
		return nil, err
	}
	addr := mip.To4()
	addr[3] = byte(start)
	startAddr := addr.String()
	addr[3] = byte(end)
	endAddr := addr.String()
	return []string{fmt.Sprintf("%s-%s", startAddr, endAddr)}, nil
}

// For platforms without native flavor support, just use our meta flavors
// Adjust flavor size if subpar.
func (vp *VMProperties) GetFlavorListInternal(ctx context.Context, caches *platform.Caches) ([]*edgeproto.FlavorInfo, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetFlavorListInternal")

	var flavors []*edgeproto.FlavorInfo
	if caches == nil {
		log.WarnLog("flavor cache is nil")
		return nil, fmt.Errorf("Flavor cache is nil")
	}
	flavorkeys := make(map[edgeproto.FlavorKey]struct{})
	caches.FlavorCache.GetAllKeys(ctx, func(k *edgeproto.FlavorKey, modRev int64) {

		flavorkeys[*k] = struct{}{}
	})

	for k := range flavorkeys {
		var flav edgeproto.Flavor
		if caches.FlavorCache.Get(&k, &flav) {
			var flavInfo edgeproto.FlavorInfo
			flavInfo.Name = flav.Key.Name
			if flav.Ram >= MINIMUM_RAM_SIZE {
				flavInfo.Ram = flav.Ram
			} else {
				flavInfo.Ram = MINIMUM_RAM_SIZE
			}
			if flav.Vcpus >= MINIMUM_VCPUS {
				flavInfo.Vcpus = flav.Vcpus
			} else {
				flavInfo.Vcpus = MINIMUM_VCPUS
			}
			if flav.Disk >= MINIMUM_DISK_SIZE {
				flavInfo.Disk = flav.Disk
			} else {
				flavInfo.Disk = MINIMUM_DISK_SIZE
			}
			flavors = append(flavors, &flavInfo)
		} else {
			return nil, fmt.Errorf("fail to fetch flavor %s", k)
		}
	}

	// add the default platform flavor as well
	var rlbFlav edgeproto.Flavor
	// in props today can't get there from here...
	err := vp.GetCloudletSharedRootLBFlavor(&rlbFlav)
	if err != nil {
		return nil, err
	}
	rootlbFlavorInfo := edgeproto.FlavorInfo{
		Name:  MEX_ROOTLB_FLAVOR_NAME,
		Vcpus: rlbFlav.Vcpus,
		Ram:   rlbFlav.Ram,
		Disk:  rlbFlav.Disk,
	}
	flavors = append(flavors, &rootlbFlavorInfo)
	log.SpanLog(ctx, log.DebugLevelInfra, "GetFlavorListInternal added SharedRootLB", "flavor", rootlbFlavorInfo)
	return flavors, nil
}

// GetCloudletSharedRootLBFlavor gets the flavor from defaults
// or environment variables
func (vp *VMProperties) GetCloudletSharedRootLBFlavor(flavor *edgeproto.Flavor) error {

	ram, _ := vp.CommonPf.Properties.GetValue("MEX_SHARED_ROOTLB_RAM")
	var err error
	if ram != "" {
		flavor.Ram, err = strconv.ParseUint(ram, 10, 64)
		if err != nil {
			return err
		}
	} else {
		flavor.Ram = 4096
	}
	vcpus, _ := vp.CommonPf.Properties.GetValue("MEX_SHARED_ROOTLB_VCPUS")
	if vcpus != "" {
		flavor.Vcpus, err = strconv.ParseUint(vcpus, 10, 64)
		if err != nil {
			return err
		}
	} else {
		flavor.Vcpus = 2
	}
	disk, _ := vp.CommonPf.Properties.GetValue("MEX_SHARED_ROOTLB_DISK")
	if disk != "" {
		flavor.Disk, err = strconv.ParseUint(disk, 10, 64)
		if err != nil {
			return err
		}
	} else {
		flavor.Disk = 40
	}
	flavor.Key.Name = MEX_ROOTLB_FLAVOR_NAME
	return nil
}
