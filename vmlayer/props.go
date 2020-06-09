package vmlayer

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/go-chef/chef"
	"github.com/mobiledgex/edge-cloud-infra/chefmgmt"
	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

type VMProperties struct {
	CommonPf         infracommon.CommonPlatform
	sharedRootLBName string
	sharedRootLB     *MEXRootLB
}

// note that qcow2 must be understood by vsphere and vmdk must
// be known by openstack so they can be converted back and forth
var ImageFormatQcow2 = "qcow2"
var ImageFormatVmdk = "vmdk"

var MEXInfraVersion = "3.1.2"
var ImageNamePrefix = "mobiledgex-v"
var DefaultOSImageName = ImageNamePrefix + MEXInfraVersion

const MINIMUM_DISK_SIZE uint64 = 20

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
var VMProviderProps = map[string]*infracommon.PropertyInfo{
	// Property: Default-Value

	"MEX_EXT_NETWORK": {
		Value: "external-network-shared",
	},
	"MEX_NETWORK": {
		Value: "mex-k8s-net-1",
	},
	// note OS_IMAGE refers to Operating System
	"MEX_OS_IMAGE": {
		Value: DefaultOSImageName,
	},
	"MEX_SECURITY_GROUP": {
		Value: "default",
	},
	"MEX_SHARED_ROOTLB_RAM": {
		Value: "4096",
	},
	"MEX_SHARED_ROOTLB_VCPUS": {
		Value: "2",
	},
	"MEX_SHARED_ROOTLB_DISK": {
		Value: "40",
	},
	"MEX_NETWORK_SCHEME": {
		Value: "cidr=10.101.X.0/24",
	},
	"MEX_COMPUTE_AVAILABILITY_ZONE": {},
	"MEX_NETWORK_AVAILABILITY_ZONE": {},
	"MEX_VOLUME_AVAILABILITY_ZONE":  {},
	"MEX_IMAGE_DISK_FORMAT": {
		Value: ImageFormatQcow2,
	},
	"MEX_ROUTER": {
		Value: NoExternalRouter,
	},
	"MEX_CRM_GATEWAY_ADDR": {},
	"MEX_SUBNET_DNS":       {},
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

func GetVaultCloudletAccessPath(key *edgeproto.CloudletKey, region, cloudletType, physicalName, filename string) string {
	return fmt.Sprintf("/secret/data/%s/cloudlet/%s/%s/%s/%s", region, cloudletType, key.Organization, physicalName, filename)
}

func GetCloudletVMImagePath(imgPath, imgVersion string) string {
	vmRegistryPath := DefaultCloudletVMImagePath
	if imgPath != "" {
		vmRegistryPath = imgPath
	}
	if !strings.HasSuffix(vmRegistryPath, "/") {
		vmRegistryPath = vmRegistryPath + "/"
	}
	return vmRegistryPath + GetCloudletVMImageName(imgVersion) + ".qcow2"
}

// GetCloudletSharedRootLBFlavor gets the flavor from defaults
// or environment variables
func (vp *VMProperties) GetCloudletSharedRootLBFlavor(flavor *edgeproto.Flavor) error {
	ram := vp.CommonPf.Properties["MEX_SHARED_ROOTLB_RAM"].Value
	var err error
	if ram != "" {
		flavor.Ram, err = strconv.ParseUint(ram, 10, 64)
		if err != nil {
			return err
		}
	} else {
		flavor.Ram = 4096
	}
	vcpus := vp.CommonPf.Properties["MEX_SHARED_ROOTLB_VCPUS"].Value
	if vcpus != "" {
		flavor.Vcpus, err = strconv.ParseUint(vcpus, 10, 64)
		if err != nil {
			return err
		}
	} else {
		flavor.Vcpus = 2
	}
	disk := vp.CommonPf.Properties["MEX_SHARED_ROOTLB_DISK"].Value
	if disk != "" {
		flavor.Disk, err = strconv.ParseUint(disk, 10, 64)
		if err != nil {
			return err
		}
	} else {
		flavor.Disk = 40
	}
	return nil
}

func (vp *VMProperties) GetCloudletSecurityGroupName() string {
	return vp.CommonPf.Properties["MEX_SECURITY_GROUP"].Value
}

func (vp *VMProperties) GetCloudletExternalNetwork() string {
	return vp.CommonPf.Properties["MEX_EXT_NETWORK"].Value
}

func (vp *VMProperties) SetCloudletExternalNetwork(name string) {
	vp.CommonPf.Properties["MEX_EXT_NETWORK"].Value = name
}

// GetCloudletNetwork returns default MEX network, internal and prepped
func (vp *VMProperties) GetCloudletMexNetwork() string {
	return vp.CommonPf.Properties["MEX_NETWORK"].Value
}

func (vp *VMProperties) GetCloudletNetworkScheme() string {
	return vp.CommonPf.Properties["MEX_NETWORK_SCHEME"].Value
}

func (vp *VMProperties) GetCloudletVolumeAvailabilityZone() string {
	return vp.CommonPf.Properties["MEX_VOLUME_AVAILABILITY_ZONE"].Value
}

func (vp *VMProperties) GetCloudletComputeAvailabilityZone() string {
	return vp.CommonPf.Properties["MEX_COMPUTE_AVAILABILITY_ZONE"].Value
}

func (vp *VMProperties) GetCloudletNetworkAvailabilityZone() string {
	return vp.CommonPf.Properties["MEX_NETWORK_AVAILABILITY_ZONE"].Value
}

func (vp *VMProperties) GetCloudletImageDiskFormat() string {
	return vp.CommonPf.Properties["MEX_IMAGE_DISK_FORMAT"].Value
}

func (vp *VMProperties) GetCloudletOSImage() string {
	return vp.CommonPf.Properties["MEX_OS_IMAGE"].Value
}

func (vp *VMProperties) GetCloudletFlavorMatchPattern() string {
	return vp.CommonPf.Properties["FLAVOR_MATCH_PATTERN"].Value
}

func (vp *VMProperties) GetCloudletExternalRouter() string {
	return vp.CommonPf.Properties["MEX_ROUTER"].Value
}

func (vp *VMProperties) GetSubnetDNS() string {
	return vp.CommonPf.Properties["MEX_SUBNET_DNS"].Value
}

func (vp *VMProperties) GetRootLBNameForCluster(ctx context.Context, clusterInst *edgeproto.ClusterInst) string {
	lbName := vp.sharedRootLBName
	if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		lbName = cloudcommon.GetDedicatedLBFQDN(vp.CommonPf.PlatformConfig.CloudletKey, &clusterInst.Key.ClusterKey, vp.CommonPf.PlatformConfig.AppDNSRoot)
	}
	return lbName
}

func (vp *VMProperties) GetCloudletCRMGatewayIPAndPort() (string, int) {
	gw := vp.CommonPf.Properties["MEX_CRM_GATEWAY_ADDR"].Value
	if gw == "" {
		return "", 0
	}
	host, portstr, err := net.SplitHostPort(gw)
	if err != nil {
		log.FatalLog("Error in MEX_CRM_GATEWAY_ADDR format")
	}
	port, err := strconv.Atoi(portstr)
	if err != nil {
		log.FatalLog("Error in MEX_CRM_GATEWAY_ADDR port format")
	}
	return host, port
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
