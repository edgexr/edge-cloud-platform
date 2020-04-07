package openstack

// This file stores a global cloudlet infra properties object.
// The long term solution is for the controller to send this via the
// notification channel when the cloudlet is provisioned.
// The controller will do the vault access and pass this data down;
// this is a stepping stone to start using edgeproto data structures
// to hold info about the cloudlet rather than custom types and so the vault
// is still directly accessed here as are env variable to populate some variables

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/mexos"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
)

// Openstack Infra Properties
var openstackProps = map[string]*mexos.PropertyInfo{
	// Property: Default-Value
	"MEX_EXT_NETWORK": &mexos.PropertyInfo{
		Value: "external-network-shared",
	},
	"MEX_NETWORK": &mexos.PropertyInfo{
		Value: "mex-k8s-net-1",
	},
	"MEX_ROUTER": &mexos.PropertyInfo{
		Value: mexos.NoExternalRouter,
	},
	"MEX_OS_IMAGE": &mexos.PropertyInfo{
		Value: mexos.DefaultOSImageName,
	},
	"MEX_SECURITY_GROUP": &mexos.PropertyInfo{
		Value: "default",
	},
	"FLAVOR_MATCH_PATTERN": &mexos.PropertyInfo{
		Value: ".*",
	},
	"MEX_CRM_GATEWAY_ADDR": &mexos.PropertyInfo{},
	"MEX_EXTERNAL_IP_MAP":  &mexos.PropertyInfo{},
	"MEX_SHARED_ROOTLB_RAM": &mexos.PropertyInfo{
		Value: "4096",
	},
	"MEX_SHARED_ROOTLB_VCPUS": &mexos.PropertyInfo{
		Value: "2",
	},
	"MEX_SHARED_ROOTLB_DISK": &mexos.PropertyInfo{
		Value: "40",
	},
	"MEX_NETWORK_SCHEME": &mexos.PropertyInfo{
		Value: "name=mex-k8s-net-1,cidr=10.101.X.0/24",
	},
	"MEX_COMPUTE_AVAILABILITY_ZONE": &mexos.PropertyInfo{},
	"MEX_VOLUME_AVAILABILITY_ZONE":  &mexos.PropertyInfo{},
	"MEX_IMAGE_DISK_FORMAT": &mexos.PropertyInfo{
		Value: mexos.ImageFormatQcow2,
	},
	"CLEANUP_ON_FAILURE": &mexos.PropertyInfo{
		Value: "true",
	},
	"MEX_SUBNET_DNS": &mexos.PropertyInfo{},
}

func GetVaultCloudletAccessPath(key *edgeproto.CloudletKey, region, physicalName string) string {
	return fmt.Sprintf("/secret/data/%s/cloudlet/openstack/%s/%s/%s", region, key.Organization, physicalName, "openrc.json")
}

func GetCertFilePath(key *edgeproto.CloudletKey) string {
	return fmt.Sprintf("/tmp/%s.%s.cert", key.Name, key.Organization)
}

func (s *Platform) GetOpenRCVars(ctx context.Context, key *edgeproto.CloudletKey, region, physicalName string, vaultConfig *vault.Config) error {
	if vaultConfig == nil || vaultConfig.Addr == "" {
		return fmt.Errorf("vaultAddr is not specified")
	}
	openRCPath := GetVaultCloudletAccessPath(key, region, physicalName)
	log.SpanLog(ctx, log.DebugLevelMexos, "interning vault", "addr", vaultConfig.Addr, "path", openRCPath)
	envData := &mexos.VaultEnvData{}
	err := vault.GetData(vaultConfig, openRCPath, 0, envData)
	if err != nil {
		if strings.Contains(err.Error(), "no secrets") {
			return fmt.Errorf("Failed to source access variables as '%s/%s' "+
				"does not exist in secure secrets storage (Vault)",
				key.Organization, physicalName)
		}
		return fmt.Errorf("Failed to source access variables from %s, %s: %v", vaultConfig.Addr, openRCPath, err)
	}
	s.openRCVars = make(map[string]string, 1)
	for _, envData := range envData.Env {
		s.openRCVars[envData.Name] = envData.Value
	}
	if authURL, ok := s.openRCVars["OS_AUTH_URL"]; ok {
		if strings.HasPrefix(authURL, "https") {
			if certData, ok := s.openRCVars["OS_CACERT_DATA"]; ok {
				certFile := GetCertFilePath(key)
				err = ioutil.WriteFile(certFile, []byte(certData), 0644)
				if err != nil {
					return err
				}
				s.openRCVars["OS_CACERT"] = certFile
			}
		}
	}
	return nil
}

func (s *Platform) InitOpenstackProps(ctx context.Context, key *edgeproto.CloudletKey, region, physicalName string, vaultConfig *vault.Config, vars map[string]string) error {
	err := s.GetOpenRCVars(ctx, key, region, physicalName, vaultConfig)
	if err != nil {
		return err
	}

	s.vaultConfig = vaultConfig

	// set default properties
	s.envVars = openstackProps

	// set user defined properties
	mexos.SetPropsFromVars(ctx, s.envVars, vars)

	return nil
}

//GetCloudletExternalRouter returns default MEX external router name
func (s *Platform) GetCloudletExternalRouter() string {
	return s.envVars["MEX_ROUTER"].Value
}

func (s *Platform) GetCloudletExternalNetwork() string {
	return s.envVars["MEX_EXT_NETWORK"].Value
}

// GetCloudletNetwork returns default MEX network, internal and prepped
func (s *Platform) GetCloudletMexNetwork() string {
	return s.envVars["MEX_NETWORK"].Value
}

func (s *Platform) GetCloudletNetworkScheme() string {
	return s.envVars["MEX_NETWORK_SCHEME"].Value
}

func (s *Platform) GetCloudletOSImage() string {
	return s.envVars["MEX_OS_IMAGE"].Value
}

func (s *Platform) GetCloudletProjectName() string {
	if val, ok := s.openRCVars["OS_PROJECT_NAME"]; ok {
		return val
	}
	return ""
}

func (s *Platform) GetCloudletFlavorMatchPattern() string {
	return s.envVars["FLAVOR_MATCH_PATTERN"].Value
}

func (s *Platform) GetSubnetDNS() string {
	return s.envVars["MEX_SUBNET_DNS"].Value
}

func (s *Platform) GetCloudletCRMGatewayIPAndPort() (string, int) {
	gw := s.envVars["MEX_CRM_GATEWAY_ADDR"].Value
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

// optional default AZ for the cloudlet for compute resources (VMs).
func (s *Platform) GetCloudletComputeAvailabilityZone() string {
	return s.envVars["MEX_COMPUTE_AVAILABILITY_ZONE"].Value
}

// optional default AZ for the cloudlet for Volumes.
func (s *Platform) GetCloudletVolumeAvailabilityZone() string {
	return s.envVars["MEX_VOLUME_AVAILABILITY_ZONE"].Value
}

func (s *Platform) GetCloudletImageDiskFormat() string {
	return s.envVars["MEX_IMAGE_DISK_FORMAT"].Value
}

// GetCleanupOnFailure should be true unless we want to debug the failure,
// in which case this env var can be set to no.  We could consider making
// this configurable at the controller but really is only needed for debugging.
func (s *Platform) GetCleanupOnFailure(ctx context.Context) bool {
	cleanup := s.envVars["CLEANUP_ON_FAILURE"].Value
	log.SpanLog(ctx, log.DebugLevelMexos, "GetCleanupOnFailure", "cleanup", cleanup)
	cleanup = strings.ToLower(cleanup)
	cleanup = strings.ReplaceAll(cleanup, "'", "")
	if cleanup == "no" || cleanup == "false" {
		return false
	}
	return true
}

// GetCloudletSharedRootLBFlavor gets the flavor from defaults
// or environment variables
func (s *Platform) GetCloudletSharedRootLBFlavor(flavor *edgeproto.Flavor) error {
	ram := s.envVars["MEX_SHARED_ROOTLB_RAM"].Value
	var err error
	if ram != "" {
		flavor.Ram, err = strconv.ParseUint(ram, 10, 64)
		if err != nil {
			return err
		}
	} else {
		flavor.Ram = 4096
	}
	vcpus := s.envVars["MEX_SHARED_ROOTLB_VCPUS"].Value
	if vcpus != "" {
		flavor.Vcpus, err = strconv.ParseUint(vcpus, 10, 64)
		if err != nil {
			return err
		}
	} else {
		flavor.Vcpus = 2
	}
	disk := s.envVars["MEX_SHARED_ROOTLB_DISK"].Value
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

// getCloudletSecurityGroupName returns the cloudlet-wide security group name.  This function cannot ever be called externally because
// this group name can be duplicated which can cause errors in some environments.   GetCloudletSecurityGroupID should be used instead.  Note
func (s *Platform) GetCloudletSecurityGroupName() string {
	return s.envVars["MEX_SECURITY_GROUP"].Value
}
