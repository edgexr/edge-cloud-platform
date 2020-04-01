package mexos

// This file stores a global cloudlet infra properties object. The long term solution is for the controller to send this via the
// notification channel when the cloudlet is provisioned.   The controller will do the vault access and pass this data down; this
// is a stepping stone to start using edgepro data strucures to hold info abou the cloudlet rather than custom types and so the vault
// is still directly accessed here as are env variable to populate some variables

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
)

type PropertyInfo struct {
	Value  string
	Secret bool
}

// Cloudlet Infra Common Properties
var infraCommonProps = map[string]*PropertyInfo{
	// Property: Default-Value
	"MEX_CF_KEY": &PropertyInfo{
		Secret: true,
	},
	"MEX_CF_USER":         &PropertyInfo{},
	"MEX_EXTERNAL_IP_MAP": &PropertyInfo{},
	"MEX_REGISTRY_FILE_SERVER": &PropertyInfo{
		Value: "registry.mobiledgex.net",
	},
	"MEX_DNS_ZONE": &PropertyInfo{
		Value: "mobiledgex.net",
	},
}

type CommonPlatform struct {
	envVars map[string]*PropertyInfo
	// mapping of FQDNs the CRM knows about to externally mapped IPs. This
	// is used mainly in lab environments that have NATed IPs which can be used to
	// access the cloudlet externally but are not visible in any way to OpenStack
	mappedExternalIPs map[string]string
}

var MEXInfraVersion = "3.1.0"
var ImageNamePrefix = "mobiledgex-v"
var DefaultOSImageName = ImageNamePrefix + MEXInfraVersion
var ImageFormatQcow2 = "qcow2"

// Default CloudletVM/Registry paths should only be used for local testing.
// Ansible should always specify the correct ones to the controller.
// These are not used if running the CRM manually, because these are only
// used by CreateCloudlet to set up the CRM VM and container.
var DefaultContainerRegistryPath = "registry.mobiledgex.net:5000/mobiledgex/edge-cloud"
var DefaultCloudletVMImagePath = "https://artifactory.mobiledgex.net/artifactory/baseimages/"

// NoConfigExternalRouter is used for the case in which we don't manage the external
// router and don't add ports to it ourself, as happens with Contrail.  The router does exist in
// this case and we use it to route from the LB to the pods
var NoConfigExternalRouter = "NOCONFIG"

// NoExternalRouter means there is no router at all and we connect the LB to the k8s pods on the same subnet
// this may eventually be the default and possibly only option
var NoExternalRouter = "NONE"

// Package level test mode variable
var testMode = false

func GetVaultCloudletCommonPath(filePath string) string {
	return fmt.Sprintf("/secret/data/cloudlet/openstack/%s", filePath)
}

func GetCloudletVMImageName(imgVersion string) string {
	if imgVersion == "" {
		imgVersion = MEXInfraVersion
	}
	return ImageNamePrefix + imgVersion
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

func SetPropsFromVars(ctx context.Context, props map[string]*PropertyInfo, vars map[string]string) {
	// Infra Props value is fetched in following order:
	// 1. Fetch props from vars passed, if nothing set then
	// 2. Fetch from env, if nothing set then
	// 3. Use default value
	for k, v := range props {
		if val, ok := vars[k]; ok {
			if props[k].Secret {
				log.SpanLog(ctx, log.DebugLevelMexos, "set infra property (secret) from vars", "key", k)
			} else {
				log.SpanLog(ctx, log.DebugLevelMexos, "set infra property from vars", "key", k, "val", val)
			}
			props[k].Value = val
		} else if val, ok := os.LookupEnv(k); ok {
			if props[k].Secret {
				log.SpanLog(ctx, log.DebugLevelMexos, "set infra property (secret) from env", "key", k)
			} else {
				log.SpanLog(ctx, log.DebugLevelMexos, "set infra property from env", "key", k, "val", val)
			}
			props[k].Value = val
		} else {
			if props[k].Secret {
				log.SpanLog(ctx, log.DebugLevelMexos, "using default infra property (secret)", "key", k)
			} else {
				log.SpanLog(ctx, log.DebugLevelMexos, "using default infra property", "key", k, "val", v.Value)
			}
		}
	}
}

func (c *CommonPlatform) InitInfraCommon(ctx context.Context, vaultConfig *vault.Config, vars map[string]string) error {
	if vaultConfig.Addr == "" {
		return fmt.Errorf("vaultAddr is not specified")
	}

	// set default properties
	c.envVars = infraCommonProps

	// fetch properties from vault
	mexEnvPath := GetVaultCloudletCommonPath("mexenv.json")
	log.SpanLog(ctx, log.DebugLevelMexos, "interning vault", "addr", vaultConfig.Addr, "path", mexEnvPath)
	envData := &VaultEnvData{}
	err := vault.GetData(vaultConfig, mexEnvPath, 0, envData)
	if err != nil {
		if strings.Contains(err.Error(), "no secrets") {
			return fmt.Errorf("Failed to source access variables as mexenv.json " +
				"does not exist in secure secrets storage (Vault)")
		}
		return fmt.Errorf("Failed to source access variables from %s, %s: %v", vaultConfig.Addr, mexEnvPath, err)
	}
	for _, envData := range envData.Env {
		if _, ok := c.envVars[envData.Name]; ok {
			c.envVars[envData.Name].Value = envData.Value
		} else {
			c.envVars[envData.Name] = &PropertyInfo{
				Value: envData.Value,
			}
		}
	}

	// fetch properties from user input
	SetPropsFromVars(ctx, c.envVars, vars)

	if c.GetCloudletCFKey() == "" {
		if testMode {
			log.SpanLog(ctx, log.DebugLevelMexos, "Env variable MEX_CF_KEY not set")
		} else {
			return fmt.Errorf("Env variable MEX_CF_KEY not set")
		}
	}
	if c.GetCloudletCFUser() == "" {
		if testMode {
			log.SpanLog(ctx, log.DebugLevelMexos, "Env variable MEX_CF_USER not set")
		} else {
			return fmt.Errorf("Env variable MEX_CF_USER not set")
		}
	}
	err = c.initMappedIPs()
	if err != nil {
		return fmt.Errorf("unable to init Mapped IPs: %v", err)
	}
	return nil
}

func (c *CommonPlatform) GetCloudletDNSZone() string {
	return c.envVars["MEX_DNS_ZONE"].Value
}

func (c *CommonPlatform) GetCloudletRegistryFileServer() string {
	return c.envVars["MEX_REGISTRY_FILE_SERVER"].Value
}

func (c *CommonPlatform) GetCloudletCFKey() string {
	return c.envVars["MEX_CF_KEY"].Value
}

func (c *CommonPlatform) GetCloudletCFUser() string {
	return c.envVars["MEX_CF_USER"].Value
}

func SetTestMode(tMode bool) {
	testMode = tMode
}

func GetCloudletNetworkIfaceFile() string {
	return "/etc/network/interfaces.d/50-cloud-init.cfg"
}

// initMappedIPs takes the env var MEX_EXTERNAL_IP_MAP contents like:
// fromip1=toip1,fromip2=toip2 and populates mappedExternalIPs
func (c *CommonPlatform) initMappedIPs() error {
	c.mappedExternalIPs = make(map[string]string)
	meip := c.envVars["MEX_EXTERNAL_IP_MAP"].Value
	if meip != "" {
		ippair := strings.Split(meip, ",")
		for _, i := range ippair {
			ia := strings.Split(i, "=")
			if len(ia) != 2 {
				return fmt.Errorf("invalid format for mapped ip, expect fromip=destip")
			}
			fromip := ia[0]
			toip := ia[1]
			c.mappedExternalIPs[fromip] = toip
		}

	}
	return nil
}

// GetMappedExternalIP returns the IP that the input IP should be mapped to. This
// is used for environments which used NATted external IPs
func (c *CommonPlatform) GetMappedExternalIP(ip string) string {
	mappedip, ok := c.mappedExternalIPs[ip]
	if ok {
		return mappedip
	}
	return ip
}
