package infracommon

// This file stores a global cloudlet infra properties object. The long term solution is for the controller to send this via the
// notification channel when the cloudlet is provisioned.   The controller will do the vault access and pass this data down; this
// is a stepping stone to start using edgepro data strucures to hold info abou the cloudlet rather than custom types and so the vault
// is still directly accessed here as are env variable to populate some variables

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-chef/chef"
	"github.com/mobiledgex/edge-cloud-infra/chefmgmt"
	pf "github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
)

type CommonPlatform struct {
	Properties        map[string]*edgeproto.PropertyInfo
	PlatformConfig    *pf.PlatformConfig
	VaultConfig       *vault.Config
	MappedExternalIPs map[string]string
	ChefClient        *chef.Client
	ChefServerPath    string
	DeploymentTag     string
}

// Package level test mode variable
var testMode = false

func (c *CommonPlatform) InitInfraCommon(ctx context.Context, platformConfig *pf.PlatformConfig, platformSpecificProps map[string]*edgeproto.PropertyInfo, vaultConfig *vault.Config) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "InitInfraCommon", "cloudletKey", platformConfig.CloudletKey)

	if vaultConfig.Addr == "" {
		return fmt.Errorf("vaultAddr is not specified")
	}
	c.Properties = make(map[string]*edgeproto.PropertyInfo)
	c.PlatformConfig = platformConfig
	c.VaultConfig = vaultConfig

	// set default properties
	for k, v := range InfraCommonProps {
		p := *v
		c.Properties[k] = &p
	}
	// append platform specific properties
	for k, v := range platformSpecificProps {
		p := *v
		c.Properties[k] = &p
	}

	// fetch properties from vault
	mexEnvPath := GetVaultCloudletCommonPath("mexenv.json")
	log.SpanLog(ctx, log.DebugLevelInfra, "interning vault", "addr", vaultConfig.Addr, "path", mexEnvPath)
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
		if _, ok := c.Properties[envData.Name]; ok {
			c.Properties[envData.Name].Value = envData.Value
		} else {
			// quick fix for EDGECLOUD-2572.  Assume the mexenv.json item is secret if we have
			// not defined it one way or another in code, of if the props that defines it is not
			// run (e.g. an Azure property defined in mexenv.json when we are running openstack)
			c.Properties[envData.Name] = &edgeproto.PropertyInfo{
				Name:   envData.Name,
				Value:  envData.Value,
				Secret: true,
			}
		}
	}
	// fetch properties from user input
	SetPropsFromVars(ctx, c.Properties, c.PlatformConfig.EnvVars)

	if !testMode {
		for name, val := range c.Properties {
			if val.Mandatory && val.Value == "" {
				log.SpanLog(ctx, log.DebugLevelInfra, "mandatory property not set", "name", name)
				return fmt.Errorf("mandatory property not set: %s", name)
			}
		}
	}

	err = c.initMappedIPs()
	if err != nil {
		return fmt.Errorf("unable to init Mapped IPs: %v", err)
	}

	if testMode {
		return nil
	}

	if platformConfig.DeploymentTag == "" {
		return fmt.Errorf("missing deployment tag")
	}

	chefAuth, err := chefmgmt.GetChefAuthKeys(ctx, vaultConfig)
	if err != nil {
		return err
	}

	chefServerPath := platformConfig.ChefServerPath
	if chefServerPath == "" {
		chefServerPath = chefmgmt.DefaultChefServerPath
	}

	chefClient, err := chefmgmt.GetChefClient(ctx, chefAuth.ApiKey, chefServerPath)
	if err != nil {
		return err
	}
	supportedTags, err := chefmgmt.ChefPolicyGroupList(ctx, chefClient)
	if err != nil {
		return err
	}
	found := false
	for _, tag := range supportedTags {
		if tag == platformConfig.DeploymentTag {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("invalid deployment tag %s, supported tags: %v", platformConfig.DeploymentTag, supportedTags)
	}
	// Set chef client, note here object is just initialised and
	// no connection has formed with chef server
	c.ChefClient = chefClient
	c.ChefServerPath = chefServerPath
	c.DeploymentTag = platformConfig.DeploymentTag
	return nil
}

func (c *CommonPlatform) GetCloudletDNSZone() string {
	return c.PlatformConfig.AppDNSRoot
}

func (c *CommonPlatform) GetCloudletRegistryFileServer() string {
	return c.Properties["MEX_REGISTRY_FILE_SERVER"].Value
}

func (c *CommonPlatform) GetCloudletCFKey() string {
	return c.Properties["MEX_CF_KEY"].Value
}

func (c *CommonPlatform) GetCloudletCFUser() string {
	return c.Properties["MEX_CF_USER"].Value
}

func SetTestMode(tMode bool) {
	testMode = tMode
}

// initMappedIPs takes the env var MEX_EXTERNAL_IP_MAP contents like:
// fromip1=toip1,fromip2=toip2 and populates mappedExternalIPs
func (c *CommonPlatform) initMappedIPs() error {
	c.MappedExternalIPs = make(map[string]string)
	meip := c.Properties["MEX_EXTERNAL_IP_MAP"].Value
	if meip != "" {
		ippair := strings.Split(meip, ",")
		for _, i := range ippair {
			ia := strings.Split(i, "=")
			if len(ia) != 2 {
				return fmt.Errorf("invalid format for mapped ip, expect fromip=destip")
			}
			fromip := ia[0]
			toip := ia[1]
			c.MappedExternalIPs[fromip] = toip
		}
	}
	return nil
}

// GetMappedExternalIP returns the IP that the input IP should be mapped to. This
// is used for environments which used NATted external IPs
func (c *CommonPlatform) GetMappedExternalIP(ip string) string {
	mappedip, ok := c.MappedExternalIPs[ip]
	if ok {
		return mappedip
	}
	return ip
}

// GetPlatformConfig builds a platform.PlatformConfig from a cloudlet and an edgeproto.PlatformConfig
func GetPlatformConfig(cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig) *pf.PlatformConfig {
	platCfg := pf.PlatformConfig{
		CloudletKey:         &cloudlet.Key,
		PhysicalName:        cloudlet.PhysicalName,
		VaultAddr:           pfConfig.VaultAddr,
		Region:              pfConfig.Region,
		TestMode:            pfConfig.TestMode,
		CloudletVMImagePath: pfConfig.CloudletVmImagePath,
		VMImageVersion:      cloudlet.VmImageVersion,
		EnvVars:             pfConfig.EnvVar,
		AppDNSRoot:          pfConfig.AppDnsRoot,
		ChefServerPath:      pfConfig.ChefServerPath,
		DeploymentTag:       pfConfig.DeploymentTag,
	}
	return &platCfg
}
