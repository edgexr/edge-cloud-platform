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
	"github.com/edgexr/edge-cloud-infra/chefmgmt"
	"github.com/edgexr/edge-cloud-infra/version"
	pf "github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
)

type CommonPlatform struct {
	Properties        InfraProperties
	PlatformConfig    *pf.PlatformConfig
	MappedExternalIPs map[string]string
	ChefClient        *chef.Client
	ChefServerPath    string
	DeploymentTag     string
	SshKey            CloudletSSHKey
}

// Package level test mode variable
var testMode = false
var edgeboxMode = false

func (c *CommonPlatform) InitInfraCommon(ctx context.Context, platformConfig *pf.PlatformConfig, platformSpecificProps map[string]*edgeproto.PropertyInfo) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "InitInfraCommon", "cloudletKey", platformConfig.CloudletKey)

	c.PlatformConfig = platformConfig
	c.Properties.Init()
	c.Properties.SetProperties(platformSpecificProps)
	// fetch properties from user input
	c.Properties.SetPropsFromVars(ctx, c.PlatformConfig.EnvVars)

	if !testMode {
		for name, val := range c.Properties.Properties {
			if val.Mandatory && val.Value == "" {
				log.SpanLog(ctx, log.DebugLevelInfra, "mandatory property not set", "name", name)
				return fmt.Errorf("mandatory property not set: %s", name)
			}
		}
	}

	err := c.initMappedIPs()
	if err != nil {
		return fmt.Errorf("unable to init Mapped IPs: %v", err)
	}

	if testMode || edgeboxMode {
		return nil
	}

	if platformConfig.DeploymentTag == "" {
		return fmt.Errorf("missing deployment tag")
	}

	chefAuth, err := platformConfig.AccessApi.GetChefAuthKey(ctx)
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

func SetTestMode(tMode bool) {
	testMode = tMode
}

func SetEdgeboxMode(mode bool) {
	edgeboxMode = mode
}

// initMappedIPs takes the env var MEX_EXTERNAL_IP_MAP contents like:
// fromip1=toip1,fromip2=toip2 and populates mappedExternalIPs
func (c *CommonPlatform) initMappedIPs() error {
	c.MappedExternalIPs = make(map[string]string)
	meip, _ := c.Properties.GetValue("MEX_EXTERNAL_IP_MAP")
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

// ValidateExternalIPMapping checjs mapped IPs are defined but there is no entry for this particular
// IP, then it may indicate a provisioning error in which the external range is not matched with the
// internal range
func (c *CommonPlatform) ValidateExternalIPMapping(ctx context.Context, ip string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ValidateExternalIPMapping", "ip", ip)

	if len(c.MappedExternalIPs) == 0 {
		// no mapped ips defined
		return nil
	}
	_, ok := c.MappedExternalIPs[ip]
	if !ok {
		return fmt.Errorf("Mapped IPs defined but IP %s not found in map", ip)
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
func GetPlatformConfig(cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, accessApi pf.AccessApi) *pf.PlatformConfig {
	platCfg := pf.PlatformConfig{
		CloudletKey:         &cloudlet.Key,
		PhysicalName:        cloudlet.PhysicalName,
		Region:              pfConfig.Region,
		TestMode:            pfConfig.TestMode,
		CloudletVMImagePath: pfConfig.CloudletVmImagePath,
		VMImageVersion:      cloudlet.VmImageVersion,
		EnvVars:             pfConfig.EnvVar,
		AppDNSRoot:          pfConfig.AppDnsRoot,
		DeploymentTag:       pfConfig.DeploymentTag,
		AccessApi:           accessApi,
		ChefServerPath:      pfConfig.ChefServerPath,
	}
	return &platCfg
}

type CommonEmbedded struct{}

func (c *CommonEmbedded) GetVersionProperties() map[string]string {
	return version.InfraBuildProps("Platform")
}
