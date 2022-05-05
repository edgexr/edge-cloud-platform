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

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"

	sh "github.com/codeskyblue/go-sh"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
)

// Default CloudletVM/Registry paths should only be used for local testing.
// Ansible should always specify the correct ones to the controller.
// These are not used if running the CRM manually, because these are only
// used by CreateCloudlet to set up the CRM VM and container.
var DefaultContainerRegistryPath = "registry.mobiledgex.net:5000/mobiledgex/edge-cloud-crm"

// Cloudlet Infra Common Properties
var InfraCommonProps = map[string]*edgeproto.PropertyInfo{
	// Property: Default-Value
	"MEX_EXTERNAL_IP_MAP": &edgeproto.PropertyInfo{
		Name:        "External IP Map",
		Description: "External IP Map",
	},
	"MEX_REGISTRY_FILE_SERVER": &edgeproto.PropertyInfo{
		Name:        "Registry File Server",
		Description: "Registry File Server",
		Value:       "registry.mobiledgex.net",
	},
	"FLAVOR_MATCH_PATTERN": &edgeproto.PropertyInfo{
		Name:        "Flavor Match Pattern",
		Description: "Flavors matching this pattern will be used by Cloudlet to bringup VMs",
		Value:       ".*",
	},
	"SKIP_INSTALL_RESOURCE_TRACKER": &edgeproto.PropertyInfo{
		Name:        "Skip Install Resource Tracker",
		Description: "If set to true, the resource tracker is not installed to save time. For test only",
		Internal:    true,
	},
	"MEX_CRM_GATEWAY_ADDR": {
		Name:        "CRM Gateway Address",
		Description: "Required if infra API endpoint is completely isolated from external network",
	},
	"MEX_PLATFORM_STATS_MAX_CACHE_TIME": {
		Name:        "Platform Stats Max Cache Time",
		Description: "Maximum time to used cached platform stats if nothing changed, in seconds",
		Internal:    true,
		Value:       "3600",
	},
}

func (ip *InfraProperties) GetCloudletCRMGatewayIPAndPort() (string, int) {
	gw, _ := ip.GetValue("MEX_CRM_GATEWAY_ADDR")
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

func GetVaultCloudletCommonPath(filePath string) string {
	// TODO this path really should not be openstack
	return fmt.Sprintf("/secret/data/cloudlet/openstack/%s", filePath)
}

func (ip *InfraProperties) GetPlatformStatsMaxCacheTime() (uint64, error) {
	val, ok := ip.GetValue("MEX_PLATFORM_STATS_MAX_CACHE_TIME")
	if !ok {
		return 0, nil
	}
	v, err := strconv.ParseUint(val, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("ERROR: unable to parse MEX_PLATFORM_STATS_MAX_CACHE_TIME %s - %v", val, err)
	}
	return v, nil
}

type InfraProperties struct {
	Properties map[string]*edgeproto.PropertyInfo
	Mux        sync.Mutex
}

func (p *InfraProperties) Init() {
	p.Properties = make(map[string]*edgeproto.PropertyInfo)
	p.SetProperties(InfraCommonProps)
}

func (p *InfraProperties) GetValue(key string) (string, bool) {
	p.Mux.Lock()
	defer p.Mux.Unlock()
	if out, ok := p.Properties[key]; ok {
		return out.Value, ok
	}
	return "", false
}

func (p *InfraProperties) SetValue(key, value string) {
	p.Mux.Lock()
	defer p.Mux.Unlock()
	if _, ok := p.Properties[key]; ok {
		p.Properties[key].Value = value
	}
}

func (p *InfraProperties) SetProperties(props map[string]*edgeproto.PropertyInfo) {
	p.Mux.Lock()
	defer p.Mux.Unlock()
	for k, v := range props {
		val := *v
		p.Properties[k] = &val
	}
}

func (p *InfraProperties) SetPropsFromVars(ctx context.Context, vars map[string]string) {
	// Infra Props value is fetched in following order:
	// 1. Fetch props from vars passed, if nothing set then
	// 2. Fetch from env, if nothing set then
	// 3. Use default value
	p.Mux.Lock()
	defer p.Mux.Unlock()
	for k, v := range p.Properties {
		if val, ok := vars[k]; ok {
			if p.Properties[k].Secret {
				log.SpanLog(ctx, log.DebugLevelInfra, "set infra property (secret) from vars", "key", k)
			} else {
				log.SpanLog(ctx, log.DebugLevelInfra, "set infra property from vars", "key", k, "val", val)
			}
			p.Properties[k].Value = val
		} else if val, ok := os.LookupEnv(k); ok {
			if p.Properties[k].Secret {
				log.SpanLog(ctx, log.DebugLevelInfra, "set infra property (secret) from env", "key", k)
			} else {
				log.SpanLog(ctx, log.DebugLevelInfra, "set infra property from env", "key", k, "val", val)
			}
			p.Properties[k].Value = val
		} else {
			if p.Properties[k].Secret {
				log.SpanLog(ctx, log.DebugLevelInfra, "using default infra property (secret)", "key", k)
			} else {
				log.SpanLog(ctx, log.DebugLevelInfra, "using default infra property", "key", k, "val", v.Value)
			}
		}
	}
}

func (p *InfraProperties) UpdatePropsFromVars(ctx context.Context, vars map[string]string) {
	p.Mux.Lock()
	defer p.Mux.Unlock()
	for k, _ := range p.Properties {
		if val, ok := vars[k]; ok {
			if p.Properties[k].Secret {
				log.SpanLog(ctx, log.DebugLevelInfra, "update infra property (secret) from vars", "key", k)
			} else {
				log.SpanLog(ctx, log.DebugLevelInfra, "update infra property from vars", "key", k, "val", val)
			}
			p.Properties[k].Value = val
		}
	}
}

func Sh(envVars map[string]string) *sh.Session {
	newSh := sh.NewSession()
	for key, val := range envVars {
		newSh.SetEnv(key, val)
	}
	return newSh
}
