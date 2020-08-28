package infracommon

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

// Default CloudletVM/Registry paths should only be used for local testing.
// Ansible should always specify the correct ones to the controller.
// These are not used if running the CRM manually, because these are only
// used by CreateCloudlet to set up the CRM VM and container.
var DefaultContainerRegistryPath = "registry.mobiledgex.net:5000/mobiledgex/edge-cloud"

// Cloudlet Infra Common Properties
var InfraCommonProps = map[string]*edgeproto.PropertyInfo{
	// Property: Default-Value
	"MEX_CF_KEY": &edgeproto.PropertyInfo{
		Name:        "Cloudflare Key",
		Description: "Cloudflare Key",
		Secret:      true,
		Mandatory:   true,
		Internal:    true,
	},
	"MEX_CF_USER": &edgeproto.PropertyInfo{
		Name:        "Cloudflare User",
		Description: "Cloudflare User",
		Mandatory:   true,
		Internal:    true,
	},
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
}

func GetVaultCloudletCommonPath(filePath string) string {
	// TODO this path really should not be openstack
	return fmt.Sprintf("/secret/data/cloudlet/openstack/%s", filePath)
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

func (p *InfraProperties) SetPropsFromEnvData(env []EnvData) {
	p.Mux.Lock()
	defer p.Mux.Unlock()
	for _, envData := range env {
		if _, ok := p.Properties[envData.Name]; ok {
			p.Properties[envData.Name].Value = envData.Value
		} else {
			// quick fix for EDGECLOUD-2572.  Assume the mexenv.json item is secret if we have
			// not defined it one way or another in code, of if the props that defines it is not
			// run (e.g. an Azure property defined in mexenv.json when we are running openstack)
			p.Properties[envData.Name] = &edgeproto.PropertyInfo{
				Name:   envData.Name,
				Value:  envData.Value,
				Secret: true,
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
