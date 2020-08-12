package infracommon

import (
	"context"
	"fmt"
	"os"

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

func SetPropsFromVars(ctx context.Context, props map[string]*edgeproto.PropertyInfo, vars map[string]string) {
	// Infra Props value is fetched in following order:
	// 1. Fetch props from vars passed, if nothing set then
	// 2. Fetch from env, if nothing set then
	// 3. Use default value
	for k, v := range props {
		if val, ok := vars[k]; ok {
			if props[k].Secret {
				log.SpanLog(ctx, log.DebugLevelInfra, "set infra property (secret) from vars", "key", k)
			} else {
				log.SpanLog(ctx, log.DebugLevelInfra, "set infra property from vars", "key", k, "val", val)
			}
			props[k].Value = val
		} else if val, ok := os.LookupEnv(k); ok {
			if props[k].Secret {
				log.SpanLog(ctx, log.DebugLevelInfra, "set infra property (secret) from env", "key", k)
			} else {
				log.SpanLog(ctx, log.DebugLevelInfra, "set infra property from env", "key", k, "val", val)
			}
			props[k].Value = val
		} else {
			if props[k].Secret {
				log.SpanLog(ctx, log.DebugLevelInfra, "using default infra property (secret)", "key", k)
			} else {
				log.SpanLog(ctx, log.DebugLevelInfra, "using default infra property", "key", k, "val", v.Value)
			}
		}
	}
}

func GetVaultCloudletCommonPath(filePath string) string {
	// TODO this path really should not be openstack
	return fmt.Sprintf("/secret/data/cloudlet/openstack/%s", filePath)
}
