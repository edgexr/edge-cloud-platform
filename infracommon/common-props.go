package infracommon

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/mobiledgex/edge-cloud/log"
)

type PropertyInfo struct {
	Value     string
	Secret    bool
	Mandatory bool
}

// Default CloudletVM/Registry paths should only be used for local testing.
// Ansible should always specify the correct ones to the controller.
// These are not used if running the CRM manually, because these are only
// used by CreateCloudlet to set up the CRM VM and container.
var DefaultContainerRegistryPath = "registry.mobiledgex.net:5000/mobiledgex/edge-cloud"

// Cloudlet Infra Common Properties
var infraCommonProps = map[string]*PropertyInfo{
	// Property: Default-Value
	"MEX_CF_KEY": &PropertyInfo{
		Secret:    true,
		Mandatory: true,
	},
	"MEX_CF_USER": &PropertyInfo{
		Mandatory: true,
	},
	"MEX_EXTERNAL_IP_MAP": &PropertyInfo{},
	"MEX_REGISTRY_FILE_SERVER": &PropertyInfo{
		Value: "registry.mobiledgex.net",
	},
	"MEX_DNS_ZONE": &PropertyInfo{
		Value: "mobiledgex.net",
	},
	"FLAVOR_MATCH_PATTERN": &PropertyInfo{
		Value: ".*",
	},
	"CLEANUP_ON_FAILURE": &PropertyInfo{
		Value: "true",
	},
}

func SetPropsFromVars(ctx context.Context, props map[string]*PropertyInfo, vars map[string]string) {
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

// GetCleanupOnFailure should be true unless we want to debug the failure,
// in which case this env var can be set to no.  We could consider making
// this configurable at the controller but really is only needed for debugging.
func (v *CommonPlatform) GetCleanupOnFailure(ctx context.Context) bool {
	cleanup := v.Properties["CLEANUP_ON_FAILURE"].Value
	log.SpanLog(ctx, log.DebugLevelInfra, "GetCleanupOnFailure", "cleanup", cleanup)
	cleanup = strings.ToLower(cleanup)
	cleanup = strings.ReplaceAll(cleanup, "'", "")
	if cleanup == "no" || cleanup == "false" {
		return false
	}
	return true
}
