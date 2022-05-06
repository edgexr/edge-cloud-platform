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

package vcd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
)

const NSXT = "NSX-T"
const NSXV = "NSX-V"

// model VcdProps after vsphere to start

// This is now an edgeproto object
var VcdProps = map[string]*edgeproto.PropertyInfo{

	"MEX_CATALOG": {
		Mandatory:   true,
		Description: "VCD Org Catalog Name",
	},
	// We don't get a value for the edgegateway xxx
	"MEX_EXTERNAL_NETWORK_EDGEGATEWAY": {
		Description: "currently unused",
	},
	"MEX_ENABLE_VCD_DISK_RESIZE": {
		Description: "VM disks cloned from the VDC template will be resized based on flavor if set to \"true\" or \"yes\".  Set to \"false\" if fast provisioning is enabled in the VDC or VM creation will fail.",
		Value:       "true",
	},
	"VCDVerbose": {
		Description: "Verbose logging for VCD",
		Internal:    true,
	},
	// Use this when we don't have OrgAdmin rights and can not disable Org lease settings
	// but still wish to run. Leases will enforced by VCD.
	"VCD_OVERRIDE_LEASE_DISABLE": {
		Description: "Accept Org runtime lease values for VCD if unable to disable",
		Internal:    true,
	},
	"VCD_OVERRIDE_VCPU_SPEED": {
		Description: "Set value for vCPU Speed if unable to read from admin VCD",
		Internal:    true,
	},
	"VCD_NSX_TYPE": {
		Description: "NSX-T or NSX-V",
		Mandatory:   true,
	},
	"VCD_CLEANUP_ORPHAN_NETS": {
		Description: "Indicates Isolated Org VDC networks with no VApps to be deleted on startup",
		Value:       "false",
		Internal:    true,
	},
	"VCD_VM_APP_STATS_MAX_VDC_CACHE_TIME": {
		Description: "How long to cache VDC objects for VM App stat collection, in seconds",
		Internal:    true,
		Value:       "3600",
	},
	"VCD_VM_APP_INTERNAL_DHCP_SERVER": {
		Description: "If \"true\" or \"yes\" sets up an internal DHCP server for VM Apps, otherwise uses VCD server",
		Value:       "true",
		Internal:    true,
	},
	"VCD_TEMPLATE_ARTIFACTORY_IMPORT_ENABLED": {
		Description: "If \"true\" or \"yes\" VCD templates are stored in Artifactory and imported to VCD.  Otherwise, templates must already exist in the catalog",
		Value:       "true",
	},
	"VCD_VM_HREF_CACHE_ENABLED": {
		Description: "If \"true\" or \"yes\" caching of VCD VM HREFs is enabled",
		Value:       "true",
		Internal:    true,
	},
}

func (v *VcdPlatform) GetVaultCloudletAccessPath(key *edgeproto.CloudletKey, region, physicalName string) string {
	return fmt.Sprintf("/secret/data/%s/cloudlet/vcd/%s/%s/vcd.json", region, key.Organization, physicalName)
}

func (v *VcdPlatform) GetVcdVars(ctx context.Context, accessApi platform.AccessApi) error {

	log.SpanLog(ctx, log.DebugLevelInfra, "vcd vars")
	vars, err := accessApi.GetCloudletAccessVars(ctx)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "vcd vars accessApi vars failed", "err", err)
		return err
	}
	v.vcdVars = vars
	if len(vars) == 0 {
		return fmt.Errorf("No cloudlet access vars returned for Vcd")
	}
	if v.Verbose {
		log.SpanLog(ctx, log.DebugLevelInfra, "vcd ", "Vars", v.vcdVars)
	}
	err = v.PopulateOrgLoginCredsFromVcdVars(ctx)

	if err != nil {
		return err
	}
	return nil
}

// access vars from the vault

func (v *VcdPlatform) GetVcdUrl() string {
	return v.vcdVars["VCD_URL"]
}
func (v *VcdPlatform) GetVcdOauthSgwUrl() string {
	return v.vcdVars["VCD_OAUTH_SGW_URL"]
}
func (v *VcdPlatform) GetVcdOauthAgwUrl() string {
	return v.vcdVars["VCD_OAUTH_AGW_URL"]
}
func (v *VcdPlatform) GetVcdOauthClientId() string {
	return v.vcdVars["VCD_OAUTH_CLIENT_ID"]
}
func (v *VcdPlatform) GetVcdOauthClientSecret() string {
	return v.vcdVars["VCD_OAUTH_CLIENT_SECRET"]
}
func (v *VcdPlatform) GetVcdClientTlsCert() string {
	return v.vcdVars["VCD_CLIENT_TLS_CERT"]
}
func (v *VcdPlatform) GetVcdClientTlsKey() string {
	return v.vcdVars["VCD_CLIENT_TLS_KEY"]
}
func (v *VcdPlatform) GetVCDUser() string {
	return v.vcdVars["VCD_USER"]
}
func (v *VcdPlatform) GetVCDPassword() string {
	return v.vcdVars["VCD_PASSWORD"]
}
func (v *VcdPlatform) GetVCDORG() string {
	return v.vcdVars["VCD_ORG"]
}
func (v *VcdPlatform) GetVDCName() string {
	if v.TestMode {
		return os.Getenv("VDC_NAME")
	}
	return v.vcdVars["VDC_NAME"]
}
func (v *VcdPlatform) GetVCDURL() string {
	return v.vcdVars["VCD_URL"]
}
func (v *VcdPlatform) GetVcdClientRefreshInterval(ctx context.Context) uint64 {
	intervalStr := v.vcdVars["VCD_CLIENT_REFRESH_INTERVAL"]
	if intervalStr == "" {
		return DefaultClientRefreshInterval
	}
	interval, err := strconv.ParseUint(intervalStr, 10, 32)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Warning: unable to parse VCD_CLIENT_REFRESH_INTERVAL %s as int, using default", intervalStr)
		return DefaultClientRefreshInterval
	}
	return interval
}

// GetVcdInsecure defaults to true unless explicitly set to false
func (v *VcdPlatform) GetVcdInsecure() bool {
	insecure := v.vcdVars["VCD_INSECURE"]
	if strings.ToLower(insecure) == "false" {
		return false
	}
	return true
}

// properties from envvars
func (v *VcdPlatform) GetVcdVerbose() bool {
	verbose, _ := v.vmProperties.CommonPf.Properties.GetValue("VCDVerbose")
	if verbose == "true" {
		return true
	}
	return false
}

func (v *VcdPlatform) GetCatalogName() string {
	if v.TestMode {
		return os.Getenv("MEX_CATALOG")
	}

	val, _ := v.vmProperties.CommonPf.Properties.GetValue("MEX_CATALOG")
	return val
}

func (v *VcdPlatform) GetEnableVcdDiskResize() bool {
	val, _ := v.vmProperties.CommonPf.Properties.GetValue("MEX_ENABLE_VCD_DISK_RESIZE")
	return strings.ToLower(val) == "true" || strings.ToLower(val) == "yes"
}

// the normal methods of querying this seem sometimes unreliable e.g. vdc.IsNsxv()
func (v *VcdPlatform) GetNsxType() string {
	val, _ := v.vmProperties.CommonPf.Properties.GetValue("VCD_NSX_TYPE")
	if val != NSXT && val != NSXV {
		log.FatalLog("VCD_NSX_TYPE must be " + NSXT + " or " + NSXV)
	}
	return val
}

// the normal methods of querying this seem sometimes unreliable e.g. vdc.IsNsxv()
func (v *VcdPlatform) GetCleanupOrphanedNetworks() bool {
	val, _ := v.vmProperties.CommonPf.Properties.GetValue("VCD_CLEANUP_ORPHAN_NETS")
	return strings.ToLower(val) == "true" || strings.ToLower(val) == "yes"
}

func (v *VcdPlatform) GetVmAppStatsVdcMaxCacheTime() (uint64, error) {
	val, ok := v.vmProperties.CommonPf.Properties.GetValue("VCD_VM_APP_STATS_MAX_VDC_CACHE_TIME")
	if !ok {
		return 0, nil
	}
	vi, err := strconv.ParseUint(val, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("ERROR: unable to parse VCD_VM_APP_STATS_MAX_VDC_CACHE_TIME %s - %v", val, err)
	}
	return vi, nil
}

func (v *VcdPlatform) GetVmAppInternalDhcpServer() bool {
	val, _ := v.vmProperties.CommonPf.Properties.GetValue("VCD_VM_APP_INTERNAL_DHCP_SERVER")
	return strings.ToLower(val) == "true" || strings.ToLower(val) == "yes"
}

// start fetching access  bits from vault
func (v *VcdPlatform) InitApiAccessProperties(ctx context.Context, accessApi platform.AccessApi, vars map[string]string) error {

	log.SpanLog(ctx, log.DebugLevelInfra, "InitApiAccessProperties")
	err := v.GetVcdVars(ctx, accessApi)
	if err != nil {
		return err
	}

	return nil
}

func (v *VcdPlatform) GetProviderSpecificProps(ctx context.Context) (map[string]*edgeproto.PropertyInfo, error) {
	return VcdProps, nil
}

func (v *VcdPlatform) GetVcpuSpeedOverride(ctx context.Context) int64 {
	val, _ := v.vmProperties.CommonPf.Properties.GetValue("VCD_OVERRIDE_VCPU_SPEED")
	if val == "" {
		return 0
	}
	speed, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Unable to convert VCD_OVERRIDE_VCPU_SPEED to int", "val", val, "err", err)
		return 0
	}
	return speed
}
func (v *VcdPlatform) GetLeaseOverride() bool {
	if v.TestMode {
		or := os.Getenv("VCD_OVERRIDE_LEASE_DISABLE")
		if or == "true" || or == "yes" {
			return true
		}
		return false
	}
	val, _ := v.vmProperties.CommonPf.Properties.GetValue("VCD_OVERRIDE_LEASE_DISABLE")
	if strings.ToLower(val) == "true" || strings.ToLower(val) == "yes" {
		return true
	} else {
		return false
	}
}

func (v *VcdPlatform) GetTemplateArtifactoryImportEnabled() bool {
	val, _ := v.vmProperties.CommonPf.Properties.GetValue("VCD_TEMPLATE_ARTIFACTORY_IMPORT_ENABLED")
	return strings.ToLower(val) == "true" || strings.ToLower(val) == "yes"
}

func (v *VcdPlatform) GetHrefCacheEnabled() bool {
	val, _ := v.vmProperties.CommonPf.Properties.GetValue("VCD_VM_HREF_CACHE_ENABLED")
	return strings.ToLower(val) == "true" || strings.ToLower(val) == "yes"
}
