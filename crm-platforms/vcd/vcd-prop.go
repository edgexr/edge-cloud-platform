package vcd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

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
	"MEX_VDC_TEMPLATE": {
		Description: "The uploaded ova template name",
	},
	"MEX_ENABLE_VCD_DISK_RESIZE": {
		Description: "VM disks cloned from the VDC template will be resized based on flavor if set to \"true\".  Must be set to \"false\" if fast provisioning is enabled in the VDC or VM creation will fail.",
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
	err = v.PopulateOrgLoginCredsFromVault(ctx)

	if err != nil {
		return err
	}
	v.vcdVars["VCD_URL"] = v.Creds.Href
	log.SpanLog(ctx, log.DebugLevelInfra, "vcd ", "HREF", v.Creds.Href)
	return nil
}

// access vars from the vault

func (v *VcdPlatform) GetVCDIP() string {
	return v.vcdVars["VCD_IP"]
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
func (v *VcdPlatform) GetVDCTemplateName() string {
	if v.TestMode {
		tmplName := os.Getenv("VDCTEMPLATE")
		if tmplName != "" {
			return tmplName
		}
	}
	return v.vcdVars["VDCTEMPLATE"]
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
	val, _ := v.vmProperties.CommonPf.Properties.GetValue("MEX_CATALOG")
	return val
}

func (v *VcdPlatform) GetEnableVcdDiskResize() bool {
	val, _ := v.vmProperties.CommonPf.Properties.GetValue("MEX_ENABLE_VCD_DISK_RESIZE")
	return strings.ToLower(val) == "true"
}

// start fetching access  bits from vault
func (v *VcdPlatform) InitApiAccessProperties(ctx context.Context, accessApi platform.AccessApi, vars map[string]string, stage vmlayer.ProviderInitStage) error {

	log.SpanLog(ctx, log.DebugLevelInfra, "InitApiAccessProperties", "Stage", stage)
	err := v.GetVcdVars(ctx, accessApi)
	if err != nil {
		return err
	}
	return nil
}

func (v *VcdPlatform) SetProviderSpecificProps(ctx context.Context) error {

	// Put template selection bits here
	return nil
}

func (v *VcdPlatform) GetProviderSpecificProps(ctx context.Context) (map[string]*edgeproto.PropertyInfo, error) {
	return VcdProps, nil
}

func (v *VcdPlatform) GetTemplateNameFromProps() string {
	val, _ := v.vmProperties.CommonPf.Properties.GetValue("MEX_VDC_TEMPLATE")
	return val
}
func (v *VcdPlatform) GetLeaseOverride() bool {
	if v.TestMode {
		or := os.Getenv("VCD_OVERRIDE_LEASE_DISABLE")
		if or == "true" {
			return true
		}
		return false
	}
	val, _ := v.vmProperties.CommonPf.Properties.GetValue("VCD_OVERRIDE_LEASE_DISABLE")
	if val == "true" {
		return true
	} else {
		return false
	}
}
