package vcd

import (
	"context"
	"fmt"
	"os"

	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

// model VcdProps after vsphere to start

// This is now an edgeproto object
var VcdProps = map[string]*edgeproto.PropertyInfo{

	"MEX_ORG": {
		Description: "vCD Org for our tenant",
		Value:       "vcd-org",
	},
	"MEX_CATALOG": {
		Mandatory:   true,
		Description: "VCD Org Catalog Name",
	},
	"MEX_EXTERNAL_IP_RANGES": {
		Description: "Override natrual ext net range if more limited",
		Mandatory:   false,
	},
	// We don't get a value for the edgegateway xxx
	"MEX_EXTERNAL_NETWORK_EDGEGATEWAY": {
		Mandatory: false,
	},
	"MEX_EXT_NETWORK": {
		Description: "External OrgVDCNetwork to use",
		Mandatory:   true,
	},
	"MEX_EXTERNAL_NETWORK_MASK": {
		Name:        "External Network Mask",
		Description: "External Network Mask",
		Mandatory:   true,
	},
	"MEX_VDC_TEMPLATE": {
		Description: "The uploaded ova template name",
		Mandatory:   false,
		// could be in the secret
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

func (v *VcdPlatform) GetVcdVerbose() bool {
	if v.TestMode {
		verbose := os.Getenv("VCDVerbose")
		if verbose == "true" {
			return true
		}
	}
	return false
}

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

func (v *VcdPlatform) GetPrimaryVdc() string {
	if v.TestMode {
		return os.Getenv("PRIMARY_VDC")
	}
	return v.vcdVars["PRIMARY_VDC"]
}

func (v *VcdPlatform) GetExtNetworkName() string {
	return v.vcdVars["MEX_EXT_NETWORK"]
}

// Sort out the spelling VCD vs VDC template name in all the secrets. It's offically a vdc template.
func (v *VcdPlatform) GetVDCTemplateName() string {
	if v.TestMode {
		tmplName := os.Getenv("VCDTEMPLATE")
		if tmplName != "" {
			return tmplName
		}
	}
	tmplName := v.vcdVars["VCDTEMPLATE"]
	if tmplName != "" {
		return tmplName
	}

	return v.vcdVars["VDCTEMPLATE"]
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

func (v *VcdPlatform) GetExternalNetmask() string {

	if v.vmProperties.Domain == vmlayer.VMDomainPlatform {
		// check for optional management netmask
		val, _ := v.vmProperties.CommonPf.Properties.GetValue("MEX_MANAGEMENT_EXTERNAL_NETWORK_MASK")
		if val != "" {
			return val
		}
	}
	val, _ := v.vmProperties.CommonPf.Properties.GetValue("MEX_EXTERNAL_NETWORK_MASK")
	return val
}

func (v *VcdPlatform) GetInternalNetmask() string {
	val, _ := v.vmProperties.CommonPf.Properties.GetValue("MEX_INTERNAL_NETWORK_MASK")
	return val
}

func (v *VcdPlatform) GetCatalogName() string {
	if v.TestMode {
		val := os.Getenv("MEX_CATALOG")
		return val
	}
	val, _ := v.vmProperties.CommonPf.Properties.GetValue("MEX_CATALOG")
	return val
}

func (v *VcdPlatform) GetTemplateName() string {
	if v.TestMode {
		val := os.Getenv("MEX_VDC_TEMPLATE")
		return val
	}

	val, _ := v.vmProperties.CommonPf.Properties.GetValue("MEX_VDC_TEMPLATE")
	return val
}
