package vsphere

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
)

var VSphereProps = map[string]*edgeproto.PropertyInfo{

	"MEX_COMPUTE_CLUSTER": {
		Name:        "vSphere Compute Cluster Name",
		Description: "vSphere Compute Cluster Name",
		Value:       "compute-cluster",
	},
	"MEX_DATASTORE": {
		Name:        "vSphere Datastore Name",
		Description: "vSphere Datastore Name",
		Mandatory:   true,
	},
	"MEX_EXTERNAL_IP_RANGES": {
		Name:        "External IP Ranges",
		Description: "Range of external IP addresses, Format: StartCIDR-EndCIDR",
		Mandatory:   true,
	},
	"MEX_EXTERNAL_NETWORK_MASK": {
		Name:        "External Network Mask",
		Description: "External Network Mask",
		Mandatory:   true,
	},
	"MEX_EXTERNAL_NETWORK_GATEWAY": {
		Name:        "External Network Gateway",
		Description: "External Network Gateway",
		Mandatory:   true,
	},
	"MEX_INTERNAL_NETWORK_MASK": {
		Name:        "Internal Network Mask",
		Description: "Internal Network Mask",
		Value:       "24",
	},
	"MEX_EXTERNAL_VSWITCH": {
		Name:        "vSphere External vSwitch Name",
		Description: "vSphere External vSwitch Name",
		Value:       "ExternalVSwitch",
	},
	"MEX_INTERNAL_VSWITCH": {
		Name:        "vSphere Internal vSwitch Name",
		Description: "vSphere Internal vSwitch Name",
		Value:       "InternalVSwitch",
	},
	"MEX_TEMPLATE_FOLDER": {
		Name:        "vSphere Template Folder Name",
		Description: "vSphere Template Folder Name",
		Value:       "templates",
	},
}

func (v *VSpherePlatform) GetApiAccessFilename() string {
	return "vcenter.json"
}

func (v *VSpherePlatform) GetVsphereVars(ctx context.Context, key *edgeproto.CloudletKey, region, physicalName string, vaultConfig *vault.Config) error {
	if vaultConfig == nil || vaultConfig.Addr == "" {
		return fmt.Errorf("vaultAddr is not specified")
	}
	vcpath := vmlayer.GetVaultCloudletAccessPath(key, region, v.GetType(), physicalName, v.GetApiAccessFilename())
	log.SpanLog(ctx, log.DebugLevelInfra, "interning vault", "addr", vaultConfig.Addr, "path", vcpath)
	envData := &infracommon.VaultEnvData{}
	err := vault.GetData(vaultConfig, vcpath, 0, envData)
	if err != nil {
		if strings.Contains(err.Error(), "no secrets") {
			return fmt.Errorf("Failed to source access variables as '%s/%s' "+
				"does not exist in secure secrets storage (Vault)",
				key.Organization, physicalName)
		}
		return fmt.Errorf("Failed to source access variables from %s, %s: %v", vaultConfig.Addr, vcpath, err)
	}
	v.vcenterVars = make(map[string]string, 1)
	for _, envData := range envData.Env {
		v.vcenterVars[envData.Name] = envData.Value
	}

	// vcenter vars are used for govc.  They are stored in the vault in a
	// generic format which is not specific to govc
	host, _, err := v.GetVCenterAddress()
	if err != nil {
		return err
	}
	v.vcenterVars["GOVC_URL"] = host
	v.vcenterVars["GOVC_USERNAME"] = v.GetVCenterUser()
	pass := v.GetVCenterPassword()
	v.vcenterVars["GOVC_PASSWORD"] = pass
	v.vcenterVars["GOVC_INSECURE"] = v.GetVCenterInsecure()

	return nil
}

func (v *VSpherePlatform) InitApiAccessProperties(ctx context.Context, key *edgeproto.CloudletKey, region, physicalName string, vaultConfig *vault.Config, vars map[string]string) error {
	err := v.GetVsphereVars(ctx, key, region, physicalName, vaultConfig)
	if err != nil {
		return err
	}
	return nil
}

func (v *VSpherePlatform) GetProviderSpecificProps() map[string]*edgeproto.PropertyInfo {
	return VSphereProps
}

// GetVSphereAddress returns host and port for the vcenter server
func (v *VSpherePlatform) GetVCenterAddress() (string, string, error) {
	vcaddr := v.vcenterVars["VCENTER_ADDR"]
	if vcaddr == "" {
		return "", "", fmt.Errorf("VCENTER_ADDR not set")
	}
	host, portstr, err := net.SplitHostPort(vcaddr)
	if err != nil {
		return "", "", fmt.Errorf("Unable to parse VCENTER_ADDR: %s, %v\n", vcaddr, err)
	}
	return host, portstr, nil
}

func (v *VSpherePlatform) GetVCenterUser() string {
	return v.vcenterVars["VCENTER_USER"]
}

func (v *VSpherePlatform) GetVCenterPassword() string {
	return v.vcenterVars["VCENTER_PASSWORD"]
}

func (v *VSpherePlatform) GetVCenterConsoleUser() string {
	return v.vcenterVars["VCENTER_CONSOLE_USER"]
}

func (v *VSpherePlatform) GetVCenterConsolePassword() string {
	return v.vcenterVars["VCENTER_CONSOLE_PASSWORD"]
}

func (v *VSpherePlatform) GetVCenterInsecure() string {
	val, ok := v.vcenterVars["VCENTER_INSECURE"]
	if !ok {
		return "false"
	}
	return val
}

func (v *VSpherePlatform) GetComputeCluster() string {
	if val, ok := v.vmProperties.CommonPf.Properties["MEX_COMPUTE_CLUSTER"]; ok {
		return val.Value
	}
	return ""
}

func (v *VSpherePlatform) GetDataStore() string {
	if val, ok := v.vmProperties.CommonPf.Properties["MEX_DATASTORE"]; ok {
		return val.Value
	}
	return ""
}

func (v *VSpherePlatform) GetInternalVSwitch() string {
	if val, ok := v.vmProperties.CommonPf.Properties["MEX_INTERNAL_VSWITCH"]; ok {
		return val.Value
	}
	return ""
}

func (v *VSpherePlatform) GetExternalVSwitch() string {
	if val, ok := v.vmProperties.CommonPf.Properties["MEX_EXTERNAL_VSWITCH"]; ok {
		return val.Value
	}
	return ""
}
func (v *VSpherePlatform) GetExternalNetmask() string {
	if val, ok := v.vmProperties.CommonPf.Properties["MEX_EXTERNAL_NETWORK_MASK"]; ok {
		return val.Value
	}
	return ""
}
func (v *VSpherePlatform) GetExternalGateway(ctx context.Context, extNetName string) (string, error) {
	if val, ok := v.vmProperties.CommonPf.Properties["MEX_EXTERNAL_NETWORK_GATEWAY"]; ok {
		return val.Value, nil
	}
	return "", nil
}

func (v *VSpherePlatform) GetInternalNetmask() string {
	if val, ok := v.vmProperties.CommonPf.Properties["MEX_INTERNAL_NETWORK_MASK"]; ok {
		return val.Value
	}
	return ""
}

func (v *VSpherePlatform) GetTemplateFolder() string {
	if val, ok := v.vmProperties.CommonPf.Properties["MEX_TEMPLATE_FOLDER"]; ok {
		return val.Value
	}
	return ""
}
