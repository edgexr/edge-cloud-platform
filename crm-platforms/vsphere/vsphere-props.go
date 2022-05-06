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

package vsphere

import (
	"context"
	"fmt"
	"net"

	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud/edgeproto"
)

var VSphereProps = map[string]*edgeproto.PropertyInfo{

	"MEX_COMPUTE_CLUSTER": {
		Name:        "vSphere Compute Cluster Name",
		Description: "vSphere Compute Cluster Name",
		Value:       "compute-cluster",
	},
	"MEX_MANAGEMENT_CLUSTER": {
		Name:        "vSphere Management Cluster Name",
		Description: "Optional vSphere Management Cluster Name for platform VMs; if not specified, platform VMs run on the same cluster as compute VMs",
	},
	"MEX_DATASTORE": {
		Name:        "vSphere Datastore Name",
		Description: "vSphere Datastore Name",
		Mandatory:   true,
	},
	"MEX_MANAGEMENT_DATASTORE": {
		Name:        "vSphere Management Datastore Name",
		Description: "Optional vSphere Management Datastore Name for platform VMs; if not specified, platform VMs run on the same datastore as compute VMs",
	},
	"MEX_EXTERNAL_IP_RANGES": {
		Name:        "External IP Ranges",
		Description: "Range of external IP addresses, Format: StartCIDR-EndCIDR",
		Mandatory:   true,
	},
	"MEX_MANAGEMENT_EXTERNAL_IP_RANGES": {
		Name:        "Management External IP Ranges",
		Description: "Optional Range of external IP addresses for management cluster; if not specified, platform VMs use same IP range as compute VMs.",
	},
	"MEX_EXTERNAL_NETWORK_GATEWAY": {
		Name:        "External Network Gateway",
		Description: "External Network Gateway",
		Mandatory:   true,
	},
	"MEX_MANAGEMENT_EXTERNAL_NETWORK_GATEWAY": {
		Name:        "Management External Network Gateway",
		Description: "Optional External Network Gateway for management cluster; if not specified, platform VMs use same gateway as compute VMs",
	},
	"MEX_EXTERNAL_NETWORK_MASK": {
		Name:        "External Network Mask",
		Description: "External Network Mask",
		Mandatory:   true,
	},
	"MEX_MANAGEMENT_EXTERNAL_NETWORK_MASK": {
		Name:        "Management External Network Mask",
		Description: "Optional External Network Mask for manangement cluster; if not specified, platform VMs use same netmask as compute VMs",
	},
	"MEX_INTERNAL_NETWORK_MASK": {
		Name:        "Internal Network Mask",
		Description: "Internal Network Mask in bits, e.g. 24",
		Value:       "24",
	},
	"MEX_EXTERNAL_VSWITCH": {
		Name:        "vSphere External vSwitch Name",
		Description: "vSphere External vSwitch Name",
		Mandatory:   true,
	},
	"MEX_MANAGEMENT_EXTERNAL_VSWITCH": {
		Name:        "vSphere Management External vSwitch Name",
		Description: "Optional vSphere External vSwitch Name for management cluster; if not specified, platform VMs use same external vSwitch as compute VMs",
	},
	"MEX_INTERNAL_VSWITCH": {
		Name:        "vSphere Internal vSwitch Name",
		Description: "vSphere Internal vSwitch Name",
		Mandatory:   true,
	},
	"MEX_TEMPLATE_FOLDER": {
		Name:        "vSphere Template Folder Name",
		Description: "vSphere Template Folder Name",
		Value:       "templates",
	},
	// default VM version is 6.7 which is forward compatible to 7.0
	"MEX_VM_VERSION": {
		Name:        "vSphere VM Version",
		Description: "vSphere VM Compatibility Version, e.g. 6.7 or 7.0",
		Value:       "6.7",
	},
}

func (v *VSpherePlatform) GetVaultCloudletAccessPath(key *edgeproto.CloudletKey, region, physicalName string) string {
	return fmt.Sprintf("/secret/data/%s/cloudlet/vsphere/%s/%s/vcenter.json", region, key.Organization, physicalName)
}

func (v *VSpherePlatform) GetVsphereVars(ctx context.Context, accessApi platform.AccessApi) error {
	vars, err := accessApi.GetCloudletAccessVars(ctx)
	if err != nil {
		return err
	}
	v.vcenterVars = vars

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

func (v *VSpherePlatform) InitApiAccessProperties(ctx context.Context, accessApi platform.AccessApi, vars map[string]string) error {
	err := v.GetVsphereVars(ctx, accessApi)
	if err != nil {
		return err
	}
	return nil
}

func (v *VSpherePlatform) GetProviderSpecificProps(ctx context.Context) (map[string]*edgeproto.PropertyInfo, error) {
	return VSphereProps, nil
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

func (v *VSpherePlatform) GetHostCluster() string {
	if v.vmProperties.Domain == vmlayer.VMDomainPlatform {
		// check for optional management cluster
		val, _ := v.vmProperties.CommonPf.Properties.GetValue("MEX_MANAGEMENT_CLUSTER")
		if val != "" {
			return val
		}
	}
	val, _ := v.vmProperties.CommonPf.Properties.GetValue("MEX_COMPUTE_CLUSTER")
	return val
}

func (v *VSpherePlatform) GetDataStore() string {
	if v.vmProperties.Domain == vmlayer.VMDomainPlatform {
		// check for optional management datastore
		val, _ := v.vmProperties.CommonPf.Properties.GetValue("MEX_MANAGEMENT_DATASTORE")
		if val != "" {
			return val
		}
	}
	val, _ := v.vmProperties.CommonPf.Properties.GetValue("MEX_DATASTORE")
	return val
}

func (v *VSpherePlatform) GetInternalVSwitch() string {
	val, _ := v.vmProperties.CommonPf.Properties.GetValue("MEX_INTERNAL_VSWITCH")
	return val
}

func (v *VSpherePlatform) GetExternalVSwitch() string {
	if v.vmProperties.Domain == vmlayer.VMDomainPlatform {
		// check for optional management vswitch
		val, _ := v.vmProperties.CommonPf.Properties.GetValue("MEX_MANAGEMENT_EXTERNAL_VSWITCH")
		if val != "" {
			return val
		}
	}
	val, _ := v.vmProperties.CommonPf.Properties.GetValue("MEX_EXTERNAL_VSWITCH")
	return val
}
func (v *VSpherePlatform) GetExternalNetmask() string {
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
func (v *VSpherePlatform) GetExternalGateway(ctx context.Context, extNetName string) (string, error) {
	if v.vmProperties.Domain == vmlayer.VMDomainPlatform {
		// check for optional management gw
		val, _ := v.vmProperties.CommonPf.Properties.GetValue("MEX_MANAGEMENT_EXTERNAL_NETWORK_GATEWAY")
		if val != "" {
			return val, nil
		}
	}
	val, ok := v.vmProperties.CommonPf.Properties.GetValue("MEX_EXTERNAL_NETWORK_GATEWAY")
	if !ok {
		return "", fmt.Errorf("Unable to find MEX_EXTERNAL_NETWORK_GATEWAY")
	}
	return val, nil
}

func (v *VSpherePlatform) GetInternalNetmask() string {
	val, _ := v.vmProperties.CommonPf.Properties.GetValue("MEX_INTERNAL_NETWORK_MASK")
	return val
}
func (v *VSpherePlatform) GetTemplateFolder() string {
	val, _ := v.vmProperties.CommonPf.Properties.GetValue("MEX_TEMPLATE_FOLDER")
	return val
}
func (v *VSpherePlatform) GetVMVersion() string {
	val, _ := v.vmProperties.CommonPf.Properties.GetValue("MEX_VM_VERSION")
	return val
}
