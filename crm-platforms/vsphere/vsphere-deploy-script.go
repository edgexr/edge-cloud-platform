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

	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/log"
)

type DeployScriptParams struct {
	DataCenterName string
	DataStoreName  string
	Cluster        string
	ResourcePool   string
	VMName         string
	Network        string
	Gateway        string
	Netmask        string
	Tags           *[]vmlayer.TagOrchestrationParams
	VM             *vmlayer.VMOrchestrationParams
	EnvVars        *map[string]string
}

var deployScriptTemplate = `
#!/bin/bash

PARAMCONFIRM="n"

cleanup(){
	echo "running cleanup after failure"
	{{- range .Tags}}
	govc tags.rm {{.Name}}
	{{- end}}
 
	govc pool.destroy -dc {{.DataCenterName}} {{.ResourcePool}}
	govc vm.destroy -dc {{.DataCenterName}} {{.VM.Name}}
}

if [ $# -ne 1 ]; then
    echo "Error: ipaddr argument expected"
    echo "Example: $0 139.178.83.27"
    exit 1
fi

PF_IP=$1

echo "setting environment variables"
{{- range $k, $v := .EnvVars}}
export {{$k}}={{$v}}
{{- end}}

echo "creating tags"
{{- range .Tags}}
govc tags.create -c {{.Category}} {{.Name}}
if [[ $? != 0 ]]; then 
	echo "ERROR: failed to create tag {{.Name}}"
	cleanup
	exit 1
fi
{{- end}}

echo "creating resource pool"
govc pool.create -dc {{.DataCenterName}} {{.ResourcePool}}
if [[ $? != 0 ]]; then 
	echo "ERROR: failed to create resource pool {{.ResourcePool}}"
	cleanup
	exit $rc
fi

echo "cloning VM from template"
govc vm.clone -vm {{.VM.ImageName}}-vsphere -dc {{.DataCenterName}} -ds {{.DataStoreName}} -on=False -pool {{.ResourcePool}} -c {{.VM.Vcpus}} -m {{.VM.Ram}} -net {{.Network}} {{.VM.Name}}
if [[ $? != 0 ]]; then 
	echo "ERROR: failed to clone VM {{.VM.Name}}"
	cleanup
	exit $rc
fi

echo "setting metadata and userdata"
govc vm.change -vm {{.VM.Name}} -dc {{.DataCenterName}} -e guestinfo.metadata={{.VM.MetaData}} -e guestinfo.metadata.encoding=base64
if [[ $? != 0 ]]; then 
	echo "ERROR: failed to set metadata"
	cleanup
	exit 1
fi

govc vm.change -vm {{.VM.Name}} -dc {{.DataCenterName}} -e guestinfo.userdata={{.VM.UserData}} -e guestinfo.userdata.encoding=base64
if [[ $? != 0 ]]; then 
	echo "ERROR: failed to set userdata"
	cleanup
	exit 1
fi

echo "updating disk size"
govc vm.disk.change -vm {{.VM.Name}} -dc {{.DataCenterName}} -size {{.VM.Disk}}G
if [[ $? != 0 ]]; then 
	echo "ERROR: failed to update disk size"
	cleanup
	exit 1
fi

echo "customizing network"
govc vm.customize -vm {{.VM.Name}} -dc {{.DataCenterName}} -dns-server {{.VM.DNSServers}} -ip $PF_IP -netmask {{.Netmask}} -gateway {{.Gateway}}
if [[ $? != 0 ]]; then 
	echo "ERROR: failed to customize network with IP $PF_IP mask {{.Netmask}} gw {{.Gateway}}"
	cleanup
	exit 1
fi

echo "powering on VM"
govc vm.power -dc {{.DataCenterName}} -on {{.VM.Name}}
if [[ $? != 0 ]]; then 
	echo "ERROR: failed to power on VM {{.VM.Name}}"
	cleanup
	exit 1
fi

echo "done!"
`

func (v *VSpherePlatform) GetRemoteDeployScript(ctx context.Context, vmgp *vmlayer.VMGroupOrchestrationParams) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetRemoteDeployScript", "vmgp", vmgp)
	if len(vmgp.VMs) != 1 {
		return "", fmt.Errorf("error, should be one VM in the customization params, found: %d", len(vmgp.VMs))
	}

	netMask, err := vmlayer.MaskLenToMask(v.GetExternalNetmask())
	if err != nil {
		return "", err
	}

	// add the external IP tag as a variable
	extNet := v.vmProperties.GetCloudletExternalNetwork()
	gw, err := v.GetExternalGateway(ctx, extNet)
	if err != nil {
		return "", err
	}
	extIpTag := v.GetVmIpTag(ctx, vmgp.GroupName, vmgp.VMs[0].Name, extNet, "$PF_IP")
	tagid := v.IdSanitize(extIpTag)
	vmgp.Tags = append(vmgp.Tags, vmlayer.TagOrchestrationParams{Category: v.GetVmIpTagCategory(ctx), Id: tagid, Name: extIpTag})

	poolName := getResourcePoolName(vmgp.GroupName, string(vmlayer.VMDomainPlatform))
	pathPrefix := fmt.Sprintf("/%s/host/%s/Resources/", v.GetDatacenterName(ctx), v.GetHostCluster())
	poolPath := pathPrefix + poolName
	scriptParams := DeployScriptParams{
		Tags:           &vmgp.Tags,
		ResourcePool:   poolPath,
		DataCenterName: v.GetDatacenterName(ctx),
		DataStoreName:  v.GetDataStore(),
		Cluster:        v.GetHostCluster(),
		VM:             &vmgp.VMs[0],
		EnvVars:        &v.vcenterVars,
		Netmask:        netMask,
		Network:        extNet,
		Gateway:        gw,
	}

	buf, err := infracommon.ExecTemplate(vmgp.GroupName, deployScriptTemplate, scriptParams)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
