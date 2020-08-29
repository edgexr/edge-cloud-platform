package vsphere

import (
	"context"
	"fmt"

	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/log"
)

type DeployScriptParams struct {
	DataCenterName string
	DataStoreName  string
	Cluster        string
	ResourcePool   string
	Netmask        string
	VMName         string
	Gateway        string
	IPAddr         string
	Network        string
	Tags           *[]vmlayer.TagOrchestrationParams
	VM             *vmlayer.VMOrchestrationParams
	EnvVars        *map[string]string
}

var deployScriptTemplate = `
#!/bin/bash

cleanup(){
	echo "running cleanup after failure"
	{{- range .Tags}}
	govc tags.rm {{.Name}}
	{{- end}}
 
	govc pool.destroy -dc {{.DataCenterName}} {{.ResourcePool}}
	govc vm.destroy -dc {{.DataCenterName}} {{.VM.Name}}
}

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
govc vm.customize -vm {{.VM.Name}} -dc {{.DataCenterName}} -dns-server {{.VM.DNSServers}} -ip {{.IPAddr}} -netmask {{.Netmask}} -gateway {{.Gateway}}
if [[ $? != 0 ]]; then 
	echo "ERROR: failed to customize network with IP {{.IPAddr}} mask {{.Netmask}} gw {{.Gateway}}"
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
	if len(vmgp.VMs[0].Ports) != 1 {
		return "", fmt.Errorf("error, VM should have one port, found: %d", len(vmgp.VMs[0].Ports))
	}
	if len(vmgp.VMs[0].FixedIPs) != 1 {
		return "", fmt.Errorf("error, VM should have one IP address, found: %d", len(vmgp.VMs[0].FixedIPs))
	}
	netMask, err := vmlayer.MaskLenToMask(vmgp.VMs[0].FixedIPs[0].Mask)
	if err != nil {
		return "", err
	}

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
		Network:        vmgp.VMs[0].Ports[0].NetworkId,
		Netmask:        netMask,
		IPAddr:         vmgp.VMs[0].FixedIPs[0].Address,
		Gateway:        vmgp.VMs[0].FixedIPs[0].Gateway,
	}

	buf, err := vmlayer.ExecTemplate(vmgp.GroupName, deployScriptTemplate, scriptParams)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
