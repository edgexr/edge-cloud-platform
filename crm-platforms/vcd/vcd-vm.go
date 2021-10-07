package vcd

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/vmware/go-vcloud-director/v2/govcd"
	"github.com/vmware/go-vcloud-director/v2/types/v56"
)

// VM related operations

// Just the vapp name and serverName
func (v *VcdPlatform) FindVM(ctx context.Context, serverName, vappName string, vcdClient *govcd.VCDClient) (*govcd.VM, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "FindVM", "serverName", serverName, "vappName", vappName)

	vdc, err := v.GetVdc(ctx, vcdClient)
	if err != nil {
		return nil, fmt.Errorf("GetVdc Failed - %v", err)
	}
	vmRec, err := vdc.QueryVM(vappName, serverName)
	if err != nil {
		return nil, err
	}
	// alt. Href
	vapp, err := vdc.GetVAppByName(vappName, true)
	if err != nil {
		return nil, err
	}
	return vapp.GetVMByName(vmRec.VM.Name, true)
}

// If all you have is the serverName (vmName)
func (v *VcdPlatform) FindVMByName(ctx context.Context, serverName string, vcdClient *govcd.VCDClient, vdc *govcd.Vdc) (*govcd.VM, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "FindVMByName", "serverName", serverName)

	vm := &govcd.VM{}

	vappRefList := vdc.GetVappList()
	for _, vappRef := range vappRefList {

		vapp, err := vdc.GetVAppByHref(vappRef.HREF)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetVappByHref failed", "vapp.HREF", vappRef.HREF, "err", err)
			continue
		}
		vm, err = vapp.GetVMByName(serverName, false)
		if err == nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "FindVMByName found", "vmName", serverName, "vappName", vapp.VApp.Name, "err", err)
			return vm, nil
		}
	}
	return nil, fmt.Errorf("Vm %s not found", serverName)
}

// Have vapp obj in hand use this one.
func (v *VcdPlatform) FindVMInVApp(ctx context.Context, serverName string, vapp govcd.VApp) (*govcd.VM, error) {
	vm, err := vapp.GetVMByName(serverName, true)
	if err != nil {
		return nil, fmt.Errorf("vm %s not found in vapp %s", serverName, vapp.VApp.Name)
	}
	return vm, nil

}

func (v *VcdPlatform) IsDhcpEnabled(ctx context.Context, net *govcd.OrgVDCNetwork) bool {
	vdcnet := net.OrgVDCNetwork

	netconfig := vdcnet.Configuration
	if netconfig != nil {
		features := netconfig.Features
		dhcpservice := features.DhcpService
		return dhcpservice.IsEnabled

	}
	return false
}

func (v *VcdPlatform) getVmInternalIp(ctx context.Context, vmparams *vmlayer.VMOrchestrationParams, vmgp *vmlayer.VMGroupOrchestrationParams, vapp *govcd.VApp) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "getVmInternalIp", "vm", vmparams.Name, "ports", vmparams.Ports)

	internalNetName := ""
	gateway := ""
	for _, p := range vmparams.Ports {
		if p.NetType == vmlayer.NetworkTypeInternalPrivate || p.NetType == vmlayer.NetworkTypeInternalSharedLb {
			internalNetName = p.SubnetId
			log.SpanLog(ctx, log.DebugLevelInfra, "found internal subnet", "internalNetName", internalNetName)
			break
		}
	}
	if internalNetName == "" {
		return "", fmt.Errorf("Could not find internal network for VM - %s", vmparams.Name)
	}
	netMap := make(map[string]networkInfo)
	if vmgp.ConnectsToSharedRootLB {
		// the name of the iso mapped network is the gateway for shared
		netName, err := v.updateIsoNamesMap(ctx, IsoMapActionRead, vmparams.Ports[0].SubnetId, "")
		if err != nil || netName == "" {
			return "", fmt.Errorf("error finding subnet %s in iso map - %v", vmparams.Ports[0].SubnetId, err)
		}
		gateway = netName
	} else {
		// for dedicated, if we find the network the gateway is the InternalVappSubnet
		for _, n := range vapp.VApp.NetworkConfigSection.NetworkNames() {
			log.SpanLog(ctx, log.DebugLevelInfra, "network name loop", "n", n, "internalNetName", internalNetName)
			if n == internalNetName {
				gateway = InternalVappSubnet
				break
			}
		}
		if gateway == "" {
			return "", fmt.Errorf("error finding internal network: %s in vapp network config", vmparams.Ports[0].SubnetId)
		}
	}
	internalNetType := vmlayer.NetworkTypeInternalPrivate
	if vmgp.ConnectsToSharedRootLB {
		internalNetType = vmlayer.NetworkTypeInternalSharedLb
	}
	netMap[internalNetName] = networkInfo{
		Name:        internalNetName,
		Gateway:     gateway,
		NetworkType: internalNetType,
	}
	vmIp, err := v.getIpFromPortParams(ctx, vmparams, vmgp, netMap)
	log.SpanLog(ctx, log.DebugLevelInfra, "getIpFromPortParams returns", "vmIp", vmIp, "err", err)
	if err != nil {
		return "", err
	}
	if vmIp == "" {
		return "", fmt.Errorf("Internal IP not found")
	}
	return vmIp, nil
}

func (v *VcdPlatform) getIpFromPortParams(ctx context.Context, vmparams *vmlayer.VMOrchestrationParams, vmgp *vmlayer.VMGroupOrchestrationParams, netMap map[string]networkInfo) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "getIpFromPortParams", "netMap", netMap)

	for _, port := range vmparams.Ports {
		for _, p := range vmgp.Ports {
			if p.Id == port.Id {
				log.SpanLog(ctx, log.DebugLevelInfra, "Found Port within orch params", "id", port.Id, "fixedips", p.FixedIPs)

				if len(p.FixedIPs) == 1 && p.FixedIPs[0].Address == vmlayer.NextAvailableResource {
					net, ok := netMap[p.SubnetId]
					if !ok {
						return "", fmt.Errorf("Cannot find GW in map for network %s", p.SubnetId)
					}
					vmIp, err := ReplaceLastOctet(ctx, net.Gateway, p.FixedIPs[0].LastIPOctet)
					if err != nil {
						return "", fmt.Errorf("Failed to replace last octet of addr %s, octet %d - %v", vmIp, p.FixedIPs[0].LastIPOctet, err)
					}
					log.SpanLog(ctx, log.DebugLevelInfra, "Found VM IP", "vmIp", vmIp, "port", port.Id)
					return vmIp, nil
				}
				log.SpanLog(ctx, log.DebugLevelInfra, "No fixd IPs for port", "id", port.Id)
				return "", nil
			}
		}
	}
	return "", fmt.Errorf("unable to get IP from PortParams")
}

func (v *VcdPlatform) RetrieveTemplate(ctx context.Context, tmplName string, vcdClient *govcd.VCDClient) (*govcd.VAppTemplate, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "RetrieveTemplate", "tmplName", tmplName)
	tmpl, err := v.FindTemplate(ctx, tmplName, vcdClient)
	if err != nil {
		if !strings.Contains(err.Error(), TemplateNotFoundError) {
			return nil, fmt.Errorf("unexpected error finding template %s - %v", tmplName, err)
		}
		// Not found as a vdc.Resource, try direct from our catalog
		log.SpanLog(ctx, log.DebugLevelInfra, "Template not vdc.Resource, Try fetch from catalog", "template", tmplName, "err", err)
		cat, err := v.GetCatalog(ctx, v.GetCatalogName(), vcdClient)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed retrieving catalog", "cat", v.GetCatalogName())
			return nil, fmt.Errorf("Template invalid - failed retrieving catalog")
		}

		emptyItem := govcd.CatalogItem{}
		catItem, err := cat.FindCatalogItem(tmplName)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "find catalog item failed", "err", err)
			return nil, fmt.Errorf("Template invalid - find catalog item failed")
		}
		if catItem == emptyItem { // empty!
			log.SpanLog(ctx, log.DebugLevelInfra, "find catalog item retured empty item")
			return nil, fmt.Errorf("Template invalid - empty catalog item ")
		}
		tmpl, err := catItem.GetVAppTemplate()
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "catItem.GetVAppTemplate failed", "err", err)
			return nil, fmt.Errorf("Template invalid - GetVAppTemplate failed")
		}

		if tmpl.VAppTemplate.Children == nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "template has no children")
			return nil, fmt.Errorf("Template invalid - template has no children")
		} else {
			// while this works for 10.1, it still does not for 10.0 so make this an error for now
			//numChildren := len(tmpl.VAppTemplate.Children.VM)
			//log.SpanLog(ctx, log.DebugLevelInfra, "template looks good from cat", "numChildren", numChildren)
			//return &tmpl, nil
			log.SpanLog(ctx, log.DebugLevelInfra, "template has children but marking invalid for 10.0")
			// Remedy to persure, fill in VM's vmSpecSection for expected resources that seem missing.
			return nil, fmt.Errorf("Template invalid - template has children but marking invalid for 10.0")
		}
	}

	// The way we look for templates this should never trigger, but just in case
	if tmpl.VAppTemplate.Children == nil {
		// Wait, try once more
		log.SpanLog(ctx, log.DebugLevelInfra, "catItem.GetVAppTemplate failed", "err", err)
		return nil, fmt.Errorf("Template invalid")

	}
	// if it was found as vdc.resource and children !nil, good to go
	log.SpanLog(ctx, log.DebugLevelInfra, "RetrieveTemplate using", "Template", tmplName)
	return tmpl, nil
}

func (v *VcdPlatform) CreateVMs(ctx context.Context, vmgp *vmlayer.VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateVMs", "grpName", vmgp.GroupName)

	vcdClient := v.GetVcdClientFromContext(ctx)
	if vcdClient == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, NoVCDClientInContext)
		return fmt.Errorf(NoVCDClientInContext)
	}
	vdc, err := v.GetVdc(ctx, vcdClient)
	if err != nil {
		return fmt.Errorf("GetVdc Failed - %v", err)
	}

	tmpl, err := v.RetrieveTemplate(ctx, vmgp.VMs[0].ImageName, vcdClient)
	if err != nil {
		return err
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "Creating Vapp for", "GroupName", vmgp.GroupName, "using template", tmpl.VAppTemplate.Name)
	vappName := vmgp.GroupName + "-vapp"
	vmName := vmgp.VMs[0].Name
	description := "vapp for " + vmgp.GroupName

	_, err = v.CreateVApp(ctx, tmpl, vmgp, description, vcdClient, updateCallback)
	if err != nil {
		return err
	}
	// Should exist
	_, err = vdc.QueryVM(vappName, vmName)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "CreateVMs failed to find resulting ", "VM", vmName, "in VApp", vappName, "err", err)
		return fmt.Errorf("VM : %s not found in vApp: %s", vmName, vappName)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateVMs  created", "vapp", vappName, "GroupName", vmgp.GroupName)

	return nil
}

// updates of a vm that is 'shared' across multiple vapps
// balks at being modified "can't modify disk of a vm with snapshots"
// So here, we remove, and replace it. XXX only first disk, doesn't
// support multiple internal disks. XXX
func (v *VcdPlatform) updateVmDisk(vm *govcd.VM, size int64) error {

	diskSettings := vm.VM.VmSpecSection.DiskSection.DiskSettings[0]
	diskId := vm.VM.VmSpecSection.DiskSection.DiskSettings[0].DiskId
	// remove this current disk
	err := vm.DeleteInternalDisk(diskId)
	if err != nil {
		return err
	}

	newDiskSettings := &types.DiskSettings{
		SizeMb:          size * 1024, // results in 1G > size ?
		AdapterType:     diskSettings.AdapterType,
		ThinProvisioned: diskSettings.ThinProvisioned,
		StorageProfile:  diskSettings.StorageProfile,
	}
	_, err = vm.AddInternalDisk(newDiskSettings)
	if err != nil {
		return err
	}
	return nil
}

func (v *VcdPlatform) updateNetworksForVM(ctx context.Context, vcdClient *govcd.VCDClient, vm *govcd.VM, vmgp *vmlayer.VMGroupOrchestrationParams, vmparams *vmlayer.VMOrchestrationParams, vmIdx int, netMap map[string]networkInfo, masterIP string) (*govcd.VM, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "updateNetworksForVM", "vm", vm.VM.Name, "MasterIP", masterIP)

	gwsToRemove := []string{}
	// currrently only internal and additional networks on the LB need be removed, but this may
	// be expanded in the future
	switch vmparams.Role {
	case vmlayer.RoleAgent:
		for netname, netinfo := range netMap {
			log.SpanLog(ctx, log.DebugLevelInfra, "Checking role and nettype for gw removal", "netname", netname, "NetworkType", netinfo.NetworkType)
			if netinfo.NetworkType == vmlayer.NetworkTypeInternalPrivate ||
				netinfo.NetworkType == vmlayer.NetworkTypeInternalSharedLb ||
				netinfo.NetworkType == vmlayer.NetworkTypeExternalAdditionalRootLb ||
				netinfo.NetworkType == vmlayer.NetworkTypeExternalAdditionalClusterNode {
				gwsToRemove = append(gwsToRemove, netinfo.Gateway)
			}
		}
	case vmlayer.RoleK8sNode:
		fallthrough
	case vmlayer.RoleDockerNode:
		for netname, netinfo := range netMap {
			log.SpanLog(ctx, log.DebugLevelInfra, "Checking role and nettype for gw removal", "netname", netname, "NetworkType", netinfo.NetworkType)
			if netinfo.NetworkType == vmlayer.NetworkTypeExternalAdditionalClusterNode {
				gwsToRemove = append(gwsToRemove, netinfo.Gateway)
			}
		}
	}
	for _, gw := range gwsToRemove {
		// Multiple GWs cause unpredictable behavior depending on the order they are processed. Since the timing
		// may sometimes be unpredictable, remove also from the netplan file
		log.SpanLog(ctx, log.DebugLevelInfra, "removing extra default gw from VM", "vm", vm.VM.Name, "gw", gw)
		vmparams.CloudConfigParams.ExtraBootCommands = append(vmparams.CloudConfigParams.ExtraBootCommands, "ip route del default via "+gw)
		netplanFile := "/etc/netplan/99-netcfg-vmware.yaml"
		removeGwFromNetplan := fmt.Sprintf("sed -i /gateway4:.%s/d %s", gw, netplanFile)
		vmparams.CloudConfigParams.ExtraBootCommands = append(vmparams.CloudConfigParams.ExtraBootCommands, removeGwFromNetplan)
	}
	// some unique key within the vapp
	key := fmt.Sprintf("%s-vm-%d", vmgp.GroupName, vmIdx)
	vm.VM.OperationKey = key

	ncs, err := vm.GetNetworkConnectionSection()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetNetworkConnectionSection failed", "err", err)
		return nil, err
	}
	ncs.NetworkConnection = []*types.NetworkConnection{}
	// make sure all networks gone
	err = vm.UpdateNetworkConnectionSection(ncs)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "UpdateNetworkConnectionSection failed", "err", err)
		return nil, err
	}
	vmIp, err := v.getIpFromPortParams(ctx, vmparams, vmgp, netMap)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to get ip from port params", "err", err)
		return nil, err
	}
	for netConIdx, port := range vmparams.Ports {
		netName := port.NetworkId
		switch port.NetType {
		case vmlayer.NetworkTypeInternalSharedLb:
			netName = v.IsoNamesMap[port.SubnetId]
		case vmlayer.NetworkTypeInternalPrivate:
			netName = port.SubnetId
		}

		log.SpanLog(ctx, log.DebugLevelInfra, "updateNetworksForVM add connection", "net", netName, "ip", vmIp, "VM", vmparams.Name)
		networkAdapterType := "VMXNET3"
		if vmparams.Role == vmlayer.RoleVMApplication {
			// VM apps may not have VMTools installed so use the generic E1000 adapter
			networkAdapterType = "E1000"
		}
		extNet := v.vmProperties.GetCloudletExternalNetwork()
		switch port.NetType {
		case vmlayer.NetworkTypeInternalPrivate:
			fallthrough
		case vmlayer.NetworkTypeInternalSharedLb:
			if vmIp == "" {
				return nil, fmt.Errorf("No IP found for internal net %s", netName)
			}
			ncs.NetworkConnection = append(ncs.NetworkConnection,
				&types.NetworkConnection{
					Network:                 netName,
					NetworkConnectionIndex:  netConIdx,
					IPAddress:               vmIp,
					IsConnected:             true,
					IPAddressAllocationMode: types.IPAllocationModeManual,
					NetworkAdapterType:      networkAdapterType,
				})
		case vmlayer.NetworkTypeExternalPrimary:
			fallthrough
		case vmlayer.NetworkTypeExternalAdditionalPlatform:
			fallthrough
		case vmlayer.NetworkTypeExternalAdditionalRootLb:
			fallthrough
		case vmlayer.NetworkTypeExternalAdditionalClusterNode:
			if netName == extNet {
				ncs.PrimaryNetworkConnectionIndex = netConIdx
			}
			ncs.NetworkConnection = append(ncs.NetworkConnection,
				&types.NetworkConnection{
					Network:                 netName,
					NetworkConnectionIndex:  netConIdx,
					IsConnected:             true,
					IPAddressAllocationMode: types.IPAllocationModePool,
					NetworkAdapterType:      networkAdapterType,
				})
			log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp adding connection", "net", netName, "ip", vmIp, "VM", vmparams.Name, "networkAdapterType", networkAdapterType, "conidx", netConIdx, "netType", port.NetType, "ncs", ncs)
		}
	}
	err = vm.UpdateNetworkConnectionSection(ncs)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp add internal net failed SLEEP 30 and Retry operation", "VM", vmparams.Name, "ncs", ncs, "error", err)
		time.Sleep(30 * time.Second)
		err = vm.UpdateNetworkConnectionSection(ncs)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp add internal net failed", "VM", vm.VM.Name, "ncs", ncs, "error", err)
			return nil, err
		}
	}
	// finish vmUpdates
	err = v.guestCustomization(ctx, vm, vmparams)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "updateVM GuestCustomization   failed", "vm", vm.VM.Name, "err", err)
		return nil, fmt.Errorf("updateVM-E-error from guestCustomize: %s", err.Error())
	}

	err = v.updateVM(ctx, vm, vmparams, masterIP)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "update vm failed ", "VAppName", vmgp.GroupName, "err", err)
		return nil, err
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "updateNetworksForVM complete")
	return vm, nil
}

// For each vm spec defined in vmgp, add a new VM to vapp with those applicable attributes.  Returns a map of VMs which
// should be powered on and customized
func (v *VcdPlatform) AddVMsToVApp(ctx context.Context, vapp *govcd.VApp, vmgp *vmlayer.VMGroupOrchestrationParams, baseImgTmpl *govcd.VAppTemplate, netMap map[string]networkInfo, vdc *govcd.Vdc, vcdClient *govcd.VCDClient, updateCallback edgeproto.CacheUpdateCallback) (VMMap, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp", "GroupName", vmgp.GroupName, "netMap", netMap)

	vmsToCustomize := make(VMMap)
	numVMs := len(vmgp.VMs)

	log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp numVMs", "count", numVMs, "GroupName", vmgp.GroupName, "baseImgTmpl", baseImgTmpl.VAppTemplate.Name, "vmgp ports", vmgp.Ports)

	//vmUpdateResults := make(chan vmUpdateResult, len(vmgp.VMs))
	err := vapp.Refresh()
	if err != nil {
		return nil, fmt.Errorf("vApp refresh failed = %v", err)
	}
	masterIP := ""
	for n, vmparams := range vmgp.VMs {
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Adding VM: %s", vmparams.Name))

		vmName := vmparams.Name
		vmRole := vmparams.Role
		if vmRole == vmlayer.RoleMaster {
			masterIP, err = v.getVmInternalIp(ctx, &vmparams, vmgp, vapp)
			if err != nil {
				return nil, fmt.Errorf("Fail to get Master internal IP - %v", err)
			}
		}

		vmType := string(vmlayer.GetVmTypeForRole(string(vmparams.Role)))
		ncs := &types.NetworkConnectionSection{}
		// check to see if this vm is already present
		vm, err := vapp.GetVMByName(vmName, false)
		if err != nil && vm == nil {
			updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Adding VM: %s", vmName))
			template := baseImgTmpl
			if vmparams.Role == vmlayer.RoleVMApplication {
				// VMApp does not use the base template, find the one for this app
				template, err = v.FindTemplate(ctx, vmparams.ImageName, vcdClient)
				if err != nil {
					return nil, err
				}
			}
			log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp add VM", "vmName", vmName, "vmRole", vmRole, "vmType", vmType, "vmparams", vmparams)
			task, err := v.addNewVMRegenUuid(vapp, vmparams.Name, *template, ncs, vcdClient)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "create add vm failed", "err", err)
				return nil, err
			}
			err = task.WaitTaskCompletion()
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "wait add vm failed", "err", err)
				return nil, err
			}

			vm, err = vapp.GetVMByName(vmName, true)
			if err != nil {
				return nil, err
			}
		}

		vm, err = v.updateNetworksForVM(ctx, vcdClient, vm, vmgp, &vmparams, n, netMap, masterIP)
		if err != nil {
			return nil, err
		} else if vmparams.Role != vmlayer.RoleVMApplication {
			vmsToCustomize[vmparams.Name] = vm
		}
	} //for n, vmparams

	log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp complete")
	return vmsToCustomize, nil
}

func (v *VcdPlatform) AddVMsToExistingVApp(ctx context.Context, vapp *govcd.VApp, vmgp *vmlayer.VMGroupOrchestrationParams, vcdClient *govcd.VCDClient) (VMMap, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToExistingVApp", "vapp", vapp.VApp.Name)

	vmMap := make(VMMap)
	numExistingVMs := len(vapp.VApp.Children.VM)

	tmpl, err := v.RetrieveTemplate(ctx, vmgp.VMs[0].ImageName, vcdClient)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToExistingVapp error retrieving vdc template", "err", err)
		return vmMap, err
	}
	ports := vmgp.Ports
	numVMs := len(vmgp.VMs)
	netName := ports[0].SubnetId
	log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToExistingVapp", "network", netName, "vms", numVMs, "to existing vms", numExistingVMs)

	netConIdx := 0
	masterIP := ""
	for n, vmparams := range vmgp.VMs {
		vmName := vmparams.Name
		vmRole := vmparams.Role
		vmType := string(vmlayer.GetVmTypeForRole(string(vmparams.Role)))
		vm := &govcd.VM{}
		ncs := &types.NetworkConnectionSection{}
		// check to see if this vm is already present
		vm, err := vapp.GetVMByName(vmName, true)
		if err != nil && vm == nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToExistingVApp", "vmName", vmName, "vmRole", vmRole, "vmType", vmType)

			// use new regen
			task, err := v.addNewVMRegenUuid(vapp, vmName, *tmpl, ncs, vcdClient)
			// task, err := vapp.AddNewVM(vmparams.Name, *tmpl, ncs, true)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "create add vm failed", "err", err)
				return nil, err
			}
			err = task.WaitTaskCompletion()
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "wait add vm failed", "err", err)
				return nil, err
			}
			// Make sure it's there
			vm, err = vapp.GetVMByName(vmparams.Name, true)
			if err != nil {
				// internal error
				return nil, err
			}
		}

		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToExistingVApp Octet fail", "err", err)
			return nil, err
		}
		if v.Verbose {
			log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToExistingVApp", "vapp", vapp.VApp.Name, "network", netName, "existingsVMs", numExistingVMs, "n", n)
		}

		log.SpanLog(ctx, log.DebugLevelInfra, "AddVmsToExstingVAppp", "vm", vmName)
		ncs.PrimaryNetworkConnectionIndex = 0
		// some unique key within the vapp
		key := fmt.Sprintf("%s-vm-%d", vapp.VApp.Name, n+numExistingVMs)
		vm.VM.OperationKey = key

		ncs, err = vm.GetNetworkConnectionSection()
		if err != nil {
			return nil, err
		}
		vmIp, err := v.getVmInternalIp(ctx, &vmparams, vmgp, vapp)
		if err != nil {
			return nil, err
		}
		if vmRole == vmlayer.RoleMaster {
			masterIP = vmIp
			log.SpanLog(ctx, log.DebugLevelInfra, "Got Master IP", "masterIP", masterIP)
		}
		ncs.NetworkConnection = append(ncs.NetworkConnection,
			&types.NetworkConnection{
				Network:                 netName,
				NetworkConnectionIndex:  netConIdx,
				IPAddress:               vmIp,
				IsConnected:             true,
				IPAddressAllocationMode: types.IPAllocationModeManual,
			})

		err = vm.UpdateNetworkConnectionSection(ncs)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp add internal net failed", "VM", vm.VM.Name, "error", err)
			return nil, err
		}

		err = v.guestCustomization(ctx, vm, &vmparams)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "updateVM GuestCustomization   failed", "vm", vm.VM.Name, "err", err)
			return nil, fmt.Errorf("updateVM-E-error from guestCustomize: %s", err.Error())
		}
		err = v.updateVM(ctx, vm, &vmparams, masterIP)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "update vm failed ", "VAppName", vmgp.GroupName, "err", err)
			return nil, err
		}
		vmMap[vm.VM.Name] = vm
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp complete")
	return vmMap, nil
}

// guestCustomization updates some fields in the customization section, including the host name
func (v *VcdPlatform) guestCustomization(ctx context.Context, vm *govcd.VM, vmparams *vmlayer.VMOrchestrationParams) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "guestCustomization ", "VM", vm.VM.Name, "HostName", vmparams.HostName)
	vm.VM.GuestCustomizationSection.ComputerName = vmparams.HostName
	vm.VM.GuestCustomizationSection.Enabled = TakeBoolPointer(true)
	return nil
}

// set vm params and call vm.UpdateVmSpecSection
func (v *VcdPlatform) updateVM(ctx context.Context, vm *govcd.VM, vmparams *vmlayer.VMOrchestrationParams, masterIP string) error {

	log.SpanLog(ctx, log.DebugLevelInfra, "updateVM", "vm", vm.VM.Name, "masterIP", masterIP)

	flavorName := vmparams.FlavorName
	flavor, err := v.GetFlavor(ctx, flavorName)
	if err != nil {
		return fmt.Errorf("Error getting flavor: %s - %v", flavorName, err)
	}
	vmSpecSec := vm.VM.VmSpecSection
	vmSpecSec.NumCpus = TakeIntPointer(int(flavor.Vcpus))
	vmSpecSec.MemoryResourceMb.Configured = int64(flavor.Ram)
	if v.GetEnableVcdDiskResize() {
		if len(vmSpecSec.DiskSection.DiskSettings) == 0 {
			return fmt.Errorf("No disk settings in VM: %s", vm.VM.Name)
		}
		vmSpecSec.DiskSection.DiskSettings[0].SizeMb = int64(flavor.Disk * 1024)
		log.SpanLog(ctx, log.DebugLevelInfra, "resizing disk", "size(gb)", flavor.Disk, "spec", vmSpecSec.DiskSection.DiskSettings[0])
	}
	// attach additional volume if specified
	if len(vmparams.Volumes) > 0 {
		firstDiskId, err := strconv.Atoi(vmSpecSec.DiskSection.DiskSettings[0].DiskId)
		if err != nil {
			return fmt.Errorf("Could not parse disk id for first disk")
		}
		// increment the disk id, which is some unpredictable number for use as the second id
		newDiskId := fmt.Sprintf("%d", firstDiskId+1)
		newDiskSettings := &types.DiskSettings{
			SizeMb: int64(vmparams.Volumes[0].Size * 1024),
			DiskId: newDiskId,
			// use same settings as first disk
			UnitNumber:      int(vmparams.Volumes[0].UnitNumber),
			BusNumber:       vmSpecSec.DiskSection.DiskSettings[0].BusNumber,
			AdapterType:     vmSpecSec.DiskSection.DiskSettings[0].AdapterType,
			ThinProvisioned: vmSpecSec.DiskSection.DiskSettings[0].ThinProvisioned,
			StorageProfile:  vmSpecSec.DiskSection.DiskSettings[0].StorageProfile,
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "adding volume to spec", "volume", vmparams.Volumes[0], "settings", newDiskSettings)
		vmSpecSec.DiskSection.DiskSettings = append(vmSpecSec.DiskSection.DiskSettings, newDiskSettings)
	}

	desc := fmt.Sprintf("Update flavor: %s", flavorName)
	_, err = vm.UpdateVmSpecSection(vmSpecSec, desc)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "updateVM UpdateVmSpecSection failed", "vm", vm.VM.Name, "err", err)
		return err
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVmSpecSection done", "vm", vm.VM.Name, "flavor", flavor)

	err = v.AddMetadataToVM(ctx, vm, vmparams)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "updateVM AddMetadataToVm  failed", "vm", vm.VM.Name, "err", err)
		return nil
	}
	if vmparams.Role == vmlayer.RoleVMApplication {
		log.SpanLog(ctx, log.DebugLevelInfra, "Skipping populateProductSection for VMApp", "vm", vm.VM.Name)
		return nil
	}
	psl, err := v.populateProductSection(ctx, vm, vmparams, masterIP)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "updateVM populateProductSection failed", "vm", vm.VM.Name, "err", err)
		return fmt.Errorf("updateVM-E-error from populateProductSection: %s", err.Error())
	}

	_, err = vm.SetProductSectionList(psl)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "updateVM vm.SetProductSectionList  failed", "vm", vm.VM.Name, "err", err)
		return fmt.Errorf("Error Setting product section %s", err.Error())
	}

	err = v.guestCustomization(ctx, vm, vmparams)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "updateVM GuestCustomization   failed", "vm", vm.VM.Name, "err", err)
		return fmt.Errorf("updateVM-E-error from guestCustomize: %s", err.Error())
	}

	return err
}

// Add/remove VM from our VApp (group)
func (v *VcdPlatform) UpdateVMs(ctx context.Context, vmgp *vmlayer.VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error {

	updateTime := time.Now()
	log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMs", "OrchParams", vmgp)
	vappName := vmgp.GroupName + v.GetVappServerSuffix()
	log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMs", "Vapp", vappName)

	vcdClient := v.GetVcdClientFromContext(ctx)
	if vcdClient == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, NoVCDClientInContext)
		return fmt.Errorf(NoVCDClientInContext)
	}
	vdc, err := v.GetVdc(ctx, vcdClient)
	if err != nil {
		return fmt.Errorf("GetVdc Failed - %v", err)
	}

	vapp, err := v.FindVApp(ctx, vappName, vcdClient, vdc)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMs GroupName not found", "Vapp", vappName, "err", err)
		return err
	}

	// 1 create a list of all vms in our current vmgp.GroupName (existing)
	existingVms, err := v.GetAllVMsInVApp(ctx, vapp)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMs GetAllVMsInVapp failed", "Vapp", vappName, "err", err)
		return err
	}
	numExistingVMs := len(existingVms)
	log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMs existing vms in", "Vapp", vappName, "vms", existingVms)

	newVMs := vmgp.VMs
	numNewVMs := len(newVMs)
	log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMs existing vs new", "numExisting", numExistingVMs, "numNew", numNewVMs)

	if numNewVMs > numExistingVMs {
		newVMOrch := []vmlayer.VMOrchestrationParams{}
		// Its an add of numNetVMs - numExistingVMs
		numToAdd := numNewVMs - numExistingVMs
		log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMs add", "count", numToAdd)
		updateCallback(edgeproto.UpdateTask, "Adding VMs to vApp")
		// now find which one is the new guy
		// need a map of the existing (we have that) and run our newVMs list over the map creating a new list
		// of vms to create. create a new list of vmgp.VMs to pass to AddVMsToExistngVApp
		for _, vmSpec := range newVMs {
			if _, found := existingVms[vmSpec.Name]; !found {
				log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMs adding new", "vm", vmSpec.Name)
				newVMOrch = append(newVMOrch, vmSpec)
			} else {
				log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMs skip existing", "vm", vmSpec.Name)
			}
		}
		newOrchLen := len(newVMOrch)
		if newOrchLen != numToAdd {
			log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMs Mismatch count", "numToAdd", numToAdd, "NewOrcLen", newOrchLen)
		}
		vmgp.VMs = newVMOrch
		newVms, err := v.AddVMsToExistingVApp(ctx, vapp, vmgp, vcdClient)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMs", "VAppName", vmgp.GroupName, "error", err)
			return err
		}
		for vmName, vm := range newVms {
			log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMs power on new", "vm", vmName)
			task, err := vm.PowerOn()
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMs error power on", "vm", vmName, "error", err)
				return err
			}
			err = task.WaitTaskCompletion()
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMs error waiting power on", "vm", vmName, "error", err)
				return err
			}

		}
		if v.Verbose {
			msg := fmt.Sprintf("Added %d VMs to vApp time %s", len(newVms), cloudcommon.FormatDuration(time.Since(updateTime), 2))
			updateCallback(edgeproto.UpdateTask, msg)
		}
	} else if numExistingVMs > numNewVMs {
		newVmMap := make(VMMap)
		rmcnt := 0
		// delete whatever is in exsiting that is not in new
		for _, newVmParams := range newVMs {
			newVmMap[newVmParams.Name] = &govcd.VM{}
		}
		for _, existingVM := range existingVms {
			if _, found := newVmMap[existingVM.VM.Name]; !found {
				updateCallback(edgeproto.UpdateTask, "Removing VMs from vApp")
				log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMs delete", "vm", existingVM.VM.Name, "VAppName", vappName, "error", err)
				err := v.DeleteVM(ctx, existingVM)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMs delete failed", "vm", existingVM.VM.Name, "err", err)
					return err
				}
				rmcnt++
				log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMs deleted", "vm", existingVM.VM.Name, "vapp", vappName)
			}
		}
		if v.Verbose {
			msg := fmt.Sprintf("Removed  %d  VMs time %s", rmcnt, cloudcommon.FormatDuration(time.Since(updateTime), 2))
			updateCallback(edgeproto.UpdateTask, msg)
		}

	} else {
		// ok, we're just updating some existing VMs then?
		for _, vm := range newVMs {
			// Trustpolicy and / or autoscale policy / skipcrmcleanupnfailre / crmoverride
			log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMs modify existing", "vm", vm.Name)
		}
	}
	return nil
}

func (v *VcdPlatform) DeleteVM(ctx context.Context, vm *govcd.VM) error {

	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVM", "vmName", vm.VM.Name)
	if vm == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Nil VM", "vmName", vm.VM.Name)
		return fmt.Errorf(vmlayer.ServerDoesNotExistError)
	}
	vapp, err := vm.GetParentVApp()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVM err obtaining ParentVapp", "vmName", vm.VM.Name, "err", err)
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVM", "vmName", vm.VM.Name, "from vapp", vapp.VApp.Name)

	status, err := vm.GetStatus()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVM error retrieving status", "vmName", vm.VM.Name, "err", err)
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "DeletedVM vm state Undeploy", "vmName", vm.VM.Name, "status", status)

	task, err := vm.Undeploy()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "DeletedVM Undeploy failed ", "vmName", vm.VM.Name, "err", err)
		return err
	}
	err = task.WaitTaskCompletion()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "DeletedVm wait failed ", "vmName", vm.VM.Name, "err", err)
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "DeletedVM power off Remove", "vmName", vm.VM.Name, "vapp", vapp.VApp.Name)
	err = vapp.RemoveVM(*vm)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "DeletedVM error on Remove", "vmName", vm.VM.Name, "vapp", vapp.VApp.Name, "err", err)
		return err
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "VM Deleted", "vmName", vm.VM.Name, "vapp", vapp.VApp.Name)
	return nil
}

// Delete All VMs in the resolution of vmGroupName
func (v *VcdPlatform) DeleteVMs(ctx context.Context, vmGroupName string) error {

	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVMs", "vmGroupName", vmGroupName)

	vcdClient := v.GetVcdClientFromContext(ctx)
	if vcdClient == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, NoVCDClientInContext)
		return fmt.Errorf(NoVCDClientInContext)
	}
	vdc, err := v.GetVdc(ctx, vcdClient)
	if err != nil {
		return fmt.Errorf("GetVdc Failed - %v", err)
	}
	vappName := vmGroupName + "-vapp"
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVMs check", "vappName", vappName)
	vapp, err := v.FindVApp(ctx, vappName, vcdClient, vdc)
	if err == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVMs deleting", "VApp", vappName)
		err := v.DeleteVapp(ctx, vapp, vcdClient)
		return err
	} else {
		if strings.Contains(err.Error(), govcd.ErrorEntityNotFound.Error()) {
			log.SpanLog(ctx, log.DebugLevelInfra, "VApp already deleted", "vappName", vappName)
			return nil
		} else {
			return fmt.Errorf("Unexpected error in FindVApp - %v", err)
		}
	}
}

// always sync.
func (v *VcdPlatform) SetPowerState(ctx context.Context, serverName, serverAction string) error {

	vcdClient := v.GetVcdClientFromContext(ctx)
	if vcdClient == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, NoVCDClientInContext)
		return fmt.Errorf(NoVCDClientInContext)
	}
	vdc, err := v.GetVdc(ctx, vcdClient)
	if err != nil {
		return fmt.Errorf("GetVdc Failed - %v", err)
	}
	vm, err := v.FindVMByName(ctx, serverName, vcdClient, vdc)
	if err != nil {
		return err
	}
	curStatus, err := vm.GetStatus()

	if serverAction == vmlayer.ActionStart {
		if curStatus == "POWERED_ON" {
			return fmt.Errorf("%s Already Powered on", vm.VM.Name)
		}

		task, err := vm.PowerOn()
		if err != nil {
			return err
		} else {
			err := task.WaitTaskCompletion()
			if err != nil {
				return err
			}
		}
	}
	if serverAction == vmlayer.ActionStop {
		if curStatus == "POWERED_OFF" {
			return fmt.Errorf("%s Already Powered off", vm.VM.Name)
		}
		task, err := vm.PowerOff()
		if err != nil {
			return err
		} else {
			err := task.WaitTaskCompletion()
			if err != nil {
				return err
			}
		}
	}
	if serverAction == vmlayer.ActionReboot {
		if curStatus != "POWERED_ON" {
			return fmt.Errorf("Can't reboot %s currently in state %s\n", vm.VM.Name, curStatus)
		}
		task, err := vm.PowerOff()
		if err != nil {
			return fmt.Errorf("Error Powering off %s err: %s\n", vm.VM.Name, err.Error())
		} else {
			err := task.WaitTaskCompletion()
			if err != nil {
				return fmt.Errorf("Error waiting for Powering on %s err: %s\n", vm.VM.Name, err.Error())
			}
		}
		task, err = vm.PowerOn()
		if err != nil {
			return err
		} else {
			err := task.WaitTaskCompletion()
			if err != nil {
				return fmt.Errorf("Error waiting for Powering on %s err: %s\n", vm.VM.Name, err.Error())
			}
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "SetPowerState", "serverName", serverName, "serverAction", serverAction)
	return nil
}

func (v *VcdPlatform) VerifyVMs(ctx context.Context, vms []edgeproto.VM) error {
	// existance? Powered ON?
	log.SpanLog(ctx, log.DebugLevelInfra, "VerifyVMs TBI")
	return nil
}

func (v *VcdPlatform) GetVMAddresses(ctx context.Context, vm *govcd.VM, vcdClient *govcd.VCDClient, vdc *govcd.Vdc) ([]vmlayer.ServerIP, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetVMAddresses", "vmname", vm.VM.Name)

	var serverIPs []vmlayer.ServerIP
	if vm == nil || vm.VM == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "nil VM", "vmname", vm.VM.Name)
		return serverIPs, fmt.Errorf(vmlayer.ServerDoesNotExistError)
	}
	if vm.VM.NetworkConnectionSection == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "nil network section", "vmname", vm.VM.Name)
		return serverIPs, fmt.Errorf(vmlayer.ServerIPNotFound)
	}
	vmName := vm.VM.Name
	//parentVapp, err := vm.GetParentVApp()
	connections := vm.VM.NetworkConnectionSection.NetworkConnection

	for _, connection := range connections {
		servIP := vmlayer.ServerIP{
			MacAddress:   connection.MACAddress,
			Network:      connection.Network,
			ExternalAddr: connection.IPAddress,
			InternalAddr: connection.IPAddress,
			PortName:     strconv.Itoa(connection.NetworkConnectionIndex),
		}
		if connection.Network != v.vmProperties.GetCloudletExternalNetwork() {
			// internal isolated net
			// two kinds, if type = 2 we need the subnetID name, not our internal netname.
			// query recs have this
			netType := 0
			qrecs, err := vdc.GetNetworkList()
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "GetNextVdcIsoSubnet GetNetworkList failed ", "err", err)
				return serverIPs, err
			}
			for _, qr := range qrecs {
				if qr.Name == connection.Network && qr.LinkType == 2 {
					netType = 2
					log.SpanLog(ctx, log.DebugLevelInfra, "GetVMAddresses ", "iso subnet", qr.Name)
				}
			}
			if netType == 2 {
				// These are iosorgvdc networks, (ioslated but shared by all VApp in this vdc (cloudlet))
				// Find the key in IsoNamesMap that matches connection.Network, and use
				// the value (subnetId) found to return.

				// find the current key for value
				k, err := v.updateIsoNamesMap(ctx, IsoMapActionRead, "", connection.Network)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "GetVMAddresses updateIsoNamesMap failed", "error", err)
					return serverIPs, err
				}
				log.SpanLog(ctx, log.DebugLevelInfra, "GetVMAddresses found type 2 network (iso) swap name", "from", connection.Network, "to", k)
				servIP.PortName = vmName + "-" + k + "-port"
			} else {
				servIP.PortName = vmName + "-" + connection.Network + "-port"
			}
			log.SpanLog(ctx, log.DebugLevelInfra, "GetVMAddresses", "servIP.PortName", servIP.PortName)
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "GetVMAddresses Added", "servIP.PortName", servIP.PortName)
		serverIPs = append(serverIPs, servIP)
	}
	return serverIPs, nil
}

func (v *VcdPlatform) SetVMProperties(vmProperties *vmlayer.VMProperties) {
	v.vmProperties = vmProperties
	vmProperties.IptablesBasedFirewall = true
	vmProperties.RunLbDhcpServerForVmApps = v.GetVmAppInternalDhcpServer()
	vmProperties.AppendFlavorToVmAppImage = true
	vmProperties.ValidateExternalIPMapping = true
	vmProperties.NumCleanupRetries = 3
}

// Should always be a vapp/cluster/group name
func (v *VcdPlatform) GetServerGroupResources(ctx context.Context, name string) (*edgeproto.InfraResources, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetServerGroupResources", "groupname", name)

	resources := &edgeproto.InfraResources{}

	vcdClient := v.GetVcdClientFromContext(ctx)
	if vcdClient == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, NoVCDClientInContext)
		return nil, fmt.Errorf(NoVCDClientInContext)
	}
	// xxx need ContainerInfo as well
	vdc, err := v.GetVdc(ctx, vcdClient)
	if err != nil {
		return nil, err
	}
	vappName := name + "-vapp"
	vapp, err := vdc.GetVAppByName(vappName, true)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetServerGroupResource vapp not found  ", "Name", name)
		// XXX if this is our pf cloudlet Vapp, and we're running crm locally, recover this error
		if strings.Contains(name, "-pf") {
			return resources, nil
		}
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "grp resources for", "grpName", name)
	if vapp.VApp.Children == nil {
		return nil, fmt.Errorf("ErrorEntityNotFound")
	}
	for _, cvm := range vapp.VApp.Children.VM {
		flavor := ""
		role := ""
		vm, err := vapp.GetVMByName(cvm.Name, true)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "Warn GetVMByName: vm not found in vapp ", "vapp", vappName, "cvm", cvm)
			return resources, fmt.Errorf("Warn GetVMByName: vm %s not found in vapp", cvm.Name)
		}
		metadata, err := vm.GetMetadata()
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetServerGroupResouce metadata not found for vapp ", "vapp", vappName, "vm", vm, "err", err)
			return nil, err
		}
		for _, md := range metadata.MetadataEntry {
			if md.Key == "FlavorName" {
				flavor = md.TypedValue.Value
			}
			if md.Key == "vmRole" {
				role = md.TypedValue.Value
			}
		}

		vminfo := edgeproto.VmInfo{
			Name:        vm.VM.Name,
			InfraFlavor: flavor,
			Type:        string(vmlayer.GetVmTypeForRole(role)),
		}
		netTypes := []vmlayer.NetworkType{
			vmlayer.NetworkTypeExternalAdditionalPlatform,
			vmlayer.NetworkTypeExternalAdditionalRootLb,
			vmlayer.NetworkTypeExternalPrimary,
		}
		sd, err := v.GetServerDetail(ctx, vm.VM.Name)
		if err != nil {
			return resources, fmt.Errorf("Failed to get server detail - %v", err)
		}
		externalNetMap := v.vmProperties.GetNetworksByType(ctx, netTypes)
		for _, sip := range sd.Addresses {
			vmip := edgeproto.IpAddr{}
			_, isExternal := externalNetMap[sip.Network]
			if isExternal {
				vmip.ExternalIp = sip.ExternalAddr
				if sip.InternalAddr != "" && sip.InternalAddr != sip.ExternalAddr {
					vmip.InternalIp = sip.InternalAddr
				}
			} else {
				vmip.InternalIp = sip.InternalAddr
			}
			vminfo.Ipaddresses = append(vminfo.Ipaddresses, vmip)
		}
		resources.Vms = append(resources.Vms, vminfo)
	}
	return resources, nil
}

// Store attrs of vm for crmrestarts and resource fetching
func (v *VcdPlatform) AddMetadataToVM(ctx context.Context, vm *govcd.VM, vmparams *vmlayer.VMOrchestrationParams) error {

	addStart := time.Now()
	log.SpanLog(ctx, log.DebugLevelInfra, "AddMetadataToVm", "vm", vm.VM.Name)
	vmType := string(vmlayer.GetVmTypeForRole(string(vmparams.Role)))
	task, err := vm.AddMetadata("vmType", vmType)
	if err != nil {
		return err
	}
	err = task.WaitTaskCompletion()
	if err != nil {
		return err
	}
	task, err = vm.AddMetadata("FlavorName", vmparams.FlavorName)
	if err != nil {
		return err
	}
	err = task.WaitTaskCompletion()
	if err != nil {
		return err
	}

	task, err = vm.AddMetadata("vmRole", string(vmparams.Role))
	if err != nil {
		return err
	}
	err = task.WaitTaskCompletion()
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "AddMetadataToVm", "vm", vm.VM.Name, "time", time.Since(addStart).String())
	return nil
}

// powerOnVmsAndForceCustomization calls PowerOnAndForceCustomization on each VM provided.  Unfortunately
// this needs to be done one at a time or it tends to fail
func (v *VcdPlatform) powerOnVmsAndForceCustomization(ctx context.Context, vms VMMap) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "powerOnVmsAndForceCustomization")
	for vmName, vm := range vms {
		log.SpanLog(ctx, log.DebugLevelInfra, "Powering on VM", "vmName", vmName)
		err := vm.PowerOnAndForceCustomization()
		if err != nil {
			return fmt.Errorf("Error powering on VM: %s - %v", vmName, vm.VM)
		}
	}
	return nil
}

// addNewVMRegenUuid is mostly cloned from govcd.addNewVMW, except it sets RegenerateBiosUuid
func (v *VcdPlatform) addNewVMRegenUuid(vapp *govcd.VApp, name string, vappTemplate govcd.VAppTemplate, network *types.NetworkConnectionSection, vcdClient *govcd.VCDClient) (govcd.Task, error) {

	if vappTemplate == (govcd.VAppTemplate{}) || vappTemplate.VAppTemplate == nil {
		return govcd.Task{}, fmt.Errorf("vApp Template can not be empty")
	}

	templateHref := vappTemplate.VAppTemplate.HREF
	if vappTemplate.VAppTemplate.Children != nil && len(vappTemplate.VAppTemplate.Children.VM) != 0 {
		templateHref = vappTemplate.VAppTemplate.Children.VM[0].HREF
	}

	// Status 8 means The object is resolved and powered off.
	// https://vdc-repo.vmware.com/vmwb-repository/dcr-public/94b8bd8d-74ff-4fe3-b7a4-41ae31516ed7/1b42f3b5-8b31-4279-8b3f-547f6c7c5aa8/doc/GUID-843BE3AD-5EF6-4442-B864-BCAE44A51867.html
	if vappTemplate.VAppTemplate.Status != 8 {
		return govcd.Task{}, fmt.Errorf("vApp Template shape is not ok (status: %d)", vappTemplate.VAppTemplate.Status)
	}

	// Validate network config only if it was supplied
	if network != nil && network.NetworkConnection != nil {
		for _, nic := range network.NetworkConnection {
			if nic.Network == "" {
				return govcd.Task{}, fmt.Errorf("missing mandatory attribute Network: %s", nic.Network)
			}
			if nic.IPAddressAllocationMode == "" {
				return govcd.Task{}, fmt.Errorf("missing mandatory attribute IPAddressAllocationMode: %s", nic.IPAddressAllocationMode)
			}
		}
	}

	vAppComposition := &types.ReComposeVAppParams{
		Ovf:         types.XMLNamespaceOVF,
		Xsi:         types.XMLNamespaceXSI,
		Xmlns:       types.XMLNamespaceVCloud,
		Deploy:      false,
		Name:        vapp.VApp.Name,
		PowerOn:     false,
		Description: vapp.VApp.Description,
		SourcedItem: &types.SourcedCompositionItemParam{
			Source: &types.Reference{
				HREF: templateHref,
				Name: name,
			},
			InstantiationParams: &types.InstantiationParams{}, // network config is injected below
			VMGeneralParams: &types.VMGeneralParams{
				RegenerateBiosUuid: true, // fix k8s duplicate weave mac address
			},
		},
		AllEULAsAccepted: true,
	}
	// Inject network config
	vAppComposition.SourcedItem.InstantiationParams.NetworkConnectionSection = network

	apiEndpoint, err := url.ParseRequestURI(vapp.VApp.HREF)
	if err != nil {
		return govcd.Task{}, fmt.Errorf("Error in addNewVMRegenUuid %v", err)
	}
	apiEndpoint.Path += "/action/recomposeVApp"

	// Return the task
	return vcdClient.Client.ExecuteTaskRequestWithApiVersion(apiEndpoint.String(), http.MethodPost,
		types.MimeRecomposeVappParams, "error instantiating a new VM: %s", vAppComposition,
		vcdClient.Client.GetSpecificApiVersionOnCondition(">= 33.0", "33.0"))

}
