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
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/vmware/go-vcloud-director/v2/govcd"
	"github.com/vmware/go-vcloud-director/v2/types/v56"
)

var VmNameToHref map[string]string
var vcdVmHrefMux sync.Mutex

func init() {
	VmNameToHref = make(map[string]string)
}

// VM related operations

// If all you have is the serverName (vmName)
func (v *VcdPlatform) FindVMByName(ctx context.Context, serverName string, vcdClient *govcd.VCDClient, vdc *govcd.Vdc) (*govcd.VM, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "FindVMByName", "serverName", serverName)

	vm := v.FindVMByHrefCache(ctx, serverName, vcdClient)
	if vm != nil {
		return vm, nil
	}
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
			// add the href to the cache
			v.AddVmHrefToCache(ctx, serverName, vm.VM.HREF)
			return vm, nil
		}
	}
	return nil, fmt.Errorf("Vm %s not found", serverName)
}

// Have vapp obj in hand use this one.
func (v *VcdPlatform) FindVMInVApp(ctx context.Context, serverName string, vapp govcd.VApp) (*govcd.VM, error) {
	vm, err := vapp.GetVMByName(serverName, false)
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

func (v *VcdPlatform) getVmInternalIp(ctx context.Context, vmparams *vmlayer.VMOrchestrationParams, vmgp *vmlayer.VMGroupOrchestrationParams, vapp *govcd.VApp, vdcClient *govcd.VCDClient, vdc *govcd.Vdc, action vmlayer.ActionType) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "getVmInternalIp", "vm", vmparams.Name, "ports", vmparams.Ports, "action", action)

	netMap, err := v.getVappNetworkInfoMap(ctx, vapp, vmgp, vdcClient, vdc, action)
	if err != nil {
		return "", err
	}
	vmIp, err := v.getIpFromPortParams(ctx, vmparams, vmgp, netMap, vdcClient, vdc)
	log.SpanLog(ctx, log.DebugLevelInfra, "getIpFromPortParams returns", "vmIp", vmIp, "err", err)
	if err != nil {
		return "", err
	}
	if vmIp == "" {
		return "", fmt.Errorf("Internal IP not found")
	}
	return vmIp, nil
}

func (v *VcdPlatform) getIpFromPortParams(ctx context.Context, vmparams *vmlayer.VMOrchestrationParams, vmgp *vmlayer.VMGroupOrchestrationParams, netMap map[string]networkInfo, vcdClient *govcd.VCDClient, vdc *govcd.Vdc) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "getIpFromPortParams", "netMap", netMap)

	ipRange := ""
	for _, port := range vmparams.Ports {
		for _, p := range vmgp.Ports {
			if p.Id == port.Id {
				log.SpanLog(ctx, log.DebugLevelInfra, "Found Port within orch params", "id", port.Id, "fixedips", p.FixedIPs, "networkInfo", netMap[p.SubnetId])
				if len(p.FixedIPs) == 1 && p.FixedIPs[0].Address == vmlayer.NextAvailableResource {
					net, ok := netMap[p.SubnetId]
					if !ok {
						log.SpanLog(ctx, log.DebugLevelInfra, "failed to find subnet in map", "port", port, "netmap", netMap)
						return "", fmt.Errorf("cannot subnet in netmap for network %s", p.SubnetId)
					}
					log.SpanLog(ctx, log.DebugLevelInfra, "FixedIPs is next available resource", "net", net)
					if vmgp.ConnectsToSharedRootLB {
						if netMap[p.SubnetId].LegacyIsoNet {
							ipRange = net.Gateway
							log.SpanLog(ctx, log.DebugLevelInfra, "Using legacy net GW as iprange", "ipRange", ipRange)
						} else if ipRange == "" {
							var err error
							ipRange, err = v.GetFreeSharedCommonIpRange(ctx, v.vappNameToInternalSubnet(ctx, vmgp.GroupName), vcdClient, vdc)
							if err != nil {
								return "", err
							}
						}
					} else {
						log.SpanLog(ctx, log.DebugLevelInfra, "Using GW as iprange for dedicated cluster", "ipRange", ipRange)
						ipRange = net.Gateway
					}
					vmIp, err := ReplaceLastOctet(ctx, ipRange, p.FixedIPs[0].LastIPOctet)
					if err != nil {
						return "", fmt.Errorf("failed to replace last octet of addr %s, octet %d - %v", net.Gateway, p.FixedIPs[0].LastIPOctet, err)
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

	_, err = v.CreateVApp(ctx, tmpl, vmgp, description, vcdClient, vdc, updateCallback)
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

func (v *VcdPlatform) updateNetworksForVM(ctx context.Context, vcdClient *govcd.VCDClient, vdc *govcd.Vdc, vm *govcd.VM, vmgp *vmlayer.VMGroupOrchestrationParams, vmparams *vmlayer.VMOrchestrationParams, vmIdx int, netMap map[string]networkInfo, masterIP string) (*govcd.VM, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "updateNetworksForVM", "vm", vm.VM.Name, "MasterIP", masterIP, "netMap", netMap)

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
	vmIp, err := v.getIpFromPortParams(ctx, vmparams, vmgp, netMap, vcdClient, vdc)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to get ip from port params", "err", err)
		return nil, err
	}
	for netConIdx, port := range vmparams.Ports {
		network, err := v.getNetworkInfo(ctx, port.NetworkId, port.SubnetId, netMap)
		if err != nil {
			return nil, err
		}
		netName := network.VcdNetworkName
		log.SpanLog(ctx, log.DebugLevelInfra, "updateNetworksForVM add connection", "net", netName, "vmIp", vmIp, "VM", vmparams.Name)
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
			log.SpanLog(ctx, log.DebugLevelInfra, "updateNetworksForVM adding internal connection", "vmname", vmparams.Name, "net", netName, "networkAdapterType", networkAdapterType, "vmip", vmIp, "conidx", netConIdx, "netType", port.NetType, "ncs", ncs)
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
			log.SpanLog(ctx, log.DebugLevelInfra, "updateNetworksForVM adding external connection", "vmname", vmparams.Name, "net", netName, "networkAdapterType", networkAdapterType, "conidx", netConIdx, "netType", port.NetType, "ncs", ncs)
		}
	}
	err = vm.UpdateNetworkConnectionSection(ncs)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "updateNetworksForVM add internal net failed SLEEP 30 and Retry operation", "VM", vmparams.Name, "ncs", ncs, "error", err)
		time.Sleep(30 * time.Second)
		err = vm.UpdateNetworkConnectionSection(ncs)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "updateNetworksForVM add internal net failed", "VM", vm.VM.Name, "ncs", ncs, "error", err)
			return nil, err
		}
	}

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
		fallthrough
	case vmlayer.RoleMaster:
		for netname, netinfo := range netMap {
			log.SpanLog(ctx, log.DebugLevelInfra, "Checking role and nettype for gw removal", "netname", netname, "NetworkType", netinfo.NetworkType)
			if netinfo.NetworkType == vmlayer.NetworkTypeExternalAdditionalClusterNode {
				gwsToRemove = append(gwsToRemove, netinfo.Gateway)
			}
		}
		if vmgp.ConnectsToSharedRootLB {
			for netname, netinfo := range netMap {
				if netinfo.NetworkType == vmlayer.NetworkTypeInternalSharedLb && !netinfo.LegacyIsoNet {
					log.SpanLog(ctx, log.DebugLevelInfra, "adding iptables rules commands to block inter-cluster traffic", "netname", netname, "vm", vm.VM.Name)
					vip := net.ParseIP(vmIp)
					if vip == nil {
						return nil, fmt.Errorf("failed to parse vmip as ip addr - %s", vmIp)
					}
					allowed := vip
					allowed[len(allowed)-1] = 0 // allow everything within the last octet range
					allowedStr := fmt.Sprintf("%s/%d", allowed.String(), 24)
					blockedStr, err := v.getCommonInternalCIDR(ctx)
					if err != nil {
						return nil, err
					}
					cmds, err := vmlayer.GetBootCommandsForInterClusterIptables(ctx, allowedStr, blockedStr, netinfo.Gateway)
					if err != nil {
						return nil, err
					}
					vmparams.CloudConfigParams.ExtraBootCommands = append(vmparams.CloudConfigParams.ExtraBootCommands, cmds...)
				}
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
			masterIP, err = v.getVmInternalIp(ctx, &vmparams, vmgp, vapp, vcdClient, vdc, vmlayer.ActionCreate)
			if err != nil {
				return nil, fmt.Errorf("Fail to get Master internal IP - %v", err)
			}
		}

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
			log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp add VM", "vmName", vmName, "vmRole", vmRole, "vmparams", vmparams)
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
		vm, err = v.updateNetworksForVM(ctx, vcdClient, vdc, vm, vmgp, &vmparams, n, netMap, masterIP)
		if err != nil {
			return nil, err
		}
		if vmparams.Role != vmlayer.RoleVMApplication {
			vmsToCustomize[vmparams.Name] = vm
		}
	} //for n, vmparams

	log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp complete")
	return vmsToCustomize, nil
}

func (v *VcdPlatform) AddVMsToExistingVApp(ctx context.Context, vapp *govcd.VApp, vmgp *vmlayer.VMGroupOrchestrationParams, vcdClient *govcd.VCDClient, vdc *govcd.Vdc) (VMMap, error) {
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

	masterIP := ""
	for n, vmparams := range vmgp.VMs {
		vmName := vmparams.Name
		vmRole := vmparams.Role
		ncs := &types.NetworkConnectionSection{}
		// check to see if this vm is already present
		if vmparams.ExistingVm {
			// for existing VMs just check if this is a master and get the IP
			if vmRole == vmlayer.RoleMaster {
				var vmIp string
				vmIp, err = v.getVmInternalIp(ctx, &vmparams, vmgp, vapp, vcdClient, vdc, vmlayer.ActionUpdate)
				if err != nil {
					return nil, err
				}
				masterIP = vmIp
				log.SpanLog(ctx, log.DebugLevelInfra, "Got Master IP", "masterIP", masterIP)
			}
			continue
		}
		vm, err := vapp.GetVMByName(vmName, true)
		if err != nil && vm == nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToExistingVApp", "vmName", vmName, "vmRole", vmRole)

			// use new regen
			task, err := v.addNewVMRegenUuid(vapp, vmName, *tmpl, ncs, vcdClient)
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
		} else {
			return nil, fmt.Errorf("Found VM already in Vapp which should not exist - %s", vmName)
		}

		if v.Verbose {
			log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToExistingVApp", "vapp", vapp.VApp.Name, "network", netName, "existingsVMs", numExistingVMs, "n", n)
		}

		netMap, err := v.getVappNetworkInfoMap(ctx, vapp, vmgp, vcdClient, vdc, vmlayer.ActionUpdate)
		if err != nil {
			return nil, err
		}
		vm, err = v.updateNetworksForVM(ctx, vcdClient, vdc, vm, vmgp, &vmparams, n, netMap, masterIP)
		if err != nil {
			return nil, err
		}
		vmMap[vm.VM.Name] = vm
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToExistingVApp complete")
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

	numNewVMs := len(vmgp.VMs)
	numToAddFound := 0
	log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMs existing vs new", "numExisting", numExistingVMs, "numNew", numNewVMs)
	if numNewVMs > numExistingVMs {
		// Its an add of numNetVMs - numExistingVMs
		numToAdd := numNewVMs - numExistingVMs
		log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMs add", "count", numToAdd)
		updateCallback(edgeproto.UpdateTask, "Adding VMs to vApp")
		// now find which one is the new guy
		// Loop thru the orch spec and mark existing VMs
		// of vms to create. create a new list of vmgp.VMs to pass to AddVMsToExistngVApp
		for i, vmSpec := range vmgp.VMs {
			if _, found := existingVms[vmSpec.Name]; !found {
				log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMs adding new", "vm", vmSpec.Name)
				numToAddFound++
			} else {
				log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMs skip existing", "vm", vmSpec.Name)
				vmgp.VMs[i].ExistingVm = true
			}
		}
		if numToAddFound != numToAdd {
			log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMs Mismatch count", "numToAdd", numToAdd, "numToAddFound", numToAddFound)
		}
		newVms, err := v.AddVMsToExistingVApp(ctx, vapp, vmgp, vcdClient, vdc)
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
		// delete whatever is in existing that is not in new
		for _, newVmParams := range vmgp.VMs {
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
			log.SpanLog(ctx, log.DebugLevelInfra, "VApp not found ", "vappName", vappName)
			return fmt.Errorf(vmlayer.ServerDoesNotExistError)
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
	connections := vm.VM.NetworkConnectionSection.NetworkConnection

	for _, connection := range connections {
		servIP := vmlayer.ServerIP{
			MacAddress:   connection.MACAddress,
			ExternalAddr: connection.IPAddress,
			InternalAddr: connection.IPAddress,
		}
		netname := connection.Network
		portNetName := netname
		if connection.Network != v.vmProperties.GetCloudletExternalNetwork() {
			// substitute the VCD network name for the mex nomenclature if this is a shared LB connected node
			// so that we can find it from vmlayer using the mex net name. This avoids having to lookup metadata
			if netname == v.vmProperties.GetSharedCommonSubnetName() {
				netname = v.vmProperties.GetCloudletMexNetwork()
				log.SpanLog(ctx, log.DebugLevelInfra, "using mex internal network for shared subnet", "netname", netname, "connection.Network", connection.Network)
			} else if strings.HasPrefix(netname, mexInternalNetRange) {
				// legacy iso net case, the subnet must be remapped to the mex version. We cannot use the mex network name here because there can be multiple on the same vm
				var err error
				portNetName, err = v.GetSubnetFromLegacyIsoMetadata(ctx, netname, vcdClient, vdc)
				if err != nil {
					return serverIPs, err
				}
				log.SpanLog(ctx, log.DebugLevelInfra, "converting legacy iso net to mex subnet", "netname", netname, "connection.Network", connection.Network)
			}
		}
		servIP.Network = netname
		servIP.PortName = vmName + "-" + portNetName + "-port"
		log.SpanLog(ctx, log.DebugLevelInfra, "GetVMAddresses Added", "vmname", vmName, "portName", servIP.PortName, "network", servIP.Network)
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
	vmProperties.UsesCommonSharedInternalLBNetwork = true
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
	vdc, err := v.GetVdcFromContext(ctx, vcdClient)
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
		vm, err := vapp.GetVMByName(cvm.Name, false)
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
		vmstat, err := v.GetVmStatus(ctx, vm, NoRefresh)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "error getting VM status", "err", err)
			vmstat = "unknown"
		}
		vminfo := edgeproto.VmInfo{
			Name:        vm.VM.Name,
			InfraFlavor: flavor,
			Type:        v.vmProperties.GetNodeTypeForVmNameAndRole(vm.VM.Name, role).String(),
			Status:      vmstat,
		}
		netTypes := []vmlayer.NetworkType{
			vmlayer.NetworkTypeExternalAdditionalPlatform,
			vmlayer.NetworkTypeExternalAdditionalRootLb,
			vmlayer.NetworkTypeExternalPrimary,
		}
		sd, err := v.GetServerDetailWithVdc(ctx, vm.VM.Name, vdc, vcdClient)
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
	vmType := v.vmProperties.GetNodeTypeForVmNameAndRole(vmparams.Name, string(vmparams.Role)).String()
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

// GetVmHrefFromCache returns an href if the VM is cached, blank string otherwise
func (v *VcdPlatform) GetVmHrefFromCache(ctx context.Context, vmName string) string {
	vcdVmHrefMux.Lock()
	defer vcdVmHrefMux.Unlock()
	return VmNameToHref[vmName]
}

func (v *VcdPlatform) AddVmHrefToCache(ctx context.Context, vmName, href string) {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddVmHrefToCache", "vmName", vmName)
	vcdVmHrefMux.Lock()
	defer vcdVmHrefMux.Unlock()
	VmNameToHref[vmName] = href
}

// DeleteVmHrefFromCache delete the VM->href mapping in the cache if present, does
// nothing otherwise
func (v *VcdPlatform) DeleteVmHrefFromCache(ctx context.Context, vmName string) {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVmHrefFromCache", "vmName", vmName)
	vcdVmHrefMux.Lock()
	defer vcdVmHrefMux.Unlock()
	delete(VmNameToHref, vmName)
}

func (v *VcdPlatform) DumpVmHrefCache(ctx context.Context) string {
	log.SpanLog(ctx, log.DebugLevelInfra, "DumpVmHrefCache")
	vcdVmHrefMux.Lock()
	defer vcdVmHrefMux.Unlock()

	out := fmt.Sprintf("VmNameToHref: %v", VmNameToHref)
	return out
}

func (v *VcdPlatform) ClearVmHrefCache(ctx context.Context) {
	log.SpanLog(ctx, log.DebugLevelInfra, "ClearVmHrefCache")
	vcdVmHrefMux.Lock()
	defer vcdVmHrefMux.Unlock()
	VmNameToHref = make(map[string]string)
}

// FindVMByHrefCache returns nil if the cache is not enabled or the vm not found
func (v *VcdPlatform) FindVMByHrefCache(ctx context.Context, vmName string, vcdClient *govcd.VCDClient) *govcd.VM {
	log.SpanLog(ctx, log.DebugLevelInfra, "FindVMByHrefCache", "vmName", vmName)
	if !v.GetHrefCacheEnabled() {
		return nil
	}
	href := v.GetVmHrefFromCache(ctx, vmName)
	if href == "" {
		log.SpanLog(ctx, log.DebugLevelInfra, "FindVMByHrefCache href not found in cache", "vmName", vmName)
		return nil
	}
	vm, err := vcdClient.Client.GetVMByHref(href)
	if err == nil {
		return vm
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "FindVMByName could not get VM by href", "err", err)
		// delete the href from the cache since we could not find anything with it
		v.DeleteVmHrefFromCache(ctx, vmName)
	}
	return nil
}
