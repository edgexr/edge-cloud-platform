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
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/vmware/go-vcloud-director/v2/govcd"
	"github.com/vmware/go-vcloud-director/v2/types/v56"
)

// VmHardwareVersion of 14 means vsphere 6.7
var VmHardwareVersion = 14

var ResolvedStateMaxWait = 4 * 60 // 4 mins
var ResolvedStateTickTime time.Duration = time.Second * 3

const VappResourceXmlType = "application/vnd.vmware.vcloud.vApp+xml"

// Compose a new vapp from the given template, using vmgrp orch params
// Creates one or more vms.
func (v *VcdPlatform) CreateVApp(ctx context.Context, vappTmpl *govcd.VAppTemplate, vmgp *vmlayer.VMGroupOrchestrationParams, description string, vcdClient *govcd.VCDClient, vdc *govcd.Vdc, updateCallback edgeproto.CacheUpdateCallback) (*govcd.VApp, error) {

	var vapp *govcd.VApp
	var err error

	numVMs := len(vmgp.VMs)
	storRef := types.Reference{}
	// Nil ref wins default storage policy
	createStart := time.Now()
	updateCallback(edgeproto.UpdateTask, "Creating vApp")

	log.SpanLog(ctx, log.DebugLevelInfra, "CreateVapp", "name", vmgp.GroupName, "tmpl", vappTmpl.VAppTemplate.Name)

	vappName := vmgp.GroupName + "-vapp"
	vapp, err = v.FindVApp(ctx, vappName, vcdClient, vdc)
	if err == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "CreateVApp vapp alredy exists", "name", vmgp.GroupName, "vapp", vapp)
		return vapp, nil
	}

	vmtmpl := &types.VAppTemplate{}
	vmparams := vmlayer.VMOrchestrationParams{}
	if vappTmpl.VAppTemplate.Children.VM == nil || len(vappTmpl.VAppTemplate.Children.VM) == 0 {
		return nil, fmt.Errorf("No children in vapp template")
	}
	vmtmpl = vappTmpl.VAppTemplate.Children.VM[0]
	vmparams = vmgp.VMs[0]
	vmtmplVMName := vmtmpl.Name
	// save orig tmplate name
	vmtmpl.Name = vmparams.Name
	vmRole := vmparams.Role

	networks := []*types.OrgVDCNetwork{}
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateVApp compose vApp", "name", vappName, "vmRole", vmRole)

	description = description + vcdProviderVersion
	composeStart := time.Now()
	task, err := vdc.ComposeVApp(networks, *vappTmpl, storRef, vappName, description, true)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "CreateVApp compose failed", "error", err)
		return nil, err
	}
	err = task.WaitTaskCompletion()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "ComposeVApp wait for completeion failed", "VAppName", vmgp.GroupName, "error", err)
		return nil, err
	}

	vmtmpl.Name = vmtmplVMName
	vapp, err = vdc.GetVAppByName(vappName, true)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "can't retrieve composed vapp", "VAppName", vmgp.GroupName, "error", err)
		return nil, err
	}

	// wait before adding vms
	err = v.BlockWhileStatusWithTickTime(ctx, vapp, "UNRESOLVED", ResolvedStateMaxWait, ResolvedStateTickTime)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "wait for RESOLVED error", "VAppName", vmgp.GroupName, "error", err)
		return nil, err
	}
	elapsedCompose := time.Since(composeStart).String()
	log.SpanLog(ctx, log.DebugLevelInfra, "Compose Vapp successfully", "VApp", vmgp.GroupName, "tmpl", vappTmpl.VAppTemplate.Name, "time", elapsedCompose)

	err = v.validateVMSpecSection(ctx, *vapp)
	if err != nil {
		return nil, err
	}
	updateCallback(edgeproto.UpdateTask, "Updating vApp Ports")
	updatePortsStart := time.Now()
	// Get the VApp network(s) in place.
	err = v.AddPortsToVapp(ctx, vapp, vmgp, updateCallback, vcdClient, vdc)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "AddPortsToVapp failed", "VAppName", vmgp.GroupName, "error", err)
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateVapp added ports", "vmRole", vmRole)

	vmtmplName := vapp.VApp.Children.VM[0].Name
	_, err = vapp.GetVMByName(vmtmplName, false)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "CreateVApp failed to retrieve", "VM", vmtmplName)
		return nil, err
	}
	if v.Verbose {
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Update vApp Ports time %s",
			cloudcommon.FormatDuration(time.Since(updatePortsStart), 2)))
	}

	updateCallback(edgeproto.UpdateTask, "Adding VMs to vApp")
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateVApp composed adding VMs for ", "GroupName", vmgp.GroupName, "count", numVMs)
	addVMStart := time.Now()

	netMap, err := v.getVappNetworkInfoMap(ctx, vapp, vmgp, vcdClient, vdc, vmlayer.ActionCreate)
	if err != nil {
		return nil, err
	}
	vmsToCustomize, err := v.AddVMsToVApp(ctx, vapp, vmgp, vappTmpl, netMap, vdc, vcdClient, updateCallback)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "CreateVApp AddVMsToVApp failed", "error", err)
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateVApp composed VMs added", "GroupName", vmgp.GroupName)
	// poweron and customize
	if v.Verbose {
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Add VMs to VApp time %s",
			cloudcommon.FormatDuration(time.Since(addVMStart), 2)))
	}

	// even if anti affinity is not enabled in the cloudlet, create the rule but disable it. This allows
	// us to test the creation and deletion of anti affinity rules in a host limited environment
	if vmgp.AntiAffinitySpecified {
		var vmReferences []*types.Reference
		for _, vm := range vmsToCustomize {
			vmReferences = append(vmReferences, &types.Reference{HREF: vm.VM.HREF})
		}
		aRuleDef := types.VmAffinityRule{
			Name: vmgp.GroupName + "-anti-affinity", Polarity: types.PolarityAntiAffinity,
			IsEnabled:   TakeBoolPointer(vmgp.AntiAffinityEnabledInCloudlet),
			IsMandatory: TakeBoolPointer(false),
			VmReferences: []*types.VMs{
				{
					VMReference: vmReferences,
				},
			}}
		log.SpanLog(ctx, log.DebugLevelInfra, "creating anti affinity rule", "def", aRuleDef)
		_, err = vdc.CreateVmAffinityRule(&aRuleDef)
		if err != nil {
			return nil, fmt.Errorf("Error creating anti affinity rule - %v", err)
		}
	}

	updateCallback(edgeproto.UpdateTask, "Powering on VMs")
	powerOnStart := time.Now()
	err = v.powerOnVmsAndForceCustomization(ctx, vmsToCustomize)
	if err != nil {
		return nil, err
	}

	if v.Verbose {
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("VM PowerOn time %s",
			cloudcommon.FormatDuration(time.Since(powerOnStart), 2)))
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateVApp composed Powering On", "Vapp", vappName)
	vappPowerOnStart := time.Now()
	updateCallback(edgeproto.UpdateTask, "Powering on Vapp")

	task, err = vapp.PowerOn()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "power on failed ", "VAppName", vapp.VApp.Name, "err", err)
		return nil, err
	}
	err = task.WaitTaskCompletion()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "wait power on failed", "VAppName", vmgp.GroupName, "error", err)
		return nil, err
	}
	if v.Verbose {
		msg := fmt.Sprintf("%s %s", "vapp power on  time ", cloudcommon.FormatDuration(time.Since(vappPowerOnStart), 2))
		updateCallback(edgeproto.UpdateTask, msg)
	}

	if v.Verbose {
		v.LogVappVMsStatus(ctx, vapp)
	}
	if v.Verbose {
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("%s %s", "CreateVMs  time ",
			cloudcommon.FormatDuration(time.Since(createStart), 2)))
	}
	return vapp, nil
}

func (v *VcdPlatform) LogVappVMsStatus(ctx context.Context, vapp *govcd.VApp) {

	vms := vapp.VApp.Children.VM
	for _, vm := range vms {
		v, err := vapp.GetVMByName(vm.Name, false)
		if err != nil {
			continue
		}
		vmstatus, err := v.GetStatus()
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "Error getting vm status", "vm", vm.Name, "error", err)
			continue
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "LogVappVmsStatus", "vm", vm.Name, "status", vmstatus)
	}
}

func (v *VcdPlatform) DeleteVapp(ctx context.Context, vapp *govcd.VApp, vcdClient *govcd.VCDClient) error {

	// are we being asked to delete vm or vapp (do we ever get asked to delete a single VM?)
	vappName := vapp.VApp.Name
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp", "name", vappName)

	vdc, err := v.GetVdc(ctx, vcdClient)
	if err != nil {
		return fmt.Errorf("GetVdc Failed - %v", err)
	}
	affinityRule, err := vdc.GetVmAffinityRuleById(vappName + "-anti-affinity")
	if err != nil {
		if !govcd.ContainsNotFound(err) {
			return fmt.Errorf("error finding affinity rule for vapp - %v", err)
		}
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "deleting affinity rule for vapp")
		err = affinityRule.Delete()
		if err != nil {
			return fmt.Errorf("error deleting affinity rule for vapp - %v", err)
		}
	}
	// cleanup VM HREF cache
	if v.GetHrefCacheEnabled() {
		if vapp.VApp != nil && vapp.VApp.Children != nil && vapp.VApp.Children.VM != nil {
			for _, vm := range vapp.VApp.Children.VM {
				// delete from cache
				v.DeleteVmHrefFromCache(ctx, vm.Name)
			}
		}
	}

	// handle deletion of an iso orgvdcnet of the client of a shared LB
	// DetachPortFromServer has already been called, and can't delete the network
	// because it's still in use, possibly by this vapp (shared clusterInst)

	// Notes on deletion order related to isolated Org VDC networks:
	// - network retrieval must happen before VMs are deleted or the network will not be found
	// - VMs are deleted next
	// - The network must then be removed from the vApp (RemoveAllNetworks) and then the vApp is deleted. This
	//   ensures that the vApp is not associated with the network, so it can be deleted
	// - Deleting the network (RemoveOrgVdcNetworkIfExists) must happen last, as if there
	//   are any users of the network this will fail. This is only done for legacy iso networks (created 3.1 and prior)

	// find the org vcd isolated network if one exists.  Do this before deleting VMs
	internalSubnetName := v.vappNameToInternalSubnet(ctx, vapp.VApp.Name)
	networkMetadataType, mappedNetName, err := v.GetNetworkMetadataForInternalSubnet(ctx, internalSubnetName, vcdClient, vdc)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "error getting metadata", "err", err)
	}

	task, err := vapp.Undeploy()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp err vapp.Undeploy ignoring", "vapp", vappName, "err", err)
	} else {
		_ = task.WaitTaskCompletion()
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp undeployed", "Vapp", vappName)
	if vapp.VApp != nil && vapp.VApp.Children != nil && vapp.VApp.Children.VM != nil {
		vms := vapp.VApp.Children.VM
		for _, tvm := range vms {
			vmName := tvm.Name
			vm, err := vapp.GetVMByName(vmName, true)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp vm not found", "vm", vmName, "for server", vappName)
				return err
			}
			log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp undeploy/poweroff/delete", "vm", vmName)
			task, err := vm.Undeploy()
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp unDeploy failed", "vm", vmName, "error", err)
			} else {
				if err = task.WaitTaskCompletion(); err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp wait for undeploy failed", "vm", vmName, "error", err)
				}
			}
			// undeployed
			task, err = vm.PowerOff()
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp PowerOff failed", "vm", vmName, "error", err)
			} else {
				if err = task.WaitTaskCompletion(); err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp wait for PowerOff failed", "vm", vmName, "error", err)
				}
			}
			// powered off
			log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp delete powered off", "vm", vmName)
			err = vm.Delete()
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp PowerOff failed", "vm", vmName, "error", err)
			}
			// deleted
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "RemoveAllNetworks")
	task, err = vapp.RemoveAllNetworks()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp RemoveAllNetworks failed ", "err", err)
	} else {
		err = task.WaitTaskCompletion()
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp wait task for RemoveAllNetworks failed", "error", err)
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "vapp Delete")
	task, err = vapp.Delete()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp failed ", "vapp", vappName, "err", err)
		return fmt.Errorf("Delete VApp %s Failed - %v", vappName, err)
	} else {
		err = task.WaitTaskCompletion()
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp wait task failed vapp.Delete", "vapp", vappName, "err", err)
			return err
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp deleted", "Vapp", vappName, "mappedNetName", mappedNetName)
	// check if we're using a isolated orgvdcnetwork /  sharedLB
	if networkMetadataType == NetworkMetadataLegacyPerClusterIsoNet {
		if v.GetNsxType() == NSXV {
			log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp nsx-v removing isoNetworks if exists", "vapp", vappName, "mappedNetName", mappedNetName, "isNsxt?", vdc.IsNsxt(), "isNsxv?", vdc.IsNsxv())
			err = govcd.RemoveOrgVdcNetworkIfExists(*vdc, mappedNetName)
			if err != nil {
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp RemoveOrgVdcNetworkIfExists failed for", "netName", mappedNetName, "error", err)
					return err
				}
			}
		} else {
			// there are no non-lab NSX-T deployments using legacy ISO networks, and in any case we will not reuse them going forward
			log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp nsx-t no action for legacy isonet", "vapp", vappName, "mappedNetName", mappedNetName)
		}

	} else if err != nil {
		// don't fail the delete cluster operation here, dedicated LBs don't use type 2 orgvcdnetworks.
		log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp GetVappIsoNetwork failed ignoring", "vapp", vappName, "mappedNetName", mappedNetName, "err", err)
	}
	if networkMetadataType != NetworkMetadataNone {
		// finally, remove the IsoNamesMap entry for shared LBs.
		err := v.DeleteMetadataForInternalSubnet(ctx, internalSubnetName, vcdClient, vdc)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "error deleting network metadata", "error", err)
			return err
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp removed network metadata ", internalSubnetName, internalSubnetName)
	}
	return nil

}
func (v *VcdPlatform) FindVApp(ctx context.Context, vappName string, vcdClient *govcd.VCDClient, vdc *govcd.Vdc) (*govcd.VApp, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "FindVApp", "vappName", vappName)

	vapp, err := vdc.GetVAppByName(vappName, true)
	if err != nil && strings.Contains(err.Error(), "NotFound") {
		return nil, fmt.Errorf(vmlayer.ServerDoesNotExistError)
	}
	return vapp, err
}

// Propteries make up the ProductSection and are retrievable in the VM
func makeProp(key, value string) *types.Property {
	prop := &types.Property{
		// We hard code UserConfigurable for now, as if false, it does not appear in the ovfenv fetched by vmtoolsd,
		UserConfigurable: true,
		Type:             "string",
		Key:              key,
		Label:            key + "-label",
		Value: &types.Value{
			Value: value,
		},
	}
	return prop
}

func vcdUserDataFormatter(instring string) string {
	instring = strings.ReplaceAll(instring, "/dev/vd", "/dev/sd")
	return base64.StdEncoding.EncodeToString([]byte(instring))
}

func makeMetaMap(ctx context.Context, mexmeta string) map[string]string {

	log.SpanLog(ctx, log.DebugLevelInfra, "makeMetaMap", "meta", mexmeta)
	smap := make(map[string]string)
	if mexmeta != "" {
		s := strings.Replace(mexmeta, "\n", ":", -1)
		parts := strings.Split(s, ":")
		for i := 0; i < len(parts); i += 2 {
			key := strings.TrimSpace(parts[i])
			val := strings.TrimSpace(parts[i+1])
			smap[key] = val
		}
	}
	return smap
}

func vcdMetaDataFormatter(instring string) string {
	return instring
}
func (v *VcdPlatform) populateProductSection(ctx context.Context, vm *govcd.VM, vmparams *vmlayer.VMOrchestrationParams, masterIP string) (*types.ProductSectionList, error) {

	log.SpanLog(ctx, log.DebugLevelInfra, "populateProductSection", "vm", vm.VM.Name, "masterIP", masterIP)
	command := ""
	manifest := ""
	// format vmparams.CloudConfigParams into yaml format, which we'll then base64 encode for the ovf datasource
	udata, err := vmlayer.GetVMUserData(vm.VM.Name, vmparams.SharedVolume, manifest, command, &vmparams.CloudConfigParams, vcdUserDataFormatter)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Unable to retrive VMUserData", "err", err)
		return nil, err
	}
	guestCustomSec, err := vm.GetGuestCustomizationSection()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetGuestCustomizationSection failed", "err", err)
		return nil, err
	}
	guestCustomSec.Enabled = TakeBoolPointer(true)
	guestCustomSec.ComputerName = vmparams.HostName
	guestCustomSec.AdminPasswordEnabled = TakeBoolPointer(false) // we have our own baseimage password
	_, err = vm.SetGuestCustomizationSection(guestCustomSec)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "SetGuestCustomizationSection failed", "err", err)
		return nil, err
	}
	if (vmparams.Role == vmlayer.RoleMaster || vmparams.Role == vmlayer.RoleK8sNode) && masterIP == "" {
		return nil, fmt.Errorf("empty master IP provided")
	}
	mexMetadata := vmlayer.GetVMMetaData(vmparams.Role, masterIP, vcdMetaDataFormatter)
	log.SpanLog(ctx, log.DebugLevelInfra, "populateProductSection", "masterIP", masterIP, "vmMetadata", mexMetadata)
	mdMap := makeMetaMap(ctx, mexMetadata)

	psl, err := vm.GetProductSectionList()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetProductSectionList failed", "vm", vm.VM.Name, "err", err)
		return nil, err
	}
	if psl.ProductSection == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetGuestCustomizationSection nil creating", "vm", vm.VM.Name)
		psl = &types.ProductSectionList{
			ProductSection: &types.ProductSection{
				Info:     "Guest Properties",
				Property: []*types.Property{},
			},
		}
	}

	var props []*types.Property

	// manditory
	props = append(props, makeProp("instance-id", vm.VM.ID))

	if udata != "" {
		props = append(props, makeProp("user-data", udata))
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "populateProductSection", "name", vmparams.Name, "role", vmparams.Role)
	for k, val := range mdMap {
		if v.Verbose {
			log.SpanLog(ctx, log.DebugLevelInfra, "populateProductSection mdata", "key", k, "value", val)
		}
		props = append(props, makeProp(k, val))
	}

	psl.ProductSection.Property = props

	return psl, nil
}

func (v *VcdPlatform) GetVMFromVAppByIdx(ctx context.Context, vapp *govcd.VApp, idx int) (*govcd.VM, error) {

	if vapp.VApp.Children == nil {
		return nil, fmt.Errorf("vapp has no children vms")
	}
	vmName := vapp.VApp.Children.VM[idx].Name
	vm, err := vapp.GetVMByName(vmName, true)
	if err != nil {
		return nil, err
	}
	return vm, nil
}

// Given a groupName / vappName, return all of its vm membership as a VMMap
func (v *VcdPlatform) GetAllVMsInVApp(ctx context.Context, vapp *govcd.VApp) (VMMap, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetAllVMsInVApp", "Vapp", vapp.VApp.Name)
	vmMap := make(VMMap)
	if vapp.VApp.Children == nil || len(vapp.VApp.Children.VM) == 0 {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetAllVMsInVApp empty Vapp has no vms", "Vapp", vapp.VApp.Name)
		return vmMap, fmt.Errorf("Empty Vapp %s encountered", vapp.VApp.Name)
	}
	var err error
	for _, child := range vapp.VApp.Children.VM {
		vm, err := vapp.GetVMByName(child.Name, false)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetAllVMsInVApp child vm not found ", "Vapp", vapp.VApp.Name, "vm", child.Name, "err", err)
			return vmMap, err
		}
		vmMap[vm.VM.Name] = vm
	}
	return vmMap, err
}

func (v *VcdPlatform) validateVMSpecSection(ctx context.Context, vapp govcd.VApp) error {

	vm, err := v.GetVMFromVAppByIdx(ctx, &vapp, 0)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "validateVMSpecSecion VM not found", "Vapp", vapp.VApp.Name, "idx", 0, "err", err)
		return fmt.Errorf("validateVMSpecSecion VM not found for Vapp %s", vapp.VApp.Name)
	}
	vmSpec := vm.VM.VmSpecSection
	if vmSpec.MemoryResourceMb == nil {
		// TODO: figure this out
		log.SpanLog(ctx, log.DebugLevelInfra, "Warning: validateVMSpecSection missing MemoryResourceMb")
		mresMB := &types.MemoryResourceMb{
			Configured: int64(vmlayer.MINIMUM_RAM_SIZE),
		}
		vmSpec.MemoryResourceMb = mresMB
		_, err := vm.UpdateVmSpecSection(vmSpec, "update missing MB")
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "validateVMSpecSecion err updating spec section", "vm", vm.VM.Name, "err", err)
		}
	}
	return nil
}

// BlockWhileStatusWithTickTime is the same as the govcd version vapp.BlockWhileStatus.  The only difference is that it
// allows a variable tickTime instead of every 200msec so that the number of API calls can be reduced
func (v *VcdPlatform) BlockWhileStatusWithTickTime(ctx context.Context, vapp *govcd.VApp, unwantedStatus string, timeOutAfterSeconds int, tickTime time.Duration) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "BlockWhileStatusWithTimer", "timeOutAfterSeconds", timeOutAfterSeconds, "tickTime", tickTime)

	timeoutAfter := time.After(time.Duration(timeOutAfterSeconds) * time.Second)
	tick := time.NewTicker(tickTime)

	for {
		select {
		case <-timeoutAfter:
			return fmt.Errorf("timed out waiting for vApp to exit state %s after %d seconds",
				unwantedStatus, timeOutAfterSeconds)
		case <-tick.C:
			currentStatus, err := vapp.GetStatus()

			if err != nil {
				return fmt.Errorf("could not get vApp status %s", err)
			}
			if currentStatus != unwantedStatus {
				return nil
			}
		}
	}
}
func (v *VcdPlatform) DumpVapps(ctx context.Context, matchPattern string) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "DumpVapps", "matchPattern", matchPattern)

	rc := ""
	if matchPattern == "all" {
		matchPattern = ".*"
	}
	reg, err := regexp.Compile(matchPattern)
	if err != nil {
		return "", fmt.Errorf("invalid regexp match pattern: %s - %v", matchPattern, err)
	}
	ctx, result, err := v.InitOperationContext(ctx, vmlayer.OperationInitStart)
	if err != nil {
		return "", err
	}
	if result == vmlayer.OperationNewlyInitialized {
		defer v.InitOperationContext(ctx, vmlayer.OperationInitComplete)
	}
	vcdClient := v.GetVcdClientFromContext(ctx)
	if vcdClient == nil {
		return "", fmt.Errorf(NoVCDClientInContext)
	}
	vdc, err := v.GetVdc(ctx, vcdClient)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "DumpVapps unable to retrieve current vdc", "err", err)
		return "", err
	}
	if v.vmProperties == nil { // paranoid check because this runs in debug
		return "", fmt.Errorf("nil vmProperties")
	}
	// For all vapps in vdc
	for _, r := range vdc.Vdc.ResourceEntities {
		for _, res := range r.ResourceEntity {

			if res.Type == VappResourceXmlType {
				if !reg.MatchString(res.Name) {
					log.SpanLog(ctx, log.DebugLevelInfra, "vapp did not match pattern", "res.Name", res.Name)
					continue
				}
				vapp, err := vdc.GetVAppByName(res.Name, false)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "GetVAppByName could not find vapp", "err", err)
					continue
				}
				log.SpanLog(ctx, log.DebugLevelInfra, "found vapp", "name", res.Name)
				rc += "VAPP: " + res.Name + "\n"
				if vapp.VApp == nil {
					rc += " - nil VApp\n"
					log.SpanLog(ctx, log.DebugLevelInfra, "nil vapp", "name", res.Name)
					continue
				}
				if vapp.VApp.NetworkConfigSection != nil {
					netNames := vapp.VApp.NetworkConfigSection.NetworkNames()
					log.SpanLog(ctx, log.DebugLevelInfra, "found vapp networks", "netNames", netNames)
					for _, n := range netNames {
						rc += "- Network: " + n + "\n"
					}
				}
				if res.Name == v.getSharedVappName() {
					meta, err := vapp.GetMetadata()
					if err != nil {
						log.SpanLog(ctx, log.DebugLevelInfra, "failed to get metadata for shared lb", "err", err)
					} else {
						rc += "- Shared LB Metadata:\n"
						for _, me := range meta.MetadataEntry {
							if me.TypedValue == nil {
								log.SpanLog(ctx, log.DebugLevelInfra, "nil metadata value", "err", err)
							} else {
								rc += "    Key: " + me.Key + " Value: " + me.TypedValue.Value + "\n"
							}
						}
					}
				}
				if vapp.VApp.Children != nil {
					for _, vm := range vapp.VApp.Children.VM {
						log.SpanLog(ctx, log.DebugLevelInfra, "found vm", "vapp", res.Name, "vm", vm.Name)
						rc += fmt.Sprintf("- VM: %s Status: %s Deployed: %t\n", vm.Name, types.VAppStatuses[vm.Status], vm.Deployed)
						if vm.NetworkConnectionSection != nil {
							for _, nc := range vm.NetworkConnectionSection.NetworkConnection {
								rc += "   - Net Connection: " + nc.Network + " IP: " + nc.IPAddress + "\n"
							}
						}
					}
				}
			}
		}
	}
	return rc, nil
}
