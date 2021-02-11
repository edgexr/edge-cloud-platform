package vcd

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/vmware/go-vcloud-director/v2/govcd"
	"github.com/vmware/go-vcloud-director/v2/types/v56"
)

// VmHardwareVersion of 14 means vsphere 6.7
var VmHardwareVersion = 14

var ResolvedStateMaxWait = 4 * 60 // 4 mins

// Compose a new vapp from the given template, using vmgrp orch params
// Creates one or more vms.
func (v *VcdPlatform) CreateVApp(ctx context.Context, vappTmpl *govcd.VAppTemplate, vmgp *vmlayer.VMGroupOrchestrationParams, description string, vcdClient *govcd.VCDClient, updateCallback edgeproto.CacheUpdateCallback) (*govcd.VApp, error) {

	var vapp *govcd.VApp
	var err error

	numVMs := len(vmgp.VMs)

	vdc, err := v.GetVdc(ctx, vcdClient)
	if err != nil {
		return nil, err
	}
	storRef := types.Reference{}
	// Nil ref wins default storage policy
	createStart := time.Now()
	updateCallback(edgeproto.UpdateTask, "Creating vApp")

	log.SpanLog(ctx, log.DebugLevelInfra, "CreateVapp", "name", vmgp.GroupName, "tmpl", vappTmpl.VAppTemplate.Name)

	vappName := vmgp.GroupName + "-vapp"
	vapp, err = v.FindVApp(ctx, vappName, vcdClient)
	if err == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "CreateVApp vapp alredy exists", "name", vmgp.GroupName, "vapp", vapp)
		return vapp, nil
	}

	vmtmpl := &types.VAppTemplate{}
	vmparams := vmlayer.VMOrchestrationParams{}
	vmtmpl = vappTmpl.VAppTemplate.Children.VM[0]
	vmparams = vmgp.VMs[0]
	vmtmplVMName := vmtmpl.Name
	// save orig tmplate name
	vmtmpl.Name = vmparams.Name
	vmRole := vmparams.Role
	vmType := string(vmlayer.GetVmTypeForRole(string(vmparams.Role)))

	networks := []*types.OrgVDCNetwork{}
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateVApp compose vApp", "name", vappName, "vmRole", vmRole, "vmType", vmType)

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
	err = vapp.BlockWhileStatus("UNRESOLVED", ResolvedStateMaxWait) // upto seconds

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
	// ensure we have a clean slate  xxx needed? speed up fodder potentially

	task, err = vapp.RemoveAllNetworks()

	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "remove networks failed", "VAppName", vmgp.GroupName, "error", err)
		return nil, err
	}
	err = task.WaitTaskCompletion()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "task completion failed", "VAppName", vmgp.GroupName, "error", err)
	}

	updateCallback(edgeproto.UpdateTask, "Updating vApp Ports")
	updatePortsStart := time.Now()
	// Get the VApp network in place, all vapps need an external network at least
	nextCidr, err := v.AddPortsToVapp(ctx, vapp, *vmgp, updateCallback, vcdClient)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "AddPortsToVapp failed", "VAppName", vmgp.GroupName, "error", err)
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateVapp nextCidr for vapp internal net", "Cidr", nextCidr, "vmRole", vmRole, "vmType", vmType)

	vmtmplName := vapp.VApp.Children.VM[0].Name
	_, err = vapp.GetVMByName(vmtmplName, false)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "CreateVApp failed to retrieve", "VM", vmtmplName)
		return nil, err
	}
	if v.Verbose {
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Update vApp Ports time %s",
			infracommon.FormatDuration(time.Since(updatePortsStart), 2)))
	}

	updateCallback(edgeproto.UpdateTask, "Adding VMs to vApp")
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateVApp composed adding VMs for ", "GroupName", vmgp.GroupName, "count", numVMs)
	addVMStart := time.Now()

	vmsToCustomize, err := v.AddVMsToVApp(ctx, vapp, vmgp, vappTmpl, nextCidr, vdc, vcdClient, updateCallback)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "CreateVApp AddVMsToVApp failed", "error", err)
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateVApp composed VMs added", "GroupName", vmgp.GroupName)
	// poweron and customize
	if v.Verbose {
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Add VMs to VApp time %s",
			infracommon.FormatDuration(time.Since(addVMStart), 2)))
	}
	updateCallback(edgeproto.UpdateTask, "Powering on VMs")
	powerOnStart := time.Now()
	err = v.powerOnVmsAndForceCustomization(ctx, vmsToCustomize)
	if err != nil {
		return nil, err
	}

	if v.Verbose {
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("VM PowerOn time %s",
			infracommon.FormatDuration(time.Since(powerOnStart), 2)))
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
		msg := fmt.Sprintf("%s %s", "vapp power on  time ", infracommon.FormatDuration(time.Since(vappPowerOnStart), 2))
		updateCallback(edgeproto.UpdateTask, msg)
	}

	if v.Verbose {
		v.LogVappVMsStatus(ctx, vapp)
	}
	if v.Verbose {
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("%s %s", "CreateVMs  time ",
			infracommon.FormatDuration(time.Since(createStart), 2)))
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

	// First, does this guy even exist?
	// If not, ok, its deleted
	vapp, err := v.FindVApp(ctx, vappName, vcdClient)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp vapp not found return success", "vapp", vappName)
		return nil
	}

	// handle deletion of an iso orgvdcnet of the client of a shared LB
	// DetachPortFromServer has already been called, and can't delete the network
	// because it's still in use, possibly by this vapp (shared clusterInst)

	vdc, err := v.GetVdc(ctx, vcdClient)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp err getting vdc", "vapp", vappName, "err", err)
		return err
	}
	// If GetVappIsoNetwork actually fails (GetNetworkList() unlikely)
	// don't fail the delete cluster operation here.
	netName, err := v.GetVappIsoNetwork(ctx, vdc, vapp)
	// if one of these is an isolated orgvdcnetwork
	if err == nil && netName != "" {
		task, err := vapp.RemoveAllNetworks()
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp RemoveAllNetworks failed ", "err", err)
		} else {
			err = task.WaitTaskCompletion()
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp wait task for RemoveAllNetworks failed", "error", err)
			}
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp removing iosNetworks", "vapp", vappName)
		err = govcd.RemoveOrgVdcNetworkIfExists(*vdc, netName)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp RemoveOrgVdcNetworkIfExists failed ", "vapp", vappName, "netName", netName, "err", err)
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp RemoveOrgVdcNetworkIfExists success", "netName", netName)
		}
	} else if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp GetVappIsoNetwork failed ignoring ", "vapp", vappName, "netName", netName, "err", err)
	}

	status, err := vapp.GetStatus()
	if err != nil {
		return err
	}

	if status == "POWERED_ON" {
		task, err := vapp.Undeploy()
		if err != nil {
			return err
		}
		err = task.WaitTaskCompletion()
		if err != nil {
			return err
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp undeployed", "Vapp", vappName)
	}
	task, err := vapp.Delete()
	if err != nil {
		return err
	}
	err = task.WaitTaskCompletion()
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp deleted", "Vapp", vappName)
	return nil
}

func (v *VcdPlatform) FindVApp(ctx context.Context, vappName string, vcdClient *govcd.VCDClient) (*govcd.VApp, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "FindVApp", "vappName", vappName)

	vdc, err := v.GetVdc(ctx, vcdClient)
	if err != nil {
		return nil, err
	}
	vapp, err := vdc.GetVAppByName(vappName, true)
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
func (v *VcdPlatform) populateProductSection(ctx context.Context, vm *govcd.VM, vmparams *vmlayer.VMOrchestrationParams) (*types.ProductSectionList, error) {

	log.SpanLog(ctx, log.DebugLevelInfra, "populateProductSection", "vm", vm.VM.Name)
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
	_, err = vm.SetGuestCustomizationSection(guestCustomSec)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "SetGuestCustomizationSection failed", "err", err)
		return nil, err
	}
	// find the master, which can be either the first or second vm in the vapp, or none
	masterIP := ""
	if vmparams.Role == vmlayer.RoleNode { // k8s-node
		log.SpanLog(ctx, log.DebugLevelInfra, "Have k8s-node find masterIP ", "vm", vm.VM.Name)
		vapp, err := vm.GetParentVApp()

		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "Could not GetParentVapp for", "vm", vm.VM.Name, "err", err)
			return nil, err
		}
		for _, child := range vapp.VApp.Children.VM {
			log.SpanLog(ctx, log.DebugLevelInfra, "found child VM in vapp", "child", child.Name)
			if !strings.Contains(child.Name, vmlayer.ClusterTypeKubernetesMasterLabel) {
				continue
			}
			tvm, err := vapp.GetVMByName(child.Name, true)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "GetVMByName failed for", "vm", child.Name, "err", err)
				return nil, err
			}
			ips, err := v.GetIntAddrsOfVM(ctx, tvm)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "populateProductSection failed to retrieve master ip for k8s-master", "vm", child.Name, "err", err)
				return nil, err
			}
			if len(ips) != 0 {
				log.SpanLog(ctx, log.DebugLevelInfra, "populateProductSection retrieve master ip for k8s-master", "vm", child.Name, "maserIP", masterIP)
				masterIP = ips[0]
			} else {
				return nil, fmt.Errorf("No IPs on master: %s", child.Name)
			}
		}
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
		vm, err := vapp.GetVMByName(child.Name, true)
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
		log.SpanLog(ctx, log.DebugLevelInfra, "validateVMSpecSecion VM not found", "Vapp", vapp.VApp.Name, "idx", 0)
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
