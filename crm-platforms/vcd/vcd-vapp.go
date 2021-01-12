package vcd

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/vmware/go-vcloud-director/v2/govcd"
	"github.com/vmware/go-vcloud-director/v2/types/v56"
)

// Compose a new vapp from the given template, using vmgrp orch params
// Creates one or more vms.
func (v *VcdPlatform) CreateVApp(ctx context.Context, vappTmpl *govcd.VAppTemplate, vmgp *vmlayer.VMGroupOrchestrationParams, description string, updateCallback edgeproto.CacheUpdateCallback) (*govcd.VApp, error) {

	var vapp *govcd.VApp
	var err error

	numVMs := len(vmgp.VMs)

	vdc, err := v.GetVdc(ctx)
	if err != nil {
		return nil, err
	}

	storRef := types.Reference{}
	// Nil ref wins default storage policy
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateVapp", "name", vmgp.GroupName, "tmpl", vappTmpl.VAppTemplate.Name)

	vappName := vmgp.GroupName + "-vapp"
	vapp, err = v.FindVApp(ctx, vappName)
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

	// MEX_EXT_NET
	vdcNet, err := v.GetExtNetwork(ctx)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "CreateVApp failed to retrieve our external network", "name", vmgp.GroupName, "vapp", vapp, "err", err)
	}
	networks := []*types.OrgVDCNetwork{}
	networks = append(networks, vdcNet.OrgVDCNetwork)

	log.SpanLog(ctx, log.DebugLevelInfra, "CreateVApp compose vapp", "name", vappName, "vmRole", vmRole, "vmType", vmType)

	description = description + vcdProviderVersion
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
	err = vapp.BlockWhileStatus("UNRESOLVED", 120) // upto seconds

	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "wait for RESOLVED error", "VAppName", vmgp.GroupName, "error", err)
		return nil, err
	}

	// ensure we have a clean slate
	task, err = vapp.RemoveAllNetworks()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "remove networks failed", "VAppName", vmgp.GroupName, "error", err)
		return nil, err
	}
	err = task.WaitTaskCompletion()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "task completion failed", "VAppName", vmgp.GroupName, "error", err)
	}

	// Get the VApp network in place, all vapps need an external network at least
	nextCidr, err := v.AddPortsToVapp(ctx, vapp, *vmgp)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "AddPortsToVapp failed", "VAppName", vmgp.GroupName, "error", err)

	}
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateVapp nextCidr for vapp internal net", "Cidr", nextCidr, "vmRole", vmRole, "vmType", vmType)

	vmtmplName := vapp.VApp.Children.VM[0].Name
	vm, err := vapp.GetVMByName(vmtmplName, false)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "CreateVApp failed to retrieve", "VM", vmtmplName)
		return nil, err
	}
	var subnet string
	err = v.updateVM(ctx, vm, vmparams, subnet)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "update vm failed ", "VAppName", vmgp.GroupName, "err", err)
		return nil, err
	}

	if numVMs > 1 {
		log.SpanLog(ctx, log.DebugLevelInfra, "CreateVApp composed adding VMs for ", "GroupName", vmgp.GroupName)
		err = v.AddVMsToVApp(ctx, vapp, vmgp, vappTmpl, nextCidr)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "CreateVApp AddVMsToVApp failed", "error", err)
			return nil, err
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "CreateVApp composed VMs added", "GroupName", vmgp.GroupName)
	} else {
		if v.Verbose {
			log.SpanLog(ctx, log.DebugLevelInfra, "CreateVApp composed VApp no extra VMs added", "GroupName", vmgp.GroupName)
		}
	}
	if v.Verbose {
		// govcd.ShowVapp(*vapp.VApp) its... quite large
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateVApp composed Powering On", "Vapp", vappName)
	err = v.refreshVappNets(ctx, vapp)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "refreshVappNets failed", "err", err)
		return nil, err
	}
	task, err = vapp.PowerOn()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "power on  failed ", "VAppName", vapp.VApp.Name, "err", err)
		return nil, err
	}
	err = task.WaitTaskCompletion()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "wait power on  failed", "VAppName", vmgp.GroupName, "error", err)
		return nil, err
	}
	vapp.Refresh()

	if v.Verbose {
		v.LogVappVMsStatus(ctx, vapp)
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

func (v *VcdPlatform) DeleteVapp(ctx context.Context, vapp *govcd.VApp) error {

	// are we being asked to delete vm or vapp (do we ever get asked to delete a single VM?)
	vappName := vapp.VApp.Name

	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp", "name", vappName)

	// First, does this guy even exist?
	// If not, ok, its deleted
	vapp, err := v.FindVApp(ctx, vappName)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVapp vapp not found return success", "vapp", vappName)
		return nil
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

func (v *VcdPlatform) FindVApp(ctx context.Context, vappName string) (*govcd.VApp, error) {

	vdc, err := v.GetVdc(ctx)
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

func (v *VcdPlatform) populateProductSection(ctx context.Context, vm *govcd.VM, vmparams *vmlayer.VMOrchestrationParams) (*types.ProductSectionList, error) {

	command := ""
	manifest := ""
	// format vmparams.CloudConfigParams into yaml format, which we'll then base64 encode for the ovf datasource
	udata, err := vmlayer.GetVMUserData(vm.VM.Name, false, manifest, command, &vmparams.CloudConfigParams, vcdUserDataFormatter)
	if err != nil {
		return nil, err
	}
	guestCustomSec, err := vm.GetGuestCustomizationSection()
	if err != nil {
		return nil, err
	}
	if !*guestCustomSec.Enabled {
		guestCustomSec.Enabled = TakeBoolPointer(true)
		// FixMe:  'AdminPassword' should either be reset or remain unchanged when auto"}
		// vault kv get -field=value secret/accounts/baseimage/password
		_, err := vm.SetGuestCustomizationSection(guestCustomSec)
		if err != nil {
			return nil, err

		}
	}

	psl, err := vm.GetProductSectionList()
	if err != nil {
		return nil, err
	}
	if psl.ProductSection == nil {
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
	role := vmparams.Role
	props = append(props, makeProp("ROLE", string(role)))
	skipk8s := vmlayer.SkipK8sYes
	if role == vmlayer.RoleMaster || role == vmlayer.RoleNode {
		skipk8s = vmlayer.SkipK8sNo
	}
	props = append(props, makeProp("SKIPK8S", string(skipk8s)))
	psl.ProductSection.Property = props

	return psl, nil
}

func (v *VcdPlatform) refreshVappNets(ctx context.Context, vapp *govcd.VApp) error {
	vmname := vapp.VApp.Children.VM[0].Name
	vm, err := vapp.GetVMByName(vmname, true)
	if err != nil {
		return err
	}
	//InternalNetConfigSec := &types.NetworkConfigSection{}
	ncs, err := vm.GetNetworkConnectionSection()
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "refreshVapp", "Vapp", vapp.VApp.Name, "vmName", vmname)
	err = vm.UpdateNetworkConnectionSection(ncs)
	if err != nil {
		return err
	}
	return nil
}
