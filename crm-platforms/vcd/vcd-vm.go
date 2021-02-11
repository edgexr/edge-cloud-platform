package vcd

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
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
func (v *VcdPlatform) FindVMByName(ctx context.Context, serverName string, vcdClient *govcd.VCDClient) (*govcd.VM, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "FindVMByName", "serverName", serverName)

	vdc, err := v.GetVdc(ctx, vcdClient)
	if err != nil {
		return nil, fmt.Errorf("GetVdc Failed - %v", err)
	}
	vm := &govcd.VM{}

	vappRefList := vdc.GetVappList()
	for _, vappRef := range vappRefList {

		vapp, err := vdc.GetVAppByHref(vappRef.HREF)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetVappByHref failed", "vapp.HREF", vappRef.HREF, "err", err)
			continue
		}
		vm, err = vapp.GetVMByName(serverName, true)
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

func (v *VcdPlatform) RetrieveTemplate(ctx context.Context, vcdClient *govcd.VCDClient) (*govcd.VAppTemplate, error) {

	// Prefer an envVar, fall back to property
	tmplName := v.GetTemplateNameFromProps()
	if tmplName == "" {
		tmplName = v.GetVDCTemplateName()
		if tmplName == "" {
			return nil, fmt.Errorf("VDCTEMPLATE not set")
		}
	}
	tmpl, err := v.FindTemplate(ctx, tmplName, vcdClient)
	if err != nil {
		// Not found as a vdc.Resource, try direct from our catalog
		log.SpanLog(ctx, log.DebugLevelInfra, "Template not vdc.Resource, Try fetch from catalog", "template", tmplName)
		cat, err := v.GetCatalog(ctx, v.GetCatalogName(), vcdClient)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed retrieving catalog", "cat", v.GetCatalogName())
			return nil, fmt.Errorf("Template invalid")
		}

		emptyItem := govcd.CatalogItem{}
		catItem, err := cat.FindCatalogItem(tmplName)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "find catalog item failed", "err", err)
			return nil, fmt.Errorf("Template invalid")
		}
		if catItem == emptyItem { // empty!
			log.SpanLog(ctx, log.DebugLevelInfra, "find catalog item retured empty item")
			return nil, fmt.Errorf("Template invalid")
		} else {
			tmpl, err := catItem.GetVAppTemplate()
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "catItem.GetVAppTemplate failed", "err", err)
				return nil, fmt.Errorf("Template invalid")
			}

			if tmpl.VAppTemplate.Children == nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "template has no children")
				return nil, fmt.Errorf("Template invalid")
			} else {
				// while this works for 10.1, it still does not for 10.0 so make this an error for now
				//numChildren := len(tmpl.VAppTemplate.Children.VM)
				//log.SpanLog(ctx, log.DebugLevelInfra, "template looks good from cat", "numChildren", numChildren)
				//return &tmpl, nil
				log.SpanLog(ctx, log.DebugLevelInfra, "template has children but marking invalid for 10.0")
				// Remedy to persure, fill in VM's vmSpecSection for expected resources that seem missing.
				return nil, fmt.Errorf("Template invalid")
			}
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
	tmpl, err := v.RetrieveTemplate(ctx, vcdClient)
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

// For each vm spec defined in vmgp, add a new VM to vapp with those applicable attributes.  Returns a map of VMs which
// should be powered on and customized
func (v *VcdPlatform) AddVMsToVApp(ctx context.Context, vapp *govcd.VApp, vmgp *vmlayer.VMGroupOrchestrationParams, baseImgTmpl *govcd.VAppTemplate, nextCidr string, vdc *govcd.Vdc, vcdClient *govcd.VCDClient, updateCallback edgeproto.CacheUpdateCallback) (VMMap, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp", "GroupName", vmgp.GroupName)

	vmsToCustomize := make(VMMap)
	var err error
	numVMs := len(vmgp.VMs)

	log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp numVMs ", "count", numVMs, "GroupName", vmgp.GroupName, "Internal IP", nextCidr, "baseImgTmpl", baseImgTmpl.VAppTemplate.Name)

	vmIp := ""
	var a []string
	baseAddr := ""
	if nextCidr != "" {
		a = strings.Split(nextCidr, "/")
		baseAddr = string(a[0])
	}
	netConIdx := 0
	for n, vmparams := range vmgp.VMs {
		vmName := vmparams.Name
		vmRole := vmparams.Role
		vmType := string(vmlayer.GetVmTypeForRole(string(vmparams.Role)))
		vm := &govcd.VM{}
		ncs := &types.NetworkConnectionSection{}
		// check to see if this vm is already present
		vm, err = vapp.GetVMByName(vmName, true)
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
			// Make sure it's there
			vm, err = vapp.GetVMByName(vmparams.Name, true)
			if err != nil {
				// internal error
				return nil, err
			}
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp exists", "vmName", vmName, "vmRole", vmRole, "vmType", vmType)
		}
		if nextCidr != "" {
			// Consider internal nextwork assignements,
			sharedRootLB := v.haveSharedRootLB(ctx, *vmgp)

			if vmparams.Role == vmlayer.RoleAgent {
				// dedicated lb
				vmIp = baseAddr
				log.SpanLog(ctx, log.DebugLevelInfra, "Dedicated RootLB", "vm", vm.VM.Name, "gateway", baseAddr)
			} else {
				if sharedRootLB {
					log.SpanLog(ctx, log.DebugLevelInfra, "SharedLB", "vm", vm.VM.Name, "gateway", baseAddr)
					vmIp, err = IncrIP(ctx, baseAddr, 101+(n-1))
					if err != nil {
						log.SpanLog(ctx, log.DebugLevelInfra, "IncrIP failed", "baseAddr", baseAddr, "delta", 100+(n-1), "err", err)
						return nil, err
					}

					ncs.PrimaryNetworkConnectionIndex = 0
				} else {
					log.SpanLog(ctx, log.DebugLevelInfra, "Dedicated", "vm", vm.VM.Name, "gateway", baseAddr)
					// a single node docker cluster will need .101 here for e
					vmIp, err = IncrIP(ctx, baseAddr, 100+(n-1))
					if err != nil {
						log.SpanLog(ctx, log.DebugLevelInfra, "IncrIP failed", "baseAddr", baseAddr, "delta", 100+(n-1), "err", err)
						return nil, err
					}
				}
			}
			// some unique key within the vapp
			key := fmt.Sprintf("%s-vm-%d", vapp.VApp.Name, n)
			vm.VM.OperationKey = key

			ncs, err = vm.GetNetworkConnectionSection()
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "GetNetworkConnectionSection failed", "err", err)
				return nil, err
			}

			internalNetName := ""
			ports := vmgp.Ports
			for _, port := range ports {
				if port.NetworkType == vmlayer.NetTypeInternal {
					internalNetName = port.SubnetId
					break
				}
			}
			if internalNetName != "" {
				log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp add connection", "net", internalNetName, "ip", vmIp, "VM", vmName)
				networkAdapterType := "VMXNET3"
				if vmparams.Role == vmlayer.RoleVMApplication {
					// VM apps may not have VMTools installed so use the generic E1000 adapter
					networkAdapterType = "E1000"
				}
				ncs.NetworkConnection = append(ncs.NetworkConnection,
					&types.NetworkConnection{
						Network:                 internalNetName,
						NetworkConnectionIndex:  netConIdx,
						IPAddress:               vmIp,
						IsConnected:             true,
						IPAddressAllocationMode: types.IPAllocationModeManual,
						NetworkAdapterType:      networkAdapterType,
					})
				log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp adding connection", "net", internalNetName, "ip", vmIp, "VM", vmName, "networkAdapterType", networkAdapterType)
				err = vm.UpdateNetworkConnectionSection(ncs)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp add internal net failed", "VM", vm.VM.Name, "netName", internalNetName, "error", err)
					return nil, err
				}
			}
		}
		// finish vmUpdates
		err = v.guestCustomization(ctx, *vm, vmparams)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "updateVM GuestCustomization   failed", "vm", vm.VM.Name, "err", err)
			return nil, fmt.Errorf("updateVM-E-error from guestCustomize: %s", err.Error())
		}

		err = v.updateVM(ctx, vm, vmparams)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "update vm failed ", "VAppName", vmgp.GroupName, "err", err)
			return nil, err
		}

		if vmparams.Role != vmlayer.RoleVMApplication {
			// VMApps do not get customized as they are unlikely to have VMTools.  If we want to support adding customization parms
			// to VCD VMs then it would require additional metadata about the VMApp, or maybe the download of a custom OVF rather than
			// generation of the OVF
			vmsToCustomize[vm.VM.Name] = vm
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp complete")
	return vmsToCustomize, nil
}

func (v *VcdPlatform) AddVMsToExistingVApp(ctx context.Context, vapp *govcd.VApp, vmgp *vmlayer.VMGroupOrchestrationParams, vcdClient *govcd.VCDClient) (VMMap, error) {
	vmMap := make(VMMap)
	numExistingVMs := len(vapp.VApp.Children.VM)

	tmpl, err := v.RetrieveTemplate(ctx, vcdClient)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToExistingVapp error retrieving vdc template", "err", err)
		return vmMap, err
	}
	ports := vmgp.Ports
	numVMs := len(vmgp.VMs)
	netName := ports[0].SubnetId
	log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToExistingVapp", "network", netName, "vms", numVMs, "to existing vms", numExistingVMs)

	// xxx keep an eye on this. Saw one instance of vapp losing all networks, but it's first born child remained sane. xxx
	baseAddr, err := v.GetAddrOfVapp(ctx, vapp, netName)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToExistingVApp GetAddrOfVapp", "vapp", vapp.VApp.Name, "netName", netName, "err", err)
	}
	cName := vapp.VApp.Children.VM[0].Name
	cvm, err := vapp.GetVMByName(cName, true)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToExistingVApp get vapp.vm[0] failed", "vapp", vapp.VApp.Name, "vmname", cName, "err", err)
		return vmMap, err
	}
	if baseAddr == "" {
		log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToExistingVApp WARN GetAddrOfVapp failed switching to vm", "vapp", vapp.VApp.Name, "vm", cName)
	}
	vmBaseAddr, err := v.GetAddrOfVM(ctx, cvm, netName)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToExistingVApp GetAddrOfVM", "vmname", cName, "netName", netName, "err", err)
	}
	if baseAddr == "" {
		log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToExistingVApp vapp baseAddr empty using", "vmBaseAddr", vmBaseAddr)
		baseAddr = vmBaseAddr
	}

	netConIdx := 0
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

		lastOctet, err := Octet(ctx, baseAddr, 3)

		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToExistingVApp Octet fail", "err", err)
			return nil, err
		}
		if v.Verbose {
			log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToExistingVApp last octet of baseAddr", "baseAddr", baseAddr, "last octet", lastOctet)
		}
		offset := 0
		if lastOctet == 1 {
			offset = 100
		}

		if v.Verbose {
			log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToExistingVApp", "vapp", vapp.VApp.Name, "network", netName, "baseAddr", baseAddr, "existingsVMs", numExistingVMs, "n", n)
		}

		// Here we need to add numWorkerNodes to base
		vmIp, err := IncrIP(ctx, baseAddr, (numExistingVMs+offset+n)-1)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "IncrIP failed", "baseAddr", baseAddr, "delta", numExistingVMs+offset+n, "err", err)
			return vmMap, err
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "AddVmsToExstingVAppp", "vm", vmName, "IP", vmIp)
		ncs.PrimaryNetworkConnectionIndex = 0
		// some unique key within the vapp
		key := fmt.Sprintf("%s-vm-%d", vapp.VApp.Name, n+numExistingVMs)
		vm.VM.OperationKey = key

		ncs, err = vm.GetNetworkConnectionSection()
		if err != nil {
			return nil, err
		}

		log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp add connection", "net", netName, "ip", vmIp, "VM", vmName)

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

		err = v.guestCustomization(ctx, *vm, vmparams)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "updateVM GuestCustomization   failed", "vm", vm.VM.Name, "err", err)
			return nil, fmt.Errorf("updateVM-E-error from guestCustomize: %s", err.Error())
		}
		err = v.updateVM(ctx, vm, vmparams)
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
func (v *VcdPlatform) guestCustomization(ctx context.Context, vm govcd.VM, vmparams vmlayer.VMOrchestrationParams) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "guestCustomization ", "VM", vm.VM.Name, "HostName", vmparams.HostName)
	vm.VM.GuestCustomizationSection.ComputerName = vmparams.HostName
	vm.VM.GuestCustomizationSection.Enabled = TakeBoolPointer(true)
	return nil
}

// set vm params and call vm.UpdateVmSpecSection
func (v *VcdPlatform) updateVM(ctx context.Context, vm *govcd.VM, vmparams vmlayer.VMOrchestrationParams) error {

	log.SpanLog(ctx, log.DebugLevelInfra, "updateVM", "vm", vm.VM.Name)

	flavorName := vmparams.FlavorName
	flavor, err := v.GetFlavor(ctx, flavorName)
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

	log.SpanLog(ctx, log.DebugLevelInfra, "updateVM done", "vm", vm.VM.Name, "flavor", flavor)

	err = v.AddMetadataToVM(ctx, vm, vmparams)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "updateVM AddMetadataToVm  failed", "vm", vm.VM.Name, "err", err)
		return nil
	}
	if vmparams.Role == vmlayer.RoleVMApplication {
		log.SpanLog(ctx, log.DebugLevelInfra, "Skipping populateProductSection for VMApp", "vm", vm.VM.Name)
		return nil
	}
	psl, err := v.populateProductSection(ctx, vm, &vmparams)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "updateVM populateProductSection failed", "vm", vm.VM.Name, "err", err)
		return fmt.Errorf("updateVM-E-error from populateProductSection: %s", err.Error())
	}

	_, err = vm.SetProductSectionList(psl)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "updateVM vm.SetProductSectionList  failed", "vm", vm.VM.Name, "err", err)
		return fmt.Errorf("Error Setting product section %s", err.Error())
	}

	err = v.guestCustomization(ctx, *vm, vmparams)
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

	vapp, err := v.FindVApp(ctx, vappName, vcdClient)
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
			msg := fmt.Sprintf("Added %d VMs to vApp time %s", len(newVms), infracommon.FormatDuration(time.Since(updateTime), 2))
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
			msg := fmt.Sprintf("Removed  %d  VMs time %s", rmcnt, infracommon.FormatDuration(time.Since(updateTime), 2))
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
		return fmt.Errorf("nil vm encountered")
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
	vappName := vmGroupName + "-vapp"
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVMs check", "vappName", vappName)
	vapp, err := v.FindVApp(ctx, vappName, vcdClient)
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

func (v *VcdPlatform) GetVMStats(ctx context.Context, key *edgeproto.AppInstKey) (*vmlayer.VMMetrics, error) {

	vm := &govcd.VM{}
	metrics := vmlayer.VMMetrics{}
	var err error

	vcdClient := v.GetVcdClientFromContext(ctx)
	if vcdClient == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, NoVCDClientInContext)
		return nil, fmt.Errorf(NoVCDClientInContext, err)
	}

	vmName := cloudcommon.GetAppFQN(&key.AppKey)
	if vmName == "" {
		return nil, fmt.Errorf("GetAppFQN failed to return vmName for AppInst %s\n", key.AppKey.Name)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "GetVMStats for", "vm", vmName)

	vm, err = v.FindVMByName(ctx, vmName, vcdClient)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetVMStats vm not found", "vnname", vmName)
		return nil, err
	}
	status, err := vm.GetStatus()
	if err == nil && status == "POWERED_ON" {
		// Check vdc_vm_test.go for the metric links
		// They don't seem to work with nsx-t boxes
		//
		/*  get these for the VM running AppInst TBI
		type VMMetrics struct {
			// Cpu is a percentage
			Cpu   float64
			CpuTS *types.Timestamp
			// Mem is bytes used
			Mem   uint64
			MemTS *types.Timestamp
			// Disk is bytes used
			Disk   uint64
			DiskTS *types.Timestamp
			// NetSent is bytes/second average
			NetSent   uint64
			NetSentTS *types.Timestamp
			// NetRecv is bytes/second average
			NetRecv   uint64
			NetRecvTS *types.Timestamp
		}
		*/
	} else {
		return nil, fmt.Errorf("No stats available for %s", vm.VM.Name)
	}
	return &metrics, nil
}

// always sync.
func (v *VcdPlatform) SetPowerState(ctx context.Context, serverName, serverAction string) error {

	vcdClient := v.GetVcdClientFromContext(ctx)
	if vcdClient == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, NoVCDClientInContext)
		return fmt.Errorf(NoVCDClientInContext)
	}
	vm, err := v.FindVMByName(ctx, serverName, vcdClient)
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

func (v *VcdPlatform) GetVMAddresses(ctx context.Context, vm *govcd.VM) ([]vmlayer.ServerIP, error) {

	log.SpanLog(ctx, log.DebugLevelInfra, "GetVMAddresses", "vmname", vm.VM.Name)
	var serverIPs []vmlayer.ServerIP
	if vm == nil {
		return serverIPs, fmt.Errorf("Nil vm received")
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
			servIP.PortName = vmName + "-" + connection.Network + "-port"
			// servIP.PortName = connection.Network
			log.SpanLog(ctx, log.DebugLevelInfra, "GetVMAddresses", "servIP.PortName", servIP.PortName)
		}
		serverIPs = append(serverIPs, servIP)
	}

	return serverIPs, nil
}

func (v *VcdPlatform) SetVMProperties(vmProperties *vmlayer.VMProperties) {
	v.vmProperties = vmProperties
	vmProperties.IptablesBasedFirewall = true
	vmProperties.RunLbDhcpServerForVmApps = true
}

// Should always be a vapp/cluster/group name
func (v *VcdPlatform) GetServerGroupResources(ctx context.Context, name string) (*edgeproto.InfraResources, error) {
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
	extNetName := v.vmProperties.GetCloudletExternalNetwork()

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
		vm, err := vapp.GetVMByName(cvm.Name, true)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "Warn GetVMByName: vm not found in vapp ", "vapp", name, "vm", cvm.Name)
			continue
		}
		metadata, err := vm.GetMetadata()
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetServerGroupResouce metadata not found for  vapp ", "vapp", name, "vm", cvm.Name, "err", err)
			return nil, err
		}
		flavor := ""
		role := ""

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
		ipAddr := edgeproto.IpAddr{}

		// Find addr of vm for the given network

		// get from meta data now xxx
		extAddr, err := v.GetAddrOfVM(ctx, vm, extNetName)
		// It fine if some vm doesn't have an external net connection
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetAddrOfVM No addr", "vm", vm.VM.Name, "network", extNetName, "error", err)
		}

		intAddrs, err := v.GetIntAddrsOfVM(ctx, vm)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetIntAddrOfVM failed", "error", err)
			return nil, err
		}
		// intAddrs could be 0, 1 or many depending on the node type
		// checkipAddrs ability to return > 1 internal address
		if len(intAddrs) > 0 {
			ipAddr.InternalIp = intAddrs[0]
		}
		ipAddr.ExternalIp = extAddr

		vminfo.Ipaddresses = append(vminfo.Ipaddresses, ipAddr)
		resources.Vms = append(resources.Vms, vminfo)
	}
	return resources, nil
}

// Store attrs of vm for crmrestarts and resource fetching
func (v *VcdPlatform) AddMetadataToVM(ctx context.Context, vm *govcd.VM, vmparams vmlayer.VMOrchestrationParams) error {

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

	apiEndpoint, _ := url.ParseRequestURI(vapp.VApp.HREF)
	apiEndpoint.Path += "/action/recomposeVApp"

	// Return the task
	return vcdClient.Client.ExecuteTaskRequestWithApiVersion(apiEndpoint.String(), http.MethodPost,
		types.MimeRecomposeVappParams, "error instantiating a new VM: %s", vAppComposition,
		vcdClient.Client.GetSpecificApiVersionOnCondition(">= 33.0", "33.0"))

}
