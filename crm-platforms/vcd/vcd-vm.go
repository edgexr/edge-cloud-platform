package vcd

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/vmware/go-vcloud-director/v2/govcd"
	"github.com/vmware/go-vcloud-director/v2/types/v56"
)

var vmsCreateLock sync.Mutex

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

// We expect Objs.PrimaryNet supports DHCP, eventually
//
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
	tmplName := v.GetTemplateName()
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

	// TODO: we need a more granular lock
	vmsCreateLock.Lock()
	defer vmsCreateLock.Unlock()

	vcdClient, err := v.GetVcdClientFromContext(ctx)
	if err != nil {
		return err
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
		log.SpanLog(ctx, log.DebugLevelInfra, "CreateVMs failed to find resulting ", "VM", vmName, "in VApp", vappName)
		return err
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

// For each vm spec defined in vmgp, add a new VM to vapp with those applicable attributes.  Returns a map of VMs added
func (v *VcdPlatform) AddVMsToVApp(ctx context.Context, vapp *govcd.VApp, vmgp *vmlayer.VMGroupOrchestrationParams, tmpl *govcd.VAppTemplate, nextCidr string) (map[string]*govcd.VM, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp", "GroupName", vmgp.GroupName)

	vmsAdded := make(map[string]*govcd.VM)
	if nextCidr == "" {
		log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp next cidr nil", "GroupName", vmgp.GroupName)
		return nil, fmt.Errorf("IP range exhaused")
	}
	var err error
	numVMs := len(vmgp.VMs)
	if numVMs < 2 {
		return nil, fmt.Errorf("invalid VMGroupOrchParams for call")
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp numVMs ", "count", numVMs, "GroupName", vmgp.GroupName, "Internal IP", nextCidr)

	lbvm := &govcd.VM{}
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
			log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp add", "vmName", vmName, "vmRole", vmRole, "vmType", vmType)
			task, err := vapp.AddNewVM(vmparams.Name, *tmpl, ncs, true)
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
		// Consider nextwork assignement XXX revist for pf and cloudlet (no internal nets)
		if vmparams.Role == vmlayer.RoleAgent {
			lbvm = vm
			vmIp = baseAddr
		} else {
			vmIp, err = IncrIP(ctx, baseAddr, 100+(n-1))
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "IncrIP failed", "baseAddr", baseAddr, "delta", 100+(n-1), "err", err)
				return nil, err
			}
			ncs.PrimaryNetworkConnectionIndex = 0
		}
		// some unique key within the vapp
		key := fmt.Sprintf("%s-vm-%d", vapp.VApp.Name, n)
		vm.VM.OperationKey = key

		ncs, err = vm.GetNetworkConnectionSection()
		if err != nil {
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

			ncs.NetworkConnection = append(ncs.NetworkConnection,
				&types.NetworkConnection{
					Network:                 internalNetName,
					NetworkConnectionIndex:  netConIdx,
					IPAddress:               vmIp,
					IsConnected:             true,
					IPAddressAllocationMode: types.IPAllocationModeManual,
				})

			err = vm.UpdateNetworkConnectionSection(ncs)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp add internal net failed", "VM", lbvm.VM.Name, "error", err)
				return nil, err
			}
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

		vmsAdded[vm.VM.Name] = vm
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp complete")
	return vmsAdded, nil
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
	psl, err := v.populateProductSection(ctx, vm, &vmparams)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "updateVM populateProdcutSection failed", "vm", vm.VM.Name, "err", err)
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

// PI UpdateVMs
// Add/remove VM from our VApp (group)
//
func (v *VcdPlatform) UpdateVMs(ctx context.Context, vmgp *vmlayer.VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMs TBI", "OrchParams", vmgp)
	// convert each vmOrchParams into a *types.VmSpecSection and call updateVM for each vm
	return nil
}

func (v *VcdPlatform) SyncVMs(ctx context.Context, vmgp *vmlayer.VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SyncVMs TBI", "OrchParams", vmgp)
	return nil
}

func (v *VcdPlatform) DeleteVM(ctx context.Context, vm *govcd.VM) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVM", "vmName", vm.VM.Name)

	if vm == nil {
		return fmt.Errorf("nil vm encountered")
	}
	vapp, err := vm.GetParentVApp()
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVM", "vmName", vm.VM.Name, "from vapp", vapp.VApp.Name)

	status, err := vm.GetStatus()
	if err != nil {
		return err
	}
	if status == "POWERED_ON" {
		task, err := vm.PowerOff()
		if err != nil {
			return err
		}
		err = task.WaitTaskCompletion()
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "DeletedVM wait power off failed", "vmName", vm.VM.Name, "err", err)
			return err
		}
	}

	err = vapp.RemoveVM(*vm)
	if err != nil {
		return err
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "VM Deleted", "vmName", vm.VM.Name)
	return nil

}

// Delete All VMs in the resolution of vmGroupName
func (v *VcdPlatform) DeleteVMs(ctx context.Context, vmGroupName string) error {

	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVMs", "vmGroupName", vmGroupName)

	vcdClient, err := v.GetVcdClientFromContext(ctx)
	if err != nil {
		return err
	}
	vappName := vmGroupName + "-vapp"
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVMs check", "vappName", vappName)
	vapp, err := v.FindVApp(ctx, vappName, vcdClient)

	if err == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVMs deleting", "VApp", vappName)
		err := v.DeleteVapp(ctx, vapp, vcdClient)
		return err
	}

	vm, err := v.FindVM(ctx, vmGroupName, vappName, vcdClient)
	if err == nil {
		return v.DeleteVM(ctx, vm)
	}
	return fmt.Errorf("Not Found")
}

func (v *VcdPlatform) GetVMStats(ctx context.Context, key *edgeproto.AppInstKey) (*vmlayer.VMMetrics, error) {

	vm := &govcd.VM{}
	metrics := vmlayer.VMMetrics{}
	var err error

	vcdClient, err := v.GetVcdClientFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("GetVcdClientFromContext failed %v", err)
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

	vcdClient, err := v.GetVcdClientFromContext(ctx)
	if err != nil {
		return fmt.Errorf("GetVcdClientFromContext failed %v", err)
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
		if connection.Network != v.GetExtNetworkName() {
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
	// TODO: the intention is to use Iptables firewall for VCD. However, as this
	// is not implemented yet, we will set this to false for now so that the forwarding
	// rules can be added. As part of the implementation of iptables for vCD, the forwarding
	// rules will be done in that code and this can be set back to true
	vmProperties.IptablesBasedFirewall = false
}

// Should always be a vapp/cluster/group name
func (v *VcdPlatform) GetServerGroupResources(ctx context.Context, name string) (*edgeproto.InfraResources, error) {
	resources := &edgeproto.InfraResources{}

	vcdClient, err := v.GetVcdClientFromContext(ctx)
	if err != nil {
		return nil, err
	}
	// xxx need ContainerInfo as well
	vdc, err := v.GetVdc(ctx, vcdClient)
	if err != nil {
		return nil, err
	}
	extNetName := v.GetExtNetworkName()

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

		//extAddr, err := v.GetExtAddrOfVM(ctx, vm, v.GetExtNetworkName())
		// Find addr of vm for the given network
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

	vmType := string(vmlayer.GetVmTypeForRole(string(vmparams.Role)))
	// why no async for vms?
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
	err = task.WaitTaskCompletion()
	if err != nil {
		return err
	}

	return nil
}

// powerOnVmsAndForceCustomization calls PowerOnAndForceCustomization on each VM provided.  Unfortunately
// this needs to be done one at a time or it tends to fail
func (v *VcdPlatform) powerOnVmsAndForceCustomization(ctx context.Context, vms map[string]*govcd.VM) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "powerOnVmsAndForceCustomization")
	for vmName, vm := range vms {
		log.SpanLog(ctx, log.DebugLevelInfra, "Powering on VM", "vmName", vmName)
		err := vm.PowerOnAndForceCustomization()
		if err != nil {
			return fmt.Errorf("Error powering on VM: %s - %v", vmName, vm)
		}
	}
	return nil
}
