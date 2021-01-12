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
func (v *VcdPlatform) FindVM(ctx context.Context, serverName, vappName string) (*govcd.VM, error) {

	vdc, err := v.GetVdc(ctx)
	if err != nil {
		return nil, err
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
func (v *VcdPlatform) FindVMByName(ctx context.Context, serverName string) (*govcd.VM, error) {

	vdc, err := v.GetVdc(ctx)
	if err != nil {
		return nil, err
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

func (v *VcdPlatform) RetrieveTemplate(ctx context.Context) (*govcd.VAppTemplate, error) {

	// Prefer an envVar, fall back to property
	tmplName := v.GetTemplateName()
	if tmplName == "" {
		tmplName = v.GetVDCTemplateName()
		if tmplName == "" {
			return nil, fmt.Errorf("VDCTEMPLATE not set")
		}
	}
	tmpl, err := v.FindTemplate(ctx, tmplName)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Template not found locally", "template", tmplName, "err", err)
		return nil, err
	}
	// The way we look for templates this should never trigger, but just in case
	if tmpl.VAppTemplate.Children == nil {
		if v.Verbose {
			log.SpanLog(ctx, log.DebugLevelInfra, "Invalid", "template", tmpl)
		}
		return nil, fmt.Errorf("Invalid Template %s", tmpl.VAppTemplate.Name)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "RetrieveTemplate using", "Template", tmplName)
	return tmpl, nil
}

func (v *VcdPlatform) CreateVMs(ctx context.Context, vmgp *vmlayer.VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateVMs", "grpName", vmgp.GroupName)

	vmsCreateLock.Lock()
	defer vmsCreateLock.Unlock()

	vdc, err := v.GetVdc(ctx)
	if err != nil {
		return err
	}

	tmpl, err := v.RetrieveTemplate(ctx)
	if err != nil {
		return err
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "Creating Vapp for", "GroupName", vmgp.GroupName, "using template", tmpl.VAppTemplate.Name)
	vappName := vmgp.GroupName + "-vapp"
	vmName := vmgp.VMs[0].Name
	description := "vapp for " + vmgp.GroupName

	_, err = v.CreateVApp(ctx, tmpl, vmgp, description, updateCallback)
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

// For each vm spec defined in vmgp, add a new VM to vapp with those applicable attributes.
func (v *VcdPlatform) AddVMsToVApp(ctx context.Context, vapp *govcd.VApp, vmgp *vmlayer.VMGroupOrchestrationParams, tmpl *govcd.VAppTemplate, nextCidr string) error {
	if nextCidr == "" {
		panic("next cider null for AddVMsToVApp")
	}

	var err error
	numVMs := len(vmgp.VMs)
	if numVMs < 2 {
		return fmt.Errorf("invalid VMGroupOrchParams for call")
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
				return err
			}
			err = task.WaitTaskCompletion()
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "wait add vm failed", "err", err)
				return err
			}
			// Make sure it's there
			vm, err = vapp.GetVMByName(vmparams.Name, true)
			if err != nil {
				// internal error
				return err
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
				return err
			}
			ncs.PrimaryNetworkConnectionIndex = 0
		}
		// some unique key within the vapp
		key := fmt.Sprintf("%s-vm-%d", vapp.VApp.Name, n)
		vm.VM.OperationKey = key

		// add portName to metadata xxx
		err = v.AddMetadataToVM(ctx, vm, vmparams, vmType, vapp.VApp.Name)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp add ext net failed", "VM", lbvm.VM.Name, "error", err)
			return err
		}

		ncs, err = vm.GetNetworkConnectionSection()
		if err != nil {
			return err
		}

		// we just want to set the ip address and connection index for an internal network
		// of the parent vapp.
		// We know the name of the internal subnet if one is needed
		// by our ports
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
				return err
			}
		}

		var subnet string
		err = v.updateVM(ctx, vm, vmparams, subnet)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "update vm failed ", "VAppName", vmgp.GroupName, "err", err)
			return err
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp complete")
	return nil
}

// useless remove
func (v *VcdPlatform) guestCustomization(ctx context.Context, vm govcd.VM, vmparams vmlayer.VMOrchestrationParams, subnet string) error {
	//script := "#!/bin/bash  &#13; ip route del default via 10.101.1.1  &#13;"

	log.SpanLog(ctx, log.DebugLevelInfra, "guestCustomization ", "VM", vm.VM.Name, "HostName", vmparams.HostName)
	vm.VM.GuestCustomizationSection.ComputerName = vmparams.HostName
	vm.VM.GuestCustomizationSection.Enabled = TakeBoolPointer(true)
	return nil
}

// set vm params and call vm.UpdateVmSpecSection
func (v *VcdPlatform) updateVM(ctx context.Context, vm *govcd.VM, vmparams vmlayer.VMOrchestrationParams, subnet string) error {

	flavorName := vmparams.FlavorName
	flavor, err := v.GetFlavor(ctx, flavorName)
	vmSpecSec := vm.VM.VmSpecSection
	vmSpecSec.NumCpus = TakeIntPointer(int(flavor.Vcpus))
	vmSpecSec.MemoryResourceMb.Configured = int64(flavor.Ram)

	//hostName := vmparams.HostName

	desc := fmt.Sprintf("Update flavor: %s", flavorName)
	_, err = vm.UpdateVmSpecSection(vmSpecSec, desc)
	if err != nil {
		return err
	}

	// meta data for Role etc
	psl, err := v.populateProductSection(ctx, vm, &vmparams)
	if err != nil {
		return fmt.Errorf("updateVM-E-error from populateProductSection: %s", err.Error())
	}

	_, err = vm.SetProductSectionList(psl)
	if err != nil {
		return fmt.Errorf("updateVM-E-error Setting product section %s", err.Error())
	}
	_, err = vm.SetProductSectionList(psl)
	if err != nil {
		return err
	}

	err = v.guestCustomization(ctx, *vm, vmparams, subnet)
	if err != nil {
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
	// resolve vmGroupName, to a single vm or a clusterName

	// if vmGroupName is the Vapp, we're removing the entire cloudlet
	vappName := vmGroupName + "-vapp"
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVMs check", "vappName", vappName)
	vapp, err := v.FindVApp(ctx, vappName)

	if err == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVMs deleting", "VApp", vappName)
		err := v.DeleteVapp(ctx, vapp)
		return err
	}

	vm, err := v.FindVM(ctx, vmGroupName, vappName)
	if err == nil {
		return v.DeleteVM(ctx, vm)
	}
	return fmt.Errorf("Not Found")
}

func (v *VcdPlatform) GetVMStats(ctx context.Context, key *edgeproto.AppInstKey) (*vmlayer.VMMetrics, error) {

	vm := &govcd.VM{}
	metrics := vmlayer.VMMetrics{}
	var err error

	vmName := cloudcommon.GetAppFQN(&key.AppKey)
	if vmName == "" {
		return nil, fmt.Errorf("GetAppFQN failed to return vmName for AppInst %s\n", key.AppKey.Name)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "GetVMStats for", "vm", vmName)

	vm, err = v.FindVMByName(ctx, vmName)
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
	vm := &govcd.VM{}
	var err error
	vm, err = v.FindVMByName(ctx, serverName)
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
	vmProperties.IptablesBasedFirewall = true
}

// Should always be a vapp/cluster/group name
func (v *VcdPlatform) GetServerGroupResources(ctx context.Context, name string) (*edgeproto.InfraResources, error) {
	resources := &edgeproto.InfraResources{}
	// xxx need ContainerInfo as well
	vdc, err := v.GetVdc(ctx)
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

// Store attrs of vm for crmrestarts
func (v *VcdPlatform) AddMetadataToVM(ctx context.Context, vm *govcd.VM, vmparams vmlayer.VMOrchestrationParams, vmType, parentCluster string) error {

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

	task, err = vm.AddMetadata("ParentCluster", parentCluster)
	if err != nil {
		return err
	}
	err = task.WaitTaskCompletion()
	if err != nil {
		return err
	}

	return nil
}
