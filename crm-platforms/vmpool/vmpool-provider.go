package vmpool

import (
	"context"
	"fmt"

	"github.com/mobiledgex/edge-cloud-infra/chefmgmt"
	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

const (
	ActionNone     string = "none"
	ActionAllocate string = "allocate"
	ActionRelease  string = "release"
)

func (o *VMPoolPlatform) GetServerDetail(ctx context.Context, serverName string) (*vmlayer.ServerDetail, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetServerDetail", "serverName", serverName)
	if o.caches == nil || o.caches.VMPool == nil {
		return nil, fmt.Errorf("missing vmpool")
	}

	sd := vmlayer.ServerDetail{}

	o.caches.VMPoolMux.Lock()
	defer o.caches.VMPoolMux.Unlock()

	for _, vm := range o.caches.VMPool.Vms {
		if vm.InternalName != serverName {
			continue
		}
		sd.Name = vm.InternalName
		sd.Status = vmlayer.ServerActive
		// Add two addresses with network name:
		// 1. External network
		// 2. Internal network
		// As there won't be more than one internal network interface
		// per VM
		sip := vmlayer.ServerIP{}
		if vm.NetInfo.ExternalIp != "" {
			sip.Network = o.VMProperties.GetCloudletExternalNetwork()
			sip.ExternalAddr = vm.NetInfo.ExternalIp
			sip.InternalAddr = vm.NetInfo.ExternalIp
			sd.Addresses = append(sd.Addresses, sip)
		}
		if vm.NetInfo.InternalIp != "" {
			sip.Network = o.VMProperties.GetCloudletMexNetwork()
			sip.ExternalAddr = vm.NetInfo.InternalIp
			sip.InternalAddr = vm.NetInfo.InternalIp
			sd.Addresses = append(sd.Addresses, sip)
		}
		return &sd, nil
	}
	return &sd, fmt.Errorf("%s: %s", vmlayer.ServerDoesNotExistError, serverName)
}

// Assumes VM pool lock is held
func (o *VMPoolPlatform) UpdateVMPoolInfo(ctx context.Context) {
	if o.caches == nil || o.caches.VMPool == nil {
		return
	}

	info := edgeproto.VMPoolInfo{}
	info.Key = o.caches.VMPool.Key
	info.Vms = o.caches.VMPool.Vms
	o.caches.VMPoolInfoCache.Update(ctx, &info, 0)
}

func (o *VMPoolPlatform) SaveVMStateInVMPool(ctx context.Context, vms map[string]edgeproto.VM, state edgeproto.VMState) {
	if o.caches == nil || o.caches.VMPool == nil {
		return
	}

	o.caches.VMPoolMux.Lock()
	defer o.caches.VMPoolMux.Unlock()

	for ii, vm := range o.caches.VMPool.Vms {
		if _, ok := vms[vm.Name]; ok {
			o.caches.VMPool.Vms[ii].State = state
			if state == edgeproto.VMState_VM_FREE {
				o.caches.VMPool.Vms[ii].GroupName = ""
				o.caches.VMPool.Vms[ii].InternalName = ""
			}
		}
	}

	o.UpdateVMPoolInfo(ctx)
}

func (o *VMPoolPlatform) markVMsForAction(ctx context.Context, action string, groupName string, vmSpecs []edgeproto.VMSpec) (map[string]edgeproto.VM, error) {
	if o.caches == nil || o.caches.VMPool == nil {
		return nil, fmt.Errorf("caches is nil")
	}

	o.caches.VMPoolMux.Lock()
	defer o.caches.VMPoolMux.Unlock()

	vmPool := o.caches.VMPool

	var vms map[string]edgeproto.VM
	var err error
	if action == ActionAllocate {
		vms, err = markVMsForAllocation(ctx, groupName, vmPool, vmSpecs)
	} else {
		vms, err = markVMsForRelease(ctx, groupName, vmPool, vmSpecs)
	}
	if err != nil {
		return nil, err
	}

	if len(vms) > 0 {
		o.UpdateVMPoolInfo(ctx)
	}

	return vms, nil
}

func setupHostname(ctx context.Context, client ssh.Client, hostname string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Setting up hostname", "hostname", hostname)
	cmd := fmt.Sprintf("sudo hostnamectl set-hostname %s", hostname)
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("failed to execute hostnamectl: %s, %v", out, err)
	}
	cmd = fmt.Sprintf(`sudo sed -i "s/127.0.0.1 \+.\+/127.0.0.1 %s/" /etc/hosts`, hostname)
	out, err = client.Output(cmd)
	if err != nil {
		return fmt.Errorf("failed to update /etc/hosts file: %s, %v", out, err)
	}
	return nil
}

func (o *VMPoolPlatform) createVMsInternal(ctx context.Context, rootLBVMName string, markedVMs map[string]edgeproto.VM, orchVMs []vmlayer.VMOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error {
	// Verify & get RootLB SSH Client
	rootLBVMIP := ""
	if rootLBVMName == o.VMProperties.SharedRootLBName {
		log.SpanLog(ctx, log.DebugLevelInfra, "CreateVMs, get shared rootlb IP", "rootLBVMName", rootLBVMName)
		sd, err := o.GetServerDetail(ctx, rootLBVMName)
		if err != nil {
			return fmt.Errorf("failed to get shared rootLB IP for %s, %v", rootLBVMName, err)
		}
		if sd == nil || len(sd.Addresses) == 0 || sd.Addresses[0].ExternalAddr == "" {
			return fmt.Errorf("missing shared rootLB IP for %s from info %v", rootLBVMName, sd)
		}
		rootLBVMIP = sd.Addresses[0].ExternalAddr
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "CreateVMs, get dedicated rootlb IP", "rootLBVMName", rootLBVMName)
		for _, vm := range markedVMs {
			if vm.InternalName == rootLBVMName {
				rootLBVMIP = vm.NetInfo.ExternalIp
				break
			}
		}
	}
	if rootLBVMIP == "" {
		return fmt.Errorf("failed to get rootLB IP for %s", rootLBVMName)
	}

	vmRoles := make(map[string]vmlayer.VMRole)
	vmChefParams := make(map[string]*chefmgmt.VMChefParams)
	for _, vm := range orchVMs {
		vmRoles[vm.Name] = vm.Role
		vmChefParams[vm.Name] = vm.ChefParams
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "Fetch VM info", "vmRoles", vmRoles, "chefParams", vmChefParams)

	rootLBClient, err := o.VMProperties.GetSSHClientFromIPAddr(ctx, rootLBVMIP)
	if err != nil {
		return fmt.Errorf("can't get rootlb ssh client for %s %v", rootLBVMIP, err)
	}

	// Setup Cluster Nodes
	masterAddr := ""
	for _, vm := range markedVMs {
		role, ok := vmRoles[vm.InternalName]
		if !ok {
			return fmt.Errorf("missing role for vm role %s", vm.InternalName)
		}

		client := rootLBClient
		if vm.InternalName != rootLBVMName {
			client, err = rootLBClient.AddHop(vm.NetInfo.InternalIp, 22)
			if err != nil {
				return err
			}

		}

		// Run cleanup script
		log.SpanLog(ctx, log.DebugLevelInfra, "Cleaning up VM", "vm", vm.Name)
		cmd := fmt.Sprintf("sudo bash /etc/mobiledgex/cleanup-vm.sh")
		out, err := client.Output(cmd)
		if err != nil {
			return fmt.Errorf("can't cleanup vm: %s, %v", out, err)
		}
		// Setup Hostname - Required for UpdateClusterInst
		err = setupHostname(ctx, client, vm.InternalName)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to setup hostname", "vm", vm.Name, "hostname", vm.InternalName, "err", err)
		}

		// Setup Chef
		chefParams, ok := vmChefParams[vm.InternalName]
		if ok && chefParams != nil {
			// Setup chef client key
			log.SpanLog(ctx, log.DebugLevelInfra, "Setting up chef-client", "vm", vm.Name)
			cmd := fmt.Sprintf(`sudo echo -e "%s" > /home/ubuntu/client.pem`, chefParams.ClientKey)
			if out, err := client.Output(cmd); err != nil {
				return fmt.Errorf("failed to copy chef client key: %s, %v", out, err)
			}

			// Start chef service
			cmd = fmt.Sprintf("sudo bash /etc/mobiledgex/setup-chef.sh -s %s -n %s", chefParams.ServerPath, chefParams.NodeName)
			if out, err := client.Output(cmd); err != nil {
				return fmt.Errorf("failed to setup chef: %s, %v", out, err)
			}
		}

		switch role {
		case vmlayer.RoleMaster:
			masterAddr = vm.NetInfo.InternalIp
		case vmlayer.RoleNode:
		default:
			// rootlb
			continue
		}

		// bringup k8s master nodes first, then k8s worker nodes
		if role == vmlayer.RoleMaster {
			updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Setting up kubernetes master node"))
			log.SpanLog(ctx, log.DebugLevelInfra, "CreateVMs, setup kubernetes master node")
			cmd := fmt.Sprintf("sudo sh -x /etc/mobiledgex/install-k8s-master.sh \"ens3\" \"%s\" \"%s\"", masterAddr, masterAddr)
			out, err := client.Output(cmd)
			if err != nil {
				return fmt.Errorf("can't setup k8s master on vm %s with masteraddr %s, %s, %v", vm.InternalName, masterAddr, out, err)
			}
		}
	}
	if masterAddr == "" {
		// See if existing k8s master node exists
		for vName, vRole := range vmRoles {
			if vRole == vmlayer.RoleMaster {
				sd, err := o.GetServerDetail(ctx, vName)
				if err != nil {
					return fmt.Errorf("failed to get k8s master node IP for %s, %v", vName, err)
				}
				if sd == nil || len(sd.Addresses) == 0 || sd.Addresses[0].ExternalAddr == "" {
					return fmt.Errorf("missing k8s master node IP for %s, %v", vName, sd)
				}
				masterAddr = sd.Addresses[0].InternalAddr
				break
			}
		}
	}
	if masterAddr != "" {
		// bring other nodes once master node is up (if deployment is k8s)
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Setting up kubernetes worker nodes"))
		for _, vm := range markedVMs {
			if vmRoles[vm.InternalName] != vmlayer.RoleNode {
				continue
			}
			client, err := rootLBClient.AddHop(vm.NetInfo.InternalIp, 22)
			if err != nil {
				return err
			}

			log.SpanLog(ctx, log.DebugLevelInfra, "CreateVMs, setup kubernetes worker node", "masterAddr", masterAddr, "nodename", vm.InternalName)
			cmd := fmt.Sprintf("sudo sh -x /etc/mobiledgex/install-k8s-node.sh \"ens3\" \"%s\" \"%s\"", masterAddr, masterAddr)
			out, err := client.Output(cmd)
			if err != nil {
				return fmt.Errorf("can't setup k8s node on vm %s with masteraddr %s, %s, %v", vm.InternalName, masterAddr, out, err)
			}
		}
	}
	return nil
}

func (o *VMPoolPlatform) CreateVMs(ctx context.Context, vmGroupOrchestrationParams *vmlayer.VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "createVMs", "params", vmGroupOrchestrationParams)
	vmSpecs := []edgeproto.VMSpec{}

	rootLBVMName := o.VMProperties.SharedRootLBName
	for _, vm := range vmGroupOrchestrationParams.VMs {
		if vm.Role == vmlayer.RoleVMApplication {
			return fmt.Errorf("VM based applications are not support by PlatformTypeVmPool")
		}
		vmSpec := edgeproto.VMSpec{}
		vmSpec.InternalName = vm.Name
		for _, p := range vm.Ports {
			if p.NetworkType == vmlayer.NetTypeExternal {
				vmSpec.ExternalNetwork = true
				rootLBVMName = vm.Name
				break
			}
		}
		vmSpec.InternalNetwork = true
		vmSpecs = append(vmSpecs, vmSpec)
	}

	groupName := vmGroupOrchestrationParams.GroupName

	updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Allocating VMs"))
	markedVMs, err := o.markVMsForAction(ctx, ActionAllocate, groupName, vmSpecs)
	if err != nil {
		return err
	}

	state := edgeproto.VMState_VM_IN_USE
	err = o.createVMsInternal(ctx, rootLBVMName, markedVMs, vmGroupOrchestrationParams.VMs, updateCallback)
	if err != nil {
		// failed to create, mark VM as free
		state = edgeproto.VMState_VM_FREE
	}
	o.SaveVMStateInVMPool(ctx, markedVMs, state)

	return err
}

func (o *VMPoolPlatform) GetVMSharedRootLBIP(ctx context.Context) (string, error) {
	if o.caches == nil || o.caches.VMPool == nil {
		return "", fmt.Errorf("caches is nil")
	}

	o.caches.VMPoolMux.Lock()
	defer o.caches.VMPoolMux.Unlock()

	for _, vm := range o.caches.VMPool.Vms {
		if vm.InternalName == o.VMProperties.SharedRootLBName {
			return vm.NetInfo.ExternalIp, nil
		}
	}
	return "", fmt.Errorf("unable to get shared rootlb ip")
}

func (o *VMPoolPlatform) deleteVMsInternal(ctx context.Context, markedVMs map[string]edgeproto.VM) error {

	// Cleanup VMs if possible
	var rootLBClient ssh.Client
	rootLBVMIP, err := o.GetVMSharedRootLBIP(ctx)
	if err == nil {
		rootLBClient, err = o.VMProperties.GetSSHClientFromIPAddr(ctx, rootLBVMIP)
	}
	if err != nil {
		// skip, as cleanup happens as part of creation as well
		log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVMs, can't get rootlb ssh client for %s %v", rootLBVMIP, err)
		return nil
	}
	for _, vm := range markedVMs {
		var client ssh.Client
		if vm.NetInfo.ExternalIp != "" {
			client, err = o.VMProperties.GetSSHClientFromIPAddr(ctx, vm.NetInfo.ExternalIp)
		} else if vm.NetInfo.InternalIp != "" {
			client, err = rootLBClient.AddHop(vm.NetInfo.InternalIp, 22)
		}
		if err != nil {
			// skip, as cleanup happens as part of creation as well
			log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVMs, can't get ssh client for %s, %v", vm.Name, err)
			continue
		}
		// Run cleanup script
		cmd := fmt.Sprintf("sudo bash /etc/mobiledgex/cleanup-vm.sh")
		out, err := client.Output(cmd)
		if err != nil {
			return fmt.Errorf("can't cleanup vm: %s, %v", out, err)
		}
		// Reset Hostname
		err = setupHostname(ctx, client, vm.Name)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to setup hostname", "vm", vm.Name, "err", err)
		}
	}
	return nil
}

func (o *VMPoolPlatform) DeleteVMs(ctx context.Context, vmGroupName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVMs", "vmGroup", vmGroupName)

	markedVMs, err := o.markVMsForAction(ctx, ActionRelease, vmGroupName, []edgeproto.VMSpec{})
	if err != nil {
		return err
	}

	state := edgeproto.VMState_VM_FREE
	err = o.deleteVMsInternal(ctx, markedVMs)
	if err != nil {
		// failed to cleanup, mark VM as in-use
		state = edgeproto.VMState_VM_IN_USE
	}
	o.SaveVMStateInVMPool(ctx, markedVMs, state)

	return err
}

func (o *VMPoolPlatform) updateVMsInternal(ctx context.Context, vmGroupOrchestrationParams *vmlayer.VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) (map[string]edgeproto.VM, string, error) {
	if o.caches == nil || o.caches.VMPool == nil {
		return nil, "", fmt.Errorf("missing vmpool")
	}

	o.caches.VMPoolMux.Lock()
	defer o.caches.VMPoolMux.Unlock()

	vmPool := o.caches.VMPool

	groupName := vmGroupOrchestrationParams.GroupName

	// Get already created VMs
	existingVms := make(map[string]bool)
	for _, vm := range vmPool.Vms {
		if vm.GroupName != groupName {
			continue
		}
		existingVms[vm.InternalName] = false
	}

	vmSpecs := []edgeproto.VMSpec{}

	for _, vm := range vmGroupOrchestrationParams.VMs {
		vmSpec := edgeproto.VMSpec{}
		vmSpec.InternalName = vm.Name
		for _, p := range vm.Ports {
			if p.NetworkType == vmlayer.NetTypeExternal {
				vmSpec.ExternalNetwork = true
				break
			}
		}
		vmSpec.InternalNetwork = true
		if _, ok := existingVms[vm.Name]; ok {
			existingVms[vm.Name] = true
			continue
		}
		vmSpecs = append(vmSpecs, vmSpec)
	}

	updateAction := ActionAllocate
	if len(vmSpecs) == 0 {
		// no new VMs to be added, see if something is to be removed
		for vName, vPresent := range existingVms {
			if !vPresent {
				vmSpec := edgeproto.VMSpec{}
				vmSpec.InternalName = vName
				vmSpecs = append(vmSpecs, vmSpec)
				updateAction = ActionRelease
			}
		}
	}

	var markedVMs map[string]edgeproto.VM
	var err error

	if len(vmSpecs) == 0 {
		log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMs, nothing to update")
		return nil, ActionNone, nil
	}

	if updateAction == ActionAllocate {
		markedVMs, err = markVMsForAllocation(ctx, groupName, vmPool, vmSpecs)
	} else {
		markedVMs, err = markVMsForRelease(ctx, groupName, vmPool, vmSpecs)
	}
	if err != nil {
		return nil, "", err
	}

	if len(markedVMs) > 0 {
		o.UpdateVMPoolInfo(ctx)
	}

	return markedVMs, updateAction, nil
}

func (o *VMPoolPlatform) UpdateVMs(ctx context.Context, vmGroupOrchestrationParams *vmlayer.VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMs", "params", vmGroupOrchestrationParams)

	markedVMs, updateAction, err := o.updateVMsInternal(ctx, vmGroupOrchestrationParams, updateCallback)
	if err != nil {
		return err
	}

	state := edgeproto.VMState_VM_IN_USE
	switch updateAction {
	case ActionAllocate:
		rootLBVMName := o.VMProperties.SharedRootLBName
		for _, vm := range vmGroupOrchestrationParams.VMs {
			for _, p := range vm.Ports {
				if p.NetworkType == vmlayer.NetTypeExternal {
					rootLBVMName = vm.Name
					break
				}
			}
		}
		err = o.createVMsInternal(ctx, rootLBVMName, markedVMs, vmGroupOrchestrationParams.VMs, updateCallback)
		if err == nil {
			state = edgeproto.VMState_VM_IN_USE
		} else {
			state = edgeproto.VMState_VM_FREE
		}
	case ActionRelease:
		err = o.deleteVMsInternal(ctx, markedVMs)
		if err == nil {
			state = edgeproto.VMState_VM_FREE
		} else {
			state = edgeproto.VMState_VM_IN_USE
		}
	}
	o.SaveVMStateInVMPool(ctx, markedVMs, state)

	return nil
}

func (o *VMPoolPlatform) SyncVMs(ctx context.Context, vmGroupOrchestrationParams *vmlayer.VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SyncVMs")
	// nothing to do right now
	return nil
}

func (s *VMPoolPlatform) GetVMStats(ctx context.Context, key *edgeproto.AppInstKey) (*vmlayer.VMMetrics, error) {
	log.SpanLog(ctx, log.DebugLevelMetrics, "GetVMStats not supported")
	return &vmlayer.VMMetrics{}, nil
}

func (s *VMPoolPlatform) GetPlatformResourceInfo(ctx context.Context) (*vmlayer.PlatformResources, error) {
	log.SpanLog(ctx, log.DebugLevelMetrics, "GetPlatformResourceInfo not supported")
	return nil, nil
}

func (s *VMPoolPlatform) VerifyVMs(ctx context.Context, vms []edgeproto.VM) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "VerifyVMs", "vms", vms)
	if len(vms) == 0 {
		// nothing to verify
		return nil
	}

	accessIP := ""
	// find one of the VM with external IP
	// we'll use this VM to test internal network access of all the VMs
	for _, poolVM := range s.caches.VMPool.Vms {
		if poolVM.NetInfo.ExternalIp != "" {
			accessIP = poolVM.NetInfo.ExternalIp
			break
		}
	}
	if accessIP == "" {
		return fmt.Errorf("At least one VM should have access to external network")
	}
	accessClient, err := s.VMProperties.GetSSHClientFromIPAddr(ctx, accessIP)
	if err != nil {
		return fmt.Errorf("can't get ssh client for %s, %v", accessIP, err)
	}

	for _, vm := range vms {
		if vm.NetInfo.ExternalIp != "" {
			client, err := s.VMProperties.GetSSHClientFromIPAddr(ctx, vm.NetInfo.ExternalIp)
			if err != nil {
				return fmt.Errorf("failed to verify vm %s, can't get ssh client for %s, %v", vm.Name, vm.NetInfo.ExternalIp, err)
			}
			out, err := client.Output("echo test")
			if err != nil {
				return fmt.Errorf("failed to verify if vm %s is accessible over external network: %s - %v", vm.Name, out, err)
			}
		}

		if vm.NetInfo.InternalIp != "" {
			client, err := accessClient.AddHop(vm.NetInfo.InternalIp, 22)
			if err != nil {
				return err
			}

			out, err := client.Output("echo test")
			if err != nil {
				return fmt.Errorf("failed to verify if vm %s is accessible over internal network: %s - %v", vm.Name, out, err)
			}
		}
	}

	return nil
}
