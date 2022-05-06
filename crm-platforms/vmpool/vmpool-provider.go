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

package vmpool

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/edgexr/edge-cloud-infra/chefmgmt"
	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/util"

	ssh "github.com/mobiledgex/golang-ssh"
)

const (
	ActionNone     string = "none"
	ActionAllocate string = "allocate"
	ActionRelease  string = "release"

	CreateVMTimeout    = 20 * time.Minute
	AllVMAccessTimeout = 30 * time.Minute
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
		return nil, fmt.Errorf("missing VM pool")
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

func setupHostname(ctx context.Context, client ssh.Client, name string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Setting up hostname", "name", name)
	// sanitize hostname
	hostname := util.HostnameSanitize(strings.Split(name, ".")[0])
	cmd := fmt.Sprintf("sudo hostnamectl set-hostname %s", hostname)
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("failed to execute hostnamectl: %s, %v", out, err)
	}
	cmd = fmt.Sprintf(`sudo sed -i "/localhost/! s/127.0.0.1 \+.\+/127.0.0.1 %s/" /etc/hosts`, hostname)
	out, err = client.Output(cmd)
	if err != nil {
		return fmt.Errorf("failed to update /etc/hosts file: %s, %v", out, err)
	}
	return nil
}

func (o *VMPoolPlatform) createVMsInternal(ctx context.Context, markedVMs map[string]edgeproto.VM, orchVMs []vmlayer.VMOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error {
	accessClient, err := o.GetAccessClient(ctx)
	if err != nil {
		return err
	}

	vmRoles := make(map[string]vmlayer.VMRole)
	ServerChefParams := make(map[string]*chefmgmt.ServerChefParams)
	vmAccessKeys := make(map[string]string)
	for _, vm := range orchVMs {
		vmRoles[vm.Name] = vm.Role
		ServerChefParams[vm.Name] = vm.CloudConfigParams.ChefParams
		vmAccessKeys[vm.Name] = vm.CloudConfigParams.AccessKey
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "Fetch VM info", "vmRoles", vmRoles, "chefParams", ServerChefParams)

	// Setup Cluster Nodes
	masterAddr := ""
	for _, vm := range markedVMs {
		role, ok := vmRoles[vm.InternalName]
		if !ok {
			return fmt.Errorf("missing role for vm role %s", vm.InternalName)
		}

		var client ssh.Client
		if vm.NetInfo.ExternalIp == "" {
			client, err = accessClient.AddHop(vm.NetInfo.InternalIp, 22)
			if err != nil {
				return err
			}
		} else {
			client, err = o.VMProperties.CommonPf.GetSSHClientFromIPAddr(ctx, vm.NetInfo.ExternalIp)
			if err != nil {
				return fmt.Errorf("can't get ssh client for %s %v", vm.NetInfo.ExternalIp, err)
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

		// Setup AccessKey if it is present
		accessKey, ok := vmAccessKeys[vm.InternalName]
		if ok && accessKey != "" {
			log.SpanLog(ctx, log.DebugLevelInfra, "Setting up access key file", "vm", vm.Name)
			err = pc.CreateDir(ctx, client, "/root/accesskey", pc.Overwrite, pc.SudoOn)
			if err != nil {
				return fmt.Errorf("Failed to created /root/accesskey directory, %v", err)
			}
			err = pc.WriteFile(client, "/root/accesskey/accesskey.pem", accessKey, "crmaccesskey", pc.SudoOn)
			if err != nil {
				return fmt.Errorf("failed to write access key: %v", err)
			}
			// change perms to 600
			cmd = fmt.Sprintf("sudo chmod 600 /root/accesskey/accesskey.pem")
			if _, err = client.Output(cmd); err != nil {
				return fmt.Errorf("failed to change perms of accesskey file: %v", err)
			}
		}

		// Setup Chef
		chefParams, ok := ServerChefParams[vm.InternalName]
		if ok && chefParams != nil {
			// Setup chef client key
			log.SpanLog(ctx, log.DebugLevelInfra, "Setting up chef-client", "vm", vm.Name)
			err = pc.WriteFile(client, "/home/ubuntu/client.pem", chefParams.ClientKey, "chefclientkey", pc.SudoOn)
			if err != nil {
				return fmt.Errorf("failed to copy chef client key: %v", err)
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
		case vmlayer.RoleK8sNode:
		case vmlayer.RoleDockerNode:
		default:
			// rootlb
			continue
		}

		// bringup k8s master nodes first, then k8s worker nodes
		if role == vmlayer.RoleMaster {
			updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Setting up kubernetes master node"))
			log.SpanLog(ctx, log.DebugLevelInfra, "CreateVMs, setup kubernetes master node", "masterAddr", masterAddr)
			cmd := fmt.Sprintf("sudo sh -x /etc/mobiledgex/install-k8s-master.sh \"%s\"", masterAddr)
			out, err := client.Output(cmd)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "failed to setup k8s master", "masterAddr", masterAddr, "nodename", vm.InternalName, "out", out, "err", err)
				return fmt.Errorf("can't setup k8s master on vm %s with masteraddr %s", vm.InternalName, masterAddr)
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
		wgError := make(chan error)
		wgDone := make(chan bool)
		var wg sync.WaitGroup

		// bring other nodes once master node is up (if deployment is k8s)
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Setting up kubernetes worker nodes"))
		for _, vm := range markedVMs {
			if vmRoles[vm.InternalName] != vmlayer.RoleK8sNode {
				continue
			}
			client, err := accessClient.AddHop(vm.NetInfo.InternalIp, 22)
			if err != nil {
				return err
			}

			wg.Add(1)
			go func(clientIn ssh.Client, nodeName string, wg *sync.WaitGroup) {
				log.SpanLog(ctx, log.DebugLevelInfra, "CreateVMs, setup kubernetes worker node", "masterAddr", masterAddr, "nodename", nodeName)
				cmd := fmt.Sprintf("sudo sh -x /etc/mobiledgex/install-k8s-node.sh \"%s\"", masterAddr)
				out, err := clientIn.Output(cmd)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "failed to setup k8s node", "masterAddr", masterAddr, "nodename", nodeName, "out", out, "err", err)
					wgError <- fmt.Errorf("can't setup k8s node on vm %s with masteraddr %s", nodeName, masterAddr)
					return
				}
				wg.Done()
			}(client, vm.InternalName, &wg)
		}

		go func() {
			wg.Wait()
			close(wgDone)
		}()

		// Wait until either WaitGroup is done or an error is received through the channel
		select {
		case <-wgDone:
			break
		case err := <-wgError:
			return err
		case <-time.After(CreateVMTimeout):
			return fmt.Errorf("Timed out setting up VMs")
		}
	}

	return nil
}

func (o *VMPoolPlatform) CreateVMs(ctx context.Context, vmGroupOrchestrationParams *vmlayer.VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "createVMs", "params", vmGroupOrchestrationParams)
	vmSpecs := []edgeproto.VMSpec{}

	for _, vm := range vmGroupOrchestrationParams.VMs {
		if vm.Role == vmlayer.RoleVMApplication {
			return fmt.Errorf("VM based applications are not support by PlatformTypeVmPool")
		}
		vmSpec := edgeproto.VMSpec{}
		vmSpec.InternalName = vm.Name
		for _, p := range vm.Ports {
			if p.NetType == vmlayer.NetworkTypeExternalPrimary {
				vmSpec.ExternalNetwork = true
				break
			}
		}
		vmSpec.InternalNetwork = true
		found := false
		for _, flavor := range o.FlavorList {
			if flavor.Name == vm.FlavorName {
				vmSpec.Flavor = edgeproto.Flavor{
					Key: edgeproto.FlavorKey{
						Name: vm.FlavorName,
					},
					Ram:       flavor.Ram,
					Vcpus:     flavor.Vcpus,
					Disk:      flavor.Disk,
					OptResMap: flavor.PropMap,
				}
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("Unable to find matching flavor %s from list %v", vm.FlavorName, o.FlavorList)
		}
		vmSpecs = append(vmSpecs, vmSpec)
	}

	groupName := vmGroupOrchestrationParams.GroupName

	updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Allocating VMs"))
	markedVMs, err := o.markVMsForAction(ctx, ActionAllocate, groupName, vmSpecs)
	if err != nil {
		return err
	}

	state := edgeproto.VMState_VM_IN_USE
	err = o.createVMsInternal(ctx, markedVMs, vmGroupOrchestrationParams.VMs, updateCallback)
	if err != nil {
		// failed to create, mark VM as free
		state = edgeproto.VMState_VM_FREE
	}
	o.SaveVMStateInVMPool(ctx, markedVMs, state)

	return err
}

func (o *VMPoolPlatform) GetAccessClient(ctx context.Context) (ssh.Client, error) {
	if o.caches == nil || o.caches.VMPool == nil {
		return nil, fmt.Errorf("missing VM pool")
	}

	o.caches.VMPoolMux.Lock()
	defer o.caches.VMPoolMux.Unlock()

	// This will be used to access nodes which are only reachable
	// over internal network, and via external network

	sharedRootLBIP := ""
	accessIP := ""
	for _, vm := range o.caches.VMPool.Vms {
		if vm.InternalName == o.VMProperties.SharedRootLBName {
			sharedRootLBIP = vm.NetInfo.ExternalIp
		}
		if vm.NetInfo.ExternalIp != "" {
			accessIP = vm.NetInfo.ExternalIp
		}
	}

	if sharedRootLBIP != "" {
		// prefer shared rootLB's IP
		accessIP = sharedRootLBIP
	}

	if accessIP == "" {
		return nil, fmt.Errorf("unable to find any VM with external IP")
	}

	accessClient, err := o.VMProperties.CommonPf.GetSSHClientFromIPAddr(ctx, accessIP)
	if err != nil {
		return nil, fmt.Errorf("can't get ssh client for %s %v", accessIP, err)
	}
	return accessClient, nil
}

func (o *VMPoolPlatform) deleteVMsInternal(ctx context.Context, markedVMs map[string]edgeproto.VM) error {
	// Cleanup VMs if possible
	var accessClient ssh.Client
	accessClient, err := o.GetAccessClient(ctx)
	if err != nil {
		// skip, as cleanup happens as part of creation as well
		log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVMs, failed to get access client", "err", err)
		return nil
	}
	for _, vm := range markedVMs {
		var client ssh.Client
		if vm.NetInfo.ExternalIp != "" {
			client, err = o.VMProperties.CommonPf.GetSSHClientFromIPAddr(ctx, vm.NetInfo.ExternalIp)
		} else if vm.NetInfo.InternalIp != "" {
			client, err = accessClient.AddHop(vm.NetInfo.InternalIp, 22)
		}
		if err != nil {
			// skip, as cleanup happens as part of creation as well
			log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVMs, can't get ssh client", "vm", vm.Name, "err", err)
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
			if p.NetType == vmlayer.NetworkTypeExternalPrimary {
				vmSpec.ExternalNetwork = true
				break
			}
		}
		vmSpec.InternalNetwork = true
		found := false
		for _, flavor := range o.FlavorList {
			if flavor.Name == vm.FlavorName {
				vmSpec.Flavor = edgeproto.Flavor{
					Key: edgeproto.FlavorKey{
						Name: vm.FlavorName,
					},
					Ram:       flavor.Ram,
					Vcpus:     flavor.Vcpus,
					Disk:      flavor.Disk,
					OptResMap: flavor.PropMap,
				}
				found = true
				break
			}
		}
		if !found {
			return nil, ActionNone, fmt.Errorf("Unable to find matching flavor %s from list %v", vm.FlavorName, o.FlavorList)
		}

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
		err = o.createVMsInternal(ctx, markedVMs, vmGroupOrchestrationParams.VMs, updateCallback)
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

	return err
}

func (o *VMPoolPlatform) SyncVMs(ctx context.Context, vmGroupOrchestrationParams *vmlayer.VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SyncVMs")
	// nothing to do right now
	return nil
}

func (s *VMPoolPlatform) GetVMStats(ctx context.Context, appInst *edgeproto.AppInst) (*vmlayer.VMMetrics, error) {
	log.SpanLog(ctx, log.DebugLevelMetrics, "GetVMStats not supported")
	return &vmlayer.VMMetrics{}, nil
}

func (s *VMPoolPlatform) VmAppChangedCallback(ctx context.Context, appInst *edgeproto.AppInst, newState edgeproto.TrackedState) {
}

func (s *VMPoolPlatform) GetPlatformResourceInfo(ctx context.Context) (*vmlayer.PlatformResources, error) {
	log.SpanLog(ctx, log.DebugLevelMetrics, "GetPlatformResourceInfo not supported")
	return &vmlayer.PlatformResources{}, nil
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

	accessClient, err := s.VMProperties.CommonPf.GetSSHClientFromIPAddr(ctx, accessIP)
	if err != nil {
		return fmt.Errorf("can't get ssh client for %s, %v", accessIP, err)
	}

	for _, vm := range vms {
		if vm.NetInfo.ExternalIp != "" {
			client, err := s.VMProperties.CommonPf.GetSSHClientFromIPAddr(ctx, vm.NetInfo.ExternalIp)
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
				return fmt.Errorf("failed to verify if vm %s is accessible over internal network from %s: %s - %v", vm.Name, accessIP, out, err)
			}
		}
	}

	return nil
}

func (s *VMPoolPlatform) CheckServerReady(ctx context.Context, client ssh.Client, serverName string) error {
	// no special checks to be done
	return nil
}

func (v *VMPoolPlatform) GetServerGroupResources(ctx context.Context, name string) (*edgeproto.InfraResources, error) {
	return nil, fmt.Errorf("GetServerGroupResources not implemented for VMPool")
}
