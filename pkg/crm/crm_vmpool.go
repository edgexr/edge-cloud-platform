// Copyright 2024 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crm

import (
	"context"
	"fmt"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
)

// VMPool is supported only for CRM because of the way the code
// was set up. The CRM caches the VMPool object locally and tracks
// which VMs are in use in CRM memory. I'm not sure it's possible
// to run it in the CCRM where local state is ephemeral.

func (cd *CRMData) VMPoolChanged(ctx context.Context, old *edgeproto.VMPool, new *edgeproto.VMPool) {
	log.SpanLog(ctx, log.DebugLevelInfra, "VMPoolChanged", "newvmpool", new, "oldvmpool", old)
	if !cd.highAvailabilityManager.PlatformInstanceActive {
		log.SpanLog(ctx, log.DebugLevelInfra, "Ignoring VM Pool changed because not active")
		return
	}
	if old == nil || old.State == new.State {
		return
	}
	if new.State != edgeproto.TrackedState_UPDATE_REQUESTED {
		return
	}

	cd.updateVMPoolWorkers.NeedsWork(ctx, new.Key)
}

func (cd *CRMData) UpdateVMPool(ctx context.Context, k interface{}) {
	key, ok := k.(edgeproto.VMPoolKey)
	if !ok {
		log.SpanLog(ctx, log.DebugLevelInfra, "Unexpected failure, key not VMPoolKey", "key", key)
		return
	}
	log.SetContextTags(ctx, key.GetTags())
	log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMPool", "vmpoolkey", key)

	var vmPool edgeproto.VMPool
	if !cd.VMPoolCache.Get(&key, &vmPool) {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to fetch vm pool cache from controller")
		return
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "found vmpool", "vmpool", vmPool)

	cd.UpdateVMPoolInfo(ctx, edgeproto.TrackedState_UPDATING, "")

	changed, oldVMs, validateVMs := cd.markUpdateVMs(ctx, &vmPool)
	if !changed {
		return
	}

	// verify if new/updated VM is reachable
	var err error
	if len(validateVMs) > 0 {
		err = cd.platform.VerifyVMs(ctx, validateVMs)
	}

	// Update lock to update VMPool & gather new flavor list (cloudletinfo)
	cd.VMPoolUpdateMux.Lock()
	defer cd.VMPoolUpdateMux.Unlock()

	// New function block so that we can call defer on VMPoolMux Unlock
	fErr := func() error {
		cd.VMPoolMux.Lock()
		defer cd.VMPoolMux.Unlock()
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to verify VMs", "vms", validateVMs, "err", err)
			// revert intermediate states
			revertVMs := []edgeproto.VM{}
			for _, vm := range cd.VMPool.Vms {
				switch vm.State {
				case edgeproto.VMState_VM_ADD:
					continue
				case edgeproto.VMState_VM_REMOVE:
					vm.State = edgeproto.VMState_VM_FREE
				case edgeproto.VMState_VM_UPDATE:
					if oVM, ok := oldVMs[vm.Name]; ok {
						vm = oVM
					}
					vm.State = edgeproto.VMState_VM_FREE
				}
				revertVMs = append(revertVMs, vm)
			}
			cd.VMPool.Vms = revertVMs
			cd.UpdateVMPoolInfo(
				ctx,
				edgeproto.TrackedState_UPDATE_ERROR,
				fmt.Sprintf("%v", err))
			return err
		}

		newVMs := []edgeproto.VM{}
		for _, vm := range cd.VMPool.Vms {
			switch vm.State {
			case edgeproto.VMState_VM_ADD:
				vm.State = edgeproto.VMState_VM_FREE
				newVMs = append(newVMs, vm)
			case edgeproto.VMState_VM_REMOVE:
				continue
			case edgeproto.VMState_VM_UPDATE:
				vm.State = edgeproto.VMState_VM_FREE
				newVMs = append(newVMs, vm)
			default:
				newVMs = append(newVMs, vm)
			}
		}
		// save VM to VM pool
		cd.VMPool.Vms = newVMs
		return nil
	}()
	if fErr != nil {
		return
	}

	// calculate Flavor info and send CloudletInfo again
	log.SpanLog(ctx, log.DebugLevelInfra, "gather vmpool flavors", "vmpool", key, "cloudlet", cd.cloudletKey)
	var cloudletInfo edgeproto.CloudletInfo
	if !cd.CloudletInfoCache.Get(cd.cloudletKey, &cloudletInfo) {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to update vmpool flavors, missing cloudletinfo", "vmpool", key, "cloudlet", cd.cloudletKey)
	} else {
		err = cd.platform.GatherCloudletInfo(ctx, &cloudletInfo)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to gather vmpool flavors", "vmpool", key, "cloudlet", cd.cloudletKey, "err", err)
		} else {
			cd.CloudletInfoCache.Update(ctx, &cloudletInfo, 0)
		}
	}

	// notify controller
	cd.UpdateVMPoolInfo(ctx, edgeproto.TrackedState_READY, "")
}

func (cd *CRMData) markUpdateVMs(ctx context.Context, vmPool *edgeproto.VMPool) (bool, map[string]edgeproto.VM, []edgeproto.VM) {
	log.SpanLog(ctx, log.DebugLevelInfra, "markUpdateVMs", "vmpool", vmPool)
	cd.VMPoolMux.Lock()
	defer cd.VMPoolMux.Unlock()

	changeVMs := make(map[string]edgeproto.VM)
	for _, vm := range vmPool.Vms {
		changeVMs[vm.Name] = vm
	}

	// Incoming VM pool will have one of four cases:
	//  - All VMs in pool, with some VMs with VMState ADD, to add new VMs
	//  - All VMs in pool, with some VMs with VMState REMOVE, to remove some VMs
	//  - All VMs in pool, with all VMs with VMState UPDATE, to replace existing set of VMs with new set
	//  - All VMs in pool, with some VMs with VMState FORCE_FREE, to forcefully free some VMs
	//  - All VMs in pool with no ADD/REMOVE/UPDATE states, this happens on notify reconnect. We treat it as UPDATE above
	//  - It should never be the case that VMs will have more than one of ADD/REMOVE/UPDATE set on them in a single update

	changed := false
	newVMs := []edgeproto.VM{}
	validateVMs := []edgeproto.VM{}
	oldVMs := make(map[string]edgeproto.VM)
	updateVMs := make(map[string]edgeproto.VM)
	for _, vm := range cd.VMPool.Vms {
		cVM, ok := changeVMs[vm.Name]
		if !ok {
			// Ignored for UPDATE.
			// For ADD/REMOVE, this really shouldn't happen,
			// but preserve the VM we have locally.
			newVMs = append(newVMs, vm)
			continue
		}
		delete(changeVMs, vm.Name)
		switch cVM.State {
		case edgeproto.VMState_VM_ADD:
			cd.UpdateVMPoolInfo(
				ctx,
				edgeproto.TrackedState_UPDATE_ERROR,
				fmt.Sprintf("VM %s already exists", vm.Name),
			)
			return false, nil, nil
		case edgeproto.VMState_VM_REMOVE:
			if vm.State != edgeproto.VMState_VM_FREE {
				log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMPool, conflicting state", "vm", vm.Name, "state", vm.State)
				cd.UpdateVMPoolInfo(
					ctx,
					edgeproto.TrackedState_UPDATE_ERROR,
					fmt.Sprintf("Unable to delete VM %s, as it is in use", vm.Name),
				)
				return false, nil, nil
			}
			changed = true
			vm.State = edgeproto.VMState_VM_REMOVE
			newVMs = append(newVMs, vm)
		case edgeproto.VMState_VM_UPDATE:
			if isVMChanged(&vm, &cVM) {
				if vm.State != edgeproto.VMState_VM_FREE {
					log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMPool, conflicting state", "vm", vm.Name, "state", vm.State)
					cd.UpdateVMPoolInfo(
						ctx,
						edgeproto.TrackedState_UPDATE_ERROR,
						fmt.Sprintf("Unable to update VM %s, as it is in use", vm.Name),
					)
					return false, nil, nil
				}
				oldVMs[vm.Name] = vm
				validateVMs = append(validateVMs, cVM)
				updateVMs[vm.Name] = cVM
			} else {
				updateVMs[vm.Name] = vm
			}
			changed = true
		case edgeproto.VMState_VM_FORCE_FREE:
			log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMPool, forcefully free vm", "vm", vm.Name, "current state", vm.State)
			vm.State = edgeproto.VMState_VM_FREE
			vm.InternalName = ""
			vm.GroupName = ""
			updateVMs[vm.Name] = vm
			changed = true
		default:
			newVMs = append(newVMs, vm)
		}
	}
	for _, vm := range changeVMs {
		validateVMs = append(validateVMs, vm)
		if vm.State == edgeproto.VMState_VM_ADD {
			newVMs = append(newVMs, vm)
		} else if vm.State == edgeproto.VMState_VM_UPDATE {
			updateVMs[vm.Name] = vm
		} else if vm.State == edgeproto.VMState_VM_FORCE_FREE {
			vm.State = edgeproto.VMState_VM_FREE
			vm.InternalName = ""
			vm.GroupName = ""
			updateVMs[vm.Name] = vm
		}
		changed = true
	}

	// As part of update, vms can also be removed,
	// hence verify those vms as well
	if len(updateVMs) > 0 {
		newVMs = []edgeproto.VM{}
		for _, vm := range cd.VMPool.Vms {
			if uVM, ok := updateVMs[vm.Name]; ok {
				newVMs = append(newVMs, uVM)
				changed = true
				delete(updateVMs, vm.Name)
			} else {
				if vm.State != edgeproto.VMState_VM_FREE {
					log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMPool, conflicting state", "vm", vm.Name, "state", vm.State)
					cd.UpdateVMPoolInfo(
						ctx,
						edgeproto.TrackedState_UPDATE_ERROR,
						fmt.Sprintf("Unable to delete VM %s, as it is in use", vm.Name),
					)
					return false, nil, nil
				}
			}
		}
		for _, vm := range updateVMs {
			newVMs = append(newVMs, vm)
			changed = true
		}
	}

	if changed {
		cd.VMPool.Vms = newVMs
	} else {
		// notify controller, nothing to update
		log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMPool, nothing to update", "vmpoolkey", vmPool.Key)
		cd.UpdateVMPoolInfo(ctx, edgeproto.TrackedState_READY, "")
	}
	return changed, oldVMs, validateVMs
}

func isVMChanged(old *edgeproto.VM, new *edgeproto.VM) bool {
	if old == nil {
		return true
	}
	if new == nil {
		return false
	}
	if new.NetInfo.ExternalIp != old.NetInfo.ExternalIp ||
		new.NetInfo.InternalIp != old.NetInfo.InternalIp {
		return true
	}
	return false
}

// This func must be called with cd.VMPoolMux lock held
func (cd *CRMData) UpdateVMPoolInfo(ctx context.Context, state edgeproto.TrackedState, errStr string) {
	info := edgeproto.VMPoolInfo{}
	info.Key = cd.VMPool.Key
	info.Vms = cd.VMPool.Vms
	info.State = state
	// note that if there are no errors, this should clear any existing errors state at the Controller
	if errStr != "" {
		info.Errors = []string{errStr}
	}
	cd.VMPoolInfoCache.Update(ctx, &info, 0)
}
