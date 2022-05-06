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
	fmt "fmt"
	"time"

	"github.com/gogo/protobuf/types"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/vmspec"
	context "golang.org/x/net/context"
)

func getFlavorBasedVM(ctx context.Context, vmList []edgeproto.VM, vmSpec *edgeproto.VMSpec) ([]edgeproto.VM, string, error) {
	// Find the closest matching vmspec
	cli := edgeproto.CloudletInfo{}
	cli.Flavors = []*edgeproto.FlavorInfo{}
	for _, newVM := range vmList {
		if newVM.Flavor == nil {
			continue
		}
		cli.Flavors = append(cli.Flavors, newVM.Flavor)
	}
	vmFlavorSpec, err := vmspec.GetVMSpec(ctx, vmSpec.Flavor, cli, nil)
	if err != nil {
		return vmList, "", err
	}
	for ii, newVM := range vmList {
		if newVM.Flavor.Name != vmFlavorSpec.FlavorName {
			continue
		}
		newList := append(vmList[:ii], vmList[ii+1:]...)
		return newList, newVM.Name, nil
	}
	return vmList, "", fmt.Errorf("Unable to find a VM with matching flavor %s", vmSpec.Flavor.Key.Name)
}

func markVMsForAllocation(ctx context.Context, groupName string, vmPool *edgeproto.VMPool, vmSpecs []edgeproto.VMSpec) (map[string]edgeproto.VM, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "markVMsForAllocation", "group", groupName, "vmPool", vmPool, "vmSpecs", vmSpecs)

	// Group available VMs
	bothNetVms := []edgeproto.VM{}
	internalNetVms := []edgeproto.VM{}
	externalNetVms := []edgeproto.VM{}
	freeVMCount := 0
	for _, vm := range vmPool.Vms {
		if vm.State != edgeproto.VMState_VM_FREE {
			continue
		}
		freeVMCount++
		if vm.NetInfo.ExternalIp != "" && vm.NetInfo.InternalIp != "" {
			bothNetVms = append(bothNetVms, vm)
			continue
		}
		if vm.NetInfo.ExternalIp != "" {
			externalNetVms = append(externalNetVms, vm)
			continue
		}
		if vm.NetInfo.InternalIp != "" {
			internalNetVms = append(internalNetVms, vm)
			continue
		}
	}

	if freeVMCount < len(vmSpecs) {
		return nil, fmt.Errorf("Failed to meet VM requirement, required VMs = %d, free VMs available = %d", len(vmSpecs), freeVMCount)
	}

	// Above grouping is done for following reason:
	//   If only internal network is required, then avoid using
	//   VM having external connectivity, unless there are no VMs with
	//   just internal connectivity

	// Allocate VMs from above groups
	selectedVms := make(map[string]string)
	for _, vmSpec := range vmSpecs {
		var err error
		foundVMName := ""
		if vmSpec.ExternalNetwork && vmSpec.InternalNetwork {
			if len(bothNetVms) == 0 {
				return nil, fmt.Errorf("Unable to find a free VM with both external and internal network connectivity")
			}
			bothNetVms, foundVMName, err = getFlavorBasedVM(ctx, bothNetVms, &vmSpec)
			if err != nil {
				return nil, err
			}
		} else if vmSpec.ExternalNetwork {
			if len(externalNetVms) == 0 {
				// try from bothNetVms
				if len(bothNetVms) == 0 {
					return nil, fmt.Errorf("Unable to find a free VM with external network connectivity")
				}
				bothNetVms, foundVMName, err = getFlavorBasedVM(ctx, bothNetVms, &vmSpec)
				if err != nil {
					return nil, err
				}
			} else {
				externalNetVms, foundVMName, err = getFlavorBasedVM(ctx, externalNetVms, &vmSpec)
				if err != nil {
					return nil, err
				}
			}
		} else {
			if len(internalNetVms) == 0 {
				// try from bothNetVms
				if len(bothNetVms) == 0 {
					return nil, fmt.Errorf("Unable to find a free VM with internal network connectivity")
				}
				bothNetVms, foundVMName, err = getFlavorBasedVM(ctx, bothNetVms, &vmSpec)
				if err != nil {
					return nil, err
				}
			} else {
				internalNetVms, foundVMName, err = getFlavorBasedVM(ctx, internalNetVms, &vmSpec)
				if err != nil {
					return nil, err
				}
			}
		}
		if foundVMName == "" {
			return nil, fmt.Errorf("Unable to find a VM from the pool with required spec")
		}
		selectedVms[foundVMName] = vmSpec.InternalName
	}

	// Mark allocated VMs as IN_USE
	markedVMs := make(map[string]edgeproto.VM)
	for ii, vm := range vmPool.Vms {
		internalName, ok := selectedVms[vm.Name]
		if !ok {
			continue
		}
		vm.State = edgeproto.VMState_VM_IN_PROGRESS
		vm.GroupName = groupName
		vm.InternalName = internalName
		ts, _ := types.TimestampProto(time.Now())
		vm.UpdatedAt = *ts
		vmPool.Vms[ii] = vm
		markedVMs[vm.Name] = vm
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "markVMsForAllocation", "marked VMs", markedVMs)
	return markedVMs, nil
}

func markVMsForRelease(ctx context.Context, groupName string, vmPool *edgeproto.VMPool, vmSpecs []edgeproto.VMSpec) (map[string]edgeproto.VM, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "markVMsForRelease", "group", groupName, "vmPool", vmPool, "vmSpecs", vmSpecs)
	freeAll := false
	if len(vmSpecs) == 0 {
		// free all vms
		freeAll = true
	}
	vmNames := map[string]struct{}{}
	for _, vmSpec := range vmSpecs {
		vmNames[vmSpec.InternalName] = struct{}{}
	}

	selectedVms := make(map[string]struct{})
	for _, poolVM := range vmPool.Vms {
		if groupName != poolVM.GroupName {
			continue
		}
		if poolVM.State == edgeproto.VMState_VM_IN_PROGRESS {
			return nil, fmt.Errorf("Unable to release VM %s as it is busy", poolVM.InternalName)
		}
		_, ok := vmNames[poolVM.InternalName]
		if ok || freeAll {
			selectedVms[poolVM.Name] = struct{}{}
		}
	}

	markedVMs := make(map[string]edgeproto.VM)
	for ii, vm := range vmPool.Vms {
		if _, ok := selectedVms[vm.Name]; ok {
			vm.State = edgeproto.VMState_VM_IN_PROGRESS
			ts, _ := types.TimestampProto(time.Now())
			vm.UpdatedAt = *ts
			vmPool.Vms[ii] = vm
			markedVMs[vm.Name] = vm
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "markVMsForRelease", "group", groupName, "marked VMs", markedVMs)
	return markedVMs, nil
}
