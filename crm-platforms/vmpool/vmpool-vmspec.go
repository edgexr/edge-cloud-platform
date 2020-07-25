package vmpool

import (
	fmt "fmt"
	"time"

	"github.com/gogo/protobuf/types"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	context "golang.org/x/net/context"
)

func markVMsForAllocation(ctx context.Context, groupName string, vmPool *edgeproto.VMPool, vmSpecs []edgeproto.VMSpec) (map[string]edgeproto.VM, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "markVMsForAllocation", "group", groupName, "vmPool", vmPool, "vmSpecs", vmSpecs)

	// Group available VMs
	bothNetVms := []string{}
	internalNetVms := []string{}
	externalNetVms := []string{}
	for _, vm := range vmPool.Vms {
		if vm.State != edgeproto.VMState_VM_FREE {
			continue
		}
		if vm.NetInfo.ExternalIp != "" && vm.NetInfo.InternalIp != "" {
			bothNetVms = append(bothNetVms, vm.Name)
			continue
		}
		if vm.NetInfo.ExternalIp != "" {
			externalNetVms = append(externalNetVms, vm.Name)
		}
		if vm.NetInfo.InternalIp != "" {
			internalNetVms = append(internalNetVms, vm.Name)
		}
	}

	// Above grouping is done for following reason:
	//   If only internal network is required, then avoid using
	//   VM having external connectivity, unless there are no VMs with
	//   just internal connectivity

	// Allocate VMs from above groups
	selectedVms := make(map[string]string)
	for _, vmSpec := range vmSpecs {
		if vmSpec.ExternalNetwork && vmSpec.InternalNetwork {
			if len(bothNetVms) == 0 {
				return nil, fmt.Errorf("Unable to find a free VM with both external and internal network connectivity")
			}
			selectedVms[bothNetVms[0]] = vmSpec.InternalName
			bothNetVms = bothNetVms[1:]
		} else if vmSpec.ExternalNetwork {
			if len(externalNetVms) == 0 {
				// try from bothNetVms
				if len(bothNetVms) == 0 {
					return nil, fmt.Errorf("Unable to find a free VM with external network connectivity")
				}
				selectedVms[bothNetVms[0]] = vmSpec.InternalName
				bothNetVms = bothNetVms[1:]
			} else {
				selectedVms[externalNetVms[0]] = vmSpec.InternalName
				externalNetVms = externalNetVms[1:]
			}
		} else {
			if len(internalNetVms) == 0 {
				// try from bothNetVms
				if len(bothNetVms) == 0 {
					return nil, fmt.Errorf("Unable to find a free VM with internal network connectivity")
				}
				selectedVms[bothNetVms[0]] = vmSpec.InternalName
				bothNetVms = bothNetVms[1:]
			} else {
				selectedVms[internalNetVms[0]] = vmSpec.InternalName
				internalNetVms = internalNetVms[1:]
			}
		}
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
