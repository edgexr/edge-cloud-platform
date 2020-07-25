package vmpool

import (
	"context"
	"testing"

	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/testutil"
	"github.com/stretchr/testify/require"
)

func verifyMarkedVMs(t *testing.T, vmPool *edgeproto.VMPool, groupName string, markedVMs map[string]edgeproto.VM) {
	count := 0
	for _, vm := range vmPool.Vms {
		if _, ok := markedVMs[vm.Name]; ok {
			require.Equal(t, vm.State, edgeproto.VMState_VM_IN_PROGRESS, "vm set to IN_PROGRESS")
			require.Equal(t, vm.GroupName, groupName, "vm group matches")
			require.NotEmpty(t, vm.InternalName, "vm internal name not empty")
			count++
		}
	}
	require.Equal(t, len(markedVMs), count, "matches vmspec count")
}

func verifyVMGroupStateCount(t *testing.T, vmPool *edgeproto.VMPool, groupName string, state edgeproto.VMState, expectedCount int) {
	count := 0
	for _, vm := range vmPool.Vms {
		if vm.GroupName != groupName {
			continue
		}
		if vm.State == state {
			count++
		}
	}
	require.Equal(t, expectedCount, count, "matches active count")
}

func setVMState(vmPool *edgeproto.VMPool, groupName string, markedVMs map[string]edgeproto.VM, state edgeproto.VMState) {
	for ii, vm := range vmPool.Vms {
		if vm.GroupName != groupName {
			continue
		}
		if _, ok := markedVMs[vm.Name]; !ok {
			continue
		}
		vmPool.Vms[ii].State = state
	}
}

func TestVMSpec(t *testing.T) {
	var err error
	log.SetDebugLevel(log.DebugLevelApi | log.DebugLevelNotify | log.DebugLevelInfra)
	log.InitTracer("")
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	// Define VM Pool
	vmPool := testutil.VMPoolData[0]
	group1 := "testvmpoolvms1"
	group2 := "testvmpoolvms2"

	// Request for 2 VMs
	vmSpecs := []edgeproto.VMSpec{
		edgeproto.VMSpec{
			InternalName:    "vm1.testcluster",
			ExternalNetwork: true,
		},
		edgeproto.VMSpec{
			InternalName:    "vm2.testcluster",
			InternalNetwork: true,
		},
	}
	markedVMs, err := markVMsForAllocation(ctx, group1, &vmPool, vmSpecs)
	require.Nil(t, err, "marked vms for allocation")
	verifyMarkedVMs(t, &vmPool, group1, markedVMs)
	verifyVMGroupStateCount(t, &vmPool, group1, edgeproto.VMState_VM_IN_PROGRESS, 2)

	// Release 1 VM from group1, should fail as it is IN_PROGRESS
	vmSpecs = []edgeproto.VMSpec{
		edgeproto.VMSpec{
			InternalName: "vm1.testcluster",
		},
	}
	_, err = markVMsForRelease(ctx, group1, &vmPool, vmSpecs)
	require.NotNil(t, err, "mark vms for release should fail")
	setVMState(&vmPool, group1, markedVMs, edgeproto.VMState_VM_IN_USE)

	// Request for additional 2 VMs, should fail as there
	// are only 2 VMs with external network
	vmSpecs = []edgeproto.VMSpec{
		edgeproto.VMSpec{
			InternalName:    "vm3.testcluster",
			ExternalNetwork: true,
		},
		edgeproto.VMSpec{
			InternalName:    "vm4.testcluster",
			ExternalNetwork: true,
			InternalNetwork: true,
		},
	}
	_, err = markVMsForAllocation(ctx, group1, &vmPool, vmSpecs)
	require.NotNil(t, err, "allocation should fail")
	verifyVMGroupStateCount(t, &vmPool, group1, edgeproto.VMState_VM_IN_USE, 2)

	// Request for 2 VMs for different group
	vmSpecs = []edgeproto.VMSpec{
		edgeproto.VMSpec{
			InternalName:    "vm1.testcluster",
			ExternalNetwork: true,
			InternalNetwork: true,
		},
		edgeproto.VMSpec{
			InternalName:    "vm2.testcluster",
			InternalNetwork: true,
		},
	}
	markedVMs, err = markVMsForAllocation(ctx, group2, &vmPool, vmSpecs)
	require.Nil(t, err, "marked vms for allocation")
	verifyMarkedVMs(t, &vmPool, group2, markedVMs)
	verifyVMGroupStateCount(t, &vmPool, group2, edgeproto.VMState_VM_IN_USE, 0)
	verifyVMGroupStateCount(t, &vmPool, group2, edgeproto.VMState_VM_IN_PROGRESS, 2)
	setVMState(&vmPool, group2, markedVMs, edgeproto.VMState_VM_IN_USE)

	// Release 1 VM with external network from group1
	vmSpecs = []edgeproto.VMSpec{
		edgeproto.VMSpec{
			InternalName: "vm1.testcluster",
		},
	}
	markedVMs, err = markVMsForRelease(ctx, group1, &vmPool, vmSpecs)
	require.Nil(t, err, "marked vms for release")
	verifyMarkedVMs(t, &vmPool, group1, markedVMs)
	verifyVMGroupStateCount(t, &vmPool, group1, edgeproto.VMState_VM_IN_PROGRESS, 1)
	setVMState(&vmPool, group1, markedVMs, edgeproto.VMState_VM_FREE)

	// Release 1 VM with external network from group2
	vmSpecs = []edgeproto.VMSpec{
		edgeproto.VMSpec{
			InternalName: "vm1.testcluster",
		},
	}
	markedVMs, err = markVMsForRelease(ctx, group2, &vmPool, vmSpecs)
	require.Nil(t, err, "marked vms for release")
	verifyMarkedVMs(t, &vmPool, group2, markedVMs)
	verifyVMGroupStateCount(t, &vmPool, group2, edgeproto.VMState_VM_IN_PROGRESS, 1)
	setVMState(&vmPool, group2, markedVMs, edgeproto.VMState_VM_FREE)

	// Request for additional 2 VMs for group1, should work now
	vmSpecs = []edgeproto.VMSpec{
		edgeproto.VMSpec{
			InternalName:    "vm3.testcluster",
			ExternalNetwork: true,
		},
		edgeproto.VMSpec{
			InternalName:    "vm4.testcluster",
			ExternalNetwork: true,
			InternalNetwork: true,
		},
	}
	markedVMs, err = markVMsForAllocation(ctx, group1, &vmPool, vmSpecs)
	require.Nil(t, err, "marked vms for allocation")
	verifyMarkedVMs(t, &vmPool, group1, markedVMs)
	verifyVMGroupStateCount(t, &vmPool, group1, edgeproto.VMState_VM_IN_USE, 1)
	verifyVMGroupStateCount(t, &vmPool, group1, edgeproto.VMState_VM_IN_PROGRESS, 2)
	setVMState(&vmPool, group1, markedVMs, edgeproto.VMState_VM_IN_USE)

	// Release all Vms from group2
	vmSpecs = []edgeproto.VMSpec{}
	markedVMs, err = markVMsForRelease(ctx, group2, &vmPool, vmSpecs)
	require.Nil(t, err, "marked vms for release")
	verifyMarkedVMs(t, &vmPool, group2, markedVMs)
	verifyVMGroupStateCount(t, &vmPool, group2, edgeproto.VMState_VM_IN_PROGRESS, 1)
	setVMState(&vmPool, group2, markedVMs, edgeproto.VMState_VM_FREE)

	// Release all Vms from group1
	vmSpecs = []edgeproto.VMSpec{}
	markedVMs, err = markVMsForRelease(ctx, group1, &vmPool, vmSpecs)
	require.Nil(t, err, "marked vms for release")
	verifyMarkedVMs(t, &vmPool, group1, markedVMs)
	verifyVMGroupStateCount(t, &vmPool, group1, edgeproto.VMState_VM_IN_PROGRESS, 3)
	setVMState(&vmPool, group1, markedVMs, edgeproto.VMState_VM_FREE)

	// Verify all VMs are free
	count := 0
	for _, vm := range vmPool.Vms {
		if vm.State == edgeproto.VMState_VM_FREE {
			count++
		}
	}
	require.Equal(t, len(vmPool.Vms), count, "all VMs are free")
}
