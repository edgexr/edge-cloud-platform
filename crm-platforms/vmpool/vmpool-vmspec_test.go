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
	"testing"

	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/testutil"
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
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	// Define VM Pool
	vmPool := testutil.VMPoolData[0]
	group1 := "testvmpoolvms1"
	group2 := "testvmpoolvms2"

	smallFlavor := edgeproto.Flavor{
		Key: edgeproto.FlavorKey{
			Name: "x1.small",
		},
		Vcpus: uint64(2),
		Ram:   uint64(2048),
		Disk:  uint64(10),
	}

	mediumFlavor := edgeproto.Flavor{
		Key: edgeproto.FlavorKey{
			Name: "x1.medium",
		},
		Vcpus: uint64(2),
		Ram:   uint64(4096),
		Disk:  uint64(40),
	}

	largeFlavor := edgeproto.Flavor{
		Key: edgeproto.FlavorKey{
			Name: "x1.large",
		},
		Vcpus: uint64(4),
		Ram:   uint64(8192),
		Disk:  uint64(80),
	}

	// Request for 2 VMs
	vmSpecs := []edgeproto.VMSpec{
		edgeproto.VMSpec{
			InternalName:    "vm1.testcluster",
			ExternalNetwork: true,
			Flavor:          smallFlavor,
		},
		edgeproto.VMSpec{
			InternalName:    "vm2.testcluster",
			InternalNetwork: true,
			Flavor:          smallFlavor,
		},
	}
	markedVMs, err := markVMsForAllocation(ctx, group1, &vmPool, vmSpecs)
	require.Nil(t, err, "marked vms for allocation")
	verifyMarkedVMs(t, &vmPool, group1, markedVMs)
	verifyVMGroupStateCount(t, &vmPool, group1, edgeproto.VMState_VM_IN_PROGRESS, 2)

	// Request for VM with large flavor, should fail
	vmSpecs = []edgeproto.VMSpec{
		edgeproto.VMSpec{
			InternalName:    "vm3.testcluster",
			ExternalNetwork: true,
			Flavor:          largeFlavor,
		},
	}
	_, err = markVMsForAllocation(ctx, group1, &vmPool, vmSpecs)
	require.NotNil(t, err, "mark vms for allocation should fail as no vm with same flavor exists")
	require.Contains(t, err.Error(), "no suitable platform flavor found", "error message should match")

	// Release 1 VM from group1, should fail as it is IN_PROGRESS
	vmSpecs = []edgeproto.VMSpec{
		edgeproto.VMSpec{
			InternalName: "vm1.testcluster",
		},
	}
	_, err = markVMsForRelease(ctx, group1, &vmPool, vmSpecs)
	require.NotNil(t, err, "mark vms for release should fail")
	require.Contains(t, err.Error(), "Unable to release VM", "error message should match")
	setVMState(&vmPool, group1, markedVMs, edgeproto.VMState_VM_IN_USE)

	// Request for VM with medium flavor, should pass
	vmSpecs = []edgeproto.VMSpec{
		edgeproto.VMSpec{
			InternalName:    "vm5.testcluster",
			InternalNetwork: true,
			Flavor:          mediumFlavor,
		},
	}
	markedVMs, err = markVMsForAllocation(ctx, group1, &vmPool, vmSpecs)
	require.Nil(t, err, "marked vm with medium flavor for allocation")
	verifyMarkedVMs(t, &vmPool, group1, markedVMs)
	verifyVMGroupStateCount(t, &vmPool, group1, edgeproto.VMState_VM_IN_PROGRESS, 1)
	for medVMName, _ := range markedVMs {
		require.Equal(t, medVMName, "vm5", "validated that vm5 which is of medium flavor is used")
	}
	setVMState(&vmPool, group1, markedVMs, edgeproto.VMState_VM_IN_USE)

	// Request for additional 2 VMs, should fail as there
	// are only 2 VMs with external network
	vmSpecs = []edgeproto.VMSpec{
		edgeproto.VMSpec{
			InternalName:    "vm3.testcluster",
			ExternalNetwork: true,
			Flavor:          smallFlavor,
		},
		edgeproto.VMSpec{
			InternalName:    "vm4.testcluster",
			ExternalNetwork: true,
			InternalNetwork: true,
			Flavor:          smallFlavor,
		},
	}
	_, err = markVMsForAllocation(ctx, group1, &vmPool, vmSpecs)
	require.NotNil(t, err, "allocation should fail")
	require.Contains(t, err.Error(), "Unable to find a free VM", "error message should match")
	verifyVMGroupStateCount(t, &vmPool, group1, edgeproto.VMState_VM_IN_USE, 3)

	// Request for additional 3 VMs, should fail as there
	// aren't enough VMs
	vmSpecs = []edgeproto.VMSpec{
		edgeproto.VMSpec{
			InternalName: "vm3.testcluster",
			Flavor:       smallFlavor,
		},
		edgeproto.VMSpec{
			InternalName:    "vm4.testcluster",
			InternalNetwork: true,
			Flavor:          smallFlavor,
		},
		edgeproto.VMSpec{
			InternalName:    "vm5.testcluster",
			InternalNetwork: true,
			Flavor:          smallFlavor,
		},
	}
	_, err = markVMsForAllocation(ctx, group1, &vmPool, vmSpecs)
	require.NotNil(t, err, "allocation should fail")
	require.Contains(t, err.Error(), "Failed to meet VM requirement", "error message should match")
	verifyVMGroupStateCount(t, &vmPool, group1, edgeproto.VMState_VM_IN_USE, 3)

	// Request for 2 VMs for different group
	vmSpecs = []edgeproto.VMSpec{
		edgeproto.VMSpec{
			InternalName:    "vm1.testcluster",
			ExternalNetwork: true,
			InternalNetwork: true,
			Flavor:          smallFlavor,
		},
		edgeproto.VMSpec{
			InternalName:    "vm2.testcluster",
			InternalNetwork: true,
			Flavor:          smallFlavor,
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
	verifyVMGroupStateCount(t, &vmPool, group1, edgeproto.VMState_VM_IN_USE, 2)
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
	verifyVMGroupStateCount(t, &vmPool, group1, edgeproto.VMState_VM_IN_PROGRESS, 4)
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
