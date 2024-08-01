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

package openstack

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	yaml "github.com/mobiledgex/yaml/v2"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	pf "github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/confignode"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/vmlayer"
	"github.com/edgexr/edge-cloud-platform/pkg/syncdata"
	"github.com/stretchr/testify/require"
)

var subnetNames = vmlayer.SubnetNames{"subnet-test", "subnet-test-ipv6"}

var vms = []*vmlayer.VMRequestSpec{
	{
		Name:                    "rootlb-xyz",
		Type:                    cloudcommon.NodeTypeDedicatedRootLB,
		FlavorName:              "m1.medium",
		ImageName:               "mobiledgex-v9.9.9",
		ComputeAvailabilityZone: "nova1",
		ExternalVolumeSize:      100,
		ConnectToExternalNet:    true,
		ConnectToSubnets:        subnetNames,
	},
	{
		Name:                    "master-xyz",
		Type:                    cloudcommon.NodeTypeK8sClusterMaster,
		FlavorName:              "m1.medium",
		ImageName:               "mobiledgex-v9.9.9",
		ComputeAvailabilityZone: "nova1",
		ExternalVolumeSize:      100,
		ConnectToExternalNet:    true,
		ConnectToSubnets:        subnetNames,
		SharedVolumeSize:        100,
	},
	{
		Name:                    "node1-xyz",
		Type:                    cloudcommon.NodeTypeK8sClusterNode,
		FlavorName:              "m1.medium",
		ImageName:               "mobiledgex-v9.9.9",
		ComputeAvailabilityZone: "nova1",
		ConnectToSubnets:        subnetNames,
	},
	{
		Name:                    "node2-xyz",
		Type:                    cloudcommon.NodeTypeK8sClusterNode,
		FlavorName:              "m1.medium",
		ImageName:               "mobiledgex-v9.9.9",
		ComputeAvailabilityZone: "nova1",
		ConnectToSubnets:        subnetNames,
	},
	{
		Name:                    "app-vm",
		Type:                    cloudcommon.NodeTypeAppVM,
		FlavorName:              "m1.medium",
		ImageName:               "mobiledgex-v9.9.9",
		ComputeAvailabilityZone: "nova1",
		ConnectToSubnets:        subnetNames,
	},
}

func validateStack(ctx context.Context, t *testing.T, vmgp *vmlayer.VMGroupOrchestrationParams, op *OpenstackPlatform) {

	reservedSubnets, err := op.reservedSubnets.Get(ctx)
	require.Nil(t, err)
	reservedFloatingIPs, err := op.reservedFloatingIPs.Get(ctx)
	require.Nil(t, err)
	// keep track of reserved resources, numbers should return to original values
	numReservedSubnetsStart := len(reservedSubnets)
	numReservedFipsStart := len(reservedFloatingIPs)

	numSubnetsToReserve := 0
	numFloatingIPsToReserve := 0
	for _, s := range vmgp.Subnets {
		if s.CIDR == vmlayer.NextAvailableResource {
			numSubnetsToReserve++
		}
	}
	for _, f := range vmgp.FloatingIPs {
		if f.FloatingIpId == vmlayer.NextAvailableResource {
			numFloatingIPsToReserve++
		}
	}

	out, err := yaml.Marshal(vmgp)
	require.Nil(t, err)
	fmt.Println(string(out))

	err = op.populateParams(ctx, vmgp, heatTest)
	require.Nil(t, err)

	// get updated reserved resources
	reservedSubnets, err = op.reservedSubnets.Get(ctx)
	require.Nil(t, err)
	reservedFloatingIPs, err = op.reservedFloatingIPs.Get(ctx)
	require.Nil(t, err)

	require.Equal(t, numReservedSubnetsStart+numSubnetsToReserve, len(reservedSubnets), "subnets initially reserved(%d) plus to reserve(%d) should equal currently reserved (%d)", numReservedSubnetsStart, numSubnetsToReserve, len(reservedSubnets))
	require.Equal(t, numReservedFipsStart+numFloatingIPsToReserve, len(reservedFloatingIPs), "floating IPs initially reserved(%d) plus to reserve(%d) should equal currently reserved (%d)", numReservedFipsStart, numFloatingIPsToReserve, len(reservedFloatingIPs))

	require.Nil(t, err)
	err = op.createOrUpdateHeatStackFromTemplate(ctx, vmgp, vmgp.GroupName, VmGroupTemplate, heatTest, edgeproto.DummyUpdateCallback)
	log.SpanLog(ctx, log.DebugLevelInfra, "created test stack file", "err", err)
	require.Nil(t, err)

	// reservations may be released when the owner is deleted,
	// or they may be released once the reservations are committed to the infra.
	err = op.reservedSubnets.ReleaseForOwner(ctx, vmgp.OwnerID)
	require.Nil(t, err)
	err = op.reservedFloatingIPs.ReleaseForOwner(ctx, vmgp.OwnerID)
	require.Nil(t, err)

	// get updated reserved resources
	reservedSubnets, err = op.reservedSubnets.Get(ctx)
	require.Nil(t, err)
	reservedFloatingIPs, err = op.reservedFloatingIPs.Get(ctx)
	require.Nil(t, err)

	// make sure reservations go back to previous values
	require.Equal(t, len(reservedSubnets), numReservedSubnetsStart)
	require.Equal(t, len(reservedFloatingIPs), numReservedFipsStart)

	log.SpanLog(ctx, log.DebugLevelInfra, "ReleaseReservations done", "ReservedSubnets", reservedSubnets, "err", err)

	generatedFile := vmgp.GroupName + "-heat.yaml"
	expectedResultsFile := vmgp.GroupName + "-heat-expected.yaml"
	genDat, err := os.ReadFile(generatedFile)
	require.Nil(t, err)
	expDat, err := os.ReadFile(expectedResultsFile)
	require.Nil(t, err)
	genObj := &OSHeatStackTemplate{}
	err = yaml.Unmarshal(genDat, &genObj)
	require.Nil(t, err)
	expObj := &OSHeatStackTemplate{}
	err = yaml.Unmarshal(expDat, &expObj)
	require.Nil(t, err)
	if !cmp.Equal(expObj, genObj) {
		diff := cmp.Diff(expObj, genObj)
		fmt.Println(diff)
		require.True(t, false, "should be equal")
	}

	stackTemplateData, err := os.ReadFile(generatedFile)
	require.Nil(t, err)

	stackTemplate := &OSHeatStackTemplate{}
	err = yaml.Unmarshal(stackTemplateData, stackTemplate)
	require.Nil(t, err)

	genVMsUserData := make(map[string]string)
	for _, v := range vmgp.VMs {
		userdata, err := vmlayer.GetVMUserData(v.Name, v.SharedVolume, v.DeploymentManifest, v.Command, &v.CloudConfigParams, reindent16)
		require.Nil(t, err)
		genVMsUserData[v.Name] = userdata
	}
}

func TestHeatTemplate(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelInfra)
	infracommon.SetTestMode(true)

	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	ckey := edgeproto.CloudletKey{
		Organization: "edgecloud",
		Name:         "unit-test",
	}

	pc := pf.PlatformConfig{}
	pc.CloudletKey = &ckey
	pc.SyncFactory = syncdata.NewMutexSyncFactory()

	op := OpenstackPlatform{}
	var vmp = vmlayer.VMPlatform{
		Type:         "openstack",
		VMProvider:   &op,
		VMProperties: vmlayer.VMProperties{},
	}
	err := vmp.InitProps(ctx, &pc)
	log.SpanLog(ctx, log.DebugLevelInfra, "init props done", "err", err)
	require.Nil(t, err)
	op.InitResourceReservations(ctx)
	op.VMProperties.CommonPf.Properties.SetValue("MEX_EXT_NETWORK", "external-network-shared")
	op.VMProperties.CommonPf.Properties.SetValue("MEX_EXT_NETWORK_SECONDARY", "external-network-shared-ipv6")
	op.VMProperties.CommonPf.Properties.SetValue("MEX_VM_APP_SUBNET_DHCP_ENABLED", "no")
	op.VMProperties.CommonPf.PlatformConfig.TestMode = true
	// Add chef params
	for _, vm := range vms {
		vm.ConfigureNodeVars = &confignode.ConfigureNodeVars{
			Key: edgeproto.CloudletNodeKey{
				Name:        vm.Name,
				CloudletKey: ckey,
			},
			NodeType:          vm.Type,
			NodeRole:          cloudcommon.NodeRoleDockerCrm,
			Password:          "ps123",
			AnsiblePublicAddr: "http://127.0.0.1:12345",
		}
	}

	vmgp1, err := vmp.GetVMGroupOrchestrationParamsFromVMSpec(ctx,
		"openstack-test", "1",
		vms,
		vmlayer.WithNewSecurityGroup("testvmgroup-sg"),
		vmlayer.WithAccessPorts("tcp:7777,udp:8888"),
		vmlayer.WithNewSubnet(subnetNames),
		vmlayer.WithEnableIPV6(true),
	)

	log.SpanLog(ctx, log.DebugLevelInfra, "got VM group params", "vmgp", vmgp1, "err", err)
	require.Nil(t, err)

	validateStack(ctx, t, vmgp1, &op)

	op.VMProperties.CommonPf.Properties.SetValue("MEX_VM_APP_SUBNET_DHCP_ENABLED", "yes")
	op.VMProperties.CommonPf.Properties.SetValue("MEX_NETWORK_SCHEME", "cidr=10.101.X.0/24,ipv6routingprefix=fc00:101:ecec,floatingipnet=public_internal,floatingipsubnet=subnetname,floatingipextnet=public")
	vmgp2, err := vmp.GetVMGroupOrchestrationParamsFromVMSpec(ctx,
		"openstack-fip-test", "2",
		vms,
		vmlayer.WithNewSecurityGroup("testvmgroup-sg"),
		vmlayer.WithAccessPorts("tcp:7777,udp:8888"),
		vmlayer.WithNewSubnet(subnetNames),
		vmlayer.WithEnableIPV6(true),
	)

	log.SpanLog(ctx, log.DebugLevelInfra, "got VM group params", "vmgp", vmgp2, "err", err)
	require.Nil(t, err)
	validateStack(ctx, t, vmgp2, &op)
}
