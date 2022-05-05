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
	"io/ioutil"
	"strings"
	"testing"

	yaml "github.com/mobiledgex/yaml/v2"

	"github.com/edgexr/edge-cloud-infra/chefmgmt"
	e2esetup "github.com/edgexr/edge-cloud-infra/e2e-tests/e2e-setup"
	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/accessapi"
	pf "github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/setup-env/util"
	"github.com/edgexr/edge-cloud/vault"
	"github.com/stretchr/testify/require"
)

var subnetName = "subnet-test"

var vms = []*vmlayer.VMRequestSpec{
	{
		Name:                    "rootlb-xyz",
		Type:                    cloudcommon.NodeTypeDedicatedRootLB,
		FlavorName:              "m1.medium",
		ImageName:               "mobiledgex-v9.9.9",
		ComputeAvailabilityZone: "nova1",
		ExternalVolumeSize:      100,
		ConnectToExternalNet:    true,
		ConnectToSubnet:         subnetName,
	},
	{
		Name:                    "master-xyz",
		Type:                    cloudcommon.NodeTypeK8sClusterMaster,
		FlavorName:              "m1.medium",
		ImageName:               "mobiledgex-v9.9.9",
		ComputeAvailabilityZone: "nova1",
		ExternalVolumeSize:      100,
		ConnectToExternalNet:    true,
		ConnectToSubnet:         subnetName,
	},
	{
		Name:                    "node1-xyz",
		Type:                    cloudcommon.NodeTypeK8sClusterNode,
		FlavorName:              "m1.medium",
		ImageName:               "mobiledgex-v9.9.9",
		ComputeAvailabilityZone: "nova1",
		ConnectToSubnet:         subnetName,
	},
	{
		Name:                    "node2-xyz",
		Type:                    cloudcommon.NodeTypeK8sClusterNode,
		FlavorName:              "m1.medium",
		ImageName:               "mobiledgex-v9.9.9",
		ComputeAvailabilityZone: "nova1",
		ConnectToSubnet:         subnetName,
	},
	{
		Name:                    "app-vm",
		Type:                    cloudcommon.NodeTypeAppVM,
		FlavorName:              "m1.medium",
		ImageName:               "mobiledgex-v9.9.9",
		ComputeAvailabilityZone: "nova1",
		ConnectToSubnet:         subnetName,
	},
}

func validateStack(ctx context.Context, t *testing.T, vmgp *vmlayer.VMGroupOrchestrationParams, op *OpenstackPlatform) {

	// keep track of reserved resources, numbers should return to original values
	numReservedSubnetsStart := len(ReservedSubnets)
	numReservedFipsStart := len(ReservedFloatingIPs)

	resources, err := op.populateParams(ctx, vmgp, heatTest)
	log.SpanLog(ctx, log.DebugLevelInfra, "populateParams done", "resources", resources, "err", err)

	require.Equal(t, len(resources.Subnets), len(ReservedSubnets)+numReservedSubnetsStart)
	require.Equal(t, len(resources.FloatingIpIds), len(ReservedFloatingIPs)+numReservedFipsStart)

	require.Nil(t, err)
	err = op.createOrUpdateHeatStackFromTemplate(ctx, vmgp, vmgp.GroupName, VmGroupTemplate, heatTest, edgeproto.DummyUpdateCallback)
	log.SpanLog(ctx, log.DebugLevelInfra, "created test stack file", "err", err)
	require.Nil(t, err)

	err = op.ReleaseReservations(ctx, resources)
	require.Nil(t, err)

	// make sure reservations go back to previous values
	require.Equal(t, len(ReservedSubnets), numReservedSubnetsStart)
	require.Equal(t, len(ReservedFloatingIPs), numReservedFipsStart)

	log.SpanLog(ctx, log.DebugLevelInfra, "ReleaseReservations done", "ReservedSubnets", ReservedSubnets, "err", err)

	generatedFile := vmgp.GroupName + "-heat.yaml"
	expectedResultsFile := vmgp.GroupName + "-heat-expected.yaml"
	compare := util.CompareYaml{
		Yaml1:    generatedFile,
		Yaml2:    expectedResultsFile,
		FileType: "heat-test",
	}
	compareResult := e2esetup.CompareYamlFiles("heat compare", []string{}, &compare)
	log.SpanLog(ctx, log.DebugLevelInfra, "yaml compare result", "compareResult", compareResult)

	require.Equal(t, compareResult, true)

	stackTemplateData, err := ioutil.ReadFile(generatedFile)
	require.Nil(t, err)

	stackTemplate := &OSHeatStackTemplate{}
	err = yaml.Unmarshal(stackTemplateData, stackTemplate)
	require.Nil(t, err)

	keys, err := GetChefKeysFromOSResource(ctx, stackTemplate)
	require.Nil(t, err)
	require.Equal(t, 5, len(keys))

	for _, key := range keys {
		require.True(t, strings.HasPrefix(key, "-----BEGIN RSA PRIVATE KEY-----"))
		require.True(t, strings.HasSuffix(key, "-----END RSA PRIVATE KEY-----"))
	}

	genVMsUserData := make(map[string]string)
	for _, v := range vmgp.VMs {
		userdata, err := vmlayer.GetVMUserData(v.Name, v.SharedVolume, v.DeploymentManifest, v.Command, &v.CloudConfigParams, reindent16)
		require.Nil(t, err)
		genVMsUserData[v.Name] = userdata
	}

	vmsUserData, err := GetUserDataFromOSResource(ctx, stackTemplate)
	require.Nil(t, err)
	require.Equal(t, 5, len(vmsUserData))
	for vName, userData := range vmsUserData {
		require.True(t, strings.HasPrefix(userData, "#cloud-config"))
		genUserData, ok := genVMsUserData[vName]
		require.True(t, ok)
		require.True(t, IsUserDataSame(ctx, genUserData, userData), "userdata mismatch")
	}
}

func validateReservations(ctx context.Context, t *testing.T, op *OpenstackPlatform) {
	log.SpanLog(ctx, log.DebugLevelInfra, "validateReservations")
	testRes := ReservedResources{
		FloatingIpIds: []string{"fipid-xyz", "fipid-abc"},
		Subnets:       []string{"10.101.99.0", "10.101.88.0"},
	}

	// reserve one of each one at a time
	err := op.reserveFloatingIPLocked(ctx, testRes.FloatingIpIds[0], "heat-test")
	require.Nil(t, err)
	err = op.reserveSubnetLocked(ctx, testRes.Subnets[0], "heat-test")
	require.Nil(t, err)

	// reserve second of each one at a time
	err = op.reserveSubnetLocked(ctx, testRes.Subnets[1], "heat-test")
	require.Nil(t, err)
	err = op.reserveFloatingIPLocked(ctx, testRes.FloatingIpIds[1], "heat-test")
	require.Nil(t, err)

	// try to reserve one already used
	err = op.reserveFloatingIPLocked(ctx, testRes.FloatingIpIds[0], "heat-test")
	require.Contains(t, err.Error(), "Floating IP already reserved")
	err = op.reserveSubnetLocked(ctx, testRes.Subnets[0], "heat-test")
	require.Contains(t, err.Error(), "Subnet CIDR already reserved")

	// release and try again
	err = op.ReleaseReservations(ctx, &testRes)
	require.Nil(t, err)

	err = op.ReserveResourcesLocked(ctx, &testRes, "heat-test")
	require.Nil(t, err)

	// should have 2 of each reserved
	require.Equal(t, len(ReservedSubnets), 2)
	require.Equal(t, len(ReservedFloatingIPs), 2)

	// release and verify nothing is still reserved
	err = op.ReleaseReservations(ctx, &testRes)
	require.Nil(t, err)

	// try to release again, this should error
	err = op.ReleaseReservations(ctx, &testRes)
	require.Contains(t, err.Error(), "Floating IP not reserved, cannot be released")
	require.Contains(t, err.Error(), "Subnet not reserved, cannot be released")

	// nothing should still be reserved
	require.Equal(t, len(ReservedSubnets), 0)
	require.Equal(t, len(ReservedFloatingIPs), 0)

}

func TestHeatTemplate(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelInfra)
	infracommon.SetTestMode(true)

	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())
	vaultServer, vaultConfig := vault.DummyServer()
	defer vaultServer.Close()

	ckey := edgeproto.CloudletKey{
		Organization: "MobiledgeX",
		Name:         "unit-test",
	}
	cloudlet := edgeproto.Cloudlet{
		Key:          ckey,
		PhysicalName: ckey.Name,
	}
	accessApi := accessapi.NewVaultClient(&cloudlet, vaultConfig, "local")

	pc := pf.PlatformConfig{}
	pc.CloudletKey = &ckey
	pc.AccessApi = accessApi

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
	op.VMProperties.CommonPf.Properties.SetValue("MEX_VM_APP_SUBNET_DHCP_ENABLED", "no")
	op.VMProperties.CommonPf.PlatformConfig.TestMode = true
	// Add chef params
	for _, vm := range vms {
		vm.ChefParams = &chefmgmt.ServerChefParams{
			NodeName:   vm.Name,
			ServerPath: "cheftestserver.mobiledgex.net/organizations/mobiledgex",
			ClientKey:  "-----BEGIN RSA PRIVATE KEY-----\nNDFGHJKLJHGHJKJNHJNBHJNBGYUJNBGHJNBGSZiO/8i6ERbmqPopV8GWC5VjxlZm\n-----END RSA PRIVATE KEY-----",
		}
	}

	vmgp1, err := vmp.GetVMGroupOrchestrationParamsFromVMSpec(ctx,
		"openstack-test",
		vms,
		vmlayer.WithNewSecurityGroup("testvmgroup-sg"),
		vmlayer.WithAccessPorts("tcp:7777,udp:8888", infracommon.RemoteCidrAll),
		vmlayer.WithNewSubnet(subnetName),
	)

	log.SpanLog(ctx, log.DebugLevelInfra, "got VM group params", "vmgp", vmgp1, "err", err)
	require.Nil(t, err)
	validateStack(ctx, t, vmgp1, &op)

	op.VMProperties.CommonPf.Properties.SetValue("MEX_VM_APP_SUBNET_DHCP_ENABLED", "yes")
	op.VMProperties.CommonPf.Properties.SetValue("MEX_NETWORK_SCHEME", "cidr=10.101.X.0/24,floatingipnet=public_internal,floatingipsubnet=subnetname,floatingipextnet=public")
	vmgp2, err := vmp.GetVMGroupOrchestrationParamsFromVMSpec(ctx,
		"openstack-fip-test",
		vms,
		vmlayer.WithNewSecurityGroup("testvmgroup-sg"),
		vmlayer.WithAccessPorts("tcp:7777,udp:8888", infracommon.RemoteCidrAll),
		vmlayer.WithNewSubnet(subnetName),
		vmlayer.WithSkipInfraSpecificCheck(true),
	)

	log.SpanLog(ctx, log.DebugLevelInfra, "got VM group params", "vmgp", vmgp2, "err", err)
	require.Nil(t, err)
	validateStack(ctx, t, vmgp2, &op)

	validateReservations(ctx, t, &op)

}
