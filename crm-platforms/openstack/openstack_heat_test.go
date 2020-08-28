package openstack

import (
	"context"
	yaml "github.com/mobiledgex/yaml/v2"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/mobiledgex/edge-cloud-infra/chefmgmt"
	e2esetup "github.com/mobiledgex/edge-cloud-infra/e2e-tests/e2e-setup"
	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	pf "github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
	"github.com/stretchr/testify/require"
)

var subnetName = "subnet-test"
var testGroupName = "openstack-test"

var vms = []*vmlayer.VMRequestSpec{
	{
		Name:                    "rootlb-xyz",
		Type:                    vmlayer.VMTypeRootLB,
		FlavorName:              "m1.medium",
		ImageName:               "mobiledgex-v9.9.9",
		ComputeAvailabilityZone: "nova1",
		ExternalVolumeSize:      100,
		ConnectToExternalNet:    true,
		ConnectToSubnet:         subnetName,
	},
	{
		Name:                    "master-xyz",
		Type:                    vmlayer.VMTypeClusterMaster,
		FlavorName:              "m1.medium",
		ImageName:               "mobiledgex-v9.9.9",
		ComputeAvailabilityZone: "nova1",
		ExternalVolumeSize:      100,
		ConnectToExternalNet:    true,
		ConnectToSubnet:         subnetName,
	},
	{
		Name:                    "node1-xyz",
		Type:                    vmlayer.VMTypeClusterNode,
		FlavorName:              "m1.medium",
		ImageName:               "mobiledgex-v9.9.9",
		ComputeAvailabilityZone: "nova1",
		ConnectToSubnet:         subnetName,
	},
	{
		Name:                    "node2-xyz",
		Type:                    vmlayer.VMTypeClusterNode,
		FlavorName:              "m1.medium",
		ImageName:               "mobiledgex-v9.9.9",
		ComputeAvailabilityZone: "nova1",
		ConnectToSubnet:         subnetName,
	},
}

func TestHeatTemplate(t *testing.T) {
	log.InitTracer("")
	defer log.FinishTracer()
	log.SetDebugLevel(log.DebugLevelInfra)
	infracommon.SetTestMode(true)

	ctx := log.StartTestSpan(context.Background())
	vaultServer, vaultConfig := vault.DummyServer()
	defer vaultServer.Close()

	ckey := edgeproto.CloudletKey{
		Organization: "MobiledgeX",
		Name:         "unit-test",
	}
	pc := pf.PlatformConfig{}
	pc.CloudletKey = &ckey

	op := OpenstackPlatform{TestMode: true}
	var vmp = vmlayer.VMPlatform{
		Type:       "openstack",
		VMProvider: &op,
	}
	err := vmp.InitProps(ctx, &pc, vaultConfig)
	log.SpanLog(ctx, log.DebugLevelInfra, "init props done", "err", err)
	require.Nil(t, err)
	op.VMProperties.CommonPf.Properties.SetValue("MEX_EXT_NETWORK", "external-network-shared")

	// Add chef params
	for _, vm := range vms {
		vm.ChefParams = &chefmgmt.VMChefParams{
			NodeName:   vm.Name,
			ServerPath: "cheftestserver.mobiledgex.net/organizations/mobiledgex",
			ClientKey:  "-----BEGIN RSA PRIVATE KEY-----\nNDFGHJKLJHGHJKJNHJNBHJNBGYUJNBGHJNBGSZiO/8i6ERbmqPopV8GWC5VjxlZm\n-----END RSA PRIVATE KEY-----",
		}
	}

	vmgp, err := vmp.GetVMGroupOrchestrationParamsFromVMSpec(ctx,
		testGroupName,
		vms,
		vmlayer.WithNewSecurityGroup("testvmgroup-sg"),
		vmlayer.WithAccessPorts("tcp:7777,udp:8888"),
		vmlayer.WithNewSubnet(subnetName),
	)

	log.SpanLog(ctx, log.DebugLevelInfra, "got VM group params", "vmgp", vmgp, "err", err)
	require.Nil(t, err)

	err = op.populateParams(ctx, vmgp, heatTest)
	require.Nil(t, err)

	err = op.createOrUpdateHeatStackFromTemplate(ctx, vmgp, testGroupName, VmGroupTemplate, heatTest, edgeproto.DummyUpdateCallback)
	log.SpanLog(ctx, log.DebugLevelInfra, "created test stack file", "err", err)
	require.Nil(t, err)

	generatedFile := testGroupName + "-heat.yaml"
	expectedResultsFile := testGroupName + "-heat-expected.yaml"
	compareResult := e2esetup.CompareYamlFiles(generatedFile, expectedResultsFile, "heat-test")
	log.SpanLog(ctx, log.DebugLevelInfra, "yaml compare result", "compareResult", compareResult)

	require.Equal(t, compareResult, true)

	stackTemplateData, err := ioutil.ReadFile(generatedFile)
	require.Nil(t, err)

	stackTemplate := &OSHeatStackTemplate{}
	err = yaml.Unmarshal(stackTemplateData, stackTemplate)
	require.Nil(t, err)

	keys, err := GetChefKeysFromOSResource(ctx, stackTemplate)
	require.Nil(t, err)
	require.Equal(t, 4, len(keys))

	for _, key := range keys {
		require.True(t, strings.HasPrefix(key, "-----BEGIN RSA PRIVATE KEY-----"))
		require.True(t, strings.HasSuffix(key, "-----END RSA PRIVATE KEY-----"))
	}
}
