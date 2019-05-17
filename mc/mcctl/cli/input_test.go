package cli

import (
	"testing"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseArgs(t *testing.T) {
	input := &Input{}

	rf := ormapi.RegionFlavor{
		Region: "local",
		Flavor: edgeproto.Flavor{
			Key: edgeproto.FlavorKey{
				Name: "x1.tiny",
			},
			Vcpus: 1,
			Disk:  2,
			Ram:   3,
		},
	}
	args := []string{"region=local", "flavor.vcpus=1", "flavor.disk=2", "flavor.key.name=\"x1.tiny\"", "flavor.ram=3"}
	// basic parsing
	testParseArgs(t, input, args, &rf, &ormapi.RegionFlavor{})

	// required args
	input.RequiredArgs = []string{"regionx"}
	_, err := input.ParseArgs(args, &ormapi.RegionFlavor{})
	require.NotNil(t, err)

	input.RequiredArgs = []string{"region"}
	testParseArgs(t, input, args, &rf, &ormapi.RegionFlavor{})

	// alias args
	input.AliasArgs = []string{"name=flavor.key.name"}
	args = []string{"region=local", "flavor.vcpus=1", "flavor.disk=2", "name=x1.tiny", "flavor.ram=3"}
	testParseArgs(t, input, args, &rf, &ormapi.RegionFlavor{})

	// test extra args
	args = []string{"region=local", "flavor.vcpus=1", "flavor.disk=2", "name=x1.tiny", "flavor.ram=3", "extra.arg=foo"}
	_, err = input.ParseArgs(args, &ormapi.RegionFlavor{})
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid args")

	// test enum
	input = &Input{
		DecodeHook: edgeproto.EnumDecodeHook,
	}

	rc := ormapi.RegionCloudlet{
		Region: "local",
		Cloudlet: edgeproto.Cloudlet{
			IpSupport: edgeproto.IpSupport_IpSupportDynamic,
		},
	}
	args = []string{"region=local", "cloudlet.ipsupport=IpSupportDynamic"}
	testParseArgs(t, input, args, &rc, &ormapi.RegionCloudlet{})
}

func testParseArgs(t *testing.T, input *Input, args []string, expected, buf1 interface{}) {
	_, err := input.ParseArgs(args, buf1)
	require.Nil(t, err)
	require.Equal(t, expected, buf1)
}

func TestConversion(t *testing.T) {
	// test converting obj to args and then back to obj

	for _, flavor := range testutil.FlavorData {
		testConversion(t, &flavor, &edgeproto.Flavor{})
	}
	for _, dev := range testutil.DevData {
		testConversion(t, &dev, &edgeproto.Developer{})
	}
	for _, app := range testutil.AppData {
		testConversion(t, &app, &edgeproto.App{})
	}
	for _, op := range testutil.OperatorData {
		testConversion(t, &op, &edgeproto.Operator{})
	}
	for _, cloudlet := range testutil.CloudletData {
		testConversion(t, &cloudlet, &edgeproto.Cloudlet{})
	}
	for _, cinst := range testutil.ClusterInstData {
		testConversion(t, &cinst, &edgeproto.ClusterInst{})
	}
	for _, appinst := range testutil.AppInstData {
		testConversion(t, &appinst, &edgeproto.AppInst{})
	}
	// CloudletInfo and CloudletRefs have arrays which aren't supported yet.
}

func testConversion(t *testing.T, obj interface{}, buf interface{}) {
	args, err := MarshalArgs(obj)
	require.Nil(t, err, "marshal %v", obj)
	input := Input{
		DecodeHook: edgeproto.EnumDecodeHook,
	}
	_, err = input.ParseArgs(args, buf)
	require.Nil(t, err, "parse args %v", args)
	require.Equal(t, obj, buf)
}
