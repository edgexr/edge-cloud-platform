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
	"strings"
	"testing"

	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/stretchr/testify/require"
)

var testprop1_map = make(map[string]string)
var testprop2_map = make(map[string]string)
var testprop3_map = make(map[string]string)

var OSFlavors = []OSFlavorDetail{

	OSFlavorDetail{
		Name:        "m4.large-gpu",
		RAM:         8192,
		Ephemeral:   0,
		Properties:  "hw:mem_page_size='large', hw:numa_nodes='1', pci_passthrough:alias='t4gpu:1'",
		VCPUs:       4,
		Swap:        "",
		Public:      true,
		Disk:        80,
		RXTX_Factor: "1.0",
		ID:          "2b0297da-5c76-475e-934f-088c57f997fd",
	},
	OSFlavorDetail{
		Name:        "m4.xlarge",
		RAM:         16384,
		Ephemeral:   0,
		Properties:  "hw:mem_page_size='large'",
		VCPUs:       8,
		Swap:        "",
		Public:      true,
		Disk:        160,
		RXTX_Factor: "1.0",
		ID:          "0a6ae797-2894-40b7-820d-6172b775a1b5",
	},
	OSFlavorDetail{
		Name:        "m4.small",
		RAM:         2048,
		Ephemeral:   0,
		Properties:  "hw:mem_page_size='large'",
		VCPUs:       2,
		Swap:        "",
		Public:      true,
		Disk:        20,
		RXTX_Factor: "1.0",
		ID:          "1d9a7925-291a-4af3-b676-d4b5d6a97c9b",
	},

	OSFlavorDetail{
		Name:      "m1.medium-gpu",
		RAM:       8192,
		Ephemeral: 0,
		//		Properties:  "vmware:vgpu='1'",
		Properties:  "pci_passthrough:alias='vmware-vpu:1'",
		VCPUs:       2,
		Swap:        "",
		Public:      true,
		Disk:        40,
		RXTX_Factor: "1.0",
		ID:          "081e9cb0-b078-49f1-b1a6-daf79f4fbe30",
	},
	OSFlavorDetail{
		Name:        "m1.large",
		RAM:         8192,
		Ephemeral:   0,
		Properties:  "",
		VCPUs:       4,
		Swap:        "",
		Public:      true,
		Disk:        80,
		RXTX_Factor: "1.0",
		ID:          "3c2b6f87-ec8c-42e9-86b2-e9b32ebfae04",
	},
	OSFlavorDetail{
		Name:        "m1.xxlarge24-64-160",
		RAM:         65535,
		Ephemeral:   0,
		Properties:  "",
		VCPUs:       24,
		Swap:        "",
		Public:      true,
		Disk:        160,
		RXTX_Factor: "1.0",
		ID:          "50a563c5-bbb4-4ceb-846a-cf52ff694b21",
	},
	OSFlavorDetail{
		Name:        "m1.tiny",
		RAM:         512,
		Ephemeral:   0,
		Properties:  "",
		VCPUs:       1,
		Swap:        "",
		Public:      true,
		Disk:        1,
		RXTX_Factor: "1.0",
		ID:          "7207db65-7721-418c-af06-64c61151083f",
	},
	OSFlavorDetail{
		Name:        "m1.medium",
		RAM:         4096,
		Ephemeral:   0,
		Properties:  "",
		VCPUs:       2,
		Swap:        "",
		Public:      true,
		Disk:        40,
		RXTX_Factor: "1.0",
		ID:          "94557fcc-d217-4270-8511-79bce1d6c0c9",
	},
	// Test auto created flavor in VIO unqiue syntax
	OSFlavorDetail{
		Name:        "vmware.medium-gpu",
		RAM:         4096,
		Ephemeral:   0,
		Properties:  "vmware:vgpu='1'",
		VCPUs:       2,
		Swap:        "",
		Public:      true,
		Disk:        40,
		RXTX_Factor: "1.0",
		ID:          "94557fcc-d217-4270-8511-79bce1d6c0c9",
	},
}

func TestParseFlavorProps(t *testing.T) {

	testprop1_map["hw"] = "mem_page_size=large"
	testprop1_map["hw"] = "numa_nodes=1"
	testprop1_map["pci_passthrough"] = "alias=t4gpu:1"
	// maps are unordered, this could be a problem.
	propmap := ParseFlavorProperties(OSFlavors[0])
	require.Equal(t, testprop1_map, propmap)

	testprop2_map["hw"] = "mem_page_size=large"
	propmap = ParseFlavorProperties(OSFlavors[1])
	require.Equal(t, testprop2_map, propmap)

	testprop3_map["hw"] = "mem_page_size=large"
	propmap = ParseFlavorProperties(OSFlavors[2])
	require.Equal(t, testprop3_map, propmap)

	var finfo []*edgeproto.FlavorInfo
	//	var props map[string]string
	for _, f := range OSFlavors {
		var props map[string]string
		if f.Properties != "" {
			props = ParseFlavorProperties(f)
		}

		finfo = append(
			finfo,
			&edgeproto.FlavorInfo{
				Name:    f.Name,
				Vcpus:   uint64(f.VCPUs),
				Ram:     uint64(f.RAM),
				Disk:    uint64(f.Disk),
				PropMap: props},
		)
	}
}

func TestHeatNodePrefix(t *testing.T) {
	data := []struct {
		name string
		num  uint32
	}{
		{cloudcommon.MexNodePrefix + "1", 1},
		{cloudcommon.MexNodePrefix + "5", 5},
		{cloudcommon.MexNodePrefix + "15", 15},
		{cloudcommon.MexNodePrefix + "548934", 548934},
		{cloudcommon.MexNodePrefix + "15x", 15},
		{cloudcommon.MexNodePrefix + "15h", 15},
		{cloudcommon.MexNodePrefix + "15a", 15},
		{cloudcommon.MexNodePrefix + "15-asdf", 15},
		{cloudcommon.MexNodePrefix + "15%!@#$%^&*()1", 15},
		{cloudcommon.MexNodePrefix + "15" + cloudcommon.MexNodePrefix + "35", 15},
	}
	for _, d := range data {
		ok, num := vmlayer.ParseClusterNodePrefix(d.name)
		require.True(t, ok, "matched %s", d.name)
		require.Equal(t, d.num, num, "matched num for %s", d.name)
		// make sure prefix gen function works
		prefix := vmlayer.ClusterNodePrefix(d.num)
		ok = strings.HasPrefix(d.name, prefix)
		require.True(t, ok, "%s has prefix %s", d.name, prefix)
	}
	bad := []string{
		cloudcommon.MexNodePrefix,
		"a" + cloudcommon.MexNodePrefix + "1",
		cloudcommon.MexNodePrefix + "-1",
		"mex-k8s-master-clust-cloudlet-1",
		"mex-k8s-nod-1",
	}
	for _, b := range bad {
		ok, _ := vmlayer.ParseClusterNodePrefix(b)
		require.False(t, ok, "should not match %s", b)
	}
}

func TestIpPoolRange(t *testing.T) {
	// single pool
	n, err := getIpCountFromPools("10.10.10.1-10.10.10.20")
	require.Nil(t, err)
	require.Equal(t, uint64(20), n)
	// several pools
	n, err = getIpCountFromPools("10.10.10.1-10.10.10.20,10.10.10.30-10.10.10.40")
	require.Nil(t, err)
	require.Equal(t, uint64(31), n)
	// ipv6 pool
	n, err = getIpCountFromPools("2a01:598:4:4011::2-2a01:598:4:4011:ffff:ffff:ffff:ffff")
	require.Nil(t, err)
	require.Equal(t, uint64(18446744073709551614), n)
	// empty pool
	n, err = getIpCountFromPools("")
	require.Contains(t, err.Error(), "invalid ip pool format")
	require.Equal(t, uint64(0), n)
	// invalid pool
	n, err = getIpCountFromPools("invalid pool")
	require.Contains(t, err.Error(), "invalid ip pool format")
	require.Equal(t, uint64(0), n)
	n, err = getIpCountFromPools("invalid-pool")
	require.Contains(t, err.Error(), "Could not parse ip pool limits")
	require.Equal(t, uint64(0), n)
}
