package mexos

import (
	"testing"

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
		Properties:  "hw:numa_nodes='1', pci_passthrough:alias='t4gpu:1'",
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
}

func TestParseFlavorProps(t *testing.T) {

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

}
