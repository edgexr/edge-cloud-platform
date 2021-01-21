package vcd

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vmware/go-vcloud-director/v2/types/v56"
)

// Relevant types.go:

// expects -vm -vapp
func TestMeta(t *testing.T) {
	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	defer testVcdClient.Disconnect()
	if live {

		fmt.Printf("TestMeta:")

		vapp, err := tv.FindVApp(ctx, *vappName, testVcdClient)
		require.Nil(t, err, "FindVApp")

		vm, err := vapp.GetVMByName(*vmName, false)
		require.Nil(t, err, "GetVMByName")

		// create entries and add 'em to our vm obj
		fmt.Printf("TestMeta-I-have valid vapp as: %+v\n", *vappName)
		fmt.Printf("\n\tTestMeta-I-have valid vm as: %+v\n", *vmName)

		task, err := vm.AddMetadata("networkName", "external-network-shared")
		require.Nil(t, err, "vm.AddMetadata")
		err = task.WaitTaskCompletion()
		task, err = vm.AddMetadata("portName", "TCP:443")
		require.Nil(t, err, "vm.AddMetadata")
		err = task.WaitTaskCompletion()

		md, err := vm.GetMetadata()
		require.Nil(t, err, "GetMetaData")
		fmt.Printf("metadata: Type %s\n", md.Type)
		for _, ent := range md.MetadataEntry {
			fmt.Printf("\tnext ent: Key %s value: %s\n", ent.Key, ent.TypedValue.Value)
		}
	} else {
		return
	}
}

func createMetaEntry(key, value string, Type string) *types.MetadataEntry {
	ent := &types.MetadataEntry{
		Type: Type,
		Key:  key,
		TypedValue: &types.TypedValue{
			Value: value,
		},
	}
	return ent
}
