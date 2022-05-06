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

package vcd

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/url"
	"testing"

	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/stretchr/testify/require"
	"github.com/vmware/go-vcloud-director/v2/govcd"
	"github.com/vmware/go-vcloud-director/v2/types/v56"
)

func TestRMAllVAppFromVdc(t *testing.T) {
	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	defer testVcdClient.Disconnect()

	if live {
		fmt.Printf("TestRAllVAppFromVdc\n")
		vdc, err := tv.GetVdc(ctx, testVcdClient)
		if err != nil {
			fmt.Printf("Failed to get vdc %s\n", err.Error())
			return
		}
		err = vdc.Refresh()
		if err != nil {
			fmt.Printf("Refresh failed%s\n", err.Error())
			return
		}
		for _, resents := range vdc.Vdc.ResourceEntities {
			for _, resent := range resents.ResourceEntity {
				if resent.Type == VappResourceXmlType {
					vappHREF, err := url.Parse(resent.HREF)
					if err != nil {
						fmt.Printf("Error url.parse %s\n", err.Error())
						return
					}
					vapp, err := vdc.GetVAppByHref(vappHREF.String())
					if err != nil {
						fmt.Printf("error retrieving vapp with url: %s and with error %s", vappHREF.Path, err)
						return
					}
					fmt.Printf("Found %s undeploy()\n", vapp.VApp.Name)
					task, err := vapp.Undeploy()
					if err != nil {
						fmt.Printf("Undeploy failed %s\n", err.Error())
						return
					}

					if task == (govcd.Task{}) {
						continue
					}
					err = task.WaitTaskCompletion()
					if err != nil {
						fmt.Printf("Undeploy failed %s\n", err.Error())
						return
					}

					task, err = vapp.Delete()
					if err != nil {
						fmt.Printf("error deleting vapp: %s", err.Error())
						return
					}
					err = task.WaitTaskCompletion()
					if err != nil {
						fmt.Printf("couldn't finish removing vapp %s", err.Error())
						return
					}
				}
			}
		}
	}
	return
}

func TestDumpVappNetworks(t *testing.T) {
	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	defer testVcdClient.Disconnect()
	if live {
		vdc, err := tv.GetVdc(ctx, testVcdClient)
		if err != nil {
			fmt.Printf("GetVdc failed: %s\n", err.Error())
			return
		}
		fmt.Printf("TestDumpVAppNetworks...")
		vappName := "mex-cldlet3.gddt.mobiledgex.net-vapp"
		//vappName := "mex-vmware-vcd.gddt.mobiledgex.net-vapp"
		vapp, err := tv.FindVApp(ctx, vappName, testVcdClient, vdc)
		if err != nil {
			fmt.Printf("%s not found\n", vappName)
			return
		}
		networkConfig, err := vapp.GetNetworkConfig()
		if err != nil {
			fmt.Printf("GetNetworkConfig failed: %s\n", err.Error())
			return
		}

		fmt.Printf("and DumpNetworkConfig: %+v \n", networkConfig)
		//vu.DumpNetworkConfigSection(networkConfig, 1)

		fmt.Printf("\n\n")
		govcd.ShowVapp(*vapp.VApp)
	} else {
		return
	}
}

// -vapp + -vdc
func TestRMVApp(t *testing.T) {

	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	defer testVcdClient.Disconnect()

	if live {
		fmt.Printf("testRMVappVApp")
		//err = testDestroyVApp(t, ctx, *vappName)
		err = testDeleteVApp(t, ctx, *vappName)
		if err != nil {
			fmt.Printf("Error deleteing %s : %s\n", *vappName, err.Error())
		}
		fmt.Printf("%s deleted\n", *vappName)
	} else {
		return
	}
}

// Test our CreateVApp using vmlayer args

func TestMexVApp(t *testing.T) {
	live, _, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	defer testVcdClient.Disconnect()

	if live {
		fmt.Printf("testCreateVM...")
		//vm := &govcd.VM{}

		var vols []vmlayer.VolumeOrchestrationParams
		vols = append(vols, vmlayer.VolumeOrchestrationParams{
			Name:               "Mex-vol1",
			ImageName:          "ubuntu-18.04",
			Size:               40,
			AvailabilityZone:   "none",
			DeviceName:         "disk1",
			AttachExternalDisk: false,
			UnitNumber:         1,
		},
		)

		port := vmlayer.PortOrchestrationParams{ // these can contain an array of SecurityGroups of type
			// ResourceReference that I suppose restrict access to port(s)
			// Name, ID string, Preexisting bool (if false, the ref is to be created as part of this op)
			// But as for securityGroup, we don't have enough info here to create it,
			// what is the source CIDR to allow/reject?

			Name: "mex-ports",
			// FixedIPs []FixedIPOrchestrationParams
			// SecurityGroups[]ResourceReference
		}

		// use fixed, maybe do dhcp
		// We should get a fixed IP from our tv.Obj.PrimaryNet
		// .51 or .52
		var fixedIps []vmlayer.FixedIPOrchestrationParams
		fixedIps = append(fixedIps, vmlayer.FixedIPOrchestrationParams{ // ...to VMs directy (or dhcp eh?)
			LastIPOctet: 2,
			Address:     "172.70.52.2",
			Mask:        "255.255.255.0",
			Subnet: vmlayer.ResourceReference{
				Name:        "",
				Id:          "",
				Preexisting: false,
			},
			Gateway: "172.70.52.1",
		},
		)
		//	cparams := chefmgmt.ServerChefParams{}

		vmgp := vmlayer.VMGroupOrchestrationParams{}
		vmgp.GroupName = "mex-plat-vapp"
		vmgp.Ports = append(vmgp.Ports, port)

		vmparams := vmlayer.VMOrchestrationParams{

			Id:          "VMtestID",
			Name:        "MexVM1",
			Role:        vmlayer.RoleVMPlatform,
			ImageName:   "ubuntu-18.04",
			ImageFolder: "MEX-CAT01",
			HostName:    "MexVMHostName",
			DNSDomain:   "MexDomain",
			FlavorName:  "mex.medium",

			Vcpus:                   2,
			Ram:                     4092,
			Disk:                    40,
			ComputeAvailabilityZone: "nova", // xxx
			UserData:                "GuestCustomizeHere",
			MetaData:                "UserMetaData",
			SharedVolume:            false,
			AuthPublicKey:           "",
			DeploymentManifest:      "",
			Command:                 "",
			Volumes:                 vols,
			//		Ports:                   ports,
			FixedIPs:           fixedIps,
			AttachExternalDisk: false,
			//		ChefParams:              &cparams,
		}

		vmgp.VMs = append(vmgp.VMs, vmparams)

	} else {
		return
	}
}

// return a canned Item reproduced from a 2 Nic VM, this being the internal
// Network Nic type VMXNET3 (3rd Gen high perf vSphere vnic)
// So, perhaps we should pass in the existing VirtualHardwareSection, and append
// this Item to VirtualHawareItem.Connection
//
func GetVirtHwItem(t *testing.T, ctx context.Context) types.VirtualHardwareItem {
	var connections []*types.VirtualHardwareConnection
	//	connections := []&types.VirtualHardwareConnection{}
	connection := types.VirtualHardwareConnection{

		IPAddress:         "10.101.1.1",
		PrimaryConnection: false,
		IpAddressingMode:  "MANUAL",
		NetworkName:       "mex-vmware.gddt.mobiledgex.net-vappinternal-1",
	}

	connections = append(connections, &connection)

	item := types.VirtualHardwareItem{

		XMLName: xml.Name{

			Space: "http://schemas.dmtf.org/ovf/envelope/1",
			Local: "Item",
		},
		ResourceType:        10,
		ResourceSubType:     "VMXNET3",
		ElementName:         "Network adapter 1",
		Description:         "Vmxnet3 ethernet adapter on \"mex-vmware.gddt.mobiledgex.net-vappinternal-1\"",
		InstanceID:          2,
		AutomaticAllocation: true,
		Address:             "00:00:00:00:00:00", // should be auto-assigned
		AddressOnParent:     1,
		AllocationUnits:     "",
		Reservation:         0,
		VirtualQuantity:     0,
		Weight:              0,
		CoresPerSocket:      0,
		Connection:          connections,
		HostResource:        nil,
		Link:                nil,
	}
	return item
}

// need
func TestShowVApp(t *testing.T) {
	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	defer testVcdClient.Disconnect()
	if live {
		fmt.Printf("TestShowVApp-Start show vapp named %s\n", *vappName)
		vdc, err := tv.GetVdc(ctx, testVcdClient)
		if err != nil {
			fmt.Printf("GetVdc failed: %s", err.Error())
			return
		}
		_, err = vdc.GetVAppByName(*vappName, false)
		require.Nil(t, err, "GetVAppByName")

		//govcd.ShowVapp(*vapp.VApp)
	} else {
		return
	}
}

// This option builds it all from scratch, but requires a media object that is our
// v4.0.4.vmdk file, which I can't upload by itself... <sigh> We need an iso for that.
// Which we probably will end up doing to prove we can have a vm with OrgVdcNetwork + isolated VApp networks.
// First, we'll prove the concept using the ubuntu-18.04 asset we have in our catalog

// This follows the example in vm_test.go, which uses 2 vdcOrgNetworks, so we'll first prove that out,
// and assuming it works fine, try and modify for our internal network.
// We'll create a vappName'd vapp
// uses -vapp
func TestRawVApp(t *testing.T) {

	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	defer testVcdClient.Disconnect()

	if live {
		vdc, err := tv.GetVdc(ctx, testVcdClient)
		if err != nil {
			fmt.Printf("GetVdc ailed: %s\n", err.Error())
			return
		}
		fmt.Printf("TestVApp-Start create vapp named %s\n", *vappName)

		// 1) create raw vapp, and 2) add networks:
		err = vdc.ComposeRawVApp(*vappName)
		require.Nil(t, err, "vdc.CreateRawVapp")

		vapp, err := vdc.GetVAppByName(*vappName, false)
		require.Nil(t, err, "GetVAppByName")

		govcd.ShowVapp(*vapp.VApp)

		// Retrive our template, we need the HREF of it's VM
		tmpl, err := tv.FindTemplate(ctx, *tmplName, testVcdClient)
		require.Nil(t, err, "FindTemplate")
		childvm := tmpl.VAppTemplate.Children.VM[0]
		// 3) and a new vm w/template and VmGeneralParams (Change the vm name)
		// The only type that includes this is SourcedCompositionItemParam
		//

		IParams := &types.InstantiationParams{
			//		CustomizationSection:         *CustomizationSection         `xml:"CustomizationSection,omitempty"`
			//	DefaultStorageProfileSection *DefaultStorageProfileSection `xml:"DefaultStorageProfileSection,omitempty"`
			//	GuestCustomizationSection    *GuestCustomizationSection    `xml:"GuestCustomizationSection,omitempty"`
			//	LeaseSettingsSection         *LeaseSettingsSection         `xml:"LeaseSettingsSection,omitempty"`
			//	NetworkConfigSection         *NetworkConfigSection         `xml:"NetworkConfigSection,omitempty"`
			//	NetworkConnectionSection     *NetworkConnectionSection     `xml:"NetworkConnectionSection,omitempty"`
			//	ProductSection               *ProductSection               `xml:"ProductSection,omitempty"`
		}
		// NetworkAssignment maps a network name specified in a Vm to the network name of a
		// vApp network defined in the VApp that contains the Vm
		netMappings := []*types.NetworkAssignment{}
		netMapping := &types.NetworkAssignment{
			InnerNetwork:     "local vm network name",
			ContainerNetwork: "Name of Vapp network to map to",
		}
		netMappings = append(netMappings, netMapping)

		vmGeneralParams := types.VMGeneralParams{
			Name: *vmName,
		}
		childRef := &types.Reference{
			HREF: childvm.HREF,
			Type: childvm.Type,
			ID:   childvm.ID,
			Name: childvm.Name,
		}
		// empty winds default
		storProf := &types.Reference{}
		locParamsRef := &types.LocalityParams{}

		// sourceItem found in InstantiateVAppTemplateParams, ReComposeVAppParams, ComposeVAppParams
		vmSourceItem := types.SourcedCompositionItemParam{
			SourceDelete:      false, // don't delete the childvm after copy
			Source:            childRef,
			VMGeneralParams:   &vmGeneralParams,
			VAppScopedLocalID: *vappName + "vm 1",

			//If Source references a Vm this can include any of the following OVF sections:
			// VirtualHardwareSection OperatingSystemSection NetworkConnectionSection GuestCustomizationSection.
			InstantiationParams: IParams,

			// If Source references a Vm, this element maps a network name specified in the
			// Vm to the network name of a vApp network defined in the composed vApp.
			NetworkAssignment: netMappings,
			StorageProfile:    storProf,

			// LocalityParams represents locality parameters.
			// Locality parameters provide a hint that may help the placement engine optimize placement
			// of a VM with respect to another VM or an independent disk.
			LocalityParams: locParamsRef,
		}

		fmt.Printf("vmSourceItem: %+v\n", vmSourceItem)
		guestCustom := &types.GuestCustomizationSection{}
		connections := []*types.NetworkConnection{}

		//connectionSection := childvm.NetworkConnectionSection

		netConnect := &types.NetworkConnectionSection{
			XMLName:                       xml.Name{},
			Xmlns:                         types.XMLNamespaceVCloud,
			Ovf:                           types.XMLNamespaceOVF,
			Info:                          " info ",
			HREF:                          childvm.HREF,
			Type:                          "10", // XXX VMXNET3 type thing.
			PrimaryNetworkConnectionIndex: 0,
			NetworkConnection:             connections,
			//		Link :
		}
		vmSpec := &types.VmSpecSection{}

		bootMedia := &types.Media{}

		createItem := &types.CreateItem{
			Name:                      *vmName,
			Description:               "test vm with 2 nics",
			GuestCustomizationSection: guestCustom,
			NetworkConnectionSection:  netConnect,
			VmSpecSection:             vmSpec,
			BootImage:                 bootMedia,
		}

		reComposeParams := types.RecomposeVAppParamsForEmptyVm{
			XMLName:          xml.Name{},
			XmlnsVcloud:      types.XMLNamespaceVCloud,
			XmlnsOvf:         types.XMLNamespaceOVF,
			CreateItem:       createItem,
			AllEULAsAccepted: true,
		}

		// before we resort to recreating our vm , try to update our existing section
		vm, err := vapp.AddEmptyVm(&reComposeParams)

		cpuCount := 4
		vmSpecSection := &types.VmSpecSection{
			NumCpus: &cpuCount,
		}

		vm, err = vm.UpdateVmSpecSection(vmSpecSection, "testing")
		if err != nil {
			fmt.Printf("error UpdateVmSpecSection: %s\n", err.Error())
		}
		/*
			err = testDestroyVApp(t, ctx, vappName)
			if err != nil {
				fmt.Printf("TestVApp-E-error deleting vapp: %s\n", err.Error())
				return
			}
		*/
		// now try recompsoing the Vapp...
	} else {
		return
	}
}

func testCreateVAppChild() (*types.VAppTemplate, error) {
	//netConfig := []VAppNetworkConfiguratin{}
	tmpl := &types.VAppTemplate{}
	/*
		netConfig = append(netconfig, types.VAppNetworkConfiguratin {
			Configuration :
		}
		// is just another vapptemplate

		tmpl := govcd.NewVappTemplate {
			Name: "mex-platform-vm-1",
			NetworkConfigSection :    *types.NetworkConfigSection {
				NetworkConfig : NetConfig
			},
	*/
	/*
		NetworkConnectionSection: *types.NetworkConnectionSection {


		},
	*/

	return tmpl, nil
}

//
// from scratch vs  using an existing template.
//
func testPopulateVappTmpl(t *testing.T, ctx context.Context, tmplName string) *govcd.VAppTemplate {
	tmpl := govcd.NewVAppTemplate(&testVcdClient.Client)

	fmt.Printf("PopuldateVappTemplate, must have VAppTemplateChildren !- nil and networks not nil\n")

	tmpl.VAppTemplate.Name = tmplName

	return tmpl
}

// For our platform LB, this net
// Alternatively, you can vapp.UpateNetwork(newNetworkSettings, orgNetwork)
// How to get from NetworkConfigSection to it's OrgVDCNetowrk?
func createInternalNetwork(t *testing.T, ctx context.Context, vapp *govcd.VApp) (*types.OrgVDCNetwork, error) {

	fmt.Printf("createInternalNetwork-I-creating for vapp %s in state %s\n", vapp.VApp.Name, types.VAppStatuses[vapp.VApp.Status])

	net := &types.OrgVDCNetwork{}
	IPScope := types.IPScope{
		IsInherited: false,
		Gateway:     "10.101.1.1",
		Netmask:     "255.255.255.0",
		//		DNS1: "
		//DNS2:
		//DNSSuffix
		//IsEnabled:
		//IPRanges: // for static pool allocation in the network
		//AllocatedIPAddresses readonly list
		//SubAllocations readonly list

	}
	//	dumpIPScopes(IPScope, 1)

	interIPRange := types.IPRange{
		StartAddress: "10.101.1.1",
		EndAddress:   "10.101.1.22",
	}
	var iprange []*types.IPRange
	iprange = append(iprange, &interIPRange)

	// This guy is the 10 dot gateway
	internalSettings := govcd.VappNetworkSettings{
		//		ID:          vdcnet.ID,
		Name:        "vapp-internal1",
		Description: "internal 10.101.1.0/24 static",
		Gateway:     "10.101.1.1",
		NetMask:     "255.255.255.0",
		DNS1:        IPScope.DNS1,
		DNS2:        IPScope.DNS2,
		DNSSuffix:   IPScope.DNSSuffix,
		//		GuestVLANAllowed: true,    default is?
		StaticIPRanges: iprange,
	}

	InternalNetConfigSec, err := vapp.CreateVappNetwork(&internalSettings, nil)
	if err != nil {
		return nil, fmt.Errorf("CreateVappNetwork Internal error %s", err.Error())
	}

	// how to wait here?
	fmt.Printf("what to do with InternalNetConfigSec?: %+v\n", InternalNetConfigSec)
	return net, nil
}

// Powering off vs Undeplpy
// Undeploy is what you want if your aim is to delete the vapp
// So for instance DeleteVMs where vmgp.GroupName represents a cluster you
// want deleted. Not going to power it back on sometime later.
// Doesn't matter if the vapp is current powered on or off, this will delete it.
//
func testDeleteVApp(t *testing.T, ctx context.Context, name string) error {
	live, ctx, err := InitVcdTestEnv()
	if err != nil {
		return err
	}
	if live {
		vdc, err := tv.GetVdc(ctx, testVcdClient)
		if err != nil {
			fmt.Printf("GetVdc failed: %s\n", err.Error())
			return err
		}
		vapp, err := vdc.GetVAppByName(name, true)
		if err != nil {
			fmt.Printf("testDestroyVApp-E-error Getting Vapp %s by name: %s\n", name, err.Error())
			return err
		}
		// Info only.
		vappStatus, err := vapp.GetStatus()
		if err != nil {
			fmt.Printf("Error fetching status for vapp %s\n", name)
			return err
		}
		fmt.Printf("Vapp %s currently in state: %s\n", name, vappStatus)
		task, err := vapp.Undeploy()
		if err != nil {
			fmt.Printf("Error from vapp.Undploy the vapp  as : %s CONTINUE \n", err.Error())
		} else {
			err = task.WaitTaskCompletion()
			if err != nil {
				fmt.Printf("Error waiting undeploy of the vapp first %s CONTINUE\n", name)
			}
		}
		vappStatus, err = vapp.GetStatus()
		fmt.Printf("vapp  status now %s \n", vappStatus)
		for _, tvm := range vapp.VApp.Children.VM {
			vm, err := vapp.GetVMByName(tvm.Name, true)
			if err != nil {
				fmt.Printf("Error GetVMByName  as : %s\n", err.Error())
				return err
			}
			vm.Undeploy()
			fmt.Printf("Powering off vm %s for vapp deletion\n", vm.VM.Name)
			task, err := vm.PowerOff()
			if err != nil {
				fmt.Printf("Error from PowerOFf  vm %s  : %s Continue\n", vm.VM.Name, err.Error())
			} else {
				err = task.WaitTaskCompletion()
				if err != nil {
					fmt.Printf("Error waiting for power off : %s Continue\n", err.Error())
				}
			}
			vm.Delete()
			fmt.Printf("VM should be off\n")
		}
		fmt.Printf("Calling vapp.Delete()\n")
		task, err = vapp.Delete()
		if err != nil {
			fmt.Printf("vapp.Delete failed: %s\n current status: %s Continue\n", err.Error(), vappStatus)
		}
		err = task.WaitTaskCompletion()
		if err != nil {
			fmt.Printf("Wait task for delete vapp failed:  %s\n", err.Error())
			return err
		} else {
			fmt.Printf("VApp %s Deleted.\n", name)
		}
	}
	return nil
}

func testUpdateVApp(t *testing.T, ctx context.Context) {

}

func testAddNetworksToVApp(t *testing.T, ctx context.Context) {

}

func testInsertMediaToVApp(t *testing.T, ctx context.Context) {

}

// Add vm from vapptemplate with a custom networkConnectionSection
//
func testAddVMToVApp(t *testing.T, ctx context.Context, netName string, vapp *govcd.VApp, tmpl govcd.VAppTemplate, network *types.NetworkConnectionSection) (*govcd.VApp, error) {

	//storRef := types.Reference{}
	task, err := vapp.AddNewVM(netName, tmpl, network, true)
	if err != nil {
		fmt.Printf("Error Adding second VM with internal net only err: %s\n", err.Error())
		return vapp, nil
	}
	fmt.Printf("Task for AddNewVM: %+v\n", task)
	return vapp, nil
}

func testPowerOnVApp(t *testing.T, ctx context.Context, vapp *govcd.VApp) error {

	task, err := vapp.PowerOn()
	if err != nil {
		fmt.Printf("Error powering on vapp %s err: %s\n", vapp.VApp.Name, err.Error())

	}
	fmt.Printf("\nTask powerOn: %+v\n", task)
	return err
}

func testPowerOffVApp(t *testing.T, ctx context.Context, vapp *govcd.VApp) error {

	task, err := vapp.PowerOff()
	if err != nil {
		fmt.Printf("Error powering off vapp %s err: %s\n", vapp.VApp.Name, err.Error())

	}
	fmt.Printf("\nTask powerOff: %+v\n", task)
	return err
}

func getCreateItemForInternalNetwork(t *testing.T, ctx context.Context) *types.CreateItem {
	ci := &types.CreateItem{}

	return ci
}

func validateNetworkConfigSettings(networkSettings *govcd.VappNetworkSettings) error {
	if networkSettings.Name == "" {
		return fmt.Errorf("network name is missing")
	}

	if networkSettings.Gateway == "" {
		return fmt.Errorf("network gateway IP is missing")
	}

	if networkSettings.NetMask == "" {
		return fmt.Errorf("network mask config is missing")
	}

	if networkSettings.NetMask == "" {
		return fmt.Errorf("network mask config is missing")
	}

	if networkSettings.DhcpSettings != nil && networkSettings.DhcpSettings.IPRange == nil {
		return fmt.Errorf("network DHCP ip range config is missing")
	}

	if networkSettings.DhcpSettings != nil && networkSettings.DhcpSettings.IPRange.StartAddress == "" {
		return fmt.Errorf("network DHCP ip range start address is missing")
	}
	return nil
}

// -vapp -net
func TestExtAddrVApp(t *testing.T) {

	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	defer testVcdClient.Disconnect()

	if live {
		vdc, err := tv.GetVdc(ctx, testVcdClient)
		if err != nil {
			fmt.Printf("GetVdc failed: %s\n", err.Error())
			return
		}
		vapp, err := tv.FindVApp(ctx, *vappName, testVcdClient, vdc)
		require.Nil(t, err, "FindVapp")
		fmt.Printf("TestVApp-Start create vapp named %s in vdc %s \n", *vappName, *vdcName)

		addr, err := tv.GetAddrOfVapp(ctx, vapp, *netName)

		if err != nil {
			fmt.Printf("error from GetAddrOfVapp : %s\n", err.Error())
			return
		}
		fmt.Printf("Vapp %s has external address as %s\n", *vappName, addr)
	}
}

func TestListAllVApps(t *testing.T) {

	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	defer testVcdClient.Disconnect()

	if live {
		vdc, err := tv.GetVdc(ctx, testVcdClient)
		if err != nil {
			fmt.Printf("GetVdc failed: %s", err.Error())
			return
		}

		fmt.Printf("List all VApps in vdc\n")
		resRefs := vdc.GetVappList()
		if err != nil {
			fmt.Printf("GetVappList failed: %s", err.Error())
			return
		}

		for _, ref := range resRefs {
			fmt.Printf("Vapp : %s\n", ref.Name)
		}
	}
}
