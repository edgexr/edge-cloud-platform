package vcd

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/stretchr/testify/require"
	"github.com/vmware/go-vcloud-director/v2/govcd"
	"github.com/vmware/go-vcloud-director/v2/types/v56"
)

// -vapp
func TestNextIntAddr(t *testing.T) {
	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	defer testVcdClient.Disconnect()
	var updateCallback edgeproto.CacheUpdateCallback
	if live {
		// vappName is just logging here
		nextAddr, reuse, err := tv.GetNextInternalSubnet(ctx, *vappName, updateCallback, testVcdClient)
		if err != nil {
			fmt.Printf("Error getting next addr  : %s\n", err.Error())
			return
		}
		// reuse true if we've reused an existing iosnet found
		fmt.Printf("reuse: %t\n", reuse)
		require.Equal(t, nextAddr, "10.101.2.1")

	}
}

func TestGetVdcNetworks(t *testing.T) {
	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	defer testVcdClient.Disconnect()

	if live {
		fmt.Printf("TestGetVdcNetworks...\n")
		vdc, err := tv.GetVdc(ctx, testVcdClient)
		if err != nil {
			fmt.Printf("GetVdc failed: %s\n", err.Error())
			return
		}
		//types.QueryResultOrgVdcNetworkRecordType
		qrecs, err := vdc.GetNetworkList()
		if err != nil {
			fmt.Printf("vdc.GetNetworkList failed: %s\n", err.Error())
			return
		}
		for _, qr := range qrecs {
			// linkType 0 = direct, 1 = routed, 2 = isolated
			fmt.Printf("vdc %s network:\n\tName:  %s\n\tType: %s\n\tMask: %s\n\tLinkType %d\n\tConnectetdTo: %s\n\tDefaultGateway: %s\n\tIsShared: %t\n", vdc.Vdc.Name, qr.Name,
				qr.Type, qr.Netmask, qr.LinkType, qr.ConnectedTo, qr.DefaultGateway, qr.IsShared)
		}
	}
}

func TestRMOrgVdcType2Networks(t *testing.T) {
	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	defer testVcdClient.Disconnect()

	if live {
		vdc, err := tv.GetVdc(ctx, testVcdClient)
		if err != nil {
			fmt.Printf("GetVdc failed: %s\n", err.Error())
			return
		}
		qrecs, err := vdc.GetNetworkList()
		if err != nil {
			fmt.Printf("vdc.GetNetworkList failed: %s\n", err.Error())
			return
		}
		for _, qr := range qrecs {
			// linkType 0 = direct, 1 = routed, 2 = isolated
			fmt.Printf("vdc %s network:\n\tName:  %s\n\tType: %s\n\tMask: %s\n\tLinkType %d\n\tConnectetdTo: %s\n\tDefaultGateway: %s\n", vdc.Vdc.Name, qr.Name,
				qr.Type, qr.Netmask, qr.LinkType, qr.ConnectedTo, qr.DefaultGateway)
			if qr.LinkType == 2 {
				fmt.Printf("Removing iso subnet %s\n", qr.Name)
				orgvcdnet, err := vdc.GetOrgVdcNetworkByName(qr.Name, false)
				if err != nil {
					fmt.Printf("Error getting %s by name: %s\n", qr.Name, err.Error())
					return
				}
				task, err := orgvcdnet.Delete()
				if err != nil {
					fmt.Printf("Error deleting  %s  %s\n", qr.Name, err.Error())
				} else {
					fmt.Printf("isolated network %s Deleted\n", qr.Name)
					err = task.WaitTaskCompletion()
					if err != nil {
						fmt.Printf("error deleting network '%s' [task]: %s", qr.Name, err)
						// continue with any others
					}
				}
			}
		}
	}
}

// -vapp -net Return the current external net address
func TestGetVappAddr(t *testing.T) {
	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	defer testVcdClient.Disconnect()

	if live {
		vapp, err := tv.FindVApp(ctx, *vappName, testVcdClient)
		if err != nil {
			fmt.Printf("Test error finding vapp %s\n", *vappName)
			return
		}
		fmt.Printf("Ask GetAddrOfVapp vapp %s netname %s\n", *vappName, *netName)
		addr, err := tv.GetAddrOfVapp(ctx, vapp, *netName)
		if err != nil {
			fmt.Printf("Test error from GetExtAddrOfVapp  %s = %s \n", *vappName, err.Error())
			return
		}

		fmt.Printf("Next ext-net Address: %s\n", addr)
	}
}

// -vapp
func TestGetVappNetworks(t *testing.T) {
	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	defer testVcdClient.Disconnect()
	if live {
		fmt.Printf("TestGetVappNetworks for %s\n", *vappName)
		vapp, err := tv.FindVApp(ctx, *vappName, testVcdClient)
		if err != nil {
			fmt.Printf("vapp %s not found err %s\n", *vappName, err.Error())
			return
		}
		ncs, err := vapp.GetNetworkConnectionSection()
		if err != nil {
			fmt.Printf("Error getting netconnectsec vapp %s not found err %s\n", *vappName, err.Error())
			return
		}
		numNets := len(ncs.NetworkConnection)
		fmt.Printf("vapp %s has %d network connections \n", *vappName, numNets)

		for n, nc := range ncs.NetworkConnection {
			fmt.Printf("vapp %s net %d ==> name: %s addr: %s\n", *vappName, n, nc.Network, nc.IPAddress)
		}
	}
}

// -vapp -vm
func TestGetVMNetworks(t *testing.T) {
	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	defer testVcdClient.Disconnect()
	if live {
		fmt.Printf("TestVMNetworks for %s\n", *vmName)
		vapp, err := tv.FindVApp(ctx, *vappName, testVcdClient)
		if err != nil {
			fmt.Printf("vapp %s not found err %s\n", *vappName, err.Error())
			return
		}
		vm, err := tv.FindVMInVApp(ctx, *vmName, *vapp)
		if err != nil {
			fmt.Printf("error findingVMInVApp(%s) err  %s\n", *vmName, err.Error())
			return
		}

		ncs, err := vm.GetNetworkConnectionSection()
		if err != nil {
			fmt.Printf("Error getting netconnectsec vapp %s not found err %s\n", *vmName, err.Error())
			return
		}
		numNets := len(ncs.NetworkConnection)
		fmt.Printf("vm %s has %d network connections \n", *vmName, numNets)

		for n, nc := range ncs.NetworkConnection {
			fmt.Printf("vapp %s :: vm %s net %d ==> name: %s addr: %s\n", *vappName, *vmName, n, nc.Network, nc.IPAddress)
		}
	}
}

func TestGetVMAddr(t *testing.T) {
	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	defer testVcdClient.Disconnect()

	if live {
		vm, err := tv.FindVMByName(ctx, *vmName, testVcdClient)
		if err != nil {
			fmt.Printf("error finding vm %s\n", *vmName)
			return
		}

		addr, err := tv.GetExtAddrOfVM(ctx, vm, *netName)
		if err != nil {
			fmt.Printf("Test error from GetExtAddrOfVM  %s = %s \n", *vmName, err.Error())
			return
		}

		fmt.Printf("Next ext-net Address: %s\n", addr)
	}
}

func getAllVdcNetworks(ctx context.Context) (NetMap, error) {

	netMap := make(NetMap)
	vdc, err := tv.GetVdc(ctx, testVcdClient)
	if err != nil {
		return netMap, err
	}

	for _, res := range vdc.Vdc.ResourceEntities {
		for _, resEnt := range res.ResourceEntity {
			fmt.Printf("GetAllVdcNetworks-I-next resName %s\n\t resType %s\n\t  resHref %s\n",
				resEnt.Name, resEnt.Type, resEnt.HREF)

			if resEnt.Type == types.MimeNetwork { // "application/vnd.vmware.vcloud.network+xml" {
				fmt.Printf("\nGetAllVdcNetworks-I-found simple network name: %s\n\n", resEnt.Name)

				//

				if resEnt.Type == types.MimeOrgVdcNetwork { // "application/vnd.vmware.vcloud.orgVdcNetwork+xml" {
					network, err := vdc.GetOrgVdcNetworkByName(resEnt.Name, true)
					if err != nil {
						fmt.Printf("Error GetOrgVdcNetworkByname for %s err: %s\n", resEnt.Name, err.Error())
						continue
					}
					netMap[resEnt.Name] = network
					govcd.ShowNetwork(*network.OrgVDCNetwork)
				}
			}
		}
	}

	return netMap, nil
}

func TestGetVdcResourceNetworks(t *testing.T) {
	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	defer testVcdClient.Disconnect()

	//	vdc, err := tv.GetVdc(ctx)
	//	if err != nil {
	//		fmt.Printf("VDC not found\n")
	//		return
	//	}
	if live {
		fmt.Printf("TestGetVdcNetworks\n")
		netMap, err := getAllVdcNetworks(ctx)
		if err != nil {
			fmt.Printf("getAllVdcNetworks failed: %s\n", err.Error())
		}
		if len(netMap) == 0 {
			fmt.Printf("getAllVdcNetworks return no networks\n")
			return
		}
		for Name, net := range netMap {
			fmt.Printf("Network %s:\n", Name)
			govcd.ShowNetwork(*net.OrgVDCNetwork)
		}
	}
}

// -vdc -net  is some OrgVdcNetwork in vdc
func TestGetAllocatedIPs(t *testing.T) {
	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	defer testVcdClient.Disconnect()

	if live {
		vdc, err := tv.GetVdc(ctx, testVcdClient)

		if err != nil {
			fmt.Printf("vdc %s not found\n", *vdcName)
			return
		}
		vdcnet, err := vdc.GetOrgVdcNetworkByName(*netName, false)
		if err != nil {
			fmt.Printf("net %s not found in vdc %s\n", *netName, *vdcName)
			return
		}
		// look in IPScope for AllocatedIPAddresses *IPAddresses
		// vdcnet.Configuration.IPScopes.
		addrs := &types.IPAddresses{}

		IPScopes := vdcnet.OrgVDCNetwork.Configuration.IPScopes

		fmt.Printf("network %s has %d scopes\n", *netName, len(IPScopes.IPScope))

		for _, ipscope := range IPScopes.IPScope {
			// this is always emtpy for nsx-t does it run in packet?
			addrs = ipscope.AllocatedIPAddresses
			fmt.Printf("net %s addrs: ===>>%s<<===\n", *netName, addrs)

			/*
				fmt.Printf("Net  %s has these allocated IP addresses\n", *netName)
				for _, address := range ipscope.AllocatedIPAddresses.IPAddress {
					fmt.Printf("\t%d %+v\n", n, address)
				}
			*/

		}

	}
}

func TestDumpNet(t *testing.T) {
	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	defer testVcdClient.Disconnect()
	if live {
		fmt.Printf("TestNetworks\n")
		// monitor.go
		net, err := tv.GetExtNetwork(ctx, testVcdClient)
		if err != nil {
			fmt.Printf("GetExtNetwork error; %s\n", err.Error())
			return
		}
		govcd.ShowNetwork(*net.OrgVDCNetwork)
	} else {
		return
	}
}

// only operate on vapp networks, not OrgVDCNetwworks
func TestRMNet(t *testing.T) {
	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	defer testVcdClient.Disconnect()

	if live {
		fmt.Printf("TestRmNetwork\n")
		_, err = testDeleteVAppNetwork(t, ctx, *vappName, *netName)
		if err != nil {
			fmt.Printf("error from testDelete VAppNetwork: %s\n", err.Error())
		}
	} else {
		return
	}

}

// Find out how much of OrgVDCNetwork we need to fill in
// This test
// 1) creates a new isolated OrgVDCNetwork subnet (Not a vapp network)
// 2) AddOrgNetwork to the target vapp
// 3) Retrieve the vapp's first VM and appends a new networkConnectionSection assigned its IP address
// 4) Updates the VMs network connection section
// 5) Removes the network from the VM/VAPP
// 6) Removes the newly created network
//
func TestIsoVdcNet(t *testing.T) {
	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	defer testVcdClient.Disconnect()

	if live {
		fmt.Printf("TestIsoVdcNet\n")
		vdc, err := tv.GetVdc(ctx, testVcdClient)
		if err != nil {
			fmt.Printf("Error obtaining Vdc: %s\n", err.Error())
			return
		}

		var (
			gateway       = "10.101.1.1"
			networkName   = "Subnet-1"
			startAddress  = "10.101.1.2"
			endAddress    = "10.101.1.254"
			netmask       = "255.255.255.0"
			dns1          = "1.1.1.1"
			dns2          = "8.8.8.8"
			dnsSuffix     = "mobiledgex.net"
			description   = "Created mex live test"
			networkConfig = types.OrgVDCNetwork{
				Xmlns:       types.XMLNamespaceVCloud,
				Name:        networkName,
				Description: description,
				Configuration: &types.NetworkConfiguration{
					FenceMode: types.FenceModeIsolated,
					/*One of:
						bridged (connected directly to the ParentNetwork),
					  isolated (not connected to any other network),
					  natRouted (connected to the ParentNetwork via a NAT service)
					  https://code.vmware.com/apis/287/vcloud#/doc/doc/types/OrgVdcNetworkType.html
					*/
					IPScopes: &types.IPScopes{
						IPScope: []*types.IPScope{&types.IPScope{
							IsInherited: false,
							Gateway:     gateway,
							Netmask:     netmask,
							DNS1:        dns1,
							DNS2:        dns2,
							DNSSuffix:   dnsSuffix,
							IPRanges: &types.IPRanges{
								IPRange: []*types.IPRange{
									&types.IPRange{
										StartAddress: startAddress,
										EndAddress:   endAddress,
									},
								},
							},
						},
						},
					},
					BackwardCompatibilityMode: true,
				},
				IsShared: false, // true,
				// XXX Requesting Shared results in: Maybe it's sharable within the vdc, but not across vdcs? Lets hope so.

				//error creating Network <Subnet-1>: error creating the network: error instantiating a new OrgVDCNetwork: API Error: 403: [ 28be4fcd-0d98-4fb0-86a5-ab031d5090f8 ] Org Vdc mex-qe(com.vmware.vcloud.entity.vdc:a9c60070-3f05-4d62-ab83-e99d6d0dd339) does not have the following network capability: shareOrgVdcNetwork
			}
		)

		fmt.Printf("CreateOrgVDCNetworkWait....\n")
		err = vdc.CreateOrgVDCNetworkWait(&networkConfig)
		if err != nil {
			fmt.Printf("error creating Network <%s>: %s\n", networkName, err)
		}

		fmt.Printf("Network %s created successfully now add it to %s\n", networkName, *vappName)
		// ok, now that it's created, we'll add it to *vappNmae eh?

		vapp, err := tv.FindVApp(ctx, *vappName, testVcdClient)
		if err != nil {
			fmt.Printf("Failed to find vapp %s\n", *vappName)
			return
		}

		// We should be able to fetch it by name now.
		newNetwork, err := vdc.GetOrgVdcNetworkByName(networkName, true)
		if err != nil {
			fmt.Printf("Failed to retrieve Orgvdcnetbyname: %s error: %s\n", networkName, err.Error())
			return
		}

		// Need to add this vdc network to the vapp? Since if we do not, UpdateNetworkConnection below says
		// 'the entity network "Subnet-1" does not exist'
		//

		IPScope := newNetwork.OrgVDCNetwork.Configuration.IPScopes.IPScope[0] // xxx

		var iprange []*types.IPRange
		iprange = append(iprange, IPScope.IPRanges.IPRange[0])

		VappNetworkSettings := govcd.VappNetworkSettings{
			// now poke our changes into the new vapp
			Name:           networkName,
			Gateway:        IPScope.Gateway,
			NetMask:        IPScope.Netmask,
			DNS1:           IPScope.DNS1,
			DNS2:           IPScope.DNS2,
			DNSSuffix:      IPScope.DNSSuffix,
			StaticIPRanges: iprange,
		}

		netConfigSec, err := vapp.AddOrgNetwork(&VappNetworkSettings, newNetwork.OrgVDCNetwork, false)
		if err != nil {
			fmt.Printf("AddOrgNetwork %s failed: %s\n", networkName, err.Error())
			return
		}
		fmt.Printf("netConfigSec: %+v\n", netConfigSec)

		fmt.Printf("Retrived newNetwork %s\n", newNetwork.OrgVDCNetwork.Name)

		vmname := vapp.VApp.Children.VM[0].Name
		vm, err := vdc.FindVMByName(*vapp, vmname)
		if err != nil {
			fmt.Printf("FindVMByName failed for %s vapp %s err: %s\n", vmname, vapp.VApp.Name, err.Error())
			return
		}

		ipAddr := "10.101.1.1" // server is gateway
		fmt.Printf("Retrived vm child of Vapp as %s adding ip %s on network %s \n", vm.VM.Name, ipAddr, networkName)

		//		netConfigSec, err := vapp.AddOrgNetwork(vappNetSettings, newNetwwork)

		ncs, err := vm.GetNetworkConnectionSection()

		ncs.NetworkConnection = append(ncs.NetworkConnection,
			&types.NetworkConnection{
				Network:                 newNetwork.OrgVDCNetwork.Name,
				NetworkConnectionIndex:  1, //  0,
				IPAddress:               ipAddr,
				IsConnected:             true,
				IPAddressAllocationMode: types.IPAllocationModeManual,
			})

		err = vm.UpdateNetworkConnectionSection(ncs)
		if err != nil {
			fmt.Printf("UpdateNetworkConnectionSection failed: %s\n", err.Error())
			return
		}

		fmt.Printf("Network %s successfully attached to vm\n", networkName)

		// well, hmm, try removing the connectin from the vm and another UpdateNetworkConnectionSection on the VM

		netConSec, err := vm.GetNetworkConnectionSection()
		if err != nil {
			fmt.Printf("Failed to retrieve NetConSec from vm %s\n", err.Error())
			return
		}
		for n, nc := range netConSec.NetworkConnection {
			if nc.Network == networkName {
				fmt.Printf("Found %s in netConSec, removing\n", networkName)
				ncs.NetworkConnection[n] = ncs.NetworkConnection[len(ncs.NetworkConnection)-1]
				ncs.NetworkConnection[len(ncs.NetworkConnection)-1] = &types.NetworkConnection{}
				ncs.NetworkConnection = ncs.NetworkConnection[:len(ncs.NetworkConnection)-1]
				err := vm.UpdateNetworkConnectionSection(ncs)
				if err != nil {
					fmt.Printf("Error UpdateNetworkCOnnectinSection after remvoing : %s\n", err.Error())
					return
				}
			}
		}

		// See if this balks wanting it out of the vm first?
		_, err = vapp.RemoveNetwork(networkName)
		if err != nil {
			fmt.Printf("vapp.RemoveNetwork(%s) failed: %s\n", networkName, err.Error())
			return
		}

		err = govcd.RemoveOrgVdcNetworkIfExists(*vdc, networkName)
		if err != nil {
			fmt.Printf("RemoveOrgVdcNetworkIfExists failed: %s\n", err.Error())
			return
		}
		fmt.Printf("New network %s deleted\n", networkName)

	}

}

// Test AttachPortToServer
// we want a new vapp, one ext and three internal subnets.
// -live -vapp
// This doesn't really work today. Vapps only want to have one internal isolated network.
// For a shared LB, (it's own groupName) it's a cluster/Vapp so it wants multiple OrgVCDNetowrks that are isolated
// and all the clusters (VApps) that the shared LB routes to, will have to have this net added as well...
//
func TestAttachPortToServer(t *testing.T) {
	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	defer testVcdClient.Disconnect()

	if live {
		fmt.Printf("TestAttachPortToServer testsubnets to %s\n", *vappName)

		// create 3 vapp internal (isolated) networks for vapp
		// then add connections to same for the first vm in target vapp

		vapp, err := tv.FindVApp(ctx, *vappName, testVcdClient)
		if err != nil {
			fmt.Printf("%s not found\n", *vappName)
			return
		}
		vmname := vapp.VApp.Children.VM[0].Name
		vm, err := vapp.GetVMByName(vmname, true)
		if err != nil {
			fmt.Printf("Error GetVMByName %s failed: %s\n", vmname, err.Error())
		}
		fmt.Printf("Add 3 subnets to vm %s\n", vmname)
		InternalNetConfigSec := &types.NetworkConfigSection{}
		ncs, err := vm.GetNetworkConnectionSection()
		if err != nil {
			fmt.Printf("GetNetworkConnectionSection for vm %s failed: %s\n", vmname, err.Error())
			return
		}

		type subnet struct {
			SubnetAddr string
			Netname    string
			ConIdx     int
			StartAddr  string
			EndAddr    string
		}

		// conIdx 1 is our external network mostly
		var subnets = []subnet{
			subnet{
				SubnetAddr: "10.101.1.1",
				Netname:    "subnet1",
				ConIdx:     0,
				StartAddr:  "10.101.1.2",
				EndAddr:    "10.101.1.254",
			},
			subnet{
				SubnetAddr: "10.101.2.1",
				Netname:    "subnet2",
				ConIdx:     2,
				StartAddr:  "10.101.2.2",
				EndAddr:    "10.101.2.254",
			},
			subnet{
				SubnetAddr: "10.101.3.1",
				Netname:    "subnet3",
				ConIdx:     3,
				StartAddr:  "10.101.3.2",
				EndAddr:    "10.101.3.254",
			},
		}

		// all intetrnal subnets are /24 for their ip ranges:

		// Ok, before we can add connections to the vm, we first need to create the
		// 3 new internal Vapp Networks

		for n, subnet := range subnets {

			var iprange []*types.IPRange
			addrRange := types.IPRange{
				StartAddress: subnet.StartAddr,
				EndAddress:   subnet.EndAddr,
			}
			iprange = append(iprange, &addrRange)

			// create each internal vapp network
			internalSettings := govcd.VappNetworkSettings{
				Name:           subnet.Netname,
				Description:    "internal " + subnet.Netname,
				Gateway:        subnet.SubnetAddr,
				NetMask:        "255.255.255.0",
				DNS1:           "1.1.1.1",
				DNS2:           "",
				DNSSuffix:      "mobiledgex.net",
				StaticIPRanges: iprange,
			}
			fmt.Printf("Create vapp subnet %s\n", subnet.Netname)
			InternalNetConfigSec, err = vapp.CreateVappNetwork(&internalSettings, nil)
			if err != nil {
				if !strings.Contains(err.Error(), "already exists") {
					fmt.Printf("Create subnet failed for %s err: %s\n",
						subnet.Netname, err.Error())
					return
				}
			}
			fmt.Printf("Network[%d]  %s created ConfigSec: %+v\n", n, subnet.Netname, InternalNetConfigSec)
		}

		fmt.Printf("All vapp isolated subnets created succesfully, now add 'em to the vm\n")

		for _, subnet := range subnets {

			ncs.NetworkConnection = append(ncs.NetworkConnection,
				&types.NetworkConnection{
					Network:                 subnet.Netname,
					NetworkConnectionIndex:  subnet.ConIdx,
					IPAddress:               subnet.SubnetAddr,
					IsConnected:             true,
					IPAddressAllocationMode: types.IPAllocationModeManual,
				})

			// update each time around the wheel, or just once? Just once
		}
		err = vm.UpdateNetworkConnectionSection(ncs)
		if err != nil {
			fmt.Printf("UpdateNetworkConnectionSection failed: %s\n", err.Error())
			return
		}
	}
}

// -live -server
// We aim to call

// -net -live
// what can we enable or not?
func testEnableVDCNetFirewall(t *testing.T, ctx context.Context, netName string) error {

	return nil
}

func testEnableVAppFirewall(t *testing.T, ctx context.Context, vappName string) error {

	return nil
}

func testDeleteVAppNetwork(t *testing.T, ctx context.Context, vappName, networkName string) (*types.NetworkConfigSection, error) {

	vapp, err := tv.FindVApp(ctx, vappName, testVcdClient)
	if err != nil {
		fmt.Printf("Error finding Vapp: %s : %s \n", vappName, err.Error())
		return nil, err
	}
	netConfig, err := vapp.RemoveNetwork(networkName)
	if err != nil {
		fmt.Printf("Error from RemoveNetwork %s\n", err.Error())
		return nil, err
	}
	return netConfig, nil
}

// -net -vapp
// cidr is selected via current iso vdc networks

func TestAddNextIsoSubnetToVapp(t *testing.T) {
	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	defer testVcdClient.Disconnect()
	if live {
		fmt.Printf("TestGetNExtIsoSubnetToVapp %s\n", *vappName)
		vdc, err := tv.GetVdc(ctx, testVcdClient)
		if err != nil {
			fmt.Printf("GetVdc failed: %s\n", err.Error())
			return
		}
		vapp, err := tv.FindVApp(ctx, *vappName, testVcdClient)
		if err != nil {
			fmt.Printf("Error getvapp %s\n", err.Error())
			return
		}

		nextCidr, err := tv.GetNextVdcIsoSubnet(ctx, testVcdClient)
		if err != nil {
			fmt.Printf("Error from GetNextVdcIsoSubnet: %s\n", err.Error())
			return
		}
		fmt.Printf("Next subnet avaiable: %s\n", nextCidr)

		// The create now adds the org net to the given vapp
		err = tv.CreateIsoVdcNetwork(ctx, vapp, *netName, nextCidr, testVcdClient, false)
		if err != nil {
			fmt.Printf("CreateIsoVdcNetwork failed: %s\n", err.Error())
			return
		}

		// now turn around and get network by name
		//
		// We should be able to fetch it by name now.
		newNetwork, err := vdc.GetOrgVdcNetworkByName(*netName, true)
		if err != nil {
			fmt.Printf("Failed to retrieve Orgvdcnetbyname: %s error: %s\n", *netName, err.Error())
			return
		}

		fmt.Printf("Have new network %+v\n", newNetwork.OrgVDCNetwork)
		// Add as a vapp net so our server vm can see it. Fenced here is false
		// we want other clusters (vapps) connect to this vdc scoped network, but it's still an OrgVDCNetwork, not just a vapp network
		// that could be fenced, and dedicated LBs use 10.101.1.1 anyway...

		/* this is now done in the create iso call
		vappNetSettings := &govcd.VappNetworkSettings{
			Name:             *netName,
			VappFenceEnabled: TakeBoolPointer(false),
		}

		netConfSec, err := vapp.AddOrgNetwork(vappNetSettings, newNetwork.OrgVDCNetwork, false)
		if err != nil {
			fmt.Printf("AddORgNetwork failed network %s  error: %s\n", *netName, err.Error())
			return
		}
		fmt.Printf("Network Config Section from AddORgNetwork: %+v\n", netConfSec)
		// now can we add a con section to this vapps first born vm?
		*/

		// Grab the first born child vm of this vapp (likely the only vm in cld that will become the shared LB
		vmName := vapp.VApp.Children.VM[0].Name

		vm, err := vapp.GetVMByName(vmName, true)
		if err != nil {
			fmt.Printf("failed to get vm of vapp error: %s\n", err.Error())
			return
		}
		ncs, err := vm.GetNetworkConnectionSection()
		if err != nil {
			fmt.Printf("error: %s\n", err.Error())
			return
		}

		curIdx, err := GetNextAvailConIdx(ctx, ncs)
		if err != nil {
			fmt.Printf("Aux test of GetNextAvailConIdx failed: %s\n", err.Error())
		}

		// conIdx, can we let it auto assign for the shared LB, no see above
		// this is the cidr as we're the gateway
		ncs.NetworkConnection = append(ncs.NetworkConnection,
			&types.NetworkConnection{
				Network:                 *netName,
				NetworkConnectionIndex:  curIdx,
				IPAddress:               nextCidr,
				IsConnected:             true,
				IPAddressAllocationMode: types.IPAllocationModeManual,
			})

		err = vm.UpdateNetworkConnectionSection(ncs)
		if err != nil {
			fmt.Printf("error %s \n", err.Error())
			return
		}
		// that's it, so for each VM in some Vapp that wants a network to the shared root lb, that cluster/vapp will
		// create a vapp network of it like this and add the vm's net connection section.
	}
}

func TestGetCidr(t *testing.T) {
	_, _, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	defer testVcdClient.Disconnect()
	mask := "255.255.255.0"
	cidr, _ := MaskToCidr(mask)
	require.Equal(t, "24", cidr)

	mask = "255.255.255.248"
	cidr, _ = MaskToCidr(mask)
	require.Equal(t, "29", cidr)

	mask = "255.255.255.224"
	cidr, _ = MaskToCidr(mask)
	require.Equal(t, "27", cidr)

}
