package vcd

import (
	"context"
	"fmt"
	"strings"

	"github.com/stretchr/testify/require"
	"github.com/vmware/go-vcloud-director/v2/govcd"
	"github.com/vmware/go-vcloud-director/v2/types/v56"
	"testing"
)

// -vdc
func TestNextExtAddr(t *testing.T) {
	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")

	if live {
		nextAddr, err := tv.GetNextExtAddrForVdcNet(ctx)
		if err != nil {
			fmt.Printf("Error getting next addr  : %s\n", err.Error())
			return
		}

		fmt.Printf("Next ext-net Address: %s\n", nextAddr)
	}
}

// -vapp
func TestNextIntAddr(t *testing.T) {
	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")

	if live {
		// vappName is just logging here
		nextAddr, err := tv.GetNextInternalSubnet(ctx, *vappName)
		if err != nil {
			fmt.Printf("Error getting next addr  : %s\n", err.Error())
			return
		}
		/*
			fmt.Printf("Next ext-net Address: %s\n", nextAddr)
			cloud.Clusters[nextAddr] = &Cluster{}
			nextAddr, err = tv.GetNextInternalNet(ctx)
			if err != nil {
				fmt.Printf("Error getting next addr  : %s\n", err.Error())
				return
			}
			fmt.Printf("Next ext-net Address: %s\n", nextAddr)
			delete(cloud.Clusters, "10.101.2.1")
			nextAddr, err = tv.GetNextInternalNet(ctx)
			if err != nil {
				fmt.Printf("Error getting next addr  : %s\n", err.Error())
				return
			}
		*/require.Equal(t, nextAddr, "10.101.2.1")

	}
}

// -vapp -net Return the current external net
func TestGetVappAddr(t *testing.T) {
	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")

	if live {
		vapp, err := tv.FindVApp(ctx, *vappName)
		if err != nil {
			fmt.Printf("Test error finding vapp %s\n", *vappName)
			return
		}

		addr, err := tv.GetAddrOfVapp(ctx, vapp, *netName)
		if err != nil {
			fmt.Printf("Test error from GetExtAddrOfVapp  %s = %s \n", *vappName, err.Error())
			return
		}

		fmt.Printf("Next ext-net Address: %s\n", addr)
	}
}

func TestGetVMAddr(t *testing.T) {
	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")

	if live {
		vm, err := tv.FindVMByName(ctx, *vmName)
		if err != nil {
			fmt.Printf("error finding vm %s\n", *vappName)
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
	vdc, err := tv.GetVdc(ctx)
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

func TestGetVdcNetworks(t *testing.T) {
	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")

	//	vdc, err := tv.GetVdc(ctx)
	//	if err != nil {
	//		fmt.Printf("VDC not found\n")
	//		return
	//	}
	if live {
		fmt.Printf("TestGetVdcNetworks\n")
		netMap, err := getAllVdcNetworks(ctx)
		if err != nil {
			fmt.Printf("GetAllVdcNetworks failed: %s\n", err.Error())
		}
		if len(netMap) == 0 {
			fmt.Printf("GetAllVdcNetworks return no networks\n")
			return
		}
		for Name, net := range netMap {
			fmt.Printf("Network %s:\n", Name)
			govcd.ShowNetwork(*net.OrgVDCNetwork)
		}
	}
}

func TestNetAddrs(t *testing.T) {
	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")

	testaddr := "10.101.5.10"
	N, err := Octet(ctx, testaddr, 2) // third octet)
	require.Nil(t, err, "ThrirdOctet err")
	require.Equal(t, 5, N, "ThirdOctet")

	testaddr = "10.101.6.10/24"
	N, err = Octet(ctx, testaddr, 2)
	require.Nil(t, err, "ThrirdOctet err")
	require.Equal(t, 6, N, "ThirdOctet")

	if live {
		_, err := tv.GetVdc(ctx)
		if err != nil {
			fmt.Printf("Error from GetVdc : %s\n", err.Error())
			return
		}

		// Expect our test begins with zero Cloudlets

		// We ask for the first external address in our PrimaryNet range
		_ /*CloudletAddr,*/, err = tv.GetNextExtAddrForVdcNet(ctx)
		if err != nil {
			fmt.Printf("GetNextExternalAddrForVdcNet failed: %s\n", err.Error())
			return
		}
	}
}

// -vdc -net  is some OrgVdcNetwork in vdc
func TestGetAllocatedIPs(t *testing.T) {
	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	if live {
		org, err := tv.GetOrg(ctx)
		if err != nil {
			fmt.Printf("GetOrgs failed: %s\n", err.Error())
			return
		}
		vdc, err := org.GetVdcByName(*vdcName)

		if err != nil {
			fmt.Printf("vdc %s not found in org %s\n", *vdcName, org.Org.Name)
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
		for _, ipscope := range IPScopes.IPScope {

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
	if live {
		fmt.Printf("TestNetworks\n")
		// monitor.go
		net, err := tv.GetExtNetwork(ctx)
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

	if live {
		fmt.Printf("TestIsoVdcNet\n")
		vdc, err := tv.GetVdc(ctx)
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

		vapp, err := tv.FindVApp(ctx, *vappName)
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
	if live {
		fmt.Printf("TestAttachPortToServer testsubnets to %s\n", *vappName)

		// create 3 vapp internal (isolated) networks for vapp
		// then add connections to same for the first vm in target vapp

		vapp, err := tv.FindVApp(ctx, *vappName)
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

	vapp, err := tv.FindVApp(ctx, vappName)
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
