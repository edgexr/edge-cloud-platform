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
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/vmware/go-vcloud-director/v2/govcd"
	"github.com/vmware/go-vcloud-director/v2/types/v56"
)

// Networks
// OrgVDCNetworks

// TODO: currently VCD assumes 10.101.x.x.  We should tweak to use the netplan value so we can have different cloudlets on one vcd
var mexInternalNetRange = "10.101"

var dhcpLeaseTime int = 60 * 60 * 24 * 365 * 10 // 10 years

type VappNetIpAllocationType string

const VappNetIpAllocationStatic = "static"
const VappNetIpAllocationDhcp = "dhcp"

// UsedCommonIpRangeTag is a range within the common shared LB IP network
const UsedCommonIpRangeTag = "UsedCommonIpRange"

// UsedLegacyPerClusterIsoNetTag is a per-cluster isolated network which was used prior to 3.1
const UsedLegacyPerClusterIsoNetTag = "UsedLegacyPerClusterIsoNet"

const InternalVappDedicatedSubnet = "10.101.1.1"

var InternalSharedCommonSubnetMask = "255.255.0.0"

type NetworkMetadataType string

const NetworkMetadataNone NetworkMetadataType = "no network metadata "
const NetworkMetadataCommonIsoNet NetworkMetadataType = "common ISO network metadata"
const NetworkMetadataLegacyPerClusterIsoNet NetworkMetadataType = "per cluster legacy ISO network metadata"

// VCD currently supports all network typesf
var supportedVcdNetTypes = map[vmlayer.NetworkType]bool{
	vmlayer.NetworkTypeExternalPrimary:               true,
	vmlayer.NetworkTypeExternalAdditionalRootLb:      true,
	vmlayer.NetworkTypeExternalAdditionalPlatform:    true,
	vmlayer.NetworkTypeExternalAdditionalClusterNode: true,

	vmlayer.NetworkTypeInternalPrivate:  true,
	vmlayer.NetworkTypeInternalSharedLb: true,
}

type networkInfo struct {
	VcdNetworkName string
	Gateway        string
	NetworkType    vmlayer.NetworkType
	Routes         []edgeproto.Route
	LegacyIsoNet   bool
	ExternalNet    bool
}

func (v *VcdPlatform) getInternalSharedCommonSubnetGW(ctx context.Context) (string, error) {
	ni, err := vmlayer.ParseNetSpec(ctx, v.vmProperties.GetCloudletNetworkScheme())
	if err != nil {
		return "", err
	}
	return IncrIP(ctx, ni.CommonInternalNetworkAddress, 1)
}

func (v *VcdPlatform) getInternalSharedCommonStartEndAddrs(ctx context.Context) (string, string, error) {
	ni, err := vmlayer.ParseNetSpec(ctx, v.vmProperties.GetCloudletNetworkScheme())
	if err != nil {
		return "", "", err
	}
	startAddr, err := IncrIP(ctx, ni.CommonInternalNetworkAddress, 2)
	if err != nil {
		return "", "", err
	}
	lastAddr, err := vmlayer.GetLastHostAddressForCidr(ni.CommonInternalCIDR)
	if err != nil {
		return "", "", err
	}
	return startAddr, lastAddr, nil
}

// returns the first 2 octets, e.g. 10.201
func (v *VcdPlatform) getInternalSharedCommonFixedPortion(ctx context.Context) (string, error) {
	ni, err := vmlayer.ParseNetSpec(ctx, v.vmProperties.GetCloudletNetworkScheme())
	if err != nil {
		return "", err
	}
	as := strings.Split(ni.CommonInternalNetworkAddress, ".")
	if len(as) != 4 {
		return "", fmt.Errorf("unexpected number of octets in common internal network - %s", ni.CommonInternalNetworkAddress)
	}
	return fmt.Sprintf("%s.%s", as[0], as[1]), nil
}

func (v *VcdPlatform) getCommonInternalCIDR(ctx context.Context) (string, error) {
	ni, err := vmlayer.ParseNetSpec(ctx, v.vmProperties.GetCloudletNetworkScheme())
	if err != nil {
		return "", err
	}
	return ni.CommonInternalCIDR, nil
}

// Use MEX_NETWORK_SCHEME to derive sharedLB orgvdcnet cidr for this cloudlet
func (v *VcdPlatform) getMexInternalNetRange(ctx context.Context) (string, error) {
	ni, err := vmlayer.ParseNetSpec(ctx, v.vmProperties.GetCloudletNetworkScheme())
	if err != nil {
		return "", err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "getMexInternalNetRange return", "prefix", ni.Octets[0]+"."+ni.Octets[1])
	return ni.Octets[0] + "." + ni.Octets[1], nil
}

func (v *VcdPlatform) GetNetworkList(ctx context.Context) ([]string, error) {
	return []string{
		v.vmProperties.GetCloudletExternalNetwork(),
	}, nil
}

// fetch the OrgVDCNetwork
func (v *VcdPlatform) GetExtNetwork(ctx context.Context, vcdClient *govcd.VCDClient, netName string) (*govcd.OrgVDCNetwork, error) {

	vdc, err := v.GetVdc(ctx, vcdClient)
	if err != nil {
		return nil, err
	}
	orgvdcnet, err := vdc.GetOrgVdcNetworkByName(netName, true)
	if err != nil {
		return nil, err
	}
	return orgvdcnet, nil
}

// No Router
func (v *VcdPlatform) GetRouterDetail(ctx context.Context, routerName string) (*vmlayer.RouterDetail, error) {
	return nil, fmt.Errorf("Router not supported for VCD")
}

func (v *VcdPlatform) GetGatewayForOrgVDCNetwork(ctx context.Context, network *types.OrgVDCNetwork) (string, error) {
	var gateways []string
	if network == nil {
		return "", fmt.Errorf("nil network")
	}
	scopes := network.Configuration.IPScopes.IPScope

	for _, scope := range scopes {
		gateways = append(gateways, scope.Gateway)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "Primary", "network", network.Name, "gateway", gateways[0], "of", len(gateways))
	return gateways[0], nil
}

// GetExternalGateway
// Gateway, Always operates on MEX_EXT_NETWORK
// Return the IP address of the external Gateway
func (v *VcdPlatform) GetExternalGateway(ctx context.Context, extNetname string) (string, error) {

	vcdClient := v.GetVcdClientFromContext(ctx)
	if vcdClient == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, NoVCDClientInContext)
		return "", fmt.Errorf(NoVCDClientInContext)
	}
	vdcNet, err := v.GetExtNetwork(ctx, vcdClient, extNetname)
	if err != nil {
		return "", err
	}

	// We have only one primary external network. So these values should match
	if vdcNet.OrgVDCNetwork.Name != extNetname {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetExternalGateway warn extNetName", "MEX_EXT_NETWORK", vdcNet.OrgVDCNetwork.Name, "extNetName", extNetname)
	}

	gateway, err := v.GetGatewayForOrgVDCNetwork(ctx, vdcNet.OrgVDCNetwork)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetExternalGateway", "error", err)
		return "", err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "GetExternalGateway", "extNetName", vdcNet.OrgVDCNetwork.Name, "IP", gateway)
	return gateway, err
}

func (v *VcdPlatform) GetInternalPortPolicy() vmlayer.InternalPortAttachPolicy {
	return vmlayer.AttachPortDuringCreate
}

var netLock sync.Mutex

func (v *VcdPlatform) createCommonSharedLBSubnet(ctx context.Context, vapp *govcd.VApp, port vmlayer.PortOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback, vcdClient *govcd.VCDClient) error {
	// shared lbs need individual orgvcd isolated networks, must be unique.
	// take the lock that is released after the network has been added to the sharedLB's VApp
	log.SpanLog(ctx, log.DebugLevelInfra, "createCommonSharedLBSubnet", "vapp", vapp.VApp.Name)

	netLock.Lock()
	defer netLock.Unlock()

	subnetName := v.vmProperties.GetSharedCommonSubnetName()

	log.SpanLog(ctx, log.DebugLevelInfra, "createCommonSharedLBSubnet", "vapp", vapp.VApp.Name, "port.Networkname", port.NetworkName, "subnetName", subnetName)
	// OrgVDCNetwork LinkType = 2 (isolated)
	// This seems to be an admin priv operation if using  nsx-t back network pool xxx
	err := v.AddCommonSharedNetToVapp(ctx, vapp, vcdClient, subnetName)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "createCommonSharedLBSubnet  create iso orgvdc internal net failed", "err", err)
		return err
	}
	return nil
}

func (v *VcdPlatform) getVappNetworkInfoMap(ctx context.Context, vapp *govcd.VApp, vmgp *vmlayer.VMGroupOrchestrationParams, vcdClient *govcd.VCDClient, vdc *govcd.Vdc, action vmlayer.ActionType) (map[string]networkInfo, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "getVappNetworkInfoMap", "vapp", vapp.VApp.Name)
	netMap := make(map[string]networkInfo)
	for _, port := range vmgp.Ports {
		log.SpanLog(ctx, log.DebugLevelInfra, "getVappNetworkInfoMap found port", "port", port)
		switch port.NetType {
		case vmlayer.NetworkTypeExternalPrimary:
			fallthrough
		case vmlayer.NetworkTypeExternalAdditionalRootLb:
			fallthrough
		case vmlayer.NetworkTypeExternalAdditionalClusterNode:
			fallthrough
		case vmlayer.NetworkTypeExternalAdditionalPlatform:
			// all the above are external org VDC networks
			net, err := v.GetExtNetwork(ctx, vcdClient, port.NetworkName)
			if err != nil {
				return nil, fmt.Errorf("unable to get external network %s - %v", port.NetworkName, err)
			}
			gw, err := v.GetGatewayForOrgVDCNetwork(ctx, net.OrgVDCNetwork)
			if err != nil {
				return nil, fmt.Errorf("Error getting GW for network %s - %v", net.OrgVDCNetwork.Name, err)
			}
			log.SpanLog(ctx, log.DebugLevelInfra, "Got external network gateway", "netName", port.NetworkName, "gw", gw)
			netMap[port.NetworkName] = networkInfo{
				VcdNetworkName: port.NetworkName,
				Gateway:        gw,
				NetworkType:    port.NetType,
				ExternalNet:    true,
			}
		case vmlayer.NetworkTypeInternalPrivate:
			netMap[port.SubnetId] = networkInfo{
				VcdNetworkName: port.SubnetId,
				Gateway:        InternalVappDedicatedSubnet,
				NetworkType:    port.NetType,
			}
		case vmlayer.NetworkTypeInternalSharedLb:
			// updates can be the legacy iso case
			gateway, err := v.getInternalSharedCommonSubnetGW(ctx)
			if err != nil {
				return nil, err
			}
			vcdNetName := v.vmProperties.GetSharedCommonSubnetName()
			legacyIsoNet := false
			if action == vmlayer.ActionUpdate {
				// for the update case it is possible this is an existing vm which is connected to
				// a legacy iso net. See if we have legacy metadata for it. This is more expensive
				// in terms of API calls to make so only do this for the update case
				metaType, legacyNet, err := v.GetNetworkMetadataForInternalSubnet(ctx, port.SubnetId, vcdClient, vdc)
				if err != nil {
					return nil, err
				}
				if metaType == NetworkMetadataLegacyPerClusterIsoNet {
					// override the network name with the mapped ISO network
					gateway = legacyNet
					vcdNetName = legacyNet
					legacyIsoNet = true
				}
			}
			netMap[port.SubnetId] = networkInfo{
				VcdNetworkName: vcdNetName,
				Gateway:        gateway,
				NetworkType:    port.NetType,
				LegacyIsoNet:   legacyIsoNet,
			}
		default:
			return nil, fmt.Errorf("unknown network type: %s", port.NetType)
		}
	}
	return netMap, nil
}

func (v *VcdPlatform) getNetworkInfo(ctx context.Context, portSubnet, portNet string, netMap map[string]networkInfo) (*networkInfo, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "getNetworkInfo", "portSubnet", portSubnet, "portNet", portNet, "netMap", netMap)

	// first try with subnet which is more specific
	networkInfo, ok := netMap[portSubnet]
	if ok {
		return &networkInfo, nil
	}
	// try with network
	networkInfo, ok = netMap[portNet]
	if ok {
		return &networkInfo, nil
	}
	return nil, fmt.Errorf("could not find port network %s or subnet %s in netmap", portNet, portSubnet)
}

// AddPortsToVapp returns netinfo map
func (v *VcdPlatform) AddPortsToVapp(ctx context.Context, vapp *govcd.VApp, vmgp *vmlayer.VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback, vcdClient *govcd.VCDClient, vdc *govcd.Vdc) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddPortsToVapp", "vapp", vapp.VApp.Name)

	ports := vmgp.Ports
	vmparams := vmgp.VMs[0]
	serverName := vmparams.Name
	netMap, err := v.getVappNetworkInfoMap(ctx, vapp, vmgp, vcdClient, vdc, vmlayer.ActionCreate)
	if err != nil {
		return err
	}
	networksAdded := make(map[string]string)
	// the vmgp contains ports for each VM so there can be duplicates
	for n, port := range ports {
		_, alreadyAdded := networksAdded[port.NetworkName]
		if alreadyAdded {
			log.SpanLog(ctx, log.DebugLevelInfra, "network already added", "port.NetworkName", port.NetworkName)
			continue
		}
		networksAdded[port.NetworkName] = port.NetworkName
		network, err := v.getNetworkInfo(ctx, port.NetworkName, port.SubnetId, netMap)
		if err != nil {
			return err
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "AddPortsToVapp adding port", "PortNum", n, "port", port, "network", network)
		if network.ExternalNet {
			log.SpanLog(ctx, log.DebugLevelInfra, "AddPortsToVapp adding external vapp net", "PortNum", n, "vapp", vapp.VApp.Name, "NetworkName", port.NetworkName, "NetworkType", port.NetType)
			vappNcs, err := v.AddVappNetwork(ctx, vapp, vcdClient, port.NetworkName)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "Error adding vapp network", "vappNcs", vappNcs, "err", err)
				return fmt.Errorf("Error adding vapp net: %s to vapp %s -- %v", port.NetworkName, vapp.VApp.Name, err)
			}
		} else if port.NetType == vmlayer.NetworkTypeInternalPrivate {
			log.SpanLog(ctx, log.DebugLevelInfra, "AddPortsToVapp adding private internal net", "PortNum", n, "vapp", vapp.VApp.Name, "NetworkName", port.NetworkName, "NetworkType", port.NetType)
			var ipAllocation VappNetIpAllocationType = VappNetIpAllocationStatic
			if !v.vmProperties.RunLbDhcpServerForVmApps {
				if len(vmgp.VMs) == 2 && vmgp.VMs[1].Role == vmlayer.RoleVMApplication {
					ipAllocation = VappNetIpAllocationDhcp
				}
			}
			_, err = v.CreateInternalNetworkForNewVm(ctx, vapp, serverName, port.SubnetId, InternalVappDedicatedSubnet, vmgp.Subnets[0].DNSServers, ipAllocation)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "create internal net failed", "err", err)
				return err
			}
		} else if port.NetType == vmlayer.NetworkTypeInternalSharedLb {
			err = v.createCommonSharedLBSubnet(ctx, vapp, port, updateCallback, vcdClient)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "AddPortsToVapp createNextShareRootLBSubnet failed", "vapp", vapp.VApp.Name, "error", err)
				return err
			}
		} else {
			// should have been handled above
			return fmt.Errorf("unexpected network type for port %s net %s", port.Name, port.NetworkName)
		}
	}

	return nil
}

// InsertConnectionIntoNcs replaces the network connection if the conIdx exists, otherwise appends it
func (v *VcdPlatform) InsertConnectionIntoNcs(ctx context.Context, ncs *types.NetworkConnectionSection, newConn *types.NetworkConnection, conIdx int) *types.NetworkConnectionSection {
	log.SpanLog(ctx, log.DebugLevelInfra, "InsertConnectionIntoNcs", "conIdx", conIdx, "newConn", newConn)
	updatedNcs := types.NetworkConnectionSection{}
	inserted := false
	for _, origConn := range ncs.NetworkConnection {
		if origConn.NetworkConnectionIndex == conIdx {
			inserted = true
			updatedNcs.NetworkConnection = append(updatedNcs.NetworkConnection, newConn)
			newConn.MACAddress = origConn.MACAddress
			log.SpanLog(ctx, log.DebugLevelInfra, "Replaced Connection in ncs", "mac", newConn.MACAddress)
		} else {
			updatedNcs.NetworkConnection = append(updatedNcs.NetworkConnection, origConn)
		}
	}
	if !inserted {
		// append to the end
		log.SpanLog(ctx, log.DebugLevelInfra, "Appended Connection to ncs")
		updatedNcs.NetworkConnection = append(updatedNcs.NetworkConnection, newConn)
	}
	return &updatedNcs
}

// AttachPortToServer
func (v *VcdPlatform) AttachPortToServer(ctx context.Context, serverName, subnetName, portName, ipaddr string, action vmlayer.ActionType) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "AttachPortToServer", "subnetName", subnetName, "portName", portName, "ipaddr", ipaddr, "action", action)
	commonNet := v.vmProperties.GetSharedCommonSubnetName()
	vappName := serverName + v.GetVappServerSuffix()
	vcdClient := v.GetVcdClientFromContext(ctx)
	if vcdClient == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, NoVCDClientInContext)
		return fmt.Errorf(NoVCDClientInContext)
	}
	vdc, err := v.GetVdc(ctx, vcdClient)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "unable to retrieve current vdc", "err", err)
		return err
	}
	vapp, err := v.FindVApp(ctx, vappName, vcdClient, vdc)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "AttachPortToServer server not found", "vapp", vappName, "for server", serverName)
		return err
	}
	vmName := vapp.VApp.Children.VM[0].Name
	vm, err := vapp.GetVMByName(vmName, false)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "AttachPortToServer server not found", "vm", vmName, "for server", serverName)
		return err
	}
	commonGw, err := v.getInternalSharedCommonSubnetGW(ctx)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "AttachPortToserver", "ServerName", serverName, "subnet", subnetName, "InternalSharedCommonSubnetGW", commonGw, "ip", ipaddr, "portName", portName, "action", action)
	if action == vmlayer.ActionCreate {
		// first see if the vapp already has this network, which can happen for the common shared net
		_, err = vapp.GetVappNetworkByNameOrId(commonNet, false)
		if err == nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "network already attached", "commonNet", commonNet)
			return nil
		}
		orgvdcnet, err := vdc.GetOrgVdcNetworkByName(commonNet, false)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "AttachPortToServer common orgvdc subnet not found", "subnetName", subnetName, "InternalSharedCommonSubnetGW", commonGw)
			return err
		}
		vappNetSettings := &govcd.VappNetworkSettings{
			Name:             subnetName,
			VappFenceEnabled: TakeBoolPointer(false),
		}

		_, err = vapp.AddOrgNetwork(vappNetSettings, orgvdcnet.OrgVDCNetwork, false)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "AttachPortToServer AddOrgNetwork failed", "subnetName", subnetName, "err", err)
			return err
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "AttachPortToServer AddOrgNetwork added", "subnetName", subnetName, "InternalSharedCommonSubnetGW", commonGw, "vapp", vapp.VApp.Name)
		scope := orgvdcnet.OrgVDCNetwork.Configuration.IPScopes.IPScope[0]
		gateway := scope.Gateway
		ncs, err := vm.GetNetworkConnectionSection()
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "Failed to retrieve networkConnectionSection from", "vm", vmName, "err", err)
			return err
		}
		conIdx, err := GetNextAvailConIdx(ctx, ncs)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "AttachPortToServer  conIdx failed", "subnetName", subnetName, "err", err)
			return err
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "AttachPortToServer ", "subnetName", subnetName, "ip", gateway, "conIdx", conIdx)
		nc := &types.NetworkConnection{
			Network:                 commonNet,
			NetworkConnectionIndex:  conIdx,
			IPAddress:               gateway,
			IsConnected:             true,
			IPAddressAllocationMode: types.IPAllocationModeManual,
		}
		ncs = v.InsertConnectionIntoNcs(ctx, ncs, nc, conIdx)
		log.SpanLog(ctx, log.DebugLevelInfra, "Update NetworkConnectionSection", "ncs", ncs)
		err = vm.UpdateNetworkConnectionSection(ncs)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp add internal net failed", "VM", vmName, "error", err)
			// cleanup net from vApp as we failed to add it to the VM
			vapp.Refresh()
			_, delerr := vapp.RemoveNetwork(commonNet)
			if delerr != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "Error deleting network from vapp", "vapp", vapp.VApp.Name, "net", v.vmProperties.GetSharedCommonSubnetName(), "delerr", delerr)
			}
			return err
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp added connection", "net", subnetName, "ip", gateway, "VM", vmName, "conIdx", conIdx)

	} else if action == vmlayer.ActionDelete {

	} else if action == vmlayer.ActionUpdate {
		log.SpanLog(ctx, log.DebugLevelInfra, "AttachPortToServer updating", "subnetName", subnetName, "portName", portName, "ip", ipaddr, "server", serverName)
	}
	return nil
}

func (v *VcdPlatform) DetachPortFromServer(ctx context.Context, serverName, subnetName, xportName string) error {

	log.SpanLog(ctx, log.DebugLevelInfra, "DetachPortFromServer", "ServerName", serverName, "subnet", subnetName, "port", xportName)

	vcdClient := v.GetVcdClientFromContext(ctx)
	networkName := subnetName
	if vcdClient == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, NoVCDClientInContext)
		return fmt.Errorf(NoVCDClientInContext)
	}
	vdc, err := v.GetVdc(ctx, vcdClient)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "DetachPortFromServer unable to retrieve current vdc", "err", err)
		return err
	}

	if strings.HasPrefix(subnetName, mexInternalNetRange) {
		// special cleanup case, we passed the cidr net as the net.
		log.SpanLog(ctx, log.DebugLevelInfra, "DetachPortFromServer using provided subnet name", "subnet", subnetName)
	} else {
		metadataType, metaVal, err := v.GetNetworkMetadataForInternalSubnet(ctx, subnetName, vcdClient, vdc)
		if err != nil {
			return err
		}
		if metadataType == NetworkMetadataLegacyPerClusterIsoNet {
			networkName = metaVal
			log.SpanLog(ctx, log.DebugLevelInfra, "DetachPortFromServer using legacy mapped iso net", "networkName", networkName)
		}
	}
	vappName := serverName + v.GetVappServerSuffix()
	vapp, err := v.FindVApp(ctx, vappName, vcdClient, vdc)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "DetachPortFromServer server not found", "vapp", vappName, "for server", serverName)
		return err
	}
	orgvdcnet, err := vdc.GetOrgVdcNetworkByName(networkName, false)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "DetachPortFromServer orgvdc network not found", "networkName", networkName)
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "Detaching network from vm", "networkName", networkName)

	// Operate on all VMs in this vapp
	vms := vapp.VApp.Children.VM
	for _, tvm := range vms {
		vmName := tvm.Name
		vm, err := vapp.GetVMByName(vmName, true)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "DetachPortFromServer server not found", "vm", vmName, "for server", serverName)
			return err
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "DetachPortFromServer", "vm", vmName, "for server", serverName)
		ncs, err := vm.GetNetworkConnectionSection()
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "DetachPortFromServer Failed to retrieve networkConnectionSection from", "vm", vmName, "err", err)
			return err
		}

		for n, nc := range ncs.NetworkConnection {
			log.SpanLog(ctx, log.DebugLevelInfra, "found network connection", "vm", vmName, "Network", nc.Network)
			if nc.Network == networkName {
				log.SpanLog(ctx, log.DebugLevelInfra, "Remove network from ncs", "nc.Network", nc.Network)
				ncs.NetworkConnection[n] = ncs.NetworkConnection[len(ncs.NetworkConnection)-1]
				ncs.NetworkConnection[len(ncs.NetworkConnection)-1] = &types.NetworkConnection{}
				ncs.NetworkConnection = ncs.NetworkConnection[:len(ncs.NetworkConnection)-1]
				err := vm.UpdateNetworkConnectionSection(ncs)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "DetachPortFromServer UpdateNetworkConnectionSection failed", "serverName", serverName, "networkName", networkName, "err", err)
					return err
				}
				log.SpanLog(ctx, log.DebugLevelInfra, "DetachPortFromServer success", "serverName", serverName, "networkName", networkName)
				break
			}
		}
	}
	for _, nc := range vapp.VApp.NetworkConfigSection.NetworkConfig {
		log.SpanLog(ctx, log.DebugLevelInfra, "DetachPortFromServer found net config", "nc", nc, "net to remove", orgvdcnet.OrgVDCNetwork.Name)
	}
	_, err = vapp.RemoveNetwork(orgvdcnet.OrgVDCNetwork.Name)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "DetachPortFromServer RemoveNetwork (byName) failed try RemoveIsolatedNetwork", "serverName", serverName, "subnet", subnetName, "err", err)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "DetachPortFromServer net removed from vapp ok")
	return nil
}

func IncrIP(ctx context.Context, a string, delta int) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "IncrIP", "a", a, "delta", delta)
	ip := net.ParseIP(a)
	if ip == nil {
		return "", fmt.Errorf("%s failed to parse as IP", a)
	}
	ip = ip.To4()
	if ip == nil {
		return "", fmt.Errorf("%s failed to parse as IP", a)
	}
	ip[3] += byte(delta)
	// we know a is a good IP
	ao, _ := Octet(ctx, a, 3)
	ipo, err := Octet(ctx, ip.String(), 3)
	if err != nil {
		return "", err
	}
	if ipo != ao+delta {
		return "", fmt.Errorf("range wrap err")
	}
	return ip.String(), nil
}

func DecrIP(ctx context.Context, a string, delta int) (string, error) {
	ip := net.ParseIP(a)
	if ip == nil {
		return "", fmt.Errorf("%s failed to parse as IP", a)
	}
	ip = ip.To4()
	if ip == nil {
		return "", fmt.Errorf("Ip %s Not a v4 address", ip)
	}
	ip[3] -= byte(delta)

	ao, _ := Octet(ctx, a, 3)
	ipo, _ := Octet(ctx, ip.String(), 3)
	if ao-delta != ipo {
		return "", fmt.Errorf("range wrap error")
	}
	return ip.String(), nil
}

func Octet(ctx context.Context, a string, n int) (int, error) {
	addr := a
	// strip any cidr mask if present
	parts := strings.Split(a, "/")
	if len(parts) > 1 {
		addr = string(parts[0])
	}

	ip := net.ParseIP(addr)
	if ip == nil {
		return 0, fmt.Errorf("%s failed to parse as IP", a)
	}
	ip = ip.To4()
	if ip == nil {
		return 0, fmt.Errorf("Ip %s Not a v4 address", ip)
	}
	return int(ip[n]), nil
}

func ReplaceLastOctet(ctx context.Context, addr string, o uint32) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "ReplaceLastOctet", "addr", addr, "o", o)

	parts := strings.Split(addr, "/")
	if len(parts) > 1 {
		addr = string(parts[0])
	}

	ip := net.ParseIP(addr)
	if ip == nil {
		return "", fmt.Errorf("%s failed to parse as IP", addr)
	}
	ip = ip.To4()
	if ip == nil {
		return "", fmt.Errorf("Ip %s Not a v4 address", ip)
	}
	ip[3] = byte(o)
	return ip.String(), nil

}

func MaskToCidr(addr string) (string, error) {

	ip := net.ParseIP(addr)
	if ip == nil {
		return "", fmt.Errorf("ip %s not valid", ip)
	}
	c, _ := net.IPMask(ip.To4()).Size()
	cidr := strconv.Itoa(c)
	return cidr, nil
}

const MaxSubnetsPerSharedLB = 254

func GetNextAvailConIdx(ctx context.Context, ncs *types.NetworkConnectionSection) (int, error) {
	// return first unused conIdx for a vapp or vm
	log.SpanLog(ctx, log.DebugLevelInfra, "GetNextAvailConIdx", "ncs", ncs)
	conIdMap := make(map[int]*types.NetworkConnection)
	for _, nc := range ncs.NetworkConnection {
		// Before we add this idx as inuse, does this entry actually point at a connection?
		if nc.Network == "" || nc.IPAddress == "" || nc.IsConnected == false {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetNextAvailConIdx skip available empty", "ConIdx", nc.NetworkConnectionIndex, "IP", nc.IPAddress, "isConnected", nc.IsConnected)
			continue
		}
		conIdMap[nc.NetworkConnectionIndex] = nc
	}
	var curIdx int
	for curIdx = 1; curIdx < MaxSubnetsPerSharedLB; curIdx++ {
		if _, found := conIdMap[curIdx]; !found {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetNextAvailConIdx returns", "conIdx", curIdx)
			return curIdx, nil
		}
	}
	return -1, fmt.Errorf("Subnet range exahusted")
}

func (v *VcdPlatform) IncrCidr(a string, delta int) (string, error) {

	addr := a
	parts := strings.Split(a, "/")
	if len(parts) > 1 {
		addr = string(parts[0])
	}

	ip := net.ParseIP(addr)
	if ip == nil {
		return "", fmt.Errorf("%s failed to parse as IP", a)
	}
	ip = ip.To4()

	ip[2] += byte(delta)
	return ip.String(), nil
}

// VappNetworks

const InternalNetMax = 100

func (v *VcdPlatform) CreateInternalNetworkForNewVm(ctx context.Context, vapp *govcd.VApp, serverName, netName string, cidr string, dnsServers []string, ipAllocation VappNetIpAllocationType) (string, error) {
	var iprange []*types.IPRange

	log.SpanLog(ctx, log.DebugLevelInfra, "create internal server net", "netname", netName, "dnsServers", dnsServers, "ipAllocation", ipAllocation)

	description := fmt.Sprintf("internal-%s", cidr)
	a := strings.Split(cidr, "/")
	addr := string(a[0])
	gateway := addr

	if len(dnsServers) == 0 {
		// NoSubnetDns is not supported for vCD
		return "", fmt.Errorf("No DNS servers specified")
	}
	dns1 := dnsServers[0]
	dns2 := ""
	if len(dnsServers) > 1 {
		dns2 = dnsServers[1]
	}

	startAddr, err := IncrIP(ctx, gateway, 1)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "IncrIP startaddr", "netname", netName, "gateway", gateway, "err", err)
		return "", err
	}
	endAddr, err := IncrIP(ctx, gateway, InternalNetMax)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "IncrIP endaddr", "netname", netName, "gateway", gateway, "err", err)
		return "", err
	}

	if v.Verbose {
		log.SpanLog(ctx, log.DebugLevelInfra, "CreateInternalNetwork ", "serverName", serverName, "netname", netName, "gateway", gateway, "StartIP", startAddr, "EndIP", endAddr)
	}
	internalSettings := govcd.VappNetworkSettings{
		Name:             netName,
		Description:      description,
		Gateway:          gateway,
		NetMask:          "255.255.255.0",
		DNS1:             dns1,
		DNS2:             dns2,
		DNSSuffix:        v.vmProperties.CommonPf.GetCloudletDNSZone(),
		VappFenceEnabled: TakeBoolPointer(true),
	}
	if ipAllocation == VappNetIpAllocationDhcp {
		// DHCP is used only for VM Apps, and just one IP in the pool is used
		addrRange := types.IPRange{
			StartAddress: endAddr,
			EndAddress:   endAddr,
		}
		iprange = append(iprange, &addrRange)
		internalSettings.DhcpSettings = &govcd.DhcpSettings{
			IsEnabled:        true,
			MaxLeaseTime:     dhcpLeaseTime,
			DefaultLeaseTime: dhcpLeaseTime,
			IPRange:          &addrRange,
		}
	} else {
		addrRange := types.IPRange{
			StartAddress: startAddr,
			EndAddress:   endAddr,
		}
		iprange = append(iprange, &addrRange)
		internalSettings.StaticIPRanges = iprange
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "Creating Vapp Network", "settings", internalSettings)
	_, err = vapp.CreateVappNetwork(&internalSettings, nil)
	if err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			log.SpanLog(ctx, log.DebugLevelInfra, "CreateInternalNetwork create", "serverName", serverName, "error", err)
			return "", err
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "CreateInternalNetwork", "network already exists", netName)
	}

	vapp.Refresh()
	return netName, nil
}

func (v *VcdPlatform) AddVappNetwork(ctx context.Context, vapp *govcd.VApp, vcdClient *govcd.VCDClient, netName string) (*types.NetworkConfigSection, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddVappNetwork", "netName", netName)

	orgNet, err := v.GetExtNetwork(ctx, vcdClient, netName)
	if err != nil {
		return nil, err
	}
	IPScope := orgNet.OrgVDCNetwork.Configuration.IPScopes.IPScope[0] // xxx

	var iprange []*types.IPRange
	iprange = append(iprange, IPScope.IPRanges.IPRange[0])

	VappNetworkSettings := govcd.VappNetworkSettings{
		// now poke our changes into the new vapp
		Name:           netName,
		Gateway:        IPScope.Gateway,
		NetMask:        IPScope.Netmask,
		DNS1:           IPScope.DNS1,
		DNS2:           IPScope.DNS2,
		DNSSuffix:      IPScope.DNSSuffix,
		StaticIPRanges: iprange,
	}

	err = vapp.Refresh()
	if err != nil {
		return nil, err
	}
	netConfigSec, err := vapp.AddOrgNetwork(&VappNetworkSettings, orgNet.OrgVDCNetwork, false)
	if err != nil {
		return nil, err
	}
	return netConfigSec, nil

}

// return a list of internal nets, a shared LB may have several
func (v *VcdPlatform) GetIntAddrsOfVM(ctx context.Context, vm *govcd.VM) ([]string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetIntAddrsOfVM", "vm", vm.VM.Name)

	addrs := []string{}
	if vm == nil {
		return addrs, fmt.Errorf("Invalid Arg")
	}
	ncs, err := vm.GetNetworkConnectionSection()
	if err != nil {
		return addrs, err
	}

	nc := ncs.NetworkConnection
	for _, n := range nc {
		if n.Network != v.vmProperties.GetCloudletExternalNetwork() {
			addrs = append(addrs, n.IPAddress)
		}
	}
	return addrs, nil

}

func (v *VcdPlatform) GetExtAddrOfVM(ctx context.Context, vm *govcd.VM, netName string) (string, error) {

	if vm == nil {
		return "", fmt.Errorf("Invalid Arg")
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "GetExtAddrOfVm", "vm", vm.VM.Name, "netname", netName)
	ncs, err := vm.GetNetworkConnectionSection()
	if err != nil {
		return "", err
	}
	nc := ncs.NetworkConnection
	for _, n := range nc {
		if n.Network == netName {
			return n.IPAddress, nil
		}
	}
	return "", fmt.Errorf("Not Found")
}

// Get the address VM is using on the given Network
func (v *VcdPlatform) GetAddrOfVM(ctx context.Context, vm *govcd.VM, netName string) (string, error) {

	if vm == nil {
		return "", fmt.Errorf("Invalid Arg")
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "GetAddrOfVm", "vm", vm.VM.Name, "netname", netName)
	ncs, err := vm.GetNetworkConnectionSection()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetAddrOfVM err retrieving NetConnection section", "vapp", vm.VM.Name, "network", netName, "err", err)
		return "", err
	}
	numNets := len(ncs.NetworkConnection)
	log.SpanLog(ctx, log.DebugLevelInfra, "GetAddrOfVM", "vapp", vm.VM.Name, "network", netName, "numNetworks", numNets)
	for _, nc := range ncs.NetworkConnection {
		if v.Verbose {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetAddrOfVM consider", "vm", vm.VM.Name, "nc.Network", nc.Network, "vs netName", netName)
		}

		if nc.Network == netName {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetAddrOfVM", "Vapp", vm.VM.Name, "Net", netName, "ip", nc.IPAddress)
			return nc.IPAddress, nil
		}
	}

	return "", fmt.Errorf("Addr Not Found on Net")
}

// Consider a GetAllSubnetsInVapp() []string err for shared lbs... XXX
// Returns the first addr on the given network.
func (v *VcdPlatform) GetAddrOfVapp(ctx context.Context, vapp *govcd.VApp, netName string) (string, error) {

	if vapp == nil || vapp.VApp == nil || vapp.VApp.Children == nil || len(vapp.VApp.Children.VM) == 0 {
		return "", fmt.Errorf("Invalid Arg")
	}
	err := vapp.Refresh()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetAddrOfVapp error refreshing vapp", "vapp", vapp.VApp.Name, "err", err)
		return "", err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "GetAddrOfVapp", "vapp", vapp.VApp.Name, "network", netName)
	// *v.2.11.0 Changed spelling of type.VM
	var vmChild *types.Vm

	for _, vmChild = range vapp.VApp.Children.VM {
		parts := strings.Split(vmChild.Name, ".")
		if len(parts) > 1 {
			break
		}
	}
	vm, err := v.FindVMInVApp(ctx, vmChild.Name, *vapp)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetAddrOfVapp failed to retrieve", "vm", vmChild.Name, "From Vapp", vapp.VApp.Name)
		return "", err
	}
	return v.GetAddrOfVM(ctx, vm, netName)
}

func (v *VcdPlatform) getSharedCommonMetadataKey(subnetName string) string {
	return UsedCommonIpRangeTag + "-" + subnetName
}

func (v *VcdPlatform) getLegacyPerClusterMetadataKey(subnetName string) string {
	return UsedLegacyPerClusterIsoNetTag + "-" + subnetName
}

func (v *VcdPlatform) getSubnetFromLegacyMetadataKey(key string) (string, error) {
	ks := strings.Split(key, UsedLegacyPerClusterIsoNetTag+"-")
	if len(ks) != 2 {
		return "", fmt.Errorf("invalid legacy metadata key - %s", key)
	}
	return ks[1], nil
}

func (v *VcdPlatform) GetNetworkMetadataForInternalSubnet(ctx context.Context, subnetName string, vcdClient *govcd.VCDClient, vdc *govcd.Vdc) (NetworkMetadataType, string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetNetworkMetadataForInternalSubnet", "subnetName", subnetName)
	shrName := v.getSharedVappName()
	commonMetadataKey := v.getSharedCommonMetadataKey(subnetName)
	legacyIsoMetadataKey := v.getLegacyPerClusterMetadataKey(subnetName)

	shrVapp, err := v.FindVApp(ctx, shrName, vcdClient, vdc)
	if err != nil {
		return NetworkMetadataNone, "", fmt.Errorf("unable to find shared vapp %s - %v", shrName, err)
	}
	meta, err := shrVapp.GetMetadata()
	if err != nil {
		return NetworkMetadataNone, "", fmt.Errorf("unable to get shared vapp metadata %s - %v", shrName, err)
	}
	for _, me := range meta.MetadataEntry {
		if me.Key == commonMetadataKey {
			log.SpanLog(ctx, log.DebugLevelInfra, "found common ip range in metadata", "key", me.Key, "val", me.TypedValue.Value)
			return NetworkMetadataCommonIsoNet, me.TypedValue.Value, nil
		}
		if me.Key == legacyIsoMetadataKey {
			log.SpanLog(ctx, log.DebugLevelInfra, "found legacy iso net in metadata", "key", me.Key, "val", me.TypedValue.Value)
			return NetworkMetadataLegacyPerClusterIsoNet, me.TypedValue.Value, nil
		}
	}
	return NetworkMetadataNone, "", nil
}

func (v *VcdPlatform) DeleteMetadataForInternalSubnet(ctx context.Context, subnetName string, vcdClient *govcd.VCDClient, vdc *govcd.Vdc) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteMetadataForInternalSubnet", "subnetName", subnetName)
	shrName := v.getSharedVappName()
	commonMetadataKey := v.getSharedCommonMetadataKey(subnetName)
	legacyIsoMetadataKey := v.getLegacyPerClusterMetadataKey(subnetName)

	shrVapp, err := v.FindVApp(ctx, shrName, vcdClient, vdc)
	if err != nil {
		return fmt.Errorf("unable to find shared vapp %s - %v", shrName, err)
	}
	meta, err := shrVapp.GetMetadata()
	if err != nil {
		return fmt.Errorf("unable to get shared vapp metadata %s - %v", shrName, err)
	}
	for _, me := range meta.MetadataEntry {
		if me.Key == commonMetadataKey || me.Key == legacyIsoMetadataKey {
			log.SpanLog(ctx, log.DebugLevelInfra, "found subnet in metadata, deleting", "key", me.Key, "val", me.TypedValue.Value)
			shrVapp.DeleteMetadata(me.Key)
		}
	}
	return nil
}

// GetSubnetFromLegacyIsoMetadata is used only in rare cases where we need to get the subnet name back from the iso net name
func (v *VcdPlatform) GetSubnetFromLegacyIsoMetadata(ctx context.Context, isonetName string, vcdClient *govcd.VCDClient, vdc *govcd.Vdc) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetSubnetFromLegacyIsoMetadata", "isonetName", isonetName)
	shrName := v.getSharedVappName()
	shrVapp, err := v.FindVApp(ctx, shrName, vcdClient, vdc)
	if err != nil {
		return "", fmt.Errorf("unable to find shared vapp %s - %v", shrName, err)
	}
	meta, err := shrVapp.GetMetadata()
	if err != nil {
		return "", fmt.Errorf("unable to get shared vapp metadata %s - %v", shrName, err)
	}
	for _, me := range meta.MetadataEntry {
		if me.TypedValue.Value == isonetName && strings.HasPrefix(me.Key, UsedLegacyPerClusterIsoNetTag) {
			return v.getSubnetFromLegacyMetadataKey(me.Key)
		}
	}
	return "", nil
}

func (v *VcdPlatform) GetFreeSharedCommonIpRange(ctx context.Context, subnetName string, vcdClient *govcd.VCDClient, vdc *govcd.Vdc) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetFreeSharedCommonIpRange", "subnetName", subnetName)

	shrName := v.getSharedVappName()
	shrVapp, err := v.FindVApp(ctx, shrName, vcdClient, vdc)
	if err != nil {
		return "", fmt.Errorf("unable to find shared vapp %s - %v", shrName, err)
	}

	netLock.Lock()
	defer netLock.Unlock()
	meta, err := shrVapp.GetMetadata()
	if err != nil {
		return "", fmt.Errorf("unable to get shared vapp metadata %s - %v", shrName, err)
	}
	for _, me := range meta.MetadataEntry {
		log.SpanLog(ctx, log.DebugLevelInfra, "Shared LB Metadata entry", "key", me.Key, "val", me.TypedValue.Value)
	}
	fixed, err := v.getInternalSharedCommonFixedPortion(ctx)
	if err != nil {
		return "", err
	}
	commonMetadataKey := v.getSharedCommonMetadataKey(subnetName)
	ipRange := ""
	for octet3 := 0; octet3 <= 255; octet3++ {
		addr := fmt.Sprintf("%s.%d.0", fixed, octet3)
		addressFree := true
		for _, me := range meta.MetadataEntry {
			if me.Key == commonMetadataKey {
				// found existing entry for this subnet
				log.SpanLog(ctx, log.DebugLevelInfra, "found existing metadata entry", "key", me.Key, "val", me.TypedValue.Value)
				return me.TypedValue.Value, nil
			}
			if me.TypedValue.Value == addr {
				log.SpanLog(ctx, log.DebugLevelInfra, "address already in use", "key", me.Key, "addr", addr)
				addressFree = false
				continue
			}
		}
		if addressFree {
			log.SpanLog(ctx, log.DebugLevelInfra, "found free shared ip range", "addr", addr)
			ipRange = addr
			break
		}
	}
	if ipRange == "" {
		// nothing free which probably means there's problem releasing the entries
		log.SpanLog(ctx, log.DebugLevelInfra, "could not find free shared ip address range")
		return "", fmt.Errorf("could not find free shared ip address range")
	}

	task, err := shrVapp.AddMetadata(commonMetadataKey, ipRange)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Add metadata failed", "err", err)
	}
	err = task.WaitTaskCompletion()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "wait Addmetadata to shared vapp failed", "error", err)
		return "", err
	}
	return ipRange, nil
}

func (v *VcdPlatform) ValidateAdditionalNetworks(ctx context.Context, additionalNets map[string]vmlayer.NetworkType) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ValidateAdditionalNetworks", "additionalNets", additionalNets)

	vcdClient := v.GetVcdClientFromContext(ctx)
	if vcdClient == nil {
		return fmt.Errorf(NoVCDClientInContext)
	}
	vdc, err := v.GetVdc(ctx, vcdClient)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "CreateIsoVdcNetwork GetVdc failed ", "err", err)
		return err
	}

	for net, netType := range additionalNets {
		log.SpanLog(ctx, log.DebugLevelInfra, "validating network", "net", net, "netType", netType)
		_, supported := supportedVcdNetTypes[netType]
		if !supported {
			return fmt.Errorf("Network type: %s not supported in VCD", netType)
		}

		network, err := vdc.GetOrgVdcNetworkByName(net, true)
		if err != nil {
			return fmt.Errorf("Error getting additional network: %s - %v", net, err)
		}
		if network.OrgVDCNetwork.Configuration.IPScopes == nil {
			return fmt.Errorf("Nil IP Scope for additional network: %s", net)
		}
		if len(network.OrgVDCNetwork.Configuration.IPScopes.IPScope) == 0 {
			return fmt.Errorf("Zero length IP Scope for additional network: %s", net)
		}
	}
	return nil
}

func (v *VcdPlatform) AddCommonSharedNetToVapp(ctx context.Context, vapp *govcd.VApp, vcdClient *govcd.VCDClient, netName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddCommonSharedNetToVapp", "netName", netName)
	vdc, err := v.GetVdc(ctx, vcdClient)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "AddCommonSharedNetToVapp GetVdc failed", "err", err)
		return err
	}
	commonGw, err := v.getInternalSharedCommonSubnetGW(ctx)
	if err != nil {
		return err
	}
	// check if exists
	orgvdcnet, err := vdc.GetOrgVdcNetworkByName(netName, true)
	if err == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "common network already exists", "net", netName)
	} else {
		startAddr, endAddr, err := v.getInternalSharedCommonStartEndAddrs(ctx)
		if err != nil {
			return err
		}
		var (
			gateway       = commonGw
			networkName   = netName
			startAddress  = startAddr
			endAddress    = endAddr
			netmask       = InternalSharedCommonSubnetMask
			dns1          = "1.1.1.1"
			dns2          = "8.8.8.8"
			dnsSuffix     = v.vmProperties.CommonPf.GetCloudletDNSZone()
			description   = "mex vdc common sharedLB subnet"
			networkConfig = types.OrgVDCNetwork{
				Xmlns:       types.XMLNamespaceVCloud,
				Name:        networkName,
				Description: description,
				Configuration: &types.NetworkConfiguration{
					FenceMode: types.FenceModeIsolated,
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
				IsShared: false, // private to this vdc
			}
		)

		task, err := vdc.CreateOrgVDCNetwork(&networkConfig)
		// accept  a pre-existing network
		if err != nil {
			if strings.Contains(err.Error(), "exists") {
				log.SpanLog(ctx, log.DebugLevelInfra, "CreateIsoVdcNetwork use existing orgvdcnet", "netName", netName)
			} else {
				log.SpanLog(ctx, log.DebugLevelInfra, "CreateIsoVdcNetwork CreateOrgVDCNetwork  failed ", "err", err)
				return err
			}
		}
		err = task.WaitTaskCompletion()
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "CreateIsoVdcNetwork CreateOrgVDCNetwork wait failed ", "err", err)
		}
		orgvdcnet, err = vdc.GetOrgVdcNetworkByName(netName, true)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "CreateIsoVdcNetwork GetOrgVDCNetwork  failed ", "netName", netName, "err", err)
			return err
		}
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "CreateIsoVdcNetowrk created", "name", netName)
	vappNetSettings := &govcd.VappNetworkSettings{
		Name:             netName,
		VappFenceEnabled: TakeBoolPointer(false),
	}

	_, err = vapp.AddOrgNetwork(vappNetSettings, orgvdcnet.OrgVDCNetwork, false)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "CreateIsoVdcNetwork AddOrgNetwork  failed ", "netName", netName, "err", err)
		return err
	}

	return nil
}

func (v *VcdPlatform) updateMetadataForLegacyIsoNets(ctx context.Context, vcdClient *govcd.VCDClient, vdc *govcd.Vdc, subnetToIsoNet map[string]string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "updateMetadataForVappNets", "subnetToIsoNet", subnetToIsoNet)
	shrName := v.getSharedVappName()
	shrVapp, err := v.FindVApp(ctx, shrName, vcdClient, vdc)
	if err != nil {
		// this can happen on first startup
		log.SpanLog(ctx, log.DebugLevelInfra, "no shared vapp")
		return nil
	}

	netLock.Lock()
	defer netLock.Unlock()

	meta, err := shrVapp.GetMetadata()
	if err != nil {
		return fmt.Errorf("unable to get shared vapp metadata %s - %v", shrName, err)
	}
	for subnetName, netName := range subnetToIsoNet {
		key := v.getLegacyPerClusterMetadataKey(subnetName)
		foundKey := false
		for _, me := range meta.MetadataEntry {
			if me.Key == key {
				foundKey = true
				break
			}
		}
		if foundKey {
			log.SpanLog(ctx, log.DebugLevelInfra, "orgnet already in metadata", "key", key, "val", netName)
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "need to add orgnet to metadata", "key", key, "val", netName)
			task, err := shrVapp.AddMetadata(key, netName)
			err = task.WaitTaskCompletion()
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "wait addmetadata to shared vapp failed", "error", err)
				return err
			}
		}
	}
	return nil

}

// on (re)start attempt ensure legacy (prior to common shared lb) ISO nets are in metadata
func (v *VcdPlatform) UpdateLegacyIsoNetMetaData(ctx context.Context) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "UpdateLegacyIsoNetMetaData")
	var err error

	ctx, result, err := v.InitOperationContext(ctx, vmlayer.OperationInitStart)
	if err != nil {
		return err
	}
	if result == vmlayer.OperationNewlyInitialized {
		defer v.InitOperationContext(ctx, vmlayer.OperationInitComplete)
	}
	vcdClient := v.GetVcdClientFromContext(ctx)
	if vcdClient == nil {
		return fmt.Errorf(NoVCDClientInContext)
	}

	vdc, err := v.GetVdc(ctx, vcdClient)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "DetachPortFromServer unable to retrieve current vdc", "err", err)
		return err
	}
	subnetMap, err := v.getSubnetLegacyIsoMap(ctx, vdc, vcdClient)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "error in getVappToSubnetMap", "err", err)
		return err
	}
	err = v.updateMetadataForLegacyIsoNets(ctx, vcdClient, vdc, subnetMap)
	if err != nil {
		return err
	}
	return nil
}

func (v *VcdPlatform) vappNameToInternalSubnet(ctx context.Context, vappName string) string {
	netName := strings.TrimSuffix(vappName, "-vapp")
	netName = vmlayer.MexSubnetPrefix + netName
	return netName

}

func (v *VcdPlatform) getSharedVappName() string {
	return v.vmProperties.SharedRootLBName + "-vapp"
}

func (v *VcdPlatform) getSubnetLegacyIsoMap(ctx context.Context, vdc *govcd.Vdc, vcdClient *govcd.VCDClient) (map[string]string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "getSubnetLegacyIsoMap", "SharedRootLBName", v.vmProperties.SharedRootLBName)
	subnetMap := make(map[string]string)
	sharedLbVappName := v.getSharedVappName()
	commonNetName := v.vmProperties.GetSharedCommonSubnetName()
	// For all vapps in vdc
	for _, r := range vdc.Vdc.ResourceEntities {
		for _, res := range r.ResourceEntity {
			if res.Name == sharedLbVappName {
				// don't want this one
				continue
			}
			if res.Type == VappResourceXmlType {
				vapp, err := vdc.GetVAppByName(res.Name, false)
				if err != nil {
					return nil, err
				}
				log.SpanLog(ctx, log.DebugLevelInfra, "Found Vapp Networks", "vappname", vapp.VApp.Name, "nets", vapp.VApp.NetworkConfigSection.NetworkNames())
				for _, n := range vapp.VApp.NetworkConfigSection.NetworkNames() {
					if n == "none" {
						continue
					}
					if n == commonNetName {
						log.SpanLog(ctx, log.DebugLevelInfra, "Skipping shared common net", "netname", n)
					}
					if !strings.HasPrefix(n, mexInternalNetRange) {
						log.SpanLog(ctx, log.DebugLevelInfra, "Skipping network not in internal range", "netname", n)
						continue
					}
					net, err := vdc.GetOrgVdcNetworkByName(n, false)
					if err != nil {
						log.SpanLog(ctx, log.DebugLevelInfra, "Cannot get net by name", "netname", n, "err", err)
						continue
					}
					mexSubnetName := v.vappNameToInternalSubnet(ctx, vapp.VApp.Name)
					log.SpanLog(ctx, log.DebugLevelInfra, "mapping vapp net to subnet", "mexSubnetName", mexSubnetName, "netname", net.OrgVDCNetwork.Name)
					subnetMap[mexSubnetName] = n
				}
			}
		}
	}
	return subnetMap, nil

}
