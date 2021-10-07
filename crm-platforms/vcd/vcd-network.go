package vcd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/vmware/go-vcloud-director/v2/govcd"
	"github.com/vmware/go-vcloud-director/v2/types/v56"
)

// Networks
// OrgVDCNetworks

// TODO: currently VCD assumes 10.101.x.x.  We should tweak to use the netplan value so we can have different cloudlets on one vcd
var mexInternalNetRange = "10.101"

var CloudletIsoNamesMap = "CloudletIsoNamesMap"

var dhcpLeaseTime int = 60 * 60 * 24 * 365 * 10 // 10 years

type VappNetIpAllocationType string

const VappNetIpAllocationStatic = "static"
const VappNetIpAllocationDhcp = "dhcp"

var InternalVappSubnet = "10.101.1.1"

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
	Name        string
	Gateway     string
	NetworkType vmlayer.NetworkType
	Routes      []edgeproto.Route
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

func (v *VcdPlatform) createNextSharedLBSubnet(ctx context.Context, vapp *govcd.VApp, port vmlayer.PortOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback, vcdClient *govcd.VCDClient) (string, error) {
	// shared lbs need individual orgvcd isolated networks, must be unique.
	// take the lock that is released after the network has been added to the sharedLB's VApp
	log.SpanLog(ctx, log.DebugLevelInfra, "createNextSharedLBSubnet", "vapp", vapp.VApp.Name)

	netLock.Lock()
	defer netLock.Unlock()

	subnet, reuseExistingNet, err := v.GetNextInternalSubnet(ctx, vapp.VApp.Name, updateCallback, vcdClient)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "createNextSharedLBSubnet  SharedLB GetNextInternalSubnet failed", "vapp", vapp.VApp.Name, "port.NetworkName", port.NetworkName, "error", err)
		return "", err
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "createNextSharedLBSubnetSharedLB", "vapp", vapp.VApp.Name, "port.Networkname", port.NetworkName, "port.SubnetId", port.SubnetId, "IP subnet", subnet, "reused", reuseExistingNet)
	// OrgVDCNetwork LinkType = 2 (isolated)
	// This seems to be an admin priv operation if using  nsx-t back network pool xxx
	err = v.CreateIsoVdcNetwork(ctx, vapp, port.SubnetId, subnet, vcdClient, reuseExistingNet)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "createNextSharedLBSubnet  create iso orgvdc internal net failed", "err", err)
		return "", err
	}
	return subnet, nil
}

// AddPortsToVapp returns netinfo map
func (v *VcdPlatform) AddPortsToVapp(ctx context.Context, vapp *govcd.VApp, vmgp vmlayer.VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback, vcdClient *govcd.VCDClient) (map[string]networkInfo, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddPortsToVapp", "vapp", vapp.VApp.Name)

	ports := vmgp.Ports
	subnet := ""
	numPorts := len(ports)
	vmparams := vmgp.VMs[0]
	serverName := vmparams.Name
	intAdded := false
	vmType := string(vmlayer.GetVmTypeForRole(string(vmparams.Role)))

	netMap := make(map[string]networkInfo)

	log.SpanLog(ctx, log.DebugLevelInfra, "AddPortsToVapp", "VAppName", vmgp.GroupName, "role", vmparams.Role, "type", vmType, "numports", numPorts)

	for n, port := range ports {
		if port.NetType != vmlayer.NetworkTypeInternalPrivate && port.NetType != vmlayer.NetworkTypeInternalSharedLb {
			net, err := v.GetExtNetwork(ctx, vcdClient, port.NetworkName)
			if err == nil {
				gw, err := v.GetGatewayForOrgVDCNetwork(ctx, net.OrgVDCNetwork)
				if err != nil {
					return nil, fmt.Errorf("Error getting GW for network %s - %v", net.OrgVDCNetwork.Name, err)
				}
				log.SpanLog(ctx, log.DebugLevelInfra, "Got external network gateway", "netName", port.NetworkName, "gw", gw)
				if err == nil {
					netMap[port.NetworkName] = networkInfo{
						Name:        port.NetworkName,
						Gateway:     gw,
						NetworkType: port.NetType,
					}
				}
			} else {
				log.SpanLog(ctx, log.DebugLevelInfra, "fail to get network", "NetworkName", port.NetworkName, "nettype", port.NetType, "err", err)
				return nil, fmt.Errorf("Failed to get network %s - %v", port.NetworkName, err)
			}
		}
		// External = 0
		switch port.NetType {
		case vmlayer.NetworkTypeExternalPrimary:
			fallthrough
		case vmlayer.NetworkTypeExternalAdditionalPlatform:
			fallthrough
		case vmlayer.NetworkTypeExternalAdditionalClusterNode:
			fallthrough
		case vmlayer.NetworkTypeExternalAdditionalRootLb:
			log.SpanLog(ctx, log.DebugLevelInfra, "AddPortsToVapp adding external vapp net", "PortNum", n, "vapp", vapp.VApp.Name, "NetworkName", port.NetworkName, "NetworkType", port.NetType)
			vappNcs, err := v.AddVappNetwork(ctx, vapp, vcdClient, port.NetworkName)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "Error adding vapp network", "vappNcs", vappNcs, "err", err)
				return nil, fmt.Errorf("Error adding vapp net: %s to vapp %s -- %v", port.NetworkName, vapp.VApp.Name, err)
			}
		case vmlayer.NetworkTypeInternalPrivate:
			fallthrough
		case vmlayer.NetworkTypeInternalSharedLb:
			if intAdded {
				continue
			}
			var err error
			log.SpanLog(ctx, log.DebugLevelInfra, "AddPortsToVapp adding internal vapp net", "PortNum", n, "vapp", vapp.VApp.Name, "port.NetowkName", port.SubnetId, "port.SubnetId", port.SubnetId)
			// We've fenced our VApp isolated networks, so they can all use the same subnet
			subnet = InternalVappSubnet
			if v.Verbose {
				log.SpanLog(ctx, log.DebugLevelInfra, "AddPortsToVapp adding internal vapp net", "PortNum", n, "vapp", vapp.VApp.Name, "port.NetworkName", port.NetworkName, "IP subnet", subnet)
			}
			if vmgp.ConnectsToSharedRootLB {
				log.SpanLog(ctx, log.DebugLevelInfra, "AddPortsToVapp adding internal vapp net for SharedLB", "vapp", vapp.VApp.Name)
				// This can return the next available cidr, or an existing cidr from the FreeIsoNets list
				subnet, err = v.createNextSharedLBSubnet(ctx, vapp, port, updateCallback, vcdClient)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "AddPortsToVapp createNextShareRootLBSubnet failed", "vapp", vapp.VApp.Name, "error", err)
					return nil, err
				}
				log.SpanLog(ctx, log.DebugLevelInfra, "AddPortsToVapp created iso vdcnet for SharedLB", "network", port.SubnetId, "vapp", vapp.VApp.Name, "IP subnet", subnet)
			} else {
				log.SpanLog(ctx, log.DebugLevelInfra, "AddPortsToVapp adding internal vapp net non-shared", "vapp", vapp.VApp.Name)
				if len(vmgp.Subnets) == 0 {
					return nil, fmt.Errorf("No subnets specified in orch params")
				}
				var ipAllocation VappNetIpAllocationType = VappNetIpAllocationStatic
				if !v.vmProperties.RunLbDhcpServerForVmApps {
					if len(vmgp.VMs) == 2 && vmgp.VMs[1].Role == vmlayer.RoleVMApplication {
						ipAllocation = VappNetIpAllocationDhcp
					}
				}
				_, err = v.CreateInternalNetworkForNewVm(ctx, vapp, serverName, port.SubnetId, subnet, vmgp.Subnets[0].DNSServers, ipAllocation)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "create internal net failed", "err", err)
					return nil, err
				}
			}
			if v.Verbose {
				log.SpanLog(ctx, log.DebugLevelInfra, "AddPortsToVapp add to vapp  internal", "network", port.Name)
			}
			intAdded = true
			netMap[port.SubnetId] = networkInfo{
				Name:        port.SubnetId,
				Gateway:     subnet,
				NetworkType: port.NetType,
			}
			log.SpanLog(ctx, log.DebugLevelInfra, "added internal net to map", "Name", port.SubnetId)
		}
	}
	if v.Verbose {
		log.SpanLog(ctx, log.DebugLevelInfra, "AddPortsToVapp return", "NextCidr", subnet, "NumPorts", numPorts)
	}
	return netMap, nil
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

	// shared LBs are asked to grow a new isolated OrgVDCNetwork
	// The network itself has been created by the client cluster vapp.
	cidrNet := ""
	cidrNet, err := v.updateIsoNamesMap(ctx, IsoMapActionRead, subnetName, "")
	if cidrNet == "" || err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "No mapping for", "Network", subnetName, "error", err, "IsoNamesMap", v.IsoNamesMap)
		return fmt.Errorf("No Matching Subnet in IsoNamesMap")
	}
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

	log.SpanLog(ctx, log.DebugLevelInfra, "AttachPortToserver", "ServerName", serverName, "subnet", subnetName, "cidrNet", cidrNet, "ip", ipaddr, "portName", portName, "action", action)
	if action == vmlayer.ActionCreate {
		// The client VM(s) that wish to be serviced by this sharedLB (serverName) have already created the needed orgvdc iso network
		orgvdcnet, err := vdc.GetOrgVdcNetworkByName(cidrNet /*subnetName,*/, false)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "AttachPortToServer orgvdc subnet not found", "subnetName", subnetName, "cidrNet", cidrNet)
			return err
		}
		vappNetSettings := &govcd.VappNetworkSettings{
			Name:             cidrNet, /* subnetname */
			VappFenceEnabled: TakeBoolPointer(false),
		}
		// need to Add this orgvdcnet to this Vapp so the vm can find it.

		_, err = vapp.AddOrgNetwork(vappNetSettings, orgvdcnet.OrgVDCNetwork, false)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "AttachPortToServer AddOrgNetwork failed", "subnetName", subnetName, "err", err)
			return err
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "AttachPortToServer AddOrgNetwork added", "subnetName", subnetName, "cidrNet", cidrNet, "vapp", vapp.VApp.Name)
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
			Network:                 cidrNet, /* subnetName */
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
			_, delerr := vapp.RemoveNetwork(cidrNet)
			if delerr != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "Error deleting network from vapp", "vapp", vapp.VApp.Name, "net", cidrNet, "delerr", delerr)
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

func (v *VcdPlatform) DetachPortFromServer(ctx context.Context, serverName, subnetName, portName string) error {

	log.SpanLog(ctx, log.DebugLevelInfra, "DetachPortFromServer", "ServerName", serverName, "subnet", subnetName, "port", portName)
	cidrNet := ""
	if strings.HasPrefix(subnetName, mexInternalNetRange) {
		// special cleanup case, we passed the cidr net as the net.
		log.SpanLog(ctx, log.DebugLevelInfra, "DetachPortFromServer using subnet name as cidrNet", "subnet", subnetName)
		cidrNet = subnetName
		portName = subnetName
	} else {
		cidrNet, _ = v.updateIsoNamesMap(ctx, IsoMapActionRead, subnetName, "")
		if cidrNet == "" {
			log.SpanLog(ctx, log.DebugLevelInfra, "No mapping for", "Network", subnetName, "IsoNamesMap", v.IsoNamesMap)
			return fmt.Errorf("No Matching Subnet in IsoNamesMap")
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "DetachPortFromServer found isoNamesMap", "subnet", subnetName, "cidrNet", cidrNet)
	}

	vcdClient := v.GetVcdClientFromContext(ctx)
	if vcdClient == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, NoVCDClientInContext)
		return fmt.Errorf(NoVCDClientInContext)
	}
	vdc, err := v.GetVdc(ctx, vcdClient)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "DetachPortFromServer unable to retrieve current vdc", "err", err)
		return err
	}
	vappName := serverName + v.GetVappServerSuffix()
	vapp, err := v.FindVApp(ctx, vappName, vcdClient, vdc)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "DetachPortFromServer server not found", "vapp", vappName, "for server", serverName)
		return err
	}
	orgvdcnet, err := vdc.GetOrgVdcNetworkByName(cidrNet /*subnetName*/, false)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "AttachPortToServer orgvdc subnet not found", "subnetName", subnetName)
		return err
	}

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
			if nc.Network == portName {
				log.SpanLog(ctx, log.DebugLevelInfra, "Remove network from ncs", "nc.Network", nc.Network, "portName", portName)
				ncs.NetworkConnection[n] = ncs.NetworkConnection[len(ncs.NetworkConnection)-1]
				ncs.NetworkConnection[len(ncs.NetworkConnection)-1] = &types.NetworkConnection{}
				ncs.NetworkConnection = ncs.NetworkConnection[:len(ncs.NetworkConnection)-1]
				err := vm.UpdateNetworkConnectionSection(ncs)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "DetachPortFromServer UpdateNetowrkConnectionSection failed", "serverName", serverName, "port", portName, "subnet", subnetName, "err", err)
					return err
				}
				log.SpanLog(ctx, log.DebugLevelInfra, "DetachPortFromServer success", "serverName", serverName, "port", portName, "subnet", subnetName)
				break
			}
		}
	}
	for _, nc := range vapp.VApp.NetworkConfigSection.NetworkConfig {
		log.SpanLog(ctx, log.DebugLevelInfra, "DetachPortFromServer found net config", "nc", nc, "net to remove", orgvdcnet.OrgVDCNetwork.Name)
	}
	_, err = vapp.RemoveNetwork(orgvdcnet.OrgVDCNetwork.Name)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "DetachPortFromServer RemoveNetwork (byName) failed try RemoveIsolatedNetwork", "serverName", serverName, "port", portName, "subnet", subnetName, "cidrNet", cidrNet, "err", err)
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
		DNSSuffix:        "mobiledgex.net",
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

// Given our scheme for networks 10.101.X.0/24 return the next available Isolated network CIDR

func (v *VcdPlatform) GetNextInternalSubnet(ctx context.Context, vappName string, updateCallback edgeproto.CacheUpdateCallback, vcdClient *govcd.VCDClient) (string, bool, error) {

	var MAX_CIDRS = 255 // These are internal /24 subnets so 255, not that we'll have that many clusters / cloudlet

	log.SpanLog(ctx, log.DebugLevelInfra, "GetNextInternalSubnet", "vapp", vappName)

	// look at the free list and use that if available
	if len(v.FreeIsoNets) > 0 {
		cidr := v.getAvailableIsoNetwork(ctx)
		log.SpanLog(ctx, log.DebugLevelInfra, "GetNetInternalSubnet  FreeNets available reusing", "net", cidr)
		return cidr, true, nil
	}

	startAddr := mexInternalNetRange + ".1.1"
	// We'll incr the netSpec.DelimiterOctet of this start addr, if it's not in our
	// All VApps map, it's available
	log.SpanLog(ctx, log.DebugLevelInfra, "GetNextInternalSubnet using", "startAddr", startAddr)
	curAddr := startAddr
	vappMap, err := v.GetVappToNetworkMap(ctx, vcdClient)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetNextInternalSubnet return", "curAddr", curAddr)
		return curAddr, false, err
	}
	if len(vappMap) == 0 {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetNextInternalSubnet  return", "curAddr", curAddr)
		return curAddr, false, nil
	}
	for i := 1; i < MAX_CIDRS; i++ {
		if _, found := vappMap[curAddr]; !found {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetNextInternalSubnet return available", "cidr", curAddr)
			return curAddr, false, nil
		}
		curAddr, err = v.IncrCidr(curAddr, 1)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetNextInternalSubnet IncrCidr failed", "curAddr", curAddr, "err", err)
			return "", false, err
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "GetNextInternalSubnet  subnet range exhasted")
	return "", false, err
}

func (v *VcdPlatform) GetFirstOrgNetworkOfVdc(ctx context.Context, vdc *govcd.Vdc) (*govcd.OrgVDCNetwork, error) {
	nets := vdc.Vdc.AvailableNetworks
	for _, net := range nets {
		for _, ref := range net.Network {
			vdcnet, err := vdc.GetOrgVdcNetworkByHref(ref.HREF)
			if err != nil {
				continue
			}
			return vdcnet, nil
		}
	}
	return nil, fmt.Errorf("Not Found")
}

func (v *VcdPlatform) AddSubnetIdToShareLBClientVapp(ctx context.Context, netName string, vapp *govcd.VApp) error {

	task, err := vapp.AddMetadata("SharedSubnetId", netName)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Addmetadata to  vapp  failed", "vapp", vapp.VApp.Name, "error", err)
		return err
	}
	err = task.WaitTaskCompletion()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "wait Addmetadata to  vapp  failed", "vapp", vapp.VApp.Name, "error", err)

		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "AddSubnetIdToSharedLBClientVapp", "SharedSubnetId", netName)
	return nil
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

func (v *VcdPlatform) getAvailableIsoNetwork(ctx context.Context) string {

	for k, _ := range v.FreeIsoNets {
		delete(v.FreeIsoNets, k)
		log.SpanLog(ctx, log.DebugLevelInfra, "getAvailableIso returns", "network", k)
		return k
	}
	return ""
}

func (v *VcdPlatform) CreateIsoVdcNetwork(ctx context.Context, vapp *govcd.VApp, netName, cidr string, vcdClient *govcd.VCDClient, reuseExistingNet bool) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateIsoVdcNetwork", "name", netName, "cidr", cidr, "reusing existing net", reuseExistingNet)

	vdc, err := v.GetVdc(ctx, vcdClient)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "CreateIsoVdcNetwork GetVdc failed ", "err", err)
		return err
	}
	// we are under lock here. First check if we have any free iosnets available to use
	if !reuseExistingNet {
		// create a new one
		log.SpanLog(ctx, log.DebugLevelInfra, "CreateIsoVdcNetwork FreeNets empty creating new", "net", cidr)
		startAddr, err := IncrIP(ctx, cidr, 1)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "IncrIP startaddr", "netname", netName, "gateway", cidr, "err", err)
			return err
		}
		endAddr, err := IncrIP(ctx, cidr, MAXCIDR)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "IncrIP endaddr", "netname", netName, "gateway", cidr, "err", err)
			return err
		}

		var (
			gateway       = cidr
			networkName   = cidr // netName
			startAddress  = startAddr
			endAddress    = endAddr
			netmask       = "255.255.255.0"
			dns1          = "1.1.1.1"
			dns2          = "8.8.8.8"
			dnsSuffix     = "mobiledgex.net"
			description   = "mex vdc sharedLB subnet"
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

	}

	orgvdcnet, err := vdc.GetOrgVdcNetworkByName(cidr, true)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "CreateIsoVdcNetwork GetOrgVDCNetwork  failed ", "netName", netName, "err", err)
		return err
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "CreateIsoVdcNetowrk created", "name", netName, "real net", cidr)
	vappNetSettings := &govcd.VappNetworkSettings{
		Name:             cidr,
		VappFenceEnabled: TakeBoolPointer(false),
	}

	netConfSec, err := vapp.AddOrgNetwork(vappNetSettings, orgvdcnet.OrgVDCNetwork, false)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "CreateIsoVdcNetwork AddOrgNetwork  failed ", "netName", netName, "cidr", cidr, "err", err)
		return err
	}
	// xlate names map for network reuse. All these iossubnets are now named with their cidrs
	// Addthe real vdc name (subnetId) using our netName
	_, err = v.updateIsoNamesMap(ctx, IsoMapActionAdd, netName, cidr)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "CreateIsoVdcNetwork updateIsoNamemsMap failed on Add", "error", err)
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateIsoVdcNetwork IsoNameMap", "key", netName, " = value", cidr)
	// enable crm restarts, stash the subnetId name in Vapp as metadata)
	v.AddSubnetIdToShareLBClientVapp(ctx, netName, vapp)
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateIsoVdcNetwork added org net ok", "network", netName, "cidr", cidr, "vapp", vapp.VApp.Name, "NetConfigSection", netConfSec)
	return nil
}

const MAXCIDR = 254

func (v *VcdPlatform) GetNextVdcIsoSubnet(ctx context.Context, vcdClient *govcd.VCDClient) (string, error) {
	var err error
	netMap := make(NetMap)
	log.SpanLog(ctx, log.DebugLevelInfra, "GetNextVdcIsoSubnet")
	// Get a list of all vdc networks type 2 and make a map
	// interate through our subnet schema  n.1 for the first available
	vdc, err := v.GetVdc(ctx, vcdClient)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetNextVdcIsoSubnet GetVdc failed ", "err", err)
		return "", err
	}
	qrecs, err := vdc.GetNetworkList()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetNextVdcIsoSubnet GetNetworkList failed ", "err", err)
		return "", err
	}
	for _, qr := range qrecs {
		if qr.LinkType == 2 {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetNextVdcIsoSubnet found ", "iso subnet", qr.Name)
			netMap[qr.DefaultGateway] = &govcd.OrgVDCNetwork{}
		}
	}
	curCidr := "10.101.1.1"
	if len(netMap) == 0 {
		return curCidr, nil
	}
	// maybe we should use 192. for this here to differentiate between vapp private subnets. ?
	for i := 0; i < MAXCIDR; i++ {
		if _, found := netMap[curCidr]; !found {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetNextVdcIsoSubnet", "subnet", curCidr)
			return curCidr, nil
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "GetNextVdcIsoSubnet skip in use", "subnet", curCidr)
		curCidr, err = v.IncrCidr(curCidr, 1)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetNextVdcIsoSubnet  IncrIP err", "curAddr", curCidr, "err", err)
			return "", err
		}
	}
	return "", fmt.Errorf("Isolated Subnet range exhausted")
}

// If this vapp is using an isolated orgvdcnet, return its name
func (v *VcdPlatform) GetVappIsoNetwork(ctx context.Context, vdc *govcd.Vdc, vapp *govcd.VApp) (string, error) {

	log.SpanLog(ctx, log.DebugLevelInfra, "GetVappIsoNetwork", "vapp", vapp.VApp.Name)

	if vapp.VApp == nil || vapp.VApp.Children == nil || len(vapp.VApp.Children.VM) == 0 {
		// prevent a VMware panic from GetNetworkConnectionSection
		return "", fmt.Errorf("Vapp has no children")
	}

	ncs, err := vapp.GetNetworkConnectionSection()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetVappIsoNetwork Failed to retrieve networkConnectionSection from", "vapp", vapp.VApp.Name, "err", err)
		return "", err
	}
	qr, err := vdc.GetNetworkList()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetVappIsoNetwork GetNetworkList  failed", "err", err)
		return "", err
	}
	for _, nc := range ncs.NetworkConnection {
		for _, q := range qr {
			if q.LinkType == 2 && nc.Network == q.Name {
				log.SpanLog(ctx, log.DebugLevelInfra, "GetVappIsoNetwork vapp using isoOrgVdcNetwork", "netName", q.Name)
				return q.Name, nil
			}
			if v.Verbose {
				log.SpanLog(ctx, log.DebugLevelInfra, "GetVappIsoNetwork vapp using non-isoOrgVdcNet", "netName", q.Name)
			}
		}

	}
	log.SpanLog(ctx, log.DebugLevelInfra, "GetVappIsoNetwork no IsoNetwork found for ", "vapp", vapp.VApp.Name)
	return "", nil

}

// on (re)start attempt to rebuild the free isolated networks and name mapping.
// On cloudlet create, if any of these isonets are in existance, (nsx-t)
// they will be placed on the free list and reused.
func (v *VcdPlatform) RebuildIsoNamesAndFreeMaps(ctx context.Context) error {
	cleanup := v.GetCleanupOrphanedNetworks()
	log.SpanLog(ctx, log.DebugLevelInfra, "RebuildIsoNamesMap", "cleanup", cleanup, "NSX Type", v.GetNsxType())
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

	vappNets, err := v.getVappToSubnetMap(ctx, vdc, vcdClient, cleanup)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "error in getVappToSubnetMap", "err", err)
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "got subnet map, now finding org vdc networks", "vappNets", vappNets)
	orgNets := make(map[string]bool)
	for _, net := range vdc.Vdc.AvailableNetworks {
		for _, ref := range net.Network {
			log.SpanLog(ctx, log.DebugLevelInfra, "Checking available networks, looking for org vdc net", "name", ref.Name)
			nn, err := vdc.GetOrgVdcNetworkByName(ref.Name, false)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "unable to find get net", "ref.Name", ref.Name, "err", err)
				continue
			}
			if strings.HasPrefix(ref.Name, mexInternalNetRange) && nn.OrgVDCNetwork.Type == types.MimeOrgVdcNetwork {
				log.SpanLog(ctx, log.DebugLevelInfra, "Mex internal OrgVDCNetwork", "name", ref.Name, "nntype", nn.OrgVDCNetwork.Type)
				orgNets[ref.Name] = true
			} else {
				// in multi vdc case this could happen
				log.SpanLog(ctx, log.DebugLevelInfra, "OrgVDCNetwork is not a mex int net", "name", ref.Name, "nntype", ref.Type)
			}
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "found org vdc networks", "num nets", len(orgNets))
	rootLBFound := false
	var rootlbVapp *govcd.VApp
	lbServerDetail, err := v.GetServerDetail(ctx, v.vmProperties.SharedRootLBName)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Shared LB find fail", "err", err)
	} else {
		lbVm, err := v.FindVMByName(ctx, v.vmProperties.SharedRootLBName, vcdClient, vdc)
		if err != nil {
			return fmt.Errorf("Cannot find rootlb vm -- %v", err)
		}
		lbVappName := v.vmProperties.SharedRootLBName + "-vapp"
		rootlbVapp, err = vdc.GetVAppByName(lbVappName, false)
		if err != nil {
			return fmt.Errorf("unable to find rootlb vapp: %s - %v", lbVappName, err)
		}
		ncs, err := lbVm.GetNetworkConnectionSection()
		if err != nil {
			return fmt.Errorf("Cannot find rootlb ncs -- %v", err)
		}
		if cleanup {
			needUpdate := false
			prunedNetConfig := &types.NetworkConnectionSection{}
			noVappNets := make(map[string]string)
			log.SpanLog(ctx, log.DebugLevelInfra, "Shared LB network connection section", "ncs", ncs)
			for _, nc := range ncs.NetworkConnection {
				log.SpanLog(ctx, log.DebugLevelInfra, "Shared LB network connection", "network", nc.Network, "ip", nc.IPAddress)
				validNetwork := true
				if nc.Network == "none" {
					// this is a nic connected to nothing.  remove it
					log.SpanLog(ctx, log.DebugLevelInfra, "found nic connected to none network, pruning", "nc", nc.IPAddress)
					validNetwork = false
				} else if !strings.HasPrefix(nc.Network, mexInternalNetRange) {
					log.SpanLog(ctx, log.DebugLevelInfra, "network is not an mex internal network, not prunable")
				} else {
					if nc.IsConnected == false {
						log.SpanLog(ctx, log.DebugLevelInfra, "found disconnected internal rootlb net, pruning", "nc", nc.IPAddress)
						validNetwork = false
					} else {
						_, ok := vappNets[nc.IPAddress]
						if !ok {
							log.SpanLog(ctx, log.DebugLevelInfra, "found internal rootlb net for no vapp, pruning", "network", nc.Network)
							validNetwork = false
							noVappNets[nc.Network] = nc.Network
						}
					}
				}
				if validNetwork {
					prunedNetConfig.NetworkConnection = append(prunedNetConfig.NetworkConnection, nc)
				} else {
					log.SpanLog(ctx, log.DebugLevelInfra, "pruning network", "nc", nc.IPAddress)
					needUpdate = true
				}
			}
			if needUpdate {
				log.SpanLog(ctx, log.DebugLevelInfra, "Updating rootLb NCS", "ncs", prunedNetConfig)
				ncs.NetworkConnection = prunedNetConfig.NetworkConnection
				err = lbVm.UpdateNetworkConnectionSection(ncs)
				if err != nil {
					return fmt.Errorf("Fail to update rootlb NCS - %v", err)
				}
			}

			// networks with no vapps will fail DetachPortFromServer because we will never find the server ip
			if len(noVappNets) > 0 {
				log.SpanLog(ctx, log.DebugLevelInfra, "Found iso nets with no vapps on rootlb, deleting")

				for _, net := range noVappNets {
					log.SpanLog(ctx, log.DebugLevelInfra, "Removing network from rootlb vapp", "net", net)
					if rootlbVapp != nil {
						_, err = rootlbVapp.RemoveNetwork(net)
						if err != nil {
							log.SpanLog(ctx, log.DebugLevelInfra, "Removing network from rootlb vapp failed", "err", err)
						}
					}
				}
			}
		}
	}

	numOphans := 0
	numFound := 0

	log.SpanLog(ctx, log.DebugLevelInfra, "Looking for vapps on org nets to find orphans")
	for o := range orgNets {
		// if cleanup enabled
		vappNet, ok := vappNets[o]
		if ok {
			log.SpanLog(ctx, log.DebugLevelInfra, "org vcd network is not an orphan", "name", o, "vappNet", vappNet)
			_, err := v.updateIsoNamesMap(ctx, IsoMapActionAdd, vappNet, o)
			if err != nil {
				return err
			}
			numFound++
		} else {
			if v.GetNsxType() == NSXV {
				log.SpanLog(ctx, log.DebugLevelInfra, "Orphan net not found on a vapp", "name", o, "cleanup", cleanup)
				numOphans++
				// delete this sucker from rootlb and then nuke it
				if cleanup {
					log.SpanLog(ctx, log.DebugLevelInfra, "Cleaning up orphaned network", "net", o)
					if rootLBFound {
						for _, sip := range lbServerDetail.Addresses {
							if sip.ExternalAddr == o {
								// remove hung network from lb
								log.SpanLog(ctx, log.DebugLevelInfra, "Remove network from lbvm", "net", o)
								err = v.DetachPortFromServer(ctx, lbServerDetail.Name, o, "")
								if err != nil {
									return fmt.Errorf("Removing orphaned net from lbvm failed - %v", err)
								}
							}
						}
					}
					// network may have been removed via DetachPortFromServer already, but in case that did not happen, remove from vapp
					log.SpanLog(ctx, log.DebugLevelInfra, "Deleting net from rootlb vapp", "net", o)
					// remove from rootlb vapp if it is there
					if rootlbVapp != nil {
						_, err = rootlbVapp.RemoveNetwork(o)
						if err != nil {
							log.SpanLog(ctx, log.DebugLevelInfra, "Removing network from rootlb vapp failed", "err", err)
						}
					}

					err = vdc.Refresh()
					if err != nil {
						return fmt.Errorf("vdc refresh failed - %v", err)
					}
					err = govcd.RemoveOrgVdcNetworkIfExists(*vdc, o)
					if err != nil {
						return fmt.Errorf("Fail to remove orphaned org vcd network %s - %v", o, err)
					}
				} //cleanup
			} else {
				// freelist for NSX-T
				orgvdcnetwork, err := vdc.GetOrgVdcNetworkByName(o, false)
				if err != nil {
					return err
				}
				v.FreeIsoNets[o] = orgvdcnetwork
			}
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "RebuildIsoNamesAndFreeMaps done", "numOphans", numOphans, "IsoNamesMap", v.IsoNamesMap, "numFound", numFound)
	return nil
}

func (v *VcdPlatform) vappNameToInternalSubnet(ctx context.Context, vappName string) string {
	netName := strings.TrimSuffix(vappName, "-vapp")
	netName = vmlayer.MexSubnetPrefix + netName
	return netName

}

func (v *VcdPlatform) getVappToSubnetMap(ctx context.Context, vdc *govcd.Vdc, vcdClient *govcd.VCDClient, cleanup bool) (map[string]string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "getVappToSubnetMap", "SharedRootLBName", v.vmProperties.SharedRootLBName)
	vappToSubnetMap := make(map[string]string)
	sharedLbVappName := v.vmProperties.SharedRootLBName + "-vapp"
	// For all vapps in vdc
	for _, r := range vdc.Vdc.ResourceEntities {
		for _, res := range r.ResourceEntity {
			if res.Name == sharedLbVappName {
				// don't want this one
				continue
			}
			if res.Type == "application/vnd.vmware.vcloud.vApp+xml" {
				vapp, err := vdc.GetVAppByName(res.Name, true)
				if err != nil {
					return nil, err
				}
				log.SpanLog(ctx, log.DebugLevelInfra, "Found Vapp Networks", "vappname", vapp.VApp.Name, "nets", vapp.VApp.NetworkConfigSection.NetworkNames())
				if len(vapp.VApp.NetworkConfigSection.NetworkNames()) == 0 && cleanup {
					log.SpanLog(ctx, log.DebugLevelInfra, "Vapp has no networks and needs cleanup", "vappname", vapp.VApp.Name)
					err = v.DeleteVapp(ctx, vapp, vcdClient)
					if err != nil {
						log.SpanLog(ctx, log.DebugLevelInfra, "cleanup vapp fail", "vappname", vapp.VApp.Name, "err", err)
					}
				}

				for _, n := range vapp.VApp.NetworkConfigSection.NetworkNames() {
					if n == "none" {
						continue
					}
					net, err := vdc.GetOrgVdcNetworkByName(n, false)
					if err != nil {
						log.SpanLog(ctx, log.DebugLevelInfra, "Cannot get net by name", "netname", n, "err", err)
						continue
					}
					if !strings.HasPrefix(net.OrgVDCNetwork.Name, mexInternalNetRange) {
						log.SpanLog(ctx, log.DebugLevelInfra, "Skipping network not in internal range", "netname", net.OrgVDCNetwork.Name)
						continue
					}
					mexSubnetName := v.vappNameToInternalSubnet(ctx, vapp.VApp.Name)
					log.SpanLog(ctx, log.DebugLevelInfra, "mapping vapp net to subnet", "netname", net.OrgVDCNetwork.Name, "mexSubnetName", mexSubnetName)
					vappToSubnetMap[net.OrgVDCNetwork.Name] = mexSubnetName
				}
			}
		}
	}
	return vappToSubnetMap, nil

}

var isoNamesLock sync.Mutex

func (v *VcdPlatform) replaceIsoNamesMap(ctx context.Context, newMap map[string]string) {
	log.SpanLog(ctx, log.DebugLevelInfra, "replaceIsoNamesMap", "newMap", newMap)

	isoNamesLock.Lock()
	defer isoNamesLock.Unlock()
	v.IsoNamesMap = newMap
}

func (v *VcdPlatform) updateIsoNamesMap(ctx context.Context, action IsoMapActionType, key, value string) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "updateIsoNamesMap", "action", action, "key", key, "value", value, "map", v.IsoNamesMap)

	cacheUpdateNeeded := false
	keyValToReturn := ""
	isoNamesLock.Lock()
	defer isoNamesLock.Unlock()

	if action == IsoMapActionRead {

		if key != "" {
			return v.IsoNamesMap[key], nil
		} else if value != "" {
			for k, val := range v.IsoNamesMap {
				if val == value {
					return k, nil
				}
			}
		} else {
			return "", fmt.Errorf("invalid args for action read")
		}
	} else if action == IsoMapActionDelete {

		if key == "" && value != "" {
			for k, val := range v.IsoNamesMap {
				if val == value {
					delete(v.IsoNamesMap, k)
					cacheUpdateNeeded = true
					keyValToReturn = k
					break
				}
			}
			if keyValToReturn == "" {
				return "", fmt.Errorf("value %s not found in map", value)
			}
		} else if key != "" {
			delete(v.IsoNamesMap, key)
			cacheUpdateNeeded = true
		} else {
			return "", fmt.Errorf("invalid args for action delete")
		}

	} else if action == IsoMapActionAdd {
		if key != "" && value != "" {
			v.IsoNamesMap[key] = value
			cacheUpdateNeeded = true
		} else {
			return "", fmt.Errorf("invalid args for action Create")
		}
	} else {
		return "", fmt.Errorf("Unsupported action type %s encountered", action)
	}
	if cacheUpdateNeeded {
		var cloudletInternal edgeproto.CloudletInternal

		if !v.caches.CloudletInternalCache.Get(v.vmProperties.CommonPf.PlatformConfig.CloudletKey, &cloudletInternal) {
			return "", fmt.Errorf("cannot get cloudlet internal from cache")
		}
		mapJson, err := json.Marshal(v.IsoNamesMap)
		if err != nil {
			return "", fmt.Errorf("Fail to marshal isoNamesMap into json for cache update")
		}
		cloudletInternal.Props[CloudletIsoNamesMap] = string(mapJson)
		log.SpanLog(ctx, log.DebugLevelInfra, "Updating cache with new isoMap", "mapJson", string(mapJson))
		v.caches.CloudletInternalCache.Update(ctx, &cloudletInternal, 0)
	}
	return keyValToReturn, nil
}
