package vcd

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/vmware/go-vcloud-director/v2/govcd"
	"github.com/vmware/go-vcloud-director/v2/types/v56"
)

// Networks
// OrgVDCNetworks

func (v *VcdPlatform) GetNetworkList(ctx context.Context) ([]string, error) {
	return []string{
		v.vmProperties.GetCloudletExternalNetwork(),
	}, nil
}

func (v *VcdPlatform) GetExternalIpNetworkCidr(ctx context.Context, vcdClient *govcd.VCDClient) (string, error) {

	extNet, err := v.GetExtNetwork(ctx, vcdClient)
	if err != nil {
		return "", err
	}
	scope := extNet.OrgVDCNetwork.Configuration.IPScopes.IPScope[0]
	mask := v.GetExternalNetmask()
	addr := scope.Gateway + "/" + mask

	log.SpanLog(ctx, log.DebugLevelInfra, "GetExternalIpNetworkCidr", "addr", addr)

	return addr, nil

}

// fetch the OrgVDCNetwork referenced by MEX_EXT_NET our Primary external network
func (v *VcdPlatform) GetExtNetwork(ctx context.Context, vcdClient *govcd.VCDClient) (*govcd.OrgVDCNetwork, error) {

	// infra propert from env
	netName := v.GetExtNetworkName()

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
	vdcNet, err := v.GetExtNetwork(ctx, vcdClient)
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

func (v *VcdPlatform) AddPortsToVapp(ctx context.Context, vapp *govcd.VApp, vmgp vmlayer.VMGroupOrchestrationParams, vcdClient *govcd.VCDClient) (string, error) {
	ports := vmgp.Ports
	nextCidr := ""
	numPorts := len(ports)
	vmparams := vmgp.VMs[0]
	serverName := vmparams.Name
	intAdded := false
	vmType := string(vmlayer.GetVmTypeForRole(string(vmparams.Role)))

	log.SpanLog(ctx, log.DebugLevelInfra, "AddPortsToVapp", "VAppName", vmgp.GroupName, "role", vmparams.Role, "type", vmType, "numports", numPorts)

	for n, port := range ports {
		// External = 0
		if port.NetworkType == vmlayer.NetTypeExternal {

			desiredNetConfig := &types.NetworkConnectionSection{}
			desiredNetConfig.PrimaryNetworkConnectionIndex = 1
			extAddr, err := v.GetNextExtAddrForVdcNet(ctx, vcdClient)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "AddPortsToVapp GetNextExtAddr failed", "err", err)
				return "", err
			}
			if extAddr == "" {
				log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp next ext net IP not found", "vapp", vmgp.GroupName)
				return "", fmt.Errorf("next available ext net ip not found")
			}
			conIdx := 1
			log.SpanLog(ctx, log.DebugLevelInfra, "AddPortsToVapp adding external vapp net", "PortNum", n, "vapp", vapp.VApp.Name, "port.NetworkName", port.NetworkName, "IP", extAddr, "ConIdx", conIdx)
			_, err = v.AddVappNetwork(ctx, vapp, vcdClient)

			desiredNetConfig.NetworkConnection = append(desiredNetConfig.NetworkConnection,
				&types.NetworkConnection{
					IsConnected:             true,
					IPAddressAllocationMode: types.IPAllocationModeManual,
					Network:                 v.GetExtNetworkName(),
					NetworkConnectionIndex:  conIdx,
					IPAddress:               extAddr,
				})

			// metadata?
			vmtmplName := vapp.VApp.Children.VM[0].Name
			vm, err := vapp.GetVMByName(vmtmplName, false)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp unable to retrieve", "vm", vmtmplName, "vapp", vapp.VApp.Name)
				return "", err
			}
			err = vm.UpdateNetworkConnectionSection(desiredNetConfig)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "update external  network failed", "VAppName", vmgp.GroupName, "err", err)
				return "", err
			}
		}
		// Internal (isolated)
		// Create isolated subnet for this vapp/clusterInst (Not OrgVDCNetwork)
		if port.NetworkType == vmlayer.NetTypeInternal && !intAdded {
			var err error
			nextCidr, err = v.GetNextInternalSubnet(ctx, vapp.VApp.Name, vcdClient)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp next internal net failed: ", "GroupName", vmgp.GroupName, "err", err)
				return "", err
			}
			if nextCidr == "" {
				log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp next internal net cid == ", "Vapp", vapp.VApp.Name, "Port.Network", port.NetworkName, "PortNum", n)
				return "", fmt.Errorf("next available subnet not found")

			}
			if v.Verbose {
				log.SpanLog(ctx, log.DebugLevelInfra, "AddPortsToVapp adding internal vapp net", "PortNum", n, "vapp", vapp.VApp.Name, "port.NetowkrNamek", port.NetworkName, "IP subnet", nextCidr)
			}
			// Subnet or portName? subnet failed,
			_, err = v.CreateInternalNetworkForNewVm(ctx, vapp, serverName, port.SubnetId, nextCidr)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "create internal net failed", "err", err)
				return "", err
			}
			if v.Verbose {
				log.SpanLog(ctx, log.DebugLevelInfra, "AddPortsToVapp  add to vapp  internal", "network", port.Name)
			}
			intAdded = true
		}
	}
	if v.Verbose {
		log.SpanLog(ctx, log.DebugLevelInfra, "AddPortsToVapp return", "NextCidr", nextCidr, "NumPorts", numPorts)
	}
	return nextCidr, nil
}

// AttachPortToServer
func (v *VcdPlatform) AttachPortToServer(ctx context.Context, serverName, subnetName, portName, ipaddr string, action vmlayer.ActionType) error {
	// shared LBs are asked to grow a new internal network
	vappName := serverName + v.GetVappServerSuffix()

	vcdClient := v.GetVcdClientFromContext(ctx)
	if vcdClient == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, NoVCDClientInContext)
		return fmt.Errorf(NoVCDClientInContext)
	}

	vapp, err := v.FindVApp(ctx, vappName, vcdClient)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "AttachPortToServer server not found", "vapp", vappName, "for server", serverName)
		return err
	}
	vmName := vapp.VApp.Children.VM[0].Name
	vm, err := vapp.GetVMByName(vmName, true)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "AttachPortToServer server not found", "vm", vmName, "for server", serverName)
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "AttachPortToserver", "ServerName", serverName, "subnet", subnetName, "ip", ipaddr, "portName", portName, "action", action)
	if action == vmlayer.ActionCreate {
		// Add the new network to this vapp
		log.SpanLog(ctx, log.DebugLevelInfra, "AttachPortToServer adding", "subnetName", subnetName, "portName", portName, "server", serverName, "vapp", vappName)

		// Get the next available internal subnet
		nextCidr, err := v.GetNextInternalSubnet(ctx, vappName, vcdClient)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "AttachPortToServer  Get next internal net failed: ", "err", err)
			return err
		}
		if v.Verbose {
			log.SpanLog(ctx, log.DebugLevelInfra, "AttachPortToServer CreateInternalNetwork for", "vapp", vappName, "portName", portName, "cidr", nextCidr)
		}

		internalNetName, err := v.CreateInternalNetworkForNewVm(ctx, vapp, serverName, subnetName, nextCidr)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "AttachPortToServer create internal net failed", "err", err)
			return err
		}
		var a []string
		vmIp := ""
		if nextCidr != "" {
			a = strings.Split(nextCidr, "/")
			vmIp = string(a[0])
		}

		// Add the connection section to the vapp's vm
		log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp add connection", "net", internalNetName, "ip", vmIp, "VM", vmName)
		ncs, err := vm.GetNetworkConnectionSection()
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "Failed to retrieve networkConnectionSection from", "vm", vmName, "err", err)
			return err
		}
		ncs.NetworkConnection = append(ncs.NetworkConnection,
			&types.NetworkConnection{
				Network:                 subnetName,
				NetworkConnectionIndex:  0,
				IPAddress:               vmIp,
				IsConnected:             true,
				IPAddressAllocationMode: types.IPAllocationModeManual,
			})

		err = vm.UpdateNetworkConnectionSection(ncs)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp add internal net failed", "VM", vmName, "error", err)
			return err
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "AddVMsToVApp added connection", "net", internalNetName, "ip", vmIp, "VM", vmName)

	} else if action == vmlayer.ActionDelete {
		ncs, err := vm.GetNetworkConnectionSection()
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "Failed to retrieve networkConnectionSection from", "vm", vmName, "err", err)
			return err
		}
		for n, nc := range ncs.NetworkConnection {
			if nc.Network == portName {
				ncs.NetworkConnection[n] = ncs.NetworkConnection[len(ncs.NetworkConnection)-1]
				ncs.NetworkConnection[len(ncs.NetworkConnection)-1] = &types.NetworkConnection{}
				ncs.NetworkConnection = ncs.NetworkConnection[:len(ncs.NetworkConnection)-1]
				err := vm.UpdateNetworkConnectionSection(ncs)
				if err != nil {
					return err
				}
			}
		}
	} else if action == vmlayer.ActionUpdate {
		log.SpanLog(ctx, log.DebugLevelInfra, "AttachPortToServer updating", "subnetName", subnetName, "portName", portName, "ip", ipaddr, "server", serverName)

	}
	return nil
}

func (v *VcdPlatform) DetachPortFromServer(ctx context.Context, serverName, subnetName, portName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "detach  port", "ServerName", serverName, "subnet", subnetName, "port", portName)
	return nil
}

func IncrIP(ctx context.Context, a string, delta int) (string, error) {
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

func (v *VcdPlatform) CreateInternalNetworkForNewVm(ctx context.Context, vapp *govcd.VApp, serverName, netName string, cidr string) (string, error) {
	var iprange []*types.IPRange

	log.SpanLog(ctx, log.DebugLevelInfra, "create internal server net", "netname", netName)

	description := fmt.Sprintf("internal-%s", cidr)
	a := strings.Split(cidr, "/")
	addr := string(a[0])
	gateway := addr
	dns2 := ""

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

	addrRange := types.IPRange{
		StartAddress: startAddr,
		EndAddress:   endAddr,
	}
	iprange = append(iprange, &addrRange)

	internalSettings := govcd.VappNetworkSettings{
		Name:           netName,
		Description:    description,
		Gateway:        gateway,
		NetMask:        "255.255.255.0",
		DNS1:           "1.1.1.1",
		DNS2:           dns2,
		DNSSuffix:      "mobiledgex.net",
		StaticIPRanges: iprange,
	}
	_ /*InternalNetConfigSec,*/, err = vapp.CreateVappNetwork(&internalSettings, nil)
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

func (v *VcdPlatform) AddVappNetwork(ctx context.Context, vapp *govcd.VApp, vcdClient *govcd.VCDClient) (*types.NetworkConfigSection, error) {

	orgNet, err := v.GetExtNetwork(ctx, vcdClient)
	if err != nil {
		return nil, err
	}
	IPScope := orgNet.OrgVDCNetwork.Configuration.IPScopes.IPScope[0] // xxx

	var iprange []*types.IPRange
	iprange = append(iprange, IPScope.IPRanges.IPRange[0])

	VappNetworkSettings := govcd.VappNetworkSettings{
		// now poke our changes into the new vapp
		Name:           "vapp-external-2",
		Gateway:        IPScope.Gateway,
		NetMask:        IPScope.Netmask,
		DNS1:           IPScope.DNS1,
		DNS2:           IPScope.DNS2,
		DNSSuffix:      IPScope.DNSSuffix,
		StaticIPRanges: iprange,
	}

	netConfigSec, err := vapp.AddOrgNetwork(&VappNetworkSettings, orgNet.OrgVDCNetwork, false)
	if err != nil {
		return nil, err
	}
	return netConfigSec, nil

}

// return a list of internal nets, a shared LB may have several
func (v *VcdPlatform) GetIntAddrsOfVM(ctx context.Context, vm *govcd.VM) ([]string, error) {
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
		if n.Network != v.GetExtNetworkName() {
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
	// if this vapp has no vms, this call panics govcd.vapp.go xxx
	// Which is really really a bad thing. How should these vapps be validated?
	// How about getting its status, and if not at least Resolved, consider it a bad egg.
	ncs, err := vm.GetNetworkConnectionSection()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetAddrOfVM err retrieving NetConnection section", "vapp", vm.VM.Name, "network", netName, "err", err)
		return "", err
	}
	numNets := len(ncs.NetworkConnection)
	log.SpanLog(ctx, log.DebugLevelInfra, "GetAddrOfVM", "vapp", vm.VM.Name, "network", netName, "numNetworks", numNets)

	for _, nc := range ncs.NetworkConnection {
		if nc.Network == netName {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetAddrOfVapp", "Vapp", vm.VM.Name, "Net", netName, "ip", nc.IPAddress)
			return nc.IPAddress, nil
		}
	}

	return "", fmt.Errorf("Not Found")
}

// Consider a GetAllSubnetsInVapp() []string err for shared lbs... XXX
// Returns the first addr on the given network.
func (v *VcdPlatform) GetAddrOfVapp(ctx context.Context, vapp *govcd.VApp, netName string) (string, error) {

	if vapp == nil || vapp.VApp == nil || vapp.VApp.Children == nil || len(vapp.VApp.Children.VM) == 0 {
		return "", fmt.Errorf("Invalid Arg")
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "GetAddrOfVapp", "vapp", vapp.VApp.Name, "network", netName)
	ncs, err := vapp.GetNetworkConnectionSection()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetAddrOfVapp err retrieving NetConnection section", "vapp", vapp.VApp.Name, "network", netName, "err", err)
		return "", err
	}
	numNets := len(ncs.NetworkConnection)
	if v.Verbose {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetAddrOfVapp", "vapp", vapp.VApp.Name, "network", netName, "numNetworks", numNets)
	}
	for _, nc := range ncs.NetworkConnection {
		if v.Verbose {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetAddrOfVapp consider", "nc.Network", nc.Network, "netName", netName)
		}

		if nc.Network == netName {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetAddrOfVapp", "Vapp", vapp.VApp.Name, "net", netName, "ip", nc.IPAddress)
			return nc.IPAddress, nil
		} else {
			if v.Verbose {
				log.SpanLog(ctx, log.DebugLevelInfra, "GetAddrOfVapp skipping ", "Vapp", vapp.VApp.Name, "network", netName)
			}
		}
	}
	return "", fmt.Errorf("Not Found")
}

func (v *VcdPlatform) GetNextExtAddrForVdcNet(ctx context.Context, vcdClient *govcd.VCDClient) (string, error) {
	// for all Vapps
	vdcnet, err := v.GetExtNetwork(ctx, vcdClient)
	if err != nil {
		return "", err
	}
	netName := vdcnet.OrgVDCNetwork.Name
	iprange := vdcnet.OrgVDCNetwork.Configuration.IPScopes.IPScope[0].IPRanges.IPRange[0]
	s, _ := Octet(ctx, iprange.StartAddress, 3)
	e, _ := Octet(ctx, iprange.EndAddress, 3)
	curAddr := iprange.StartAddress

	if v.Verbose {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetNextExtAddr", "start", s, "end", e, "curAddr", curAddr, "network", netName)
	}
	vappMap, err := v.GetAllVAppsForVdc(ctx, vcdClient)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetNextExtAddr return", "curAddr", curAddr)
		return curAddr, err
	}

	if len(vappMap) == 0 {
		// No vapps yet in this vdc
		log.SpanLog(ctx, log.DebugLevelInfra, "GetNextExtAddr return", "curAddr", curAddr)
		return curAddr, nil
	}

	for i := s; i <= e; i++ {
		if _, found := vappMap[curAddr]; !found {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetNextExtAddr return", "curAddr", curAddr)
			return curAddr, nil
		} else {
			if v.Verbose {
				log.SpanLog(ctx, log.DebugLevelInfra, "GetNextExtAddr in use", "curAddr", curAddr)
			}
		}
		curAddr, err = IncrIP(ctx, curAddr, 1)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetNextExtAddr IncrIP err", "curAddr", curAddr, "err", err)
			return "", err
		}
		_, err := Octet(ctx, curAddr, 3)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetNextExtAddr Octet err", "curAddr", curAddr, "err", err)
			return "", err
		}
	}
	return "", fmt.Errorf("net %s ip pool full", netName)
}

// Given our scheme for networks 10.101.X.0/24 return the next available Isolated network CIDR
func (v *VcdPlatform) GetNextInternalSubnet(ctx context.Context, vappName string, vcdClient *govcd.VCDClient) (string, error) {

	var MAX_CIDRS = 255 // These are internal /24 subnets so 255, not that we'll have that many clusters / cloudlet

	log.SpanLog(ctx, log.DebugLevelInfra, "GetNextInternalSubnet", "vapp", vappName)
	// use schema xxx
	startAddr := "10.101.1.1"
	// We'll incr the netSpec.DelimiterOctet of this start addr, if it's not in our
	// All VApps map, it's available
	curAddr := startAddr

	vappMap, err := v.GetAllVAppsForVdcByIntAddr(ctx, vcdClient)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetNextExtAddr return", "curAddr", curAddr)
		return curAddr, err
	}
	if len(vappMap) == 0 {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetNextExtAddr return", "curAddr", curAddr)
		return curAddr, nil
	}
	for i := 1; i < MAX_CIDRS; i++ {
		if v.Verbose {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetNextInternalNet consider", "cidr", curAddr)
		}
		if _, found := vappMap[curAddr]; !found {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetNextInternalSubnet return available", "cidr", curAddr)
			return curAddr, nil
		}
		curAddr, err = v.IncrCidr(curAddr, 1)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetNextInternalSubnet IncrCidr failed", "curAddr", curAddr, "err", err)
			return "", err
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "GetNextInternalSubnet  subnet range exhasted")
	return "", err
}

// vm networks

func (v *VcdPlatform) AddExtNetToVm(ctx context.Context, vm *govcd.VM, netName string, ip string) error {

	ncs, err := vm.GetNetworkConnectionSection()
	if err != nil {
		return err
	}

	ncs.NetworkConnection = append(ncs.NetworkConnection,
		&types.NetworkConnection{
			IsConnected:             true,
			IPAddressAllocationMode: types.IPAllocationModeManual,
			Network:                 netName,
			NetworkConnectionIndex:  1,
			IPAddress:               ip,
		})

	err = vm.UpdateNetworkConnectionSection(ncs)
	if err != nil {

		return err
	}

	return nil
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

func (o *VcdPlatform) ValidateAdditionalNetworks(ctx context.Context, additionalNets []string) error {
	return fmt.Errorf("Additional networks not supported in vCD  cloudlets")
}
