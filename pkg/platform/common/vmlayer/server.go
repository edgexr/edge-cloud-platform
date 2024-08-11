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

package vmlayer

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	"github.com/edgexr/edge-cloud-platform/pkg/proxy"
	ssh "github.com/edgexr/golang-ssh"
)

type CacheOption bool

const UseCache CacheOption = true
const NoCache CacheOption = false

var serverCacheLock sync.Mutex // optimization only to reduce API calls

// map of group name to server name to ip
var serverExternalIpCache map[string]*ServerIP
var serverExternalIpv6Cache map[string]*ServerIP

const ServerDoesNotExistError string = "Server does not exist"
const ServerIPNotFound string = "unable to find IP"

var ServerActive = "ACTIVE"
var ServerShutoff = "SHUTOFF"

var ActionStart = "start"
var ActionStop = "stop"
var ActionReboot = "reboot"

type ServerDetail struct {
	Addresses []ServerIP
	Networks  map[string]*NetworkDetail
	ID        string
	Name      string
	Status    string
}

type NetworkDetail struct {
	ID      string
	Name    string
	Status  string
	MTU     int
	Subnets []SubnetDetail
}

type SubnetDetail struct {
	ID             string
	Name           string
	IPVersion      infracommon.IPVersion
	DHCP           bool // if DHCP is set, IP info may be empty
	SLAAC          bool // ipv6 only
	SubnetIPRanges []SubnetIPRange
	CIDR           netip.Prefix
	DNSServers     []string
	GatewayIP      string
}

type SubnetIPRange struct {
	Start string
	End   string
}

type VMUpdateList struct {
	CurrentVMs  (map[string]string)
	NewVMs      (map[string]*VMOrchestrationParams)
	VmsToCreate (map[string]*VMOrchestrationParams)
	VmsToDelete (map[string]string)
}

func init() {
	serverExternalIpCache = make(map[string]*ServerIP)
	serverExternalIpv6Cache = make(map[string]*ServerIP)
}

func (s *NetworkDetail) GetSubnet(name string) *SubnetDetail {
	for ii := range s.Subnets {
		subnet := &s.Subnets[ii]
		if subnet.Name == name {
			return subnet
		}
	}
	return nil
}

// SubnetNames is a fixed length array of ip type subnet names
type SubnetNames = infracommon.IPs

var NoSubnets SubnetNames

// ServerIPs is a fixed length array of ServerIPs. IPs may be nil.
type ServerIPs [infracommon.NumIPTypes]*ServerIP

func (s ServerIPs) IsSet() bool {
	return s[0] != nil || s[1] != nil
}

func (s ServerIPs) IPV4() *ServerIP {
	return s[infracommon.IndexIPV4]
}

func (s ServerIPs) IPV6() *ServerIP {
	return s[infracommon.IndexIPV6]
}

func (s ServerIPs) IPV4ExternalAddr() string {
	return s.ExternalAddr(infracommon.IndexIPV4)
}

func (s ServerIPs) IPV6ExternalAddr() string {
	return s.ExternalAddr(infracommon.IndexIPV6)
}

func (s ServerIPs) ExternalAddr(index int) string {
	sip := s[index]
	if sip != nil {
		return sip.ExternalAddr
	}
	return ""
}

// GetIPOptions for getting ServerIPs information
type GetIPOptions struct {
	CachedIP     bool
	ServerDetail *ServerDetail
}

type GetIPOp func(ops *GetIPOptions)

func (s *GetIPOptions) Apply(ops ...GetIPOp) {
	for _, op := range ops {
		op(s)
	}
}
func WithCachedIP(cached bool) GetIPOp {
	return func(ops *GetIPOptions) { ops.CachedIP = cached }
}

// WithServerDetail avoids an extra lookup if needed
func WithServerDetail(sd *ServerDetail) GetIPOp {
	return func(ops *GetIPOptions) { ops.ServerDetail = sd }
}

// GetIPOpsFromSSHOps allows for passing down ssh options to getIP options
// that are common to both. Previously we only used ssh options, but
// that did not allow for adding getIP-specific options.
func GetIPOpsFromSSHOps(ops []pc.SSHClientOp) []GetIPOp {
	sshOptions := pc.SSHOptions{}
	sshOptions.Apply(ops)
	getIPOps := []GetIPOp{}
	if sshOptions.CachedIP {
		getIPOps = append(getIPOps, WithCachedIP(true))
	}
	return getIPOps
}

// GetIPFromServerName returns the IPv4 and IPv6 for the givens serverName,
// on either the network or subnetName, preferring the subnet name.
// Optionally lookup and store to cache can be specified.
func (v *VMPlatform) GetIPFromServerName(ctx context.Context, networkName string, subnetNames SubnetNames, serverName string, ops ...GetIPOp) (ServerIPs, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetIPFromServerName", "networkName", networkName, "subnetNames", subnetNames, "serverName", serverName)
	opts := GetIPOptions{}
	opts.Apply(ops...)
	isExtNet := false
	if networkName != "" && (networkName == v.VMProperties.GetCloudletExternalNetwork() || networkName == v.VMProperties.GetCloudletExternalNetworkSecondary()) {
		isExtNet = true
	}
	if isExtNet && opts.CachedIP {
		sipIPV4, sipIPV6 := GetServerIPFromCache(ctx, serverName)
		if sipIPV4 != nil || sipIPV6 != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetIPFromServerName found ip in cache", "serverName", serverName, "sip", sipIPV4, "sipIPV6", sipIPV6)
			serverIPs := ServerIPs{}
			serverIPs[infracommon.IndexIPV4] = sipIPV4
			serverIPs[infracommon.IndexIPV6] = sipIPV6
			return serverIPs, nil
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetIPFromServerName did not find ip in cache", "serverName", serverName)
		}
	}
	// Note that subnetNames is always the internal subnets we create,
	// and both the ipv4 and ipv6 subnets should be on the same port.
	portName := ""
	if subnetNames.IsSet() {
		portName = GetPortNameFromSubnet(serverName, subnetNames)
	}
	sd := opts.ServerDetail
	var err error
	if sd == nil {
		sd, err = v.VMProvider.GetServerDetail(ctx, serverName)
		if err != nil {
			return ServerIPs{}, err
		}
	}
	sips, err := GetIPFromServerDetails(ctx, networkName, portName, sd)
	if err == nil && isExtNet && opts.CachedIP {
		AddServerExternalIpToCache(ctx, serverName, sips)
	}
	return sips, err
}

func GetServerIPsByMAC(ctx context.Context, sd *ServerDetail) map[string]ServerIPs {
	sipsByMAC := make(map[string]ServerIPs)
	for _, sip := range sd.Addresses {
		sips, ok := sipsByMAC[sip.MacAddress]
		if !ok {
			sips = ServerIPs{}
			sipsByMAC[sip.MacAddress] = sips
		}
		ipindex := infracommon.IndexIPV4
		if sip.IPVersion == infracommon.IPV6 {
			ipindex = infracommon.IndexIPV6
		}
		if sips[ipindex] != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "multiple server IPs of same version found on mac address, ignoring later ones", "existing", sips[ipindex], "ignore", sip)
			continue
		}
		sips[ipindex] = &sip
	}
	return sipsByMAC
}

// GetIPFromServerDetails returns the IPv4 and IPv6 IPs for the given network
// name or port name. While an interface may technically have multiple IPv4
// or IPv6 addresses, we only recognize one IPv4 and/or one IPv6. Because
// this is retreiving IPs based on the infra and the subnet attached to the
// network, it will not report any IPv6 link-local addresses that are
// automatically assigned by the VM's operating system.
func GetIPFromServerDetails(ctx context.Context, networkName string, portName string, sd *ServerDetail) (ServerIPs, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetIPFromServerDetails", "server", sd.Name, "networkName", networkName, "portName", portName)
	var sips ServerIPs
	netFound := [infracommon.NumIPTypes]bool{}
	portFound := [infracommon.NumIPTypes]bool{}
	for i, s := range sd.Addresses {
		addr := sd.Addresses[i]
		ipindex := infracommon.IndexIPV4
		if addr.IPVersion == infracommon.IPV6 {
			ipindex = infracommon.IndexIPV6
		}
		// with the new common shared network in some platforms (currently VCD) combined with preexisting legacy pre-common networks there is a chance
		// for multiple ips to be found, once with the port and once with the network. If this happens, give preference networks found via the port name
		// which is more specific
		if networkName != "" && s.Network == networkName {
			if netFound[ipindex] {
				log.SpanLog(ctx, log.DebugLevelInfra, "Error: GetIPFromServerDetails found multiple matches via network", "networkName", networkName, "portName", portName, "serverDetail", sd, "ipversion", addr.IPVersion)
				return sips, fmt.Errorf("Multiple %s IP addresses found for server: %s on same network: %s", addr.IPVersion, sd.Name, networkName)
			}
			netFound[ipindex] = true
			if portFound[ipindex] {
				log.SpanLog(ctx, log.DebugLevelInfra, "prioritizing IP address previously found via port", "networkName", networkName, "portName", portName, "serverDetail", sd, "ipversion", addr.IPVersion)
			} else {
				log.SpanLog(ctx, log.DebugLevelInfra, "GetIPFromServerDetails found network match", "serverAddress", s)
				sips[ipindex] = &addr
			}
		}
		if portName != "" && s.PortName == portName {
			if portFound[ipindex] {
				// this indicates we passed in multiple parameters that found an IP.  For example, an external network name plus an internal port name
				log.SpanLog(ctx, log.DebugLevelInfra, "Error: GetIPFromServerDetails found multiple matches via port", "networkName", networkName, "portName", portName, "serverDetail", sd)
				return sips, fmt.Errorf("Multiple %s IP addresses found for server: %s on same port: %s", addr.IPVersion, sd.Name, portName)
			}
			log.SpanLog(ctx, log.DebugLevelInfra, "GetIPFromServerDetails found port match", "serverAddress", s)
			portFound[ipindex] = true
			sips[ipindex] = &addr
		}
	}
	if !sips.IsSet() {
		return sips, fmt.Errorf(ServerIPNotFound+" for server: %s on network: %s port: %s", sd.Name, networkName, portName)
	}
	return sips, nil
}

func (v *VMPlatform) SetExternalGateways(ctx context.Context, serverDetail *ServerDetail, gatewayIPs infracommon.IPs) error {
	extNets := []string{
		v.VMProperties.GetCloudletExternalNetwork(),
		v.VMProperties.GetCloudletExternalNetworkSecondary(),
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "SetExternalGateways", "gatewayIPs", gatewayIPs, "external-networks", extNets)

	gwNetIPs, err := gatewayIPs.NetIPs()
	if err != nil {
		return fmt.Errorf("failed to parse gateway IPs, %s", err)
	}
	for _, extNet := range extNets {
		network, ok := serverDetail.Networks[extNet]
		if !ok {
			continue
		}
		for ii := range network.Subnets {
			index := infracommon.IPIndexOf(network.Subnets[ii].IPVersion)
			gw := gwNetIPs[index]
			if network.Subnets[ii].CIDR.Contains(gw) {
				log.SpanLog(ctx, log.DebugLevelInfra, "overridding gateway IP", "network", network.Name, "subnet", network.Subnets[ii].Name, "old-gateway", network.Subnets[ii].GatewayIP, "new-gateway", gatewayIPs[index])
				network.Subnets[ii].GatewayIP = gatewayIPs[index]
			}
		}
	}
	return nil
}

// GetExternalIPFromServerName gets the external ipv4 and ipv6 addresses
// from the defined external network names, for the given server name.
// We expect that if multiple external networks are defined, only one IP
// of each type is present across all networks.
func (v *VMPlatform) GetExternalIPFromServerName(ctx context.Context, serverName string, ops ...GetIPOp) (ServerIPs, error) {
	var sips ServerIPs
	nets := []string{
		v.VMProperties.GetCloudletExternalNetwork(),
		v.VMProperties.GetCloudletExternalNetworkSecondary(),
	}
	for _, net := range nets {
		_sips, err := v.GetIPFromServerName(ctx, net, NoSubnets, serverName, ops...)
		if err != nil && !strings.Contains(err.Error(), ServerIPNotFound) {
			return sips, err
		}
		for i := 0; i < len(sips); i++ {
			if sips[i] == nil {
				sips[i] = _sips[i]
			}
		}
	}
	if !sips.IsSet() {
		return sips, fmt.Errorf(ServerIPNotFound+" for server %s on networks %v", serverName, nets)
	}
	return sips, nil
}

// NewProxyConfig creates a proxy config to be passed to the proxy code.
// Listen addresses will proxy data to the destination addresses.
func NewProxyConfig(listenIPs infracommon.IPs, destIPs ServerIPs, enableIPV6 bool) *proxy.ProxyConfig {
	proxyConfig := &proxy.ProxyConfig{
		ListenIP: listenIPs.IPV4(),
		DestIP:   destIPs.IPV4ExternalAddr(),
	}
	if enableIPV6 {
		proxyConfig.ListenIPV6 = listenIPs.IPV6()
		proxyConfig.DestIPV6 = destIPs.IPV6ExternalAddr()
	}
	return proxyConfig
}

func GetCloudletNetworkIfaceFile() string {
	return "/etc/netplan/50-cloud-init.yaml"
}

func (v *VMPlatform) GetConsoleUrl(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst) (string, error) {
	var err error
	var result OperationInitResult
	ctx, result, err = v.VMProvider.InitOperationContext(ctx, OperationInitStart)
	if err != nil {
		return "", err
	}
	if result == OperationNewlyInitialized {
		defer v.VMProvider.InitOperationContext(ctx, OperationInitComplete)
	}

	switch deployment := app.Deployment; deployment {
	case cloudcommon.DeploymentTypeVM:
		return v.VMProvider.GetConsoleUrl(ctx, appInst.UniqueId)
	default:
		return "", fmt.Errorf("unsupported deployment type %s", deployment)
	}
}

func (v *VMPlatform) SetPowerState(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	PowerState := appInst.PowerState

	var result OperationInitResult
	var err error
	ctx, result, err = v.VMProvider.InitOperationContext(ctx, OperationInitStart)
	if err != nil {
		return err
	}
	if result == OperationNewlyInitialized {
		defer v.VMProvider.InitOperationContext(ctx, OperationInitComplete)
	}

	switch deployment := app.Deployment; deployment {
	case cloudcommon.DeploymentTypeVM:
		serverName := appInst.UniqueId
		fqdn := appInst.Uri
		log.SpanLog(ctx, log.DebugLevelInfra, "setting server state", "serverName", serverName, "fqdn", fqdn, "PowerState", PowerState)

		updateCallback(edgeproto.UpdateTask, "Verifying AppInst state")
		serverDetail, err := v.VMProvider.GetServerDetail(ctx, serverName)
		if err != nil {
			return err
		}

		serverAction := ""
		switch PowerState {
		case edgeproto.PowerState_POWER_ON_REQUESTED:
			if serverDetail.Status == ServerActive {
				return fmt.Errorf("server %s is already active", serverName)
			}
			serverAction = ActionStart
		case edgeproto.PowerState_POWER_OFF_REQUESTED:
			if serverDetail.Status == ServerShutoff {
				return fmt.Errorf("server %s is already stopped", serverName)
			}
			serverAction = ActionStop
		case edgeproto.PowerState_REBOOT_REQUESTED:
			serverAction = ActionReboot
			if serverDetail.Status != ServerActive {
				return fmt.Errorf("server %s is not active", serverName)
			}
		default:
			return fmt.Errorf("unsupported server power action: %s", PowerState)
		}

		serverNetwork := v.VMProperties.GetCloudletExternalNetwork()
		if app.AccessType == edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER {
			serverNetwork = serverName + "-subnet"
		}
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Fetching external address of %s", serverName))
		oldServerIPs, err := GetIPFromServerDetails(ctx, serverNetwork, "", serverDetail)
		if err != nil || (oldServerIPs.IPV4ExternalAddr() == "" && oldServerIPs.IPV6ExternalAddr() == "") {
			return fmt.Errorf("unable to fetch external ip for %s, network %s, err %v", serverName, serverNetwork, err)
		}
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Performing action %s on %s", serverAction, serverName))
		err = v.VMProvider.SetPowerState(ctx, serverName, serverAction)
		if err != nil {
			return err
		}

		if PowerState == edgeproto.PowerState_POWER_ON_REQUESTED || PowerState == edgeproto.PowerState_REBOOT_REQUESTED {
			updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Waiting for server %s to become active", serverName))
			serverDetail, err := v.VMProvider.GetServerDetail(ctx, serverName)
			if err != nil {
				return err
			}
			updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Fetching external address of %s", serverName))
			newServerIPs, err := GetIPFromServerDetails(ctx, serverNetwork, "", serverDetail)
			if err != nil || (newServerIPs.IPV4ExternalAddr() == "" && newServerIPs.IPV6ExternalAddr() == "") {
				return fmt.Errorf("unable to fetch external ip for %s, subnet %s, err %v", serverName, serverNetwork, err)
			}
			if err := v.updateExternalIPFQDN(ctx, oldServerIPs, newServerIPs, serverName, fqdn, updateCallback); err != nil {
				return err
			}
		}
		updateCallback(edgeproto.UpdateTask, "Performed power control action successfully")
	default:
		return fmt.Errorf("unsupported deployment type %s", deployment)
	}
	return nil
}

func (v *VMPlatform) updateExternalIPFQDN(ctx context.Context, oldServerIPs, newServerIPs ServerIPs, serverName, fqdn string, updateCallback edgeproto.CacheUpdateCallback) error {
	for ii := range newServerIPs {
		newIP := newServerIPs.ExternalAddr(ii)
		oldIP := oldServerIPs.ExternalAddr(ii)
		if newIP == "" || newIP == oldIP {
			// no external ip or no change
			continue
		}
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Updating DNS entry as IP changed to %s for %s", newIP, serverName))
		log.SpanLog(ctx, log.DebugLevelInfra, "updating DNS entry", "serverName", serverName, "fqdn", fqdn, "ip", newIP)
		err := v.VMProperties.CommonPf.ActivateFQDN(ctx, fqdn, newIP, newServerIPs[ii].IPVersion)
		if err != nil {
			return fmt.Errorf("unable to update fqdn for %s, addr %s, err %v", serverName, newIP, err)
		}
	}
	return nil
}

// WaitServerReady waits up to the specified duration for the server to be reachable via SSH
// and pass any additional checks from the provider
func WaitServerReady(ctx context.Context, provider VMProvider, client ssh.Client, server string, timeout time.Duration) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "WaitServerReady", "server", server)
	start := time.Now()
	for {
		out, err := client.Output("sudo grep 'Finished edgecloud init' /var/log/edgecloud.log")
		if err != nil {
			out, err = client.Output("sudo grep 'Finished mobiledgex init' /var/log/mobiledgex.log")
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "grep Finished edgecloud init result", "out", out, "err", err)
		if err == nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "Server has completed edgecloud init", "server", server)
			// perform any additional checks from the provider
			err = provider.CheckServerReady(ctx, client, server)
			log.SpanLog(ctx, log.DebugLevelInfra, "CheckServerReady result", "err", err)
			if err == nil {
				break
			}
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "server not ready", "err", err)
		elapsed := time.Since(start)
		if elapsed > timeout {
			return fmt.Errorf("timed out waiting for VM %s", server)
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "sleeping 10 seconds before retry", "elapsed", elapsed, "timeout", timeout)
		time.Sleep(10 * time.Second)

	}
	log.SpanLog(ctx, log.DebugLevelInfra, "WaitServerReady OK", "server", server)
	return nil
}

func GetServerIPFromCache(ctx context.Context, serverName string) (*ServerIP, *ServerIP) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetServerIPFromCache", "serverName", serverName)
	serverCacheLock.Lock()
	defer serverCacheLock.Unlock()
	return serverExternalIpCache[serverName], serverExternalIpv6Cache[serverName]
}

func AddServerExternalIpToCache(ctx context.Context, serverName string, sips ServerIPs) {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddServerExternalIpToCache", "serverName", serverName)
	serverCacheLock.Lock()
	defer serverCacheLock.Unlock()
	if sips.IPV4() != nil {
		serverExternalIpCache[serverName] = sips.IPV4()
	}
	if sips.IPV6() != nil {
		serverExternalIpv6Cache[serverName] = sips.IPV6()
	}
}

func DeleteServerIpFromCache(ctx context.Context, serverName string) {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteServerIpFromCache", "serverName", serverName)
	serverCacheLock.Lock()
	defer serverCacheLock.Unlock()
	delete(serverExternalIpCache, serverName)
	delete(serverExternalIpv6Cache, serverName)
}

func GetVmwareMappedOsType(osType edgeproto.VmAppOsType) (string, error) {
	switch osType {
	case edgeproto.VmAppOsType_VM_APP_OS_UNKNOWN:
		return "otherGuest64", nil
	case edgeproto.VmAppOsType_VM_APP_OS_LINUX:
		return "otherLinux64Guest", nil
	case edgeproto.VmAppOsType_VM_APP_OS_WINDOWS_10:
		return "windows9_64Guest", nil
	case edgeproto.VmAppOsType_VM_APP_OS_WINDOWS_2012:
		return "windows8Server64Guest", nil
	case edgeproto.VmAppOsType_VM_APP_OS_WINDOWS_2016:
		fallthrough // shows as 2016 in vcenter
	case edgeproto.VmAppOsType_VM_APP_OS_WINDOWS_2019:
		return "windows9Server64Guest", nil
	}
	return "", fmt.Errorf("Invalid value for VmAppOsType %v", osType)
}

func (v *VMPlatform) ConfigureNetworkInterfaces(ctx context.Context, client ssh.Client, serverDetail *ServerDetail, configNetworks map[string]struct{}, defaultRouteNets map[string]struct{}, additionalRoutesByNetwork map[string][]edgeproto.Route) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ConfigureNetworkInterfaces", "configNetworks", configNetworks, "defaultRouteNets", defaultRouteNets, "server", serverDetail, "subnetsIgnoreDHCP", v.VMProperties.GetSubnetsIgnoreDHCP())

	subnetsIgnoreDHCP := make(map[string]struct{})
	for _, sn := range v.VMProperties.GetSubnetsIgnoreDHCP() {
		subnetsIgnoreDHCP[sn] = struct{}{}
	}

	macToIface, _, err := infracommon.GetMacAddrToInterfaceNames(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to get mac address to interface names for server %s, %s", serverDetail.Name, err)
	}

	// group addresses by interface so we can clear any unknown data from the
	// interface, and clear any unknown interfaces
	addrsByInterface := map[string][]ServerIP{}
	for _, addr := range serverDetail.Addresses {
		iface, ok := macToIface[addr.MacAddress]
		if !ok {
			return fmt.Errorf("cannot find interface for server IP mac %s", addr.MacAddress)
		}
		addrsByInterface[iface] = append(addrsByInterface[iface], addr)
	}
	// get network configuration
	networkConfig, err := infracommon.GetNetworkConfig(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to get network config for %s, %s", serverDetail.Name, err)
	}
	for iface, addrs := range addrsByInterface {
		netName := addrs[0].Network
		if _, found := configNetworks[netName]; !found {
			continue
		}
		eth := networkConfig.GetInterface(iface, addrs[0].PortName)
		network, found := serverDetail.Networks[addrs[0].Network]
		if !found {
			log.SpanLog(ctx, log.DebugLevelInfra, "missing network for interface", "interface", iface, "network", addrs[0].Network)
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "configuring interface", "interface", iface, "addresses", addrs)
		// reset config governed by serverIPs
		eth.DHCP4 = false
		eth.DHCP6 = false
		eth.Addresses = []string{}
		eth.Routes = []*infracommon.NetplanRoute{}
		// set config
		if network.MTU != 0 {
			eth.MTU = network.MTU
		}
		for _, addr := range addrs {
			network, ok := serverDetail.Networks[addr.Network]
			if !ok {
				return fmt.Errorf("server %s detail has address %s on network %s but no info for network", serverDetail.Name, addr.InternalAddr, addr.Network)
			}
			var subnet *SubnetDetail
			for ii := range network.Subnets {
				if network.Subnets[ii].Name == addr.SubnetName {
					subnet = &network.Subnets[ii]
				}
			}
			if subnet == nil {
				return fmt.Errorf("server %s detail has address %s on network %s, subnet %s, but no info for subnet", serverDetail.Name, addr.InternalAddr, network.Name, addr.SubnetName)
			}
			_, ignoreDHCP := subnetsIgnoreDHCP[subnet.Name]
			if !ignoreDHCP && addr.IPVersion == infracommon.IPV4 && subnet.DHCP && addr.InternalAddr != subnet.GatewayIP {
				eth.DHCP4 = true
				// address and routes are configured by DHCP
				continue
			}
			if !ignoreDHCP && addr.IPVersion == infracommon.IPV6 && subnet.DHCP && addr.InternalAddr != subnet.GatewayIP {
				eth.DHCP6 = true
				// address and routes are configured by DHCP
				continue
			}
			eth.Addresses = append(eth.Addresses, fmt.Sprintf("%s/%d", addr.InternalAddr, subnet.CIDR.Bits()))
			if _, found := defaultRouteNets[addr.Network]; found && subnet.GatewayIP != "" {
				to := "0.0.0.0/0"
				if addr.IPVersion == infracommon.IPV6 {
					to = "::/0"
				}
				eth.Routes = append(eth.Routes, &infracommon.NetplanRoute{
					To:  to,
					Via: subnet.GatewayIP,
				})
			}
		}
		if additionalRoutesByNetwork != nil {
			if routes, ok := additionalRoutesByNetwork[addrs[0].Network]; ok {
				for _, route := range routes {
					eth.Routes = append(eth.Routes, &infracommon.NetplanRoute{
						To:  route.DestinationCidr,
						Via: route.NextHopIp,
					})
				}
			}
		}
	}
	// remove any interfaces on the configured networks without addresses
	for _, planFile := range networkConfig.NetplanFiles {
		for iface, eth := range planFile.Netplan.Network.Ethernets {
			addrs, ok := addrsByInterface[iface]
			if !ok || (len(addrs) == 0 && !eth.DHCP4 && !eth.DHCP6) {
				// remove from network config
				log.SpanLog(ctx, log.DebugLevelInfra, "no addresses or DHCP configured for interface, removing it", "interface", iface)
				delete(planFile.Netplan.Network.Ethernets, iface)
				continue
			}
		}
	}
	_, err = networkConfig.Apply(ctx, client)
	return err
}
