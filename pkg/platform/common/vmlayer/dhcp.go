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
	"net"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	ssh "github.com/edgexr/golang-ssh"
)

// Notes for IPv6:
// IPv6 DHCP operates differently from IPv4. It does not provide the gateway IP
// (i.e. default route) option, so there is no way to configure routing via
// DHCP6. Instead, that functionality has been relegated to radvd (router advertisement
// daemon). In addition, SLAAC (stateless address auto-configuration) can be
// done via just radvd. So either you can run just radvd, or you run radvd with DHCP6.
// But DHCP6 by itself is not sufficient for auto-configuration, unless routes are
// configured manually.
// Additionally, radvd does not appear to provide any way to limit by client
// MAC address.

// Notes for ISC-DHCP:
// ISC-DHCP is now no longer being developed as of 2023. It has been replaced by
// Kea, a more modern DHCP server also developed by ISC.

type DhcpConfigParms struct {
	Subnet         string
	Gateway        string
	Mask           string
	DnsServers     string
	IpAddressStart string
	IpAddressEnd   string
	Interface      string
}

// dhcpdConfig is used for /etc/dhcp/dhcpd.conf
var dhcpdConfig = `
default-lease-time -1;
max-lease-time -1;

subnet {{.Subnet}} netmask {{.Mask}} {
	option routers {{.Gateway}};
	option subnet-mask {{.Mask}};
	option domain-name-servers {{.DnsServers}};
	range {{.IpAddressStart}} {{.IpAddressEnd}};
}
`

// iscDhcpConfig is used for /etc/default/isc-dhcp-server
var iscDhcpConfig = `
INTERFACESv4="{{.Interface}}"
INTERFACESv6=""
`

// StartDhcpServerForVmApp sets up a DHCP server on the LB to enable the VMApp to get an IP
// address configured for VM providers which do not have DHCP built in for internal networks.
func (v *VMPlatform) StartDHCPServerForVMApp(ctx context.Context, client ssh.Client, serverDetail *ServerDetail, internalIfName string, vmips ServerIPs, vmname string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "StartDhcpServerForVmApp", "internalIfName", internalIfName, "vmname", vmname, "vmips", vmips)

	if vmips.IPV4() == nil {
		return nil
	}
	vmip := vmips.IPV4().InternalAddr

	pc.WriteFile(client, "/tmp/manifest.txt", "asdf", "dhcpconfig", pc.SudoOn)
	ns := v.VMProperties.GetCloudletNetworkScheme()
	nspec, err := ParseNetSpec(ctx, ns)
	if err != nil {
		return nil
	}
	netmask, err := MaskLenToMask(nspec.NetmaskBits)
	if err != nil {
		return err
	}
	_, subnet, err := net.ParseCIDR(vmip + "/" + nspec.NetmaskBits)
	if err != nil {
		return err
	}
	subnetIp := subnet.IP.String()

	// GW IP is the first address in the subnet
	infracommon.IncrIP(subnet.IP)
	if err != nil {
		return err
	}
	gwIp := subnet.IP.String()

	dhcpConfigParams := DhcpConfigParms{
		Subnet:         subnetIp,
		Gateway:        gwIp,
		Mask:           netmask,
		DnsServers:     v.VMProperties.GetCloudletDNS(),
		IpAddressStart: vmip,
		IpAddressEnd:   vmip,
		Interface:      internalIfName,
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "DHCP Config params set", "dhcpConfigParams", dhcpConfigParams)

	// install DHCP on the LB
	_, err = client.Output("sudo apt list --installed | grep isc-dhcp-server")
	if err != nil {
		cmd := fmt.Sprintf("sudo apt-get install isc-dhcp-server -y")
		if out, err := client.Output(cmd); err != nil {
			return fmt.Errorf("failed to install isc-dhcp-server: %s, %v", out, err)
		}
	}
	dhcpdBuf, err := infracommon.ExecTemplate("DhcpdConfig", dhcpdConfig, dhcpConfigParams)
	if err != nil {
		return err
	}
	iscDhcpBuf, err := infracommon.ExecTemplate("IscDhcp", iscDhcpConfig, dhcpConfigParams)
	if err != nil {
		return err
	}
	dhcpdConfContents := dhcpdBuf.String()
	dhcpdServiceContents := iscDhcpBuf.String()

	cmd := "sudo cat /etc/dhcp/dhcpd.conf"
	dhcpConfOut, err := client.Output(cmd)
	log.SpanLog(ctx, log.DebugLevelInfra, "check dhcpd.conf", "cmd", cmd, "out", dhcpConfOut, "err", err)

	cmd = "sudo cat /etc/default/isc-dhcp-server"
	dhcpServiceOut, err := client.Output(cmd)
	log.SpanLog(ctx, log.DebugLevelInfra, "check service conf", "cmd", cmd, "out", dhcpServiceOut, "err", err)

	cmd = "sudo systemctl is-active isc-dhcp-server.service"
	isActive, err := client.Output(cmd)
	log.SpanLog(ctx, log.DebugLevelInfra, "check service active", "cmd", cmd, "out", isActive, "err", err)

	if dhcpConfOut == dhcpdConfContents && dhcpServiceOut == dhcpdServiceContents && isActive == "active" {
		log.SpanLog(ctx, log.DebugLevelInfra, "dhcp server already running with correct config, no changes needed")
		return nil
	}

	// write DHCP Config files
	err = pc.WriteFile(client, "/etc/dhcp/dhcpd.conf", dhcpdConfContents, "iscDhcp", pc.SudoOn)
	if err != nil {
		return err
	}
	err = pc.WriteFile(client, "/etc/default/isc-dhcp-server", dhcpdServiceContents, "dhcpdConfig", pc.SudoOn)
	if err != nil {
		return err
	}

	// enable DHCP across reboots
	cmd = fmt.Sprintf("sudo systemctl enable isc-dhcp-server.service")
	if out, err := client.Output(cmd); err != nil {
		return fmt.Errorf("failed to enable isc-dhcp-server.service: %s, %v", out, err)
	}

	serviceAction := "start"
	if isActive == "active" {
		serviceAction = "restart"
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "Updating DHCP service on LB", "action", serviceAction)
	cmd = fmt.Sprintf("sudo systemctl %s isc-dhcp-server.service", serviceAction)
	if out, err := client.Output(cmd); err != nil {
		return fmt.Errorf("failed to %s isc-dhcp-server.service: %s, %v", serviceAction, out, err)
	}

	// reboot to let the VM Vpp get the IP address from DHCP
	log.SpanLog(ctx, log.DebugLevelInfra, "Rebooting VM", "vmname", vmname)
	return v.VMProvider.SetPowerState(ctx, vmname, ActionReboot)
}
