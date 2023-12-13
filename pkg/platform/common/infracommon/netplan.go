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

package infracommon

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	ssh "github.com/edgexr/golang-ssh"
	yaml "github.com/mobiledgex/yaml/v2"
)

const NetplanFileNotFound = "netplan file not found"

type NetplanDeviceMatch struct {
	Name       string   `yaml:"name,omitempty"`
	MACAddress string   `yaml:"macaddress,omitempty"`
	Driver     []string `yaml:"driver,omitempty"`
}

type NetplanNameservers struct {
	Addresses []string `yaml:"addresses,omitempty"`
	Search    []string `yaml:"search,omitempty"`
}

type NetplanRoute struct {
	From   string `yaml:"from,omitempty"`
	To     string `yaml:"to,omitempty"`
	Via    string `yaml:"via,omitempty"`
	OnLink bool   `yaml:"on-link,omitempty"`
	Metric int    `yaml:"metric,omitempty"`
	Type   string `yaml:"type,omitempty"`
	Scope  string `yaml:"scope,omitempty"`
	MTU    int    `yaml:"mtu,omitempty"`
}

type NetplanDevice struct {
	Addresses   []string           `yaml:"addresses,omitempty"`
	DHCP4       bool               `yaml:"dhcp4,omitempty"`
	DHCP6       bool               `yaml:"dhcp6,omitempty"`
	IPV6MTU     int                `yaml:"ipv6-mtu,omitempty"`
	IPV6Privacy bool               `yaml:"ipv6-privacy,omitempty"`
	LinkLocal   []string           `yaml:"link-local,omitempty"`
	Nameservers NetplanNameservers `yaml:"nameservers,omitempty"`
	MTU         int                `yaml:"mtu,omitempty"`
	Routes      []*NetplanRoute    `yaml:"routes,omitempty"`
}

type NetplanEthernet struct {
	NetplanDevice `yaml:",inline"`
	Match         NetplanDeviceMatch `yaml:"match,omitempty"`
}

type NetplanNetwork struct {
	Version   int                         `yaml:"version"`
	Ethernets map[string]*NetplanEthernet `yaml:"ethernets,omitempty"`
}

type NetplanInfo struct {
	Network NetplanNetwork `yaml:"network"`
}

type NetplanFile struct {
	FileName     string
	Netplan      NetplanInfo
	FileContents string
}

type NetworkConfig struct {
	NetplanFiles []*NetplanFile
	ethLookup    map[string]*NetplanEthernet
}

// The base image currently only supports netplan.
func ServerIsNetplanEnabled(ctx context.Context, client ssh.Client) bool {
	cmd := "netplan info"
	_, err := client.Output(cmd)
	return err == nil
}

func GetNetplanFilename(portName string) string {
	return "/etc/netplan/" + portName + ".yaml"
}

func GetMacAddrToInterfaceNames(ctx context.Context, client ssh.Client) (map[string]string, map[string]string, error) {
	cmd := "ip -o -br link show"
	out, err := client.Output(cmd)
	if err != nil {
		return nil, nil, fmt.Errorf("cmd %q failed, %s, %s", cmd, out, err)
	}
	macToName := make(map[string]string)
	nameToMAC := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		parts := strings.Fields(line)
		iface := parts[0]
		macaddr := parts[2]
		macToName[macaddr] = iface
		nameToMAC[iface] = macaddr
		log.SpanLog(ctx, log.DebugLevelInfra, "GetMacAddrToInterfaceNames", "mac", macaddr, "interface", iface)
	}
	return macToName, nameToMAC, nil
}

// GenerateNetworkFileDetailsForIP returns interfaceFileName, fileMatchPattern, contents based on whether netplan is enabled
// Deprecated: should instead use GetNetworkConfig
func GenerateNetworkFileDetailsForIP(ctx context.Context, portName string, ifName string, ipAddr string, maskbits uint32, ipv6Addr string) (string, string, string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GenerateNetworkFileDetailsForIP", "portName", portName, "ifName", ifName, "ipAddr", ipAddr, "ipv6Addr", ipv6Addr)
	fileName := GetNetplanFilename(portName)
	fileMatch := "/etc/netplan/*-port.yaml"
	plan := NetplanInfo{
		Network: NetplanNetwork{
			Version:   2,
			Ethernets: map[string]*NetplanEthernet{},
		},
	}
	ethernet := NetplanEthernet{}
	if ipAddr != "" {
		ethernet.Addresses = append(ethernet.Addresses, fmt.Sprintf(ipAddr+"/%d", maskbits))
	}
	if ipv6Addr != "" {
		ethernet.Addresses = append(ethernet.Addresses, ipv6Addr+"/64")
	}
	plan.Network.Ethernets[ifName] = &ethernet

	out, err := yaml.Marshal(plan)
	if err != nil {
		return "", "", "", err
	}
	fileContents := string(out)
	return fileName, fileMatch, fileContents, nil
}

func getNetplanInfo(ctx context.Context, client ssh.Client, fileName string) (*NetplanInfo, string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetNetplanInfo", "fileName", fileName)
	out, err := client.Output("cat " + fileName)
	if err != nil {
		if strings.Contains(out, "No such file") {
			return nil, "", fmt.Errorf("%s - %s", NetplanFileNotFound, fileName)
		}
		return nil, "", fmt.Errorf("error getting netplan file %s: %v", fileName, err)
	}
	info := &NetplanInfo{}
	err = yaml.Unmarshal([]byte(out), info)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to unmashal netplan info", "netplanContents", string(out), "err", err)
		return nil, "", fmt.Errorf("failed to unmarshal netplan file %s: %s", fileName, err)
	}
	return info, out, nil
}

// GetIPAddressFromNetplan returns the ipv4 and ipv6 addr
// Deprecated: should instead use GetNetworkConfig.
func GetIPAddressFromNetplan(ctx context.Context, client ssh.Client, portName string) (IPs, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetIpAddressFromNetplan", "portName", portName)
	fileName := GetNetplanFilename(portName)
	netplanInfo, _, err := getNetplanInfo(ctx, client, fileName)
	if err != nil {
		return IPs{}, err
	}
	var ips IPs
	if len(netplanInfo.Network.Ethernets) != 1 {
		return ips, fmt.Errorf("unexpected number of ethernet interfaces in netplan file - %d - %+v", len(netplanInfo.Network.Ethernets), netplanInfo)
	}
	if len(netplanInfo.Network.Ethernets) != 1 {
		return ips, fmt.Errorf("expected only one interface in netplan: %+v", netplanInfo)
	}
	for _, eth := range netplanInfo.Network.Ethernets {
		for _, addr := range eth.Addresses {
			// remove the cidr
			s := strings.Split(addr, "/")
			if len(s) != 2 {
				return ips, fmt.Errorf("bad address format in netplan file - %s", addr)
			}
			netipAddr, err := netip.ParseAddr(s[0])
			if err != nil {
				return ips, fmt.Errorf("failed to parse IP %s in netplan: %+v", s[0], netplanInfo)
			}
			if netipAddr.Is4() {
				if ips.IPV4() != "" {
					return ips, fmt.Errorf("expected at most one IPv4 address specified in netplan: %+v", netplanInfo)
				}
				ips[IndexIPV4] = s[0]
			} else if netipAddr.Is6() {
				if ips.IPV6() != "" {
					return ips, fmt.Errorf("expected at most one IPv6 address specified in netplan: %+v", netplanInfo)
				}
				ips[IndexIPV6] = s[0]
			}
		}
	}
	if !ips.IsSet() {
		return ips, fmt.Errorf("no static ips found in netplan: %+v", netplanInfo)
	}
	return ips, nil
}

// ChangeDefaultToIPSpecific changes the "to" field if it is set to "default"
// to the IP-specific default route, i.e. 0.0.0.0/0 for IPv4 or ::/0 for IPv6.
// If the route is the default for both IPv4 and IPv6, it should be "default",
// but if the system has separate gateways for IPv4 and IPv6, neither should
// use "default", but instead should use the IP-specific CIDRs.
func (s *NetplanRoute) ChangeDefaultToIPSpecific() error {
	if s.To == "default" {
		viaAddr, err := netip.ParseAddr(strings.Split(s.Via, "/")[0])
		if err != nil {
			return fmt.Errorf("failed to parse %s for netplan route via, %s", s.Via, err)
		}
		if viaAddr.Is4() {
			s.To = "0.0.0.0/0"
		} else if viaAddr.Is6() {
			s.To = "::/0"
		}
	}
	return nil
}

// GetNetworkConfig reads the network configuration from all netplan files.
// Interfaces may be defined in any netplan file. Ubuntu cloud-init puts all interfaces
// it detects into 50-network-config.yaml, and we have traditionally put
// additional port interfaces into separate files. However, depending upon if cloud-init
// detects ports or not, additional ports may also end up in 50-network-config.yaml.
// So we need to read all netplan yaml files to really understand the network config.
func GetNetworkConfig(ctx context.Context, client ssh.Client) (*NetworkConfig, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetNetworkConfig")
	cmd := "ls -1 /etc/netplan/*.yaml"
	out, err := client.Output(cmd)
	if err != nil {
		return nil, fmt.Errorf("cmd %q failed, %s, %s", cmd, out, err)
	}
	config := &NetworkConfig{
		ethLookup: make(map[string]*NetplanEthernet),
	}
	out = strings.TrimSpace(out)
	for _, filename := range strings.Split(out, "\n") {
		filename = strings.TrimSpace(filename)
		netplan, contents, err := getNetplanInfo(ctx, client, filename)
		if err != nil {
			return nil, fmt.Errorf("failed to read netplan contents from %s, %s", filename, err)
		}
		config.NetplanFiles = append(config.NetplanFiles, &NetplanFile{
			FileName:     filename,
			Netplan:      *netplan,
			FileContents: contents,
		})
		for interfaceName, eth := range netplan.Network.Ethernets {
			config.ethLookup[interfaceName] = eth
		}
	}
	return config, nil
}

// GetInterface returns the ethernet object for the given interface name.
// The object is created if it does not already exist, and is put into a new
// netplan file whose name is derived from the portName.
func (s *NetworkConfig) GetInterface(ifaceName string, portName string) *NetplanEthernet {
	fileName := GetNetplanFilename(portName)
	if eth, found := s.ethLookup[ifaceName]; found {
		return eth
	}
	// create new interface
	var planFile *NetplanFile
	for _, nf := range s.NetplanFiles {
		if nf.FileName == fileName {
			planFile = nf
		}
	}
	if planFile == nil {
		planFile = &NetplanFile{
			FileName: fileName,
			Netplan: NetplanInfo{
				Network: NetplanNetwork{
					Version: 2,
				},
			},
		}
		s.NetplanFiles = append(s.NetplanFiles, planFile)
	}
	eth := &NetplanEthernet{}
	if planFile.Netplan.Network.Ethernets == nil {
		planFile.Netplan.Network.Ethernets = make(map[string]*NetplanEthernet)
	}
	planFile.Netplan.Network.Ethernets[ifaceName] = eth
	s.ethLookup[ifaceName] = eth
	return eth
}

// Apply writes changed netplan files to the system and applies the changes, if any.
// It returns true if there were any changes applied.
// Note that file changes are based on file content string comparison, so
// formatting, comments, etc in the initial cloud-init config file may trigger
// a no-op apply. "netplan apply" itself also only applies what it determines as
// network configuration changes, so there is no harm in this.
func (s *NetworkConfig) Apply(ctx context.Context, client ssh.Client) (bool, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "applying network config")
	updated := false
	for _, netplanFile := range s.NetplanFiles {
		out, err := yaml.Marshal(netplanFile.Netplan)
		if err != nil {
			return updated, fmt.Errorf("failed to marshal netplan file %s, %s", netplanFile.FileName, err)
		}
		if string(out) != netplanFile.FileContents {
			log.SpanLog(ctx, log.DebugLevelInfra, "netplan file contents changed, writing file", "file", netplanFile.FileName, "contents", string(out))
			err = pc.WriteFile(client, netplanFile.FileName, string(out), "netplan", pc.SudoOn)
			if err != nil {
				return updated, fmt.Errorf("failed to write new netplan file %s, %s", netplanFile.FileName, err)
			}
			updated = true
		}
	}
	if updated {
		apply, err := client.Output("sudo netplan apply")
		if err != nil {
			return updated, fmt.Errorf("failed to apply new netplan, %s, %s", apply, err)
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "applied netplan files", "numFiles", len(s.NetplanFiles), "updated", updated)
	return updated, nil
}
