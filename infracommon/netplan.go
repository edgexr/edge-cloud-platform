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
	"strings"

	"github.com/edgexr/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
	yaml "github.com/mobiledgex/yaml/v2"
)

const NetplanFileNotFound = "netplan file not found"

type EthInterface struct {
	Addresses []string `yaml:"addresses"`
}

type Ethernet struct {
	EthInterface `yaml:",inline"`
}

type NetplanNetwork struct {
	Version   int                 `yaml:"version"`
	Ethernets map[string]Ethernet `yaml:"ethernets"`
}

type NetplanInfo struct {
	Network NetplanNetwork `yaml:"network"`
}

// serverIsNetplanEnabled checks for the existence of netplan, in which case there are no ifcfg files.  The current
// baseimage uses netplan, but CRM can still run on older rootLBs.
func ServerIsNetplanEnabled(ctx context.Context, client ssh.Client) bool {
	cmd := "netplan info"
	_, err := client.Output(cmd)
	return err == nil
}

func getNetplanContents(portName, ifName string, ipAddr string) string {
	return fmt.Sprintf(`## config for %s
network:
    version: 2
    ethernets:
        %s:
            dhcp4: no
            dhcp6: no
            addresses:
             - %s
`, portName, ifName, ipAddr)
}

func GetNetplanFilename(portName string) string {
	return "/etc/netplan/" + portName + ".yaml"
}

// GenerateNetworkFileDetailsForIP returns interfaceFileName, fileMatchPattern, contents based on whether netplan is enabled
func GenerateNetworkFileDetailsForIP(ctx context.Context, portName string, ifName string, ipAddr string, maskbits uint32, netPlanEnabled bool) (string, string, string) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GenerateNetworkFileDetailsForIP", "portName", portName, "ifName", ifName, "ipAddr", ipAddr, "netPlanEnabled", netPlanEnabled)
	fileName := "/etc/network/interfaces.d/" + portName + ".cfg"
	fileMatch := "/etc/network/interfaces.d/*-port.cfg"
	contents := fmt.Sprintf("auto %s\niface %s inet static\n   address %s/%d", ifName, ifName, ipAddr, maskbits)
	if netPlanEnabled {
		fileName = GetNetplanFilename(portName)
		fileMatch = "/etc/netplan/*-port.yaml"
		contents = getNetplanContents(portName, ifName, fmt.Sprintf(ipAddr+"/%d", maskbits))
	}
	return fileName, fileMatch, contents
}

// GetIpAddressFromNetplan returns the ip addr
func GetIPAddressFromNetplan(ctx context.Context, client ssh.Client, portName string) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetIpAddressFromNetplan", "portName", portName)
	fileName := GetNetplanFilename(portName)
	out, err := client.Output("cat " + fileName)
	if err != nil {
		if strings.Contains(out, "No such file") {
			return "", fmt.Errorf("%s - %s", NetplanFileNotFound, fileName)
		}
		return "", fmt.Errorf("error getting netplan file: %v", err)
	}
	return GetIPAddressFromNetplanContents(ctx, out)
}

// GetIPAddressFromNetplanContents returns an error unless there is exactly one address
func GetIPAddressFromNetplanContents(ctx context.Context, netplanContents string) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "parsing netplan", "netplanContents", netplanContents)

	netplanInfo := NetplanInfo{}
	err := yaml.Unmarshal([]byte(netplanContents), &netplanInfo)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to unmashal netplan info", "netplanContents", netplanContents, "err", err)
		return "", fmt.Errorf("failed to unmashal netplan info - %v", err)
	}
	if len(netplanInfo.Network.Ethernets) != 1 {
		return "", fmt.Errorf("unexpected number of ethernet interfaces in netplan file - %d - %+v", len(netplanInfo.Network.Ethernets), netplanInfo)
	}
	for _, eth := range netplanInfo.Network.Ethernets {
		if len(eth.Addresses) != 1 {
			return "", fmt.Errorf("unexpected number of addresses in netplan file - %d", len(eth.Addresses))
		}
		// remove the cidr
		s := strings.Split(eth.Addresses[0], "/")
		if len(s) != 2 {
			return "", fmt.Errorf("bad address format in netplan file - %s", eth.Addresses[0])
		}
		return s[0], nil
	}
	return "", fmt.Errorf("unexpected error parsing network contents")
}
