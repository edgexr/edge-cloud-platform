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

package k8sbm

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/edgexr/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

var ipLock sync.Mutex

func (k *K8sBareMetalPlatform) RemoveIp(ctx context.Context, client ssh.Client, addr, dev, name string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "RemoveIp", "addr", addr, "dev", dev)
	cmd := fmt.Sprintf("sudo ip address del %s/32 dev %s", addr, dev)
	out, err := client.Output(cmd)
	if err != nil {
		// Not intuitive, but "Cannot assign" is reported when trying to delete a nonexistent address
		if !strings.Contains(out, "Cannot assign") {
			return fmt.Errorf("Error deleting ip: %s - %s - %v", addr, out, err)
		}
	}
	filename := infracommon.GetNetplanFilename(name)
	err = pc.DeleteFile(client, filename, pc.SudoOn)
	if err != nil {
		return fmt.Errorf("unable to delete network config file: %s -- %v", filename, err)
	}
	return nil
}

// GetUsedSecondaryIpAddresses gets a map of address->interface name of IPs current in use on the device
func (k *K8sBareMetalPlatform) GetUsedSecondaryIpAddresses(ctx context.Context, client ssh.Client, devname string) (map[string]string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetUsedSecondaryIpAddresses", "devname", devname)
	cmd := fmt.Sprintf("ip address show %s", devname)
	out, err := client.Output(cmd)
	if err != nil {
		return nil, fmt.Errorf("Error in finding secondary interfaces: %s - %v", out, err)
	}
	usedIps := make(map[string]string)
	lines := strings.Split(out, "\n")
	ifPattern := fmt.Sprintf("inet (\\d+\\.\\d+\\.\\d+\\.\\d+)/\\d+ .*(%s)", devname)
	ifReg := regexp.MustCompile(ifPattern)
	for _, line := range lines {
		if ifReg.MatchString(line) {
			matches := ifReg.FindStringSubmatch(line)
			ip := matches[1]
			ifname := matches[2]
			usedIps[ip] = ifname
			log.SpanLog(ctx, log.DebugLevelInfra, "GetUsedSecondaryIpAddresses found ip", "ip", ip, "ifname", ifname)
		}
	}
	return usedIps, nil
}

// AssignFreeLbIp returns externalIp
func (k *K8sBareMetalPlatform) AssignFreeLbIp(ctx context.Context, name string, client ssh.Client) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "AssignFreeLbIp", "name", name)
	ipLock.Lock()
	defer ipLock.Unlock()
	extDevName := k.GetExternalEthernetInterface()
	accessIp := k.GetControlAccessIp()
	usedIps, err := k.GetUsedSecondaryIpAddresses(ctx, client, extDevName)
	if err != nil {
		return "", err
	}
	freeExternalIp := ""
	for _, addr := range k.externalIps {
		if addr == accessIp {
			continue
		}
		_, used := usedIps[addr]
		if used {
			continue
		}
		freeExternalIp = addr
	}
	if freeExternalIp == "" {
		return "", fmt.Errorf("No free LB IP Found")
	}
	out, err := client.Output(fmt.Sprintf("sudo ip address add %s/32 dev %s", freeExternalIp, extDevName))
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Error adding external ip", "ip", freeExternalIp, "devName", extDevName, "out", out, "err", err)
		return "", fmt.Errorf("Error assigning new external IP: %s - %v", out, err)
	}
	// persist the ip address
	filename, _, contents := infracommon.GenerateNetworkFileDetailsForIP(ctx, name, extDevName, freeExternalIp, 32, true)
	err = pc.WriteFile(client, filename, contents, "netconfig", pc.SudoOn)
	if err != nil {
		return "", fmt.Errorf("unable to write network config file: %s -- %v", filename, err)
	}
	return freeExternalIp, nil
}

func (k *K8sBareMetalPlatform) WhitelistSecurityRules(ctx context.Context, client ssh.Client, wlParams *infracommon.WhiteListParams) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "WhitelistSecurityRules", "wlParams", wlParams)
	return infracommon.AddIngressIptablesRules(ctx, client, wlParams.Label, wlParams.AllowedCIDR, wlParams.DestIP, wlParams.Ports)
}

func (k *K8sBareMetalPlatform) RemoveWhitelistSecurityRules(ctx context.Context, client ssh.Client, wlParams *infracommon.WhiteListParams) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "RemoveWhitelistSecurityRules", "wlParams", wlParams)
	return infracommon.RemoveIngressIptablesRules(ctx, client, wlParams.Label, wlParams.AllowedCIDR, wlParams.DestIP, wlParams.Ports)
}
