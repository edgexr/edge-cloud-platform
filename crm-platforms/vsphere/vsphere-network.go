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

package vsphere

import (
	"context"
	"fmt"
	"net"

	ssh "github.com/mobiledgex/golang-ssh"

	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
)

const PortDoesNotExist = "Port does not exist"

func (v *VSpherePlatform) GetExternalIpRanges() ([]string, error) {
	log.DebugLog(log.DebugLevelInfra, "GetExternalIpRanges")
	var extIPs = ""
	if v.vmProperties.Domain == vmlayer.VMDomainPlatform {
		// check for optional management gw
		extIPs, _ = v.vmProperties.CommonPf.Properties.GetValue("MEX_MANAGEMENT_EXTERNAL_IP_RANGES")
	}
	if extIPs == "" {
		extIPs, _ = v.vmProperties.CommonPf.Properties.GetValue("MEX_EXTERNAL_IP_RANGES")
		if extIPs == "" {
			return nil, fmt.Errorf("MEX_EXTERNAL_IP_RANGES not defined")
		}
		log.DebugLog(log.DebugLevelInfra, "Using MEX_EXTERNAL_IP_RANGES", "extIPs", extIPs)
	} else {
		log.DebugLog(log.DebugLevelInfra, "Using MEX_MANAGEMENT_EXTERNAL_IP_RANGES", "extIPs", extIPs)
	}
	return infracommon.ParseIpRanges(extIPs)
}

func (v *VSpherePlatform) GetFreeExternalIP(ctx context.Context) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetFreeExternalIP")

	ipsUsed, err := v.GetUsedExternalIPs(ctx)
	ips, err := v.GetExternalIpRanges()
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		_, used := ipsUsed[ip]
		if !used {
			return ip, nil
		}
	}
	return "", fmt.Errorf("No available IPs")
}

func (v *VSpherePlatform) GetExternalIpNetworkCidr(ctx context.Context) (string, error) {
	gw, err := v.GetExternalGateway(ctx, v.vmProperties.GetCloudletExternalNetwork())
	if err != nil {
		return "", err
	}

	mask := v.GetExternalNetmask()
	netString := gw + "/" + mask
	_, netCidr, err := net.ParseCIDR(netString)
	if err != nil {
		return "", err
	}
	return netCidr.String(), nil
}

// GetExternalIPCounts returns Total, Used
func (v *VSpherePlatform) GetExternalIPCounts(ctx context.Context) (uint64, uint64, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetExternalIPCounts")

	ips, err := v.GetExternalIpRanges()
	if err != nil {
		return 0, 0, err
	}
	ipsUsed, err := v.GetUsedExternalIPs(ctx)
	return uint64(len(ips)), uint64(len(ipsUsed)), nil
}

func (v *VSpherePlatform) GetRouterDetail(ctx context.Context, routerName string) (*vmlayer.RouterDetail, error) {
	return nil, fmt.Errorf("Router not supported for VSphere")
}

func (v *VSpherePlatform) GetInternalPortPolicy() vmlayer.InternalPortAttachPolicy {
	return vmlayer.AttachPortDuringCreate
}

func (v *VSpherePlatform) GetNetworkList(ctx context.Context) ([]string, error) {
	return []string{v.vmProperties.GetCloudletExternalNetwork()}, nil
}

func (v *VSpherePlatform) GetPortGroup(ctx context.Context, serverName, network string) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetPortGroup", "serverName", serverName, "network", network)

	if network == v.vmProperties.GetCloudletExternalNetwork() {
		return network, nil
	}
	subnetTag, err := v.GetTagMatchingField(ctx, v.GetSubnetTagCategory(ctx), TagFieldSubnetName, network)
	if err != nil {
		return "", fmt.Errorf("Error in GetPortName: %v", err)
	}
	subnetTagContents, err := v.ParseSubnetTag(ctx, subnetTag.Name)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("VLAN-%d", subnetTagContents.Vlan), nil
}

func (v *VSpherePlatform) ValidateAdditionalNetworks(ctx context.Context, additionalNets map[string]vmlayer.NetworkType) error {
	return fmt.Errorf("Additional networks not supported in vSphere cloudlets")
}

func (v *VSpherePlatform) ConfigureCloudletSecurityRules(ctx context.Context, egressRestricted bool, TrustPolicy *edgeproto.TrustPolicy, rootlbClients map[string]ssh.Client, action vmlayer.ActionType, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}
