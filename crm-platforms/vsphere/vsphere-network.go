package vsphere

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/log"
)

const PortDoesNotExist = "Port does not exist"

func incrIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

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
	var rc []string
	if extIPs == "" {
		return rc, fmt.Errorf("No external IPs assigned")
	}
	ipRanges := strings.Split(extIPs, ",")
	for _, ipRange := range ipRanges {
		ranges := strings.Split(ipRange, "-")
		if len(ranges) != 2 {
			return rc, fmt.Errorf("IP range must be in format startcidr-endcidr: %s", ipRange)
		}
		startCidr := ranges[0]
		endCidr := ranges[1]

		ipStart, ipnetStart, err := net.ParseCIDR(startCidr)
		if err != nil {
			return rc, fmt.Errorf("cannot parse start cidr: %v", err)
		}
		ipEnd, ipnetEnd, err := net.ParseCIDR(endCidr)
		if err != nil {
			return rc, fmt.Errorf("cannot parse end cidr: %v", err)
		}
		if ipnetStart.String() != ipnetEnd.String() {
			return rc, fmt.Errorf("start and end network address must match: %s neq %s", ipnetStart, ipnetEnd)
		}
		for ip := ipStart.Mask(ipnetStart.Mask); ipnetStart.Contains(ip); incrIP(ip) {
			if string(ipStart.To16()) <= string(ip.To16()) && string(ipEnd.To16()) >= string(ip.To16()) {
				rc = append(rc, ip.String())
			}
		}
	}
	return rc, nil
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
