package vsphere

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/log"
)

func incrIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func (v *VSpherePlatform) GetExternalIpRanges() ([]string, error) {
	extIPs, ok := v.vmProperties.CommonPf.Properties["MEX_EXTERNAL_IP_RANGES"]
	if !ok || extIPs.Value == "" {
		return nil, fmt.Errorf("MEX_EXTERNAL_IP_RANGES not defined")
	}
	var rc []string
	if extIPs.Value == "" {
		return rc, fmt.Errorf("No external IPs assigned")
	}
	ipRanges := strings.Split(extIPs.Value, ",")
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

func (v *VSpherePlatform) GetRouterDetail(ctx context.Context, routerName string) (*vmlayer.RouterDetail, error) {
	return nil, fmt.Errorf("Router not supported for VSphere")
}

func (v *VSpherePlatform) GetInternalPortPolicy() vmlayer.InternalPortAttachPolicy {
	return vmlayer.AttachPortDuringCreate
}

func (v *VSpherePlatform) GetNetworkList(ctx context.Context) ([]string, error) {
	return []string{v.vmProperties.GetCloudletExternalNetwork()}, nil
}
