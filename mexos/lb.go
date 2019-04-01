package mexos

import (
	"fmt"
	"strings"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/log"
)

// LBAddRouteAndSecRules adds an external route and sec rules
func LBAddRouteAndSecRules(client pc.PlatformClient, rootLBName string) error {
	log.DebugLog(log.DebugLevelMexos, "Adding route to reach internal networks", "rootLBName", rootLBName)

	if rootLBName == "" {
		return fmt.Errorf("empty rootLB")
	}
	ni, err := ParseNetSpec(GetCloudletNetworkScheme())
	if err != nil {
		return err
	}
	// add to the /16 range for all the possible subnets
	subnet := fmt.Sprintf("%s.%s.0.0/16", ni.Octets[0], ni.Octets[1])

	rd, err := GetRouterDetail(GetCloudletExternalRouter())
	if err != nil {
		return err
	}
	gw, err := GetRouterDetailExternalGateway(rd)
	if err != nil {
		return err
	}
	fip := gw.ExternalFixedIPs
	log.DebugLog(log.DebugLevelMexos, "external fixed ips", "ips", fip)

	if len(fip) != 1 {
		return fmt.Errorf("Unexpected fixed ips for mex router %v", fip)
	}
	cmd := fmt.Sprintf("sudo ip route add %s via %s dev ens3", subnet, fip[0].IPAddress)
	if err != nil {
		return err
	}
	out, err := client.Output(cmd)
	if err != nil {
		if strings.Contains(out, "RTNETLINK") && strings.Contains(out, " exists") {
			log.DebugLog(log.DebugLevelMexos, "warning, can't add existing route to rootLB", "cmd", cmd, "out", out, "error", err)
		} else {
			return fmt.Errorf("can't add route to rootlb, %s, %s, %v", cmd, out, err)
		}
	}

	// open the firewall for internal traffic
	if err := AddSecurityRuleCIDR(subnet, "tcp", "default", "1:65535"); err != nil {
		// this error is nonfatal because it may already exist
		log.DebugLog(log.DebugLevelMexos, "notice, cannot add security rule", "error", err, "cidr", subnet)
	}

	return nil
}
