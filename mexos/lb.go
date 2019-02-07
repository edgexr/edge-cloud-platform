package mexos

import (
	"fmt"
	"net"
	"strings"

	"github.com/mobiledgex/edge-cloud/log"
)

//LBAddRoute adds a route to LB
func LBAddRoute(rootLBName, extNet, name string) error {
	if rootLBName == "" {
		return fmt.Errorf("empty rootLB")
	}
	if name == "" {
		return fmt.Errorf("empty name")
	}
	if extNet == "" {
		return fmt.Errorf("empty external network")
	}
	ap, err := LBGetRoute(rootLBName, name)
	if err != nil {
		return err
	}
	if len(ap) != 2 {
		return fmt.Errorf("expected 2 addresses, got %d", len(ap))
	}
	cmd := fmt.Sprintf("sudo ip route add %s via %s dev ens3", ap[0], ap[1])
	client, err := GetSSHClient(rootLBName, extNet, sshUser)
	if err != nil {
		return err
	}
	out, err := client.Output(cmd)
	if err != nil {
		if strings.Contains(out, "RTNETLINK") && strings.Contains(out, " exists") {
			log.DebugLog(log.DebugLevelMexos, "warning, can't add existing route to rootLB", "cmd", cmd, "out", out, "error", err)
			return nil
		}
		return fmt.Errorf("can't add route to rootlb, %s, %s, %v", cmd, out, err)
	}
	return nil
}

//LBRemoveRoute removes route for LB
func LBRemoveRoute(rootLB, extNet, name string) error {
	ap, err := LBGetRoute(rootLB, name)
	if err != nil {
		return err
	}
	if len(ap) != 2 {
		return fmt.Errorf("expected 2 addresses, got %d", len(ap))
	}
	cmd := fmt.Sprintf("sudo ip route delete %s via %s dev ens3", ap[0], ap[1])
	client, err := GetSSHClient(rootLB, extNet, sshUser)
	if err != nil {
		return err
	}
	out, err := client.Output(cmd)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "can't delete route at rootLB", "cmd", cmd, "out", out, "error", err)
		//not a fatal error
		return nil
	}
	return nil
}

//LBGetRoute returns route of LB
func LBGetRoute(rootLB, name string) ([]string, error) {
	cidr, err := GetInternalCIDR(name)
	if err != nil {
		return nil, err
	}
	_, ipn, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("can't parse %s, %v", cidr, err)
	}
	v4 := ipn.IP.To4()
	dn := fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
	rn := GetCloudletExternalRouter()
	rd, err := GetRouterDetail(rn)
	if err != nil {
		return nil, fmt.Errorf("can't get router detail for %s, %v", rn, err)
	}
	reg, err := GetRouterDetailExternalGateway(rd)
	if err != nil {
		return nil, fmt.Errorf("can't get router detail external gateway, %v", err)
	}
	if len(reg.ExternalFixedIPs) < 1 {
		return nil, fmt.Errorf("can't get external fixed ips list from router detail external gateway")
	}
	fip := reg.ExternalFixedIPs[0]
	return []string{dn, fip.IPAddress}, nil
}
