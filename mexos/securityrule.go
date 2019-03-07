package mexos

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

// TODO service to periodically clean up the leftover rules

func AddProxySecurityRules(rootLB *MEXRootLB, masteraddr string, appName string, appInst *edgeproto.AppInst) error {

	ports, err := GetPortDetail(appInst)
	log.DebugLog(log.DebugLevelMexos, "AddProxySecurityRules", "port", ports)

	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "GetPortDetail failed", "err", err)
		return err
	}
	sr := GetCloudletSecurityRule()
	allowedClientCIDR := GetAllowedClientCIDR()
	for _, port := range ports {
		if err := AddSecurityRuleCIDR(allowedClientCIDR, strings.ToLower(port.Proto), sr, port.PublicPort); err != nil {
			log.DebugLog(log.DebugLevelMexos, "warning, error while adding security rule", "addr", allowedClientCIDR, "port", port.PublicPort)
		}
	}
	if len(ports) > 0 {
		if err := AddNginxProxy(rootLB.Name, appName, masteraddr, ports, ""); err != nil {
			log.DebugLog(log.DebugLevelMexos, "cannot add nginx proxy", "appName", appName)
			return err
		}
	}
	log.DebugLog(log.DebugLevelMexos, "added nginx proxy", "appName", appName, "ports", appInst.MappedPorts)
	return nil
}

func DeleteProxySecurityRules(rootLB *MEXRootLB, ipaddr string, appName string) error {

	log.DebugLog(log.DebugLevelMexos, "delete proxy rules", "name", appName)
	err := DeleteNginxProxy(rootLB.Name, appName)

	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "cannot delete nginx proxy", "name", appName, "rootlb", rootLB.Name, "error", err)
	}
	if err := DeleteSecurityRule(ipaddr); err != nil {
		return err
	}
	// TODO - implement the clean up of security rules
	return nil
}

func AddSecurityRuleCIDR(cidr string, proto string, name string, port int) error {
	portStr := fmt.Sprintf("%d", port)

	out, err := TimedOpenStackCommand("openstack", "security", "group", "rule", "create", "--remote-ip", cidr, "--proto", proto, "--dst-port", portStr, "--ingress", name)
	if err != nil {
		return fmt.Errorf("can't add security group rule for port %d to %s,%s,%v", port, name, out, err)
	}
	return nil
}

type SecurityRule struct {
	IPRange   string `json:"IP Range"`
	PortRange string `json:"Port Range"`
	SGID      string `json:"Security Group"`
	ID        string `json:"ID"`
	Proto     string `json:"IP Protocol"`
}

func DeleteSecurityRule(sip string) error {
	sr := []SecurityRule{}
	dat, err := TimedOpenStackCommand("openstack", "security", "group", "rule", "list", "-f", "json")
	if err != nil {
		return fmt.Errorf("cannot get list of security group rules, %v", err)
	}
	if err := json.Unmarshal(dat, &sr); err != nil {
		return fmt.Errorf("cannot unmarshal security group rule list, %v", err)
	}
	for _, s := range sr {
		if strings.HasSuffix(s.IPRange, "/32") {
			adr := strings.Replace(s.IPRange, "/32", "", -1)
			if adr == sip {
				_, err := TimedOpenStackCommand("openstack", "security", "group", "rule", "delete", s.ID)
				if err != nil {
					log.DebugLog(log.DebugLevelMexos, "warning, cannot delete security rule", "id", s.ID, "error", err)
				}
			}
		}
	}
	return nil
}
