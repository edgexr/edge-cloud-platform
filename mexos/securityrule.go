package mexos

import (
	"encoding/json"
	"fmt"
	"strings"

	sh "github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

// TODO service to periodically clean up the leftover rules

func AddProxySecurityRules(rootLB *MEXRootLB, masteraddr string, appInst *edgeproto.AppInst) error {

	name := NormalizeName(appInst.Key.AppKey.Name)

	ports, err := GetPortDetail(appInst)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "GetPortDetail failed", "err", err)
		return err
	}
	sr := GetCloudletSecurityRule()
	allowedClientCIDR := GetAllowedClientCIDR()
	for _, port := range ports {
		for _, sec := range []struct {
			addr string
			port int
		}{
			{allowedClientCIDR, port.PublicPort},
			{allowedClientCIDR, port.InternalPort},
		} {
			// go func(addr string, port int, proto string) {
			// 	err := AddSecurityRuleCIDR(mf, addr, strings.ToLower(proto), sr, port)
			// 	if err != nil {
			// 		log.DebugLog(log.DebugLevelMexos, "warning, error while adding security rule", "cidr", addr, "securityrule", sr, "port", port, "proto", proto)
			// 	}
			// }(sec.addr, sec.port, port.Proto)
			if err := AddSecurityRuleCIDR(sec.addr, strings.ToLower(port.Proto), sr, sec.port); err != nil {
				log.DebugLog(log.DebugLevelMexos, "warning, error while adding security rule", "addr", sec.addr, "port", sec.port, "proto", port.Proto)
			}
		}
	}
	if len(ports) > 0 {
		if err := AddNginxProxy(rootLB.Name, name, masteraddr, ports, ""); err != nil {
			log.DebugLog(log.DebugLevelMexos, "cannot add nginx proxy", "name", name)
			return err
		}
	}
	log.DebugLog(log.DebugLevelMexos, "added nginx proxy", "name", name, "ports", appInst.MappedPorts)
	return nil
}

func DeleteProxySecurityRules(rootLB *MEXRootLB, ipaddr string, appInst *edgeproto.AppInst) error {
	appName := NormalizeName(appInst.Key.AppKey.Name)

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
	out, err := sh.Command("openstack", "security", "group", "rule", "create", "--remote-ip", cidr, "--proto", proto, "--dst-port", portStr, "--ingress", name).Output()
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
	dat, err := sh.Command("openstack", "security", "group", "rule", "list", "-f", "json").Output()
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
				_, err := sh.Command("openstack", "security", "group", "rule", "delete", s.ID).Output()
				if err != nil {
					log.DebugLog(log.DebugLevelMexos, "warning, cannot delete security rule", "id", s.ID, "error", err)
				}
			}
		}
	}
	return nil
}
