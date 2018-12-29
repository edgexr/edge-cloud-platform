package mexos

import (
	"encoding/json"
	"fmt"
	"strings"

	sh "github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud/log"
)

// TODO service to periodically clean up the leftover rules

func AddProxySecurityRules(rootLB *MEXRootLB, mf *Manifest, masteraddr string) error {
	// rootLBIPaddr, err := GetServerIPAddr(mf, mf.Values.Network.External, rootLB.Name)
	// if err != nil {
	// 	log.DebugLog(log.DebugLevelMexos, "cannot get rootlb IP address", "error", err)
	// 	return fmt.Errorf("cannot deploy kubernetes app, cannot get rootlb IP")
	// }
	sr := GetMEXSecurityRule(mf)
	allowedClientCIDR := GetAllowedClientCIDR()
	for _, port := range mf.Spec.Ports {
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
			if err := AddSecurityRuleCIDR(mf, sec.addr, strings.ToLower(port.Proto), sr, sec.port); err != nil {
				log.DebugLog(log.DebugLevelMexos, "warning, error while adding security rule", "addr", sec.addr, "port", sec.port, "proto", port.Proto)
			}
		}
	}
	if len(mf.Spec.Ports) > 0 {
		if err := AddNginxProxy(mf, rootLB.Name, mf.Metadata.Name, masteraddr, mf.Spec.Ports); err != nil {
			log.DebugLog(log.DebugLevelMexos, "cannot add nginx proxy", "name", mf.Metadata.Name, "ports", mf.Spec.Ports)
			return err
		}
	}
	log.DebugLog(log.DebugLevelMexos, "added nginx proxy", "name", mf.Metadata.Name, "ports", mf.Spec.Ports)
	return nil
}

func DeleteProxySecurityRules(rootLB *MEXRootLB, mf *Manifest, ipaddr string) error {
	log.DebugLog(log.DebugLevelMexos, "delete spec ports", "ports", mf.Spec.Ports)
	err := DeleteNginxProxy(mf, rootLB.Name, mf.Metadata.Name)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "cannot delete nginx proxy", "name", mf.Metadata.Name, "rootlb", rootLB.Name, "error", err)
	}
	if err := DeleteSecurityRule(mf, ipaddr); err != nil {
		return err
	}
	// TODO - implement the clean up of security rules
	return nil
}

func AddSecurityRuleCIDR(mf *Manifest, cidr string, proto string, name string, port int) error {
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

func DeleteSecurityRule(mf *Manifest, sip string) error {
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
