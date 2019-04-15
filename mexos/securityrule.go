package mexos

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mobiledgex/edge-cloud/log"
)

func AddSecurityRules(ports []PortDetail) error {
	sg := GetCloudletSecurityGroup()
	allowedClientCIDR := GetAllowedClientCIDR()
	for _, port := range ports {
		//todo: distinguish already-exists errors from others
		portString := fmt.Sprintf("%d", port.PublicPort)
		if err := AddSecurityRuleCIDR(allowedClientCIDR, strings.ToLower(port.Proto), sg, portString); err != nil {
			return err
		}
	}
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

func AddSecurityRuleCIDR(cidr string, proto string, name string, port string) error {

	out, err := TimedOpenStackCommand("openstack", "security", "group", "rule", "create", "--remote-ip", cidr, "--proto", proto, "--dst-port", port, "--ingress", name)
	if err != nil {
		if strings.Contains(string(out), "Security group rule already exists") {
			log.DebugLog(log.DebugLevelMexos, "security group already exists, proceeding")
		} else {
			return fmt.Errorf("can't add security group rule for port %s to %s,%s,%v", port, name, string(out), err)
		}
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
