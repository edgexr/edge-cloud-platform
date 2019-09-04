package mexos

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/nginx"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	dme "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

func AddSecurityRules(ctx context.Context, ports []dme.AppPort) error {
	sg := GetCloudletSecurityGroup()
	allowedClientCIDR := GetAllowedClientCIDR()
	for _, port := range ports {
		//todo: distinguish already-exists errors from others
		portString := fmt.Sprintf("%d", port.PublicPort)
		proto, err := edgeproto.L4ProtoStr(port.Proto)
		if err != nil {
			return err
		}
		if err := AddSecurityRuleCIDR(ctx, allowedClientCIDR, proto, sg, portString); err != nil {
			return err
		}
	}
	return nil
}

func DeleteProxySecurityRules(ctx context.Context, client pc.PlatformClient, ipaddr string, appName string) error {

	log.SpanLog(ctx, log.DebugLevelMexos, "delete proxy rules", "name", appName)
	err := nginx.DeleteNginxProxy(client, appName)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelMexos, "cannot delete nginx proxy", "name", appName, "error", err)
	}
	if err := DeleteSecurityRule(ctx, ipaddr); err != nil {
		return err
	}
	// TODO - implement the clean up of security rules
	return nil
}

func AddSecurityRuleCIDR(ctx context.Context, cidr string, proto string, name string, port string) error {

	out, err := TimedOpenStackCommand(ctx, "openstack", "security", "group", "rule", "create", "--remote-ip", cidr, "--proto", proto, "--dst-port", port, "--ingress", name)
	if err != nil {
		if strings.Contains(string(out), "Security group rule already exists") {
			log.SpanLog(ctx, log.DebugLevelMexos, "security group already exists, proceeding")
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

func DeleteSecurityRule(ctx context.Context, sip string) error {
	sr := []SecurityRule{}
	dat, err := TimedOpenStackCommand(ctx, "openstack", "security", "group", "rule", "list", "-f", "json")
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
				_, err := TimedOpenStackCommand(ctx, "openstack", "security", "group", "rule", "delete", s.ID)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelMexos, "warning, cannot delete security rule", "id", s.ID, "error", err)
				}
			}
		}
	}
	return nil
}
