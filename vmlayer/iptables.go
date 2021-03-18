package vmlayer

import (
	"context"
	"fmt"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

// setupForwardingIptables creates iptables rules to allow the cluster nodes to use the LB as a
// router for internet access
func (v *VMPlatform) setupForwardingIptables(ctx context.Context, client ssh.Client, externalIfname, internalIfname string, action *infracommon.InterfaceActionsOp) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "setupForwardingIptables", "externalIfname", externalIfname, "internalIfname", internalIfname, "action", fmt.Sprintf("%+v", action))
	// get current iptables
	cmd := fmt.Sprintf("sudo iptables-save|grep -e POSTROUTING -e FORWARD")
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("unable to run iptables-save: %s - %v", out, err)
	}
	// add or remove rules based on the action
	option := "-A"
	if action.DeleteIptables {
		option = "-D"
	}
	// we are looking only for the FORWARD or postrouting entries
	masqueradeRuleMatch := fmt.Sprintf("POSTROUTING -o %s -j MASQUERADE", externalIfname)
	masqueradeRule := fmt.Sprintf("-t nat %s %s", option, masqueradeRuleMatch)
	forwardExternalRuleMatch := fmt.Sprintf("FORWARD -i %s -o %s -m state --state RELATED,ESTABLISHED -j ACCEPT", externalIfname, internalIfname)
	forwardExternalRule := fmt.Sprintf("%s %s", option, forwardExternalRuleMatch)
	forwardInternalRuleMatch := fmt.Sprintf("FORWARD -i %s -j ACCEPT", internalIfname)
	forwardInternalRule := fmt.Sprintf("%s %s", option, forwardInternalRuleMatch)

	masqueradeRuleExists := false
	forwardExternalRuleExists := false
	forwardInternalRuleExists := false

	lines := strings.Split(out, "\n")
	for _, l := range lines {
		if strings.Contains(l, masqueradeRuleMatch) {
			masqueradeRuleExists = true
		}
		if strings.Contains(l, forwardExternalRuleMatch) {
			forwardExternalRuleExists = true
		}
		if strings.Contains(l, forwardInternalRuleMatch) {
			forwardInternalRuleExists = true
		}
	}
	if action.CreateIptables {
		// this rule is never deleted because it applies to all subnets.   Multiple adds will
		// not create duplicates
		err = infracommon.DoIptablesCommand(ctx, client, masqueradeRule, masqueradeRuleExists, action)
		if err != nil {
			return err
		}
	}
	// only add forwarding-permits rules if iptables is not used for firewalls
	if !v.VMProperties.IptablesBasedFirewall {
		err = infracommon.DoIptablesCommand(ctx, client, forwardExternalRule, forwardExternalRuleExists, action)
		if err != nil {
			return err
		}
		err = infracommon.DoIptablesCommand(ctx, client, forwardInternalRule, forwardInternalRuleExists, action)
		if err != nil {
			return err
		}
	}
	//now persist the rules
	err = infracommon.PersistIptablesRules(ctx, client)
	if err != nil {
		return err
	}
	return nil
}

func (v *VMProperties) SetupIptablesRulesForRootLB(ctx context.Context, client ssh.Client, sshCidrsAllowed []string, TrustPolicy *edgeproto.TrustPolicy) error {

	var netRules infracommon.FirewallRules
	var ppRules infracommon.FirewallRules

	//First create the global rules on this LB
	log.SpanLog(ctx, log.DebugLevelInfra, "creating cloudlet-wide rules")
	err := v.CommonPf.CreateCloudletFirewallRules(ctx, client)
	if err != nil {
		return err
	}

	// Allow SSH from provided cidrs
	for _, netCidr := range sshCidrsAllowed {
		sshIngress := infracommon.FirewallRule{
			Protocol:     "tcp",
			RemoteCidr:   netCidr,
			PortRange:    "22",
			PortEndpoint: infracommon.DestPort,
		}
		netRules.IngressRules = append(netRules.IngressRules, sshIngress)
	}

	// all traffic between the internal networks is allowed
	internalRoute, err := v.GetInternalNetworkRoute(ctx)
	if err != nil {
		return err
	}
	internalNetInRule := infracommon.FirewallRule{
		RemoteCidr: internalRoute,
	}
	netRules.IngressRules = append(netRules.IngressRules, internalNetInRule)

	internalNetOutRule := infracommon.FirewallRule{
		RemoteCidr: internalRoute,
	}
	netRules.EgressRules = append(netRules.EgressRules, internalNetOutRule)
	err = infracommon.AddIptablesRules(ctx, client, "rootlb-networking", &netRules)
	if err != nil {
		return err
	}

	// optionally add Privacy Policy
	allowEgressAll := false
	if TrustPolicy != nil {
		if len(TrustPolicy.OutboundSecurityRules) == 0 {
			// a privacy policy with no rules means we need to open all egress traffic
			allowEgressAll = true
		}
		for _, p := range TrustPolicy.OutboundSecurityRules {
			allowEgressAll = false
			portRange := fmt.Sprintf("%d", p.PortRangeMin)
			if p.PortRangeMax != 0 {
				portRange += fmt.Sprintf(":%d", p.PortRangeMax)
			}
			egressRule := infracommon.FirewallRule{
				Protocol:     p.Protocol,
				PortRange:    portRange,
				RemoteCidr:   p.RemoteCidr,
				PortEndpoint: infracommon.DestPort,
			}
			ppRules.EgressRules = append(ppRules.EgressRules, egressRule)
		}
	}
	if allowEgressAll {
		allowAllEgressRule := infracommon.FirewallRule{
			RemoteCidr: "0.0.0.0/0",
		}
		ppRules.EgressRules = append(ppRules.EgressRules, allowAllEgressRule)
	}
	err = infracommon.AddIptablesRules(ctx, client, "privacy-policy", &ppRules)
	if err != nil {
		return err
	}
	return infracommon.AddDefaultIptablesRules(ctx, client)
}
