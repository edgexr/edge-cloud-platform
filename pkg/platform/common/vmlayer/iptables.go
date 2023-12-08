// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vmlayer

import (
	"context"
	"fmt"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	ssh "github.com/edgexr/golang-ssh"
)

// setupForwardingIptables creates iptables rules to allow the cluster nodes to use the LB as a
// router for internet access
func (v *VMPlatform) setupForwardingIptables(ctx context.Context, client ssh.Client, externalIfname, internalIfname string, action *infracommon.InterfaceActionsOp, ipversion infracommon.IPVersion) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "setupForwardingIptables", "externalIfname", externalIfname, "internalIfname", internalIfname, "action", fmt.Sprintf("%+v", action), "ipversion", ipversion)
	// get current iptables
	iptablesSaveBin := infracommon.IPTablesSaveBin
	if ipversion == infracommon.IPV6 {
		iptablesSaveBin = infracommon.IP6TablesSaveBin
	}
	// note: do not grep here, as it causes command to fail if no rules match grep
	cmd := fmt.Sprintf("sudo %s", iptablesSaveBin)

	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("unable to run %s: %s - %v", cmd, out, err)
	}

	// Note: having docker installed sets default FORWARDING policy to DROP.
	// It also enables sysctl ipv4 forwarding (which is needed for LB).
	// It also enables sysctl ipv6 forwarding if configured for ipv6
	// (which is needed for LB for ipv6).
	// We rely on docker being installed on the LB for these settings,
	// rather than configuring them ourselves.

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
	forwardInternalRuleMatch := fmt.Sprintf("FORWARD -i %s -o %s -j ACCEPT", internalIfname, externalIfname)
	forwardInternalRule := fmt.Sprintf("%s %s", option, forwardInternalRuleMatch)

	masqueradeRuleExists := false
	forwardExternalRuleExists := false
	forwardInternalRuleExists := false

	lines := strings.Split(out, "\n")
	for _, l := range lines {
		if !strings.Contains(l, "POSTROUTING") && !strings.Contains(l, "FORWARD") {
			continue
		}
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
		err = infracommon.DoIptablesCommand(ctx, client, masqueradeRule, masqueradeRuleExists, action, ipversion)
		if err != nil {
			return err
		}
	}
	// only add forwarding-permits rules if iptables is not used for firewalls
	if !v.VMProperties.IptablesBasedFirewall {
		err = infracommon.DoIptablesCommand(ctx, client, forwardExternalRule, forwardExternalRuleExists, action, ipversion)
		if err != nil {
			return err
		}
		err = infracommon.DoIptablesCommand(ctx, client, forwardInternalRule, forwardInternalRuleExists, action, ipversion)
		if err != nil {
			return err
		}
	}
	//now persist the rules
	err = infracommon.PersistIptablesRules(ctx, client, ipversion)
	if err != nil {
		return err
	}
	return nil
}

// iptable is case sensitive and does not like upper case for some options
// convert protocol to lower case
func fixupSecurityRules(ctx context.Context, rules []edgeproto.SecurityRule) {
	for i, o := range rules {
		rules[i].Protocol = strings.ToLower(o.Protocol)
	}
}

func (v *VMProperties) SetupIptablesRulesForRootLB(ctx context.Context, client ssh.Client, sshCidrsAllowed []string, egressRestricted bool, secGrpName string, rules []edgeproto.SecurityRule, commonSharedAccess, enableIPV6 bool) error {

	log.SpanLog(ctx, log.DebugLevelInfra, "SetupIptablesRulesForRootLB", "egressRestricted", egressRestricted, "secGrpName", secGrpName, "len(rules)", len(rules))
	fixupSecurityRules(ctx, rules)

	var netRules infracommon.FirewallRules
	var ppRules infracommon.FirewallRules

	// Allow SSH from provided cidrs
	for _, netCidr := range sshCidrsAllowed {
		ipversion, err := infracommon.GetCIDRIPVersion(ctx, netCidr)
		if err != nil {
			return err
		}
		sshIngress := infracommon.FirewallRule{
			Protocol:     "tcp",
			RemoteCidr:   netCidr,
			PortRange:    "22",
			PortEndpoint: infracommon.DestPort,
			IPVersion:    ipversion,
		}
		netRules.IngressRules = append(netRules.IngressRules, sshIngress)
	}
	// all traffic between the internal networks is allowed
	internalRoute, internalRouteIPV6, err := v.GetInternalNetworkRoute(ctx, commonSharedAccess)
	if err != nil {
		return err
	}
	internalNetInRule := infracommon.FirewallRule{
		RemoteCidr: internalRoute,
		IPVersion:  infracommon.IPV4,
	}
	netRules.IngressRules = append(netRules.IngressRules, internalNetInRule)

	internalNetOutRule := infracommon.FirewallRule{
		RemoteCidr: internalRoute,
		IPVersion:  infracommon.IPV4,
	}
	netRules.EgressRules = append(netRules.EgressRules, internalNetOutRule)

	if enableIPV6 {
		internalNetInRuleIPV6 := infracommon.FirewallRule{
			RemoteCidr: internalRouteIPV6,
			IPVersion:  infracommon.IPV6,
		}
		netRules.IngressRules = append(netRules.IngressRules, internalNetInRuleIPV6)

		internalNetOutRuleIPV6 := infracommon.FirewallRule{
			RemoteCidr: internalRouteIPV6,
			IPVersion:  infracommon.IPV6,
		}
		netRules.EgressRules = append(netRules.EgressRules, internalNetOutRuleIPV6)
	}
	err = infracommon.AddIptablesRules(ctx, client, "rootlb-networking", &netRules)
	if err != nil {
		return err
	}

	// delete obsolete cloudlet-wide rules
	err = v.CommonPf.DeleteIptableRulesForCloudletWideLabel(ctx, client)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "SetupIpTablesRulesForRootLB DeleteIptableRulesForCloudletWideLabel fail", "error", err)
	}

	// always delete the trust rules first, they will be re-added as required
	err = infracommon.RemoveRulesForLabel(ctx, client, secGrpName)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "SetupIpTablesRulesForRootLB RemoveRulesForLabel fail", "error", err)
	}

	allowEgressAll := !egressRestricted

	for _, p := range rules {
		portRange := fmt.Sprintf("%d", p.PortRangeMin)
		if p.PortRangeMax != 0 {
			portRange += fmt.Sprintf(":%d", p.PortRangeMax)
		}
		ipversion, err := infracommon.GetCIDRIPVersion(ctx, p.RemoteCidr)
		if err != nil {
			return err
		}
		egressRule := infracommon.FirewallRule{
			Protocol:     p.Protocol,
			PortRange:    portRange,
			RemoteCidr:   p.RemoteCidr,
			PortEndpoint: infracommon.DestPort,
			IPVersion:    ipversion,
		}
		ppRules.EgressRules = append(ppRules.EgressRules, egressRule)
	}

	if allowEgressAll {
		allowAllEgressRule := infracommon.FirewallRule{
			RemoteCidr: "0.0.0.0/0",
			IPVersion:  infracommon.IPV4,
		}
		ppRules.EgressRules = append(ppRules.EgressRules, allowAllEgressRule)

		if enableIPV6 {
			allowAllEgressRuleIPV6 := infracommon.FirewallRule{
				RemoteCidr: "::/0",
				IPVersion:  infracommon.IPV6,
			}
			ppRules.EgressRules = append(ppRules.EgressRules, allowAllEgressRuleIPV6)
		}
	}

	err = infracommon.AddIptablesRules(ctx, client, secGrpName, &ppRules)
	if err != nil {
		return err
	}
	err = infracommon.AddDefaultIptablesRules(ctx, client, infracommon.IPV4)
	if err != nil {
		return err
	}
	if enableIPV6 {
		err = infracommon.AddDefaultIptablesRules(ctx, client, infracommon.IPV6)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetBootCommandsForInterClusterIptables generates a list of commands that can be used to block all traffic from a specified CIDR
// with exceptions for an allowed range and a gateway.
func GetBootCommandsForInterClusterIptables(ctx context.Context, allowedCidr, blockedCidr, gateway string, ipversion infracommon.IPVersion) ([]string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetBootCommandsForInterClusterIptables", "allowedCidr", allowedCidr, "blockedCidr", blockedCidr, "gateway", gateway, "ipversion", ipversion)
	var commands []string
	rules := []string{
		fmt.Sprintf("INPUT -s %s -j ACCEPT", allowedCidr),
		fmt.Sprintf("INPUT -s %s/32 -j ACCEPT", gateway),
		fmt.Sprintf("INPUT -s %s -j DROP", blockedCidr),
	}
	cmd := infracommon.IPTablesBin
	persistCmd := infracommon.IPTablesPersistCmd
	if ipversion == infracommon.IPV6 {
		cmd = infracommon.IP6TablesBin
		persistCmd = infracommon.IP6TablesPersistCmd
	}
	for _, r := range rules {
		// add rule only if it does not exist
		commands = append(commands, fmt.Sprintf("%s -C %s || %s -A %s", cmd, r, cmd, r))
	}
	commands = append(commands, persistCmd)
	return commands, nil
}
