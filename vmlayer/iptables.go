package vmlayer

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"

	dme "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

type FirewallRules struct {
	EgressRules  []FirewallRule
	IngressRules []FirewallRule
}

// PortSourceOrDestChoice indicates whether the port(s) are the source or destination ports
type PortSourceOrDestChoice string

const SourcePort PortSourceOrDestChoice = "sport"
const DestPort PortSourceOrDestChoice = "dport"

type FirewallRule struct {
	Protocol     string
	RemoteCidr   string
	PortRange    string
	InterfaceIn  string
	InterfaceOut string
	PortEndpoint PortSourceOrDestChoice
	Conntrack    string
}

// doIptablesCommand runs an iptables add or delete conditionally based on whether the entry already exists or not
func doIptablesCommand(ctx context.Context, client ssh.Client, rule string, ruleExists bool, action *InterfaceActionsOp) error {
	runCommand := false
	if ruleExists {
		if action.deleteIptables {
			log.SpanLog(ctx, log.DebugLevelInfra, "deleting existing iptables rule", "rule", rule)
			runCommand = true
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "do not re-add existing iptables rule", "rule", rule)
		}
	} else {
		if action.createIptables {
			log.SpanLog(ctx, log.DebugLevelInfra, "adding new iptables rule", "rule", rule)
			runCommand = true
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "do not delete nonexistent iptables rule", "rule", rule)
		}
	}

	if runCommand {
		log.SpanLog(ctx, log.DebugLevelInfra, "running iptables command", "rule", rule)
		cmd := fmt.Sprintf("sudo iptables %s", rule)
		out, err := client.Output(cmd)
		if err != nil {
			return fmt.Errorf("unable to modify iptables rule: %s, %s - %v", rule, out, err)
		}
	}
	return nil
}

//	parseFirewallRules parses rules in the format:
// Value: "protocol=tcp,portrange=1:65535,remotecidr=0.0.0.0/0;protocol=udp,portrange=1:65535,remotecidr=0.0.0.0/0;protocol=icmp,remotecidr=0.0.0.0/0",
func parseFirewallRules(ctx context.Context, ruleString string) ([]FirewallRule, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "parseFirewallRules", "ruleString", ruleString)

	if ruleString == "" {
		return nil, nil
	}
	var firewallRules []FirewallRule
	rules := strings.Split(ruleString, ";")
	portRangeReg := regexp.MustCompile("\\d+(:\\d+)?")
	for _, rs := range rules {
		log.SpanLog(ctx, log.DebugLevelInfra, "parseFirewallRules", "rule", rs)
		var firewallRule FirewallRule
		ss := strings.Split(rs, ",")
		for _, s := range ss {
			s = strings.ToLower(s)
			kvs := strings.Split(s, "=")
			if len(kvs) != 2 {
				return nil, fmt.Errorf("unable to parse firewall rule, not in key=val format: %s", s)
			}
			key := kvs[0]
			val := kvs[1]
			switch key {
			case "protocol":
				firewallRule.Protocol = val
			case "remotecidr":
				_, _, err := net.ParseCIDR(val)
				if err != nil {
					return nil, fmt.Errorf("unable to parse firewall rule, bad cidr: %s", val)
				}
				firewallRule.RemoteCidr = val
			case "portrange":
				match := portRangeReg.MatchString(val)
				if !match {
					return nil, fmt.Errorf("unable to parse firewall rule, bad port range: %s", val)
				}
				firewallRule.PortRange = val
			default:
				return nil, fmt.Errorf("unable to parse firewall rule, bad key: %s", key)
			}
		}
		if firewallRule.RemoteCidr == "" {
			return nil, fmt.Errorf("invalid firewall rule, missing cidr")
		}
		firewallRule.PortEndpoint = DestPort
		firewallRules = append(firewallRules, firewallRule)
	}

	return firewallRules, nil
}

// createCloudletFirewallRules adds cloudlet-wide egress rules based on properties
func (v *VMProperties) createCloudletFirewallRules(ctx context.Context, client ssh.Client) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "createCloudletFirewallRules")

	var firewallRules FirewallRules
	var err error
	if val, ok := v.CommonPf.Properties.GetValue("MEX_CLOUDLET_FIREWALL_WHITELIST_EGRESS"); ok {
		firewallRules.EgressRules, err = parseFirewallRules(ctx, val)
		if err != nil {
			return err
		}
	}
	if val, ok := v.CommonPf.Properties.GetValue("MEX_CLOUDLET_FIREWALL_WHITELIST_INGRESS"); ok {
		firewallRules.IngressRules, err = parseFirewallRules(ctx, val)
		if err != nil {
			return err
		}
	}
	return addIptablesRules(ctx, client, "cloudlet-wide", &firewallRules)
}

// getIpTablesEntryForRule gets the iptables string for the rule
func getIpTablesEntriesForRule(ctx context.Context, direction string, label string, rule *FirewallRule) []string {
	log.SpanLog(ctx, log.DebugLevelInfra, "getIpTablesEntriesForRule", "rule", rule)
	cidrStr := ""
	var chains []string
	var rules []string
	if direction == "egress" {
		chains = append(chains, "OUTPUT", "FORWARD")
		if rule.RemoteCidr != "0.0.0.0/0" {
			cidrStr = "-d " + rule.RemoteCidr
		}
	} else {
		chains = append(chains, "INPUT")
		if rule.RemoteCidr != "0.0.0.0/0" {
			cidrStr = "-s " + rule.RemoteCidr
		}
	}
	portStr := ""
	if rule.PortRange != "" && rule.PortRange != "0" {
		portStr = "--" + string(rule.PortEndpoint) + " " + rule.PortRange
	}
	icmpType := ""
	if rule.Protocol == "icmp" {
		icmpType = " --icmp-type any"
	}
	protostr := ""
	if rule.Protocol != "" {
		protostr = fmt.Sprintf("-p %s -m %s", rule.Protocol, rule.Protocol)
	}
	ifstr := ""
	if rule.InterfaceIn != "" {
		ifstr = "-i " + rule.InterfaceIn
	} else if rule.InterfaceOut != "" {
		ifstr = "-o " + rule.InterfaceOut
	}
	conntrackStr := ""
	if rule.Conntrack != "" {
		conntrackStr = "-m conntrack --ctstate " + rule.Conntrack
	}
	for _, chain := range chains {
		rulestr := fmt.Sprintf("%s %s %s %s %s %s %s -m comment --comment \"label %s\" -j ACCEPT", chain, ifstr, conntrackStr, cidrStr, protostr, icmpType, portStr, label)
		// remove double spaces
		rulestr = strings.Join(strings.Fields(rulestr), " ")
		rules = append(rules, rulestr)
	}
	return rules
}

// getCurrentIptableRulesForLabel retrieves the current rules matching the label
func getCurrentIptableRulesForLabel(ctx context.Context, client ssh.Client, label string) (map[string]string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "getCurrentIptableRulesForLabel", "label", label)

	rules := make(map[string]string)

	cmd := fmt.Sprintf("sudo iptables-save")
	out, err := client.Output(cmd)
	if err != nil {
		return nil, fmt.Errorf("Failed to run iptables-save to get current rules: %s - %v", out, err)
	}
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if strings.Contains(line, "\"label "+label+"\"") && strings.HasPrefix(line, "-A") {
			rules[line] = line
		}
	}
	return rules, nil
}

// addIptablesRule adds a rule
func addIptablesRule(ctx context.Context, client ssh.Client, direction string, label string, rule *FirewallRule, currentRules map[string]string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "addIptablesRule", "direction", direction, "label", label, "rule", rule)
	entries := getIpTablesEntriesForRule(ctx, direction, label, rule)
	for _, entry := range entries {
		addCmd := "-A " + entry
		_, exists := currentRules[addCmd]
		action := InterfaceActionsOp{createIptables: true}
		err := doIptablesCommand(ctx, client, addCmd, exists, &action)
		if err != nil {
			return err
		}
	}
	return nil
}

// removeIptablesRule removes a rule
func removeIptablesRule(ctx context.Context, client ssh.Client, direction string, label string, rule *FirewallRule, currentRules map[string]string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "removeIptablesRule", "direction", direction, "label", label, "rule", rule)
	entries := getIpTablesEntriesForRule(ctx, direction, label, rule)
	for _, entry := range entries {
		addCmd := "-A " + entry
		delCmd := "-D " + entry
		_, exists := currentRules[addCmd]
		action := InterfaceActionsOp{deleteIptables: true}
		err := doIptablesCommand(ctx, client, delCmd, exists, &action)
		if err != nil {
			return err
		}
	}
	return nil
}

// addIptablesRules adds a set of rules
func addIptablesRules(ctx context.Context, client ssh.Client, label string, rules *FirewallRules) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "addIptablesRules", "rules", rules)
	currentRules, err := getCurrentIptableRulesForLabel(ctx, client, label)
	if err != nil {
		return err
	}
	for _, erule := range rules.EgressRules {
		err := addIptablesRule(ctx, client, "egress", label, &erule, currentRules)
		if err != nil {
			return err
		}
	}
	for _, irule := range rules.IngressRules {
		err := addIptablesRule(ctx, client, "ingress", label, &irule, currentRules)
		if err != nil {
			return err
		}
	}
	return persistIptablesRules(ctx, client)
}

// deleteIptablesRules deletes a set of rules
func deleteIptablesRules(ctx context.Context, client ssh.Client, label string, rules *FirewallRules) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "deleteIptablesRules", "rules", rules)
	currentRules, err := getCurrentIptableRulesForLabel(ctx, client, label)
	if err != nil {
		return err
	}
	for _, erule := range rules.EgressRules {
		err := removeIptablesRule(ctx, client, "egress", label, &erule, currentRules)
		if err != nil {
			return err
		}
	}
	for _, irule := range rules.IngressRules {
		err := removeIptablesRule(ctx, client, "ingress", label, &irule, currentRules)
		if err != nil {
			return err
		}
	}
	// make this an option?
	return persistIptablesRules(ctx, client)
}

// addDefaultIptablesRules adds the default set of rules which are always needed
func addDefaultIptablesRules(ctx context.Context, client ssh.Client) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "addDefaultIptablesRules")

	var rules FirewallRules
	// local loopback traffic is open
	loopInRule := FirewallRule{
		RemoteCidr:  "0.0.0.0/0",
		InterfaceIn: "lo",
	}
	rules.IngressRules = append(rules.IngressRules, loopInRule)
	loopOutRule := FirewallRule{
		RemoteCidr:   "0.0.0.0/0",
		InterfaceOut: "lo",
	}
	rules.EgressRules = append(rules.EgressRules, loopOutRule)

	// allow established sessions
	conntrackInRule := FirewallRule{
		RemoteCidr: "0.0.0.0/0",
		Conntrack:  "ESTABLISHED,RELATED",
	}
	rules.IngressRules = append(rules.IngressRules, conntrackInRule)
	conntrackOutRule := FirewallRule{
		RemoteCidr: "0.0.0.0/0",
		Conntrack:  "ESTABLISHED,RELATED",
	}
	rules.EgressRules = append(rules.EgressRules, conntrackOutRule)

	err := addIptablesRules(ctx, client, "default-rules", &rules)
	if err != nil {
		return err
	}

	// anything not matching the chain is dropped.   These will not create
	// duplicate entries if done multiple times
	dropInputPolicy := "-P INPUT DROP"
	dropOutputPolicy := "-P OUTPUT DROP"
	action := InterfaceActionsOp{createIptables: true}
	err = doIptablesCommand(ctx, client, dropInputPolicy, false, &action)
	if err != nil {
		return err
	}
	return doIptablesCommand(ctx, client, dropOutputPolicy, false, &action)
}

// getFirewallRulesFromAppPorts accepts a CIDR and a set of AppPorts and converts to a set of rules
func getFirewallRulesFromAppPorts(ctx context.Context, cidr string, ports []dme.AppPort) (*FirewallRules, error) {
	var fwRules FirewallRules
	for _, p := range ports {
		portStr := fmt.Sprintf("%d", p.PublicPort)
		if p.EndPort != 0 {
			portStr += fmt.Sprintf(":%d", p.EndPort)
		}
		proto, err := edgeproto.L4ProtoStr(p.Proto)
		if err != nil {
			return nil, err
		}
		fwRuleDest := FirewallRule{
			Protocol:     proto,
			RemoteCidr:   cidr,
			PortRange:    portStr,
			PortEndpoint: DestPort,
		}
		fwRules.IngressRules = append(fwRules.IngressRules, fwRuleDest)
	}
	return &fwRules, nil
}

func persistIptablesRules(ctx context.Context, client ssh.Client) error {
	cmd := fmt.Sprintf("sudo bash -c 'iptables-save > /etc/iptables/rules.v4'")
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("unable to run iptables-save to persistent rules file: %s - %v", out, err)
	}
	return nil
}

// setupForwardingIptables creates iptables rules to allow the cluster nodes to use the LB as a
// router for internet access
func (v *VMPlatform) setupForwardingIptables(ctx context.Context, client ssh.Client, externalIfname, internalIfname string, action *InterfaceActionsOp) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "setupForwardingIptables", "externalIfname", externalIfname, "internalIfname", internalIfname, "action", fmt.Sprintf("%+v", action))
	// get current iptables
	cmd := fmt.Sprintf("sudo iptables-save|grep -e POSTROUTING -e FORWARD")
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("unable to run iptables-save: %s - %v", out, err)
	}
	// add or remove rules based on the action
	option := "-A"
	if action.deleteIptables {
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
	if action.createIptables {
		// this rule is never deleted because it applies to all subnets.   Multiple adds will
		// not create duplicates
		err = doIptablesCommand(ctx, client, masqueradeRule, masqueradeRuleExists, action)
		if err != nil {
			return err
		}
	}
	// only add forwarding-permits rules if iptables is not used for firewalls
	if !v.VMProperties.IptablesBasedFirewall {
		err = doIptablesCommand(ctx, client, forwardExternalRule, forwardExternalRuleExists, action)
		if err != nil {
			return err
		}
		err = doIptablesCommand(ctx, client, forwardInternalRule, forwardInternalRuleExists, action)
		if err != nil {
			return err
		}
	}
	//now persist the rules
	err = persistIptablesRules(ctx, client)
	if err != nil {
		return err
	}
	return nil
}

// AddIngressIptablesRules adds rules using a CIDR and AppPorts as input
func AddIngressIptablesRules(ctx context.Context, client ssh.Client, label string, cidr string, ports []dme.AppPort) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddIngressIptablesRules", "label", label, "cidr", cidr, "ports", ports)

	fwRules, err := getFirewallRulesFromAppPorts(ctx, cidr, ports)
	if err != nil {
		return err
	}
	return addIptablesRules(ctx, client, label, fwRules)
}

// RemoveIngressIptablesRules removes rules using a CIDR and AppPorts as input
func RemoveIngressIptablesRules(ctx context.Context, client ssh.Client, label string, cidr string, ports []dme.AppPort) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "RemoveIngressIptablesRules", "secGrp", label)

	fwRules, err := getFirewallRulesFromAppPorts(ctx, cidr, ports)
	if err != nil {
		return err
	}
	return deleteIptablesRules(ctx, client, label, fwRules)
}

func (v *VMProperties) SetupIptablesRulesForRootLB(ctx context.Context, client ssh.Client, sshCidrsAllowed []string, privacyPolicy *edgeproto.PrivacyPolicy) error {

	var netRules FirewallRules
	var ppRules FirewallRules

	//First create the global rules on this LB
	log.SpanLog(ctx, log.DebugLevelInfra, "creating cloudlet-wide rules")
	err := v.createCloudletFirewallRules(ctx, client)
	if err != nil {
		return err
	}

	// Allow SSH from provided cidrs
	for _, netCidr := range sshCidrsAllowed {
		sshIngress := FirewallRule{
			Protocol:     "tcp",
			RemoteCidr:   netCidr,
			PortRange:    "22",
			PortEndpoint: DestPort,
		}
		netRules.IngressRules = append(netRules.IngressRules, sshIngress)
	}

	// all traffic between the internal networks is allowed
	internalRoute, err := v.GetInternalNetworkRoute(ctx)
	if err != nil {
		return err
	}
	internalNetInRule := FirewallRule{
		RemoteCidr: internalRoute,
	}
	netRules.IngressRules = append(netRules.IngressRules, internalNetInRule)

	internalNetOutRule := FirewallRule{
		RemoteCidr: internalRoute,
	}
	netRules.EgressRules = append(netRules.EgressRules, internalNetOutRule)
	err = addIptablesRules(ctx, client, "rootlb-networking", &netRules)
	if err != nil {
		return err
	}

	// optionally add Privacy Policy
	allowEgressAll := false
	if privacyPolicy != nil {
		if len(privacyPolicy.OutboundSecurityRules) == 0 {
			// a privacy policy with no rules means we need to open all egress traffic
			allowEgressAll = true
		}
		for _, p := range privacyPolicy.OutboundSecurityRules {
			allowEgressAll = false
			portRange := fmt.Sprintf("%d", p.PortRangeMin)
			if p.PortRangeMax != 0 {
				portRange += fmt.Sprintf(":%d", p.PortRangeMax)
			}
			egressRule := FirewallRule{
				Protocol:     p.Protocol,
				PortRange:    portRange,
				RemoteCidr:   p.RemoteCidr,
				PortEndpoint: DestPort,
			}
			ppRules.EgressRules = append(ppRules.EgressRules, egressRule)
		}
	}
	if allowEgressAll {
		allowAllEgressRule := FirewallRule{
			RemoteCidr: "0.0.0.0/0",
		}
		ppRules.EgressRules = append(ppRules.EgressRules, allowAllEgressRule)
	}
	err = addIptablesRules(ctx, client, "privacy-policy", &ppRules)
	if err != nil {
		return err
	}
	return addDefaultIptablesRules(ctx, client)
}
