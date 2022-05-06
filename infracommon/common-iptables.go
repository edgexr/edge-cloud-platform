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

package infracommon

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"

	dme "github.com/edgexr/edge-cloud/d-match-engine/dme-proto"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

type FirewallRules struct {
	EgressRules  []FirewallRule
	IngressRules []FirewallRule
}

type InterfaceActionsOp struct {
	AddInterface    bool
	DeleteInterface bool
	CreateIptables  bool
	DeleteIptables  bool
}

// PortSourceOrDestChoice indicates whether the port(s) are the source or destination ports
type PortSourceOrDestChoice string

const SourcePort PortSourceOrDestChoice = "sport"
const DestPort PortSourceOrDestChoice = "dport"

const TrustPolicySecGrpNameLabel string = "trust-policy"

type FirewallRule struct {
	Protocol     string
	RemoteCidr   string
	PortRange    string
	InterfaceIn  string
	InterfaceOut string
	PortEndpoint PortSourceOrDestChoice
	Conntrack    string
	DestIP       string
}

// DoIptablesCommand runs an iptables add or delete conditionally based on whether the entry already exists or not
func DoIptablesCommand(ctx context.Context, client ssh.Client, rule string, ruleExists bool, action *InterfaceActionsOp) error {
	runCommand := false
	if ruleExists {
		if action.DeleteIptables {
			log.SpanLog(ctx, log.DebugLevelInfra, "deleting existing iptables rule", "rule", rule)
			runCommand = true
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "do not re-add existing iptables rule", "rule", rule)
		}
	} else {
		if action.CreateIptables {
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
			key = strings.TrimSpace(key)

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

// getIpTablesEntryForRule gets the iptables string for the rule
func getIpTablesEntriesForRule(ctx context.Context, direction string, label string, rule *FirewallRule) []string {
	log.SpanLog(ctx, log.DebugLevelInfra, "getIpTablesEntriesForRule", "rule", rule)
	cidrStr := ""
	var chains []string
	var rules []string
	ranges := strings.Split(rule.PortRange, ":")
	if len(ranges) == 2 {
		if ranges[0] == ranges[1] {
			// start and end port range are the same, collapse into one port
			rule.PortRange = ranges[0]
		}
	}
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
	protostr := ""
	if rule.Protocol != "" {
		rule.Protocol = strings.ToLower(rule.Protocol)
		protostr = fmt.Sprintf("-p %s -m %s", rule.Protocol, rule.Protocol)
	}
	icmpType := ""
	if rule.Protocol == "icmp" {
		icmpType = " --icmp-type any"
	}
	ifstr := ""
	if rule.InterfaceIn != "" {
		ifstr = "-i " + string(rule.InterfaceIn)
	} else if rule.InterfaceOut != "" {
		ifstr = "-o " + string(rule.InterfaceOut)
	}
	destStr := ""
	if rule.DestIP != "" {
		destStr = "-d " + rule.DestIP + "/32"
	}
	conntrackStr := ""
	if rule.Conntrack != "" {
		conntrackStr = "-m conntrack --ctstate " + rule.Conntrack
	}
	for _, chain := range chains {
		rulestr := fmt.Sprintf("%s %s %s %s %s %s %s %s -m comment --comment \"label %s\" -j ACCEPT", chain, ifstr, destStr, conntrackStr, cidrStr, protostr, icmpType, portStr, label)
		// remove double spaces
		rulestr = strings.Join(strings.Fields(rulestr), " ")
		rules = append(rules, rulestr)
	}
	return rules
}

func (c *CommonPlatform) DeleteIptableRulesForCloudletWideLabel(ctx context.Context, client ssh.Client) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteIptableRulesForCloudletWideLabel")
	return RemoveRulesForLabel(ctx, client, "cloudlet-wide")
}

// DeleteCloudletFirewallRules deletes cloudlet-wide rules based on properties
func (c *CommonPlatform) DeleteCloudletFirewallRules(ctx context.Context, client ssh.Client) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteCloudletFirewallRules")

	var firewallRules FirewallRules
	var err error
	if val, ok := c.Properties.GetValue("MEX_CLOUDLET_FIREWALL_WHITELIST_EGRESS"); ok {
		firewallRules.EgressRules, err = parseFirewallRules(ctx, val)
		if err != nil {
			return err
		}
	}
	if val, ok := c.Properties.GetValue("MEX_CLOUDLET_FIREWALL_WHITELIST_INGRESS"); ok {
		firewallRules.IngressRules, err = parseFirewallRules(ctx, val)
		if err != nil {
			return err
		}
	}
	return DeleteIptablesRules(ctx, client, "cloudlet-wide", &firewallRules)
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
		if label == "" {
			if strings.HasPrefix(line, "-A") {
				rules[line] = line
			}
		} else if strings.Contains(line, "\"label "+label+"\"") && strings.HasPrefix(line, "-A") {
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
		// we insert into the chain, but when searching, match -A
		addCmd := "-I " + entry
		findCmd := "-A " + entry
		_, exists := currentRules[findCmd]
		action := InterfaceActionsOp{CreateIptables: true}
		err := DoIptablesCommand(ctx, client, addCmd, exists, &action)
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
		findCmd := "-A " + entry
		delCmd := "-D " + entry
		_, exists := currentRules[findCmd]
		action := InterfaceActionsOp{DeleteIptables: true}
		err := DoIptablesCommand(ctx, client, delCmd, exists, &action)
		if err != nil {
			return err
		}
	}
	return nil
}

// AddIptablesRules adds a set of rules
func AddIptablesRules(ctx context.Context, client ssh.Client, label string, rules *FirewallRules) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddIptablesRules", "rules", rules)
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
	return PersistIptablesRules(ctx, client)
}

// DeleteIptablesRules deletes a set of rules
func DeleteIptablesRules(ctx context.Context, client ssh.Client, label string, rules *FirewallRules) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteIptablesRules", "rules", rules)
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
	return PersistIptablesRules(ctx, client)
}

// AddDefaultIptablesRules adds the default set of rules which are always needed
func AddDefaultIptablesRules(ctx context.Context, client ssh.Client) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddDefaultIptablesRules")

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
		Conntrack:  "RELATED,ESTABLISHED",
	}
	rules.IngressRules = append(rules.IngressRules, conntrackInRule)
	conntrackOutRule := FirewallRule{
		RemoteCidr: "0.0.0.0/0",
		Conntrack:  "RELATED,ESTABLISHED",
	}
	rules.EgressRules = append(rules.EgressRules, conntrackOutRule)

	err := AddIptablesRules(ctx, client, "default-rules", &rules)
	if err != nil {
		return err
	}

	// anything not matching the chain is dropped.   These will not create
	// duplicate entries if done multiple times
	dropInputPolicy := "-P INPUT DROP"
	dropOutputPolicy := "-P OUTPUT DROP"
	action := InterfaceActionsOp{CreateIptables: true}
	err = DoIptablesCommand(ctx, client, dropInputPolicy, false, &action)
	if err != nil {
		return err
	}
	return DoIptablesCommand(ctx, client, dropOutputPolicy, false, &action)
}

// GetFirewallRulesFromAppPorts accepts a CIDR and a set of AppPorts and converts to a set of rules
func GetFirewallRulesFromAppPorts(ctx context.Context, cidr string, destIp string, ports []dme.AppPort) (*FirewallRules, error) {
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
			DestIP:       destIp,
		}
		fwRules.IngressRules = append(fwRules.IngressRules, fwRuleDest)
	}
	return &fwRules, nil
}

func PersistIptablesRules(ctx context.Context, client ssh.Client) error {
	cmd := fmt.Sprintf("sudo bash -c 'iptables-save > /etc/iptables/rules.v4'")
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("unable to run iptables-save to persistent rules file: %s - %v", out, err)
	}
	return nil
}

// AddIngressIptablesRules adds rules using a CIDR and AppPorts as input
func AddIngressIptablesRules(ctx context.Context, client ssh.Client, label, cidr, destIp string, ports []dme.AppPort) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddIngressIptablesRules", "label", label, "cidr", cidr, "ports", ports)

	fwRules, err := GetFirewallRulesFromAppPorts(ctx, cidr, destIp, ports)
	if err != nil {
		return err
	}
	return AddIptablesRules(ctx, client, label, fwRules)
}

// RemoveIngressIptablesRules removes rules using a CIDR and AppPorts as input
func RemoveIngressIptablesRules(ctx context.Context, client ssh.Client, label, cidr, destIP string, ports []dme.AppPort) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "RemoveIngressIptablesRules", "secGrp", label)

	fwRules, err := GetFirewallRulesFromAppPorts(ctx, cidr, destIP, ports)
	if err != nil {
		return err
	}
	return DeleteIptablesRules(ctx, client, label, fwRules)
}

func RemoveRulesForLabel(ctx context.Context, client ssh.Client, label string) error {

	log.SpanLog(ctx, log.DebugLevelInfra, "RemoveRulesForLabel", "label", label)

	currentRules, err := getCurrentIptableRulesForLabel(ctx, client, label)

	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "RemoveRulesForLabel getCurrentIptableRulesForLabel failed", "err", err)
		return err
	}
	if len(currentRules) == 0 {
		log.SpanLog(ctx, log.DebugLevelInfra, "RemoveRulesForLabel no rules for", "label", label)
		return nil
	}
	action := InterfaceActionsOp{DeleteIptables: true}
	for _, rule := range currentRules {
		delCmd := strings.Replace(rule, "-A", "-D", 1)
		log.SpanLog(ctx, log.DebugLevelInfra, "RemoveRulesForLabel doIpTblsCmd", "delCmd", delCmd)
		err := DoIptablesCommand(ctx, client, delCmd, true, &action)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "error deleting rule, continuing", "rule", rule, "error", err)
			continue // fail one fail all?
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "removed", "rule", rule)
		}
	}
	return nil
}
