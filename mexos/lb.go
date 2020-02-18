package mexos

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

var udevRulesFile = "/etc/udev/rules.d/70-persistent-net.rules"

var actionAdd string = "ADD"
var actionDelete string = "DELETE"

// LBAddRouteAndSecRules adds an external route and sec rules
func LBAddRouteAndSecRules(ctx context.Context, client ssh.Client, rootLBName string) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "Adding route to reach internal networks", "rootLBName", rootLBName)

	ni, err := ParseNetSpec(ctx, GetCloudletNetworkScheme())
	if err != nil {
		return err
	}
	if ni.FloatingIPNet != "" {
		// For now we do nothing when we have a floating IP because it means we are using the
		// openstack router to get everywhere anyway.
		log.SpanLog(ctx, log.DebugLevelMexos, "No route changes needed due to floating IP")
		return nil
	}
	if rootLBName == "" {
		return fmt.Errorf("empty rootLB")
	}

	//TODO: this may not be necessary, as instead we can allow group to remote group rules
	// add to the /16 range for all the possible subnets
	subnet := fmt.Sprintf("%s.%s.0.0/16", ni.Octets[0], ni.Octets[1])
	subnetNomask := fmt.Sprintf("%s.%s.0.0", ni.Octets[0], ni.Octets[1])
	mask := "255.255.0.0"

	rtr := GetCloudletExternalRouter()
	gatewayIP := ni.RouterGatewayIP
	if gatewayIP == "" && rtr != NoConfigExternalRouter && rtr != NoExternalRouter {
		rd, err := GetRouterDetail(ctx, GetCloudletExternalRouter())
		if err != nil {
			return err
		}
		gw, err := GetRouterDetailExternalGateway(rd)
		if err != nil {
			return err
		}
		fip := gw.ExternalFixedIPs
		log.SpanLog(ctx, log.DebugLevelMexos, "external fixed ips", "ips", fip)

		if len(fip) != 1 {
			return fmt.Errorf("Unexpected fixed ips for mex router %v", fip)
		}
		gatewayIP = fip[0].IPAddress
	}
	if gatewayIP != "" {
		cmd := fmt.Sprintf("sudo ip route add %s via %s", subnet, gatewayIP)
		if err != nil {
			return err
		}

		out, err := client.Output(cmd)
		if err != nil {
			if strings.Contains(out, "RTNETLINK") && strings.Contains(out, " exists") {
				log.SpanLog(ctx, log.DebugLevelMexos, "warning, can't add existing route to rootLB", "cmd", cmd, "out", out, "error", err)
			} else {
				return fmt.Errorf("can't add route to rootlb, %s, %s, %v", cmd, out, err)
			}
		}

		// make the route persist by adding the following line if not already present via grep.
		routeAddLine := fmt.Sprintf("up route add -net %s netmask %s gw %s", subnetNomask, mask, gatewayIP)
		interfacesFile := GetCloudletNetworkIfaceFile()
		cmd = fmt.Sprintf("grep -l '%s' %s", routeAddLine, interfacesFile)
		out, err = client.Output(cmd)
		if err != nil {
			// grep failed so not there already
			log.SpanLog(ctx, log.DebugLevelMexos, "adding route to interfaces file", "route", routeAddLine, "file", interfacesFile)
			cmd = fmt.Sprintf("echo '%s'|sudo tee -a %s", routeAddLine, interfacesFile)
			out, err = client.Output(cmd)
			if err != nil {
				return fmt.Errorf("can't add route to interfaces file: %v", err)
			}
		} else {
			log.SpanLog(ctx, log.DebugLevelMexos, "route already present in interfaces file")
		}
	}

	// open the firewall for internal traffic
	groupName := GetSecurityGroupName(ctx, rootLBName)

	allowedClientCIDR := GetAllowedClientCIDR()
	for _, p := range rootLBPorts {
		portString := fmt.Sprintf("%d", p)
		if err := AddSecurityRuleCIDRWithRetry(ctx, allowedClientCIDR, "tcp", groupName, portString, rootLBName); err != nil {
			return err
		}
	}
	return nil
}

// creates entries in the 70-persistent-net.rules files to ensure the interface names are consistent after reboot
func persistInterfaceName(ctx context.Context, client ssh.Client, ifName, mac, action string) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "persistInterfaceName", "ifName", ifName, "mac", mac)
	cmd := fmt.Sprintf("sudo cat %s", udevRulesFile)
	newFileContents := ""

	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("unable to cat udev rules file: %s - %v", out, err)
	}

	lines := strings.Split(out, "\n")
	for _, l := range lines {
		// if the mac is already there remove it, it will be appended later
		if strings.Contains(l, mac) {
			log.SpanLog(ctx, log.DebugLevelMexos, "found existing rule for mac", "line", l)
		} else {
			newFileContents = newFileContents + l + "\n"
		}
	}
	newRule := fmt.Sprintf("SUBSYSTEM==\"net\", ACTION==\"add\", DRIVERS==\"?*\", ATTR{address}==\"%s\", NAME=\"%s\"", mac, ifName)
	if action == actionAdd {
		newFileContents = newFileContents + newRule + "\n"
	}
	return pc.WriteFile(client, udevRulesFile, newFileContents, "udev-rules", pc.SudoOn)
}

// run an iptables add or delete conditionally based on whether the entry already exists or not
func doIptablesCommand(ctx context.Context, client ssh.Client, rule string, ruleExists bool, action string) error {
	runCommand := false
	if ruleExists {
		if action == actionDelete {
			log.SpanLog(ctx, log.DebugLevelMexos, "deleting existing iptables rule", "rule", rule)
			runCommand = true
		} else {
			log.SpanLog(ctx, log.DebugLevelMexos, "do not re-add existing iptables rule", "rule", rule)
		}
	} else {
		if action == actionAdd {
			log.SpanLog(ctx, log.DebugLevelMexos, "adding new iptables rule", "rule", rule)
			runCommand = true
		} else {
			log.SpanLog(ctx, log.DebugLevelMexos, "do not delete nonexistent iptables rule", "rule", rule)
		}
	}

	if runCommand {
		cmd := fmt.Sprintf("sudo iptables %s", rule)
		out, err := client.Output(cmd)
		if err != nil {
			return fmt.Errorf("unable to modify iptables rule: %s, %s - %v", rule, out, err)
		}
	}
	return nil
}

// setupForwardingIptables creates iptables rules to allow the cluster nodes to use the LB as a
// router for internet access
func setupForwardingIptables(ctx context.Context, client ssh.Client, externalIfname, internalIfname, action string) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "setupForwardingIptables", "externalIfname", externalIfname, "internalIfname", internalIfname)
	// get current iptables
	cmd := fmt.Sprintf("sudo iptables-save|grep -e POSTROUTING -e FORWARD")
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("unable to run iptables-save: %s - %v", out, err)
	}
	// add or remove rules based on the action
	option := "-A"
	if action == actionDelete {
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
	if action == actionAdd {
		// this rule is never deleted because it applies to all subnets.   Multiple adds will
		// not create duplicates
		err = doIptablesCommand(ctx, client, masqueradeRule, masqueradeRuleExists, action)
		if err != nil {
			return err
		}
	}
	err = doIptablesCommand(ctx, client, forwardExternalRule, forwardExternalRuleExists, action)
	if err != nil {
		return err
	}
	err = doIptablesCommand(ctx, client, forwardInternalRule, forwardInternalRuleExists, action)
	if err != nil {
		return err
	}
	//now persist the rules
	cmd = fmt.Sprintf("sudo bash -c 'iptables-save > /etc/iptables/rules.v4'")
	out, err = client.Output(cmd)
	if err != nil {
		return fmt.Errorf("unable to run iptables-save to persistent rules file: %s - %v", out, err)
	}
	return nil
}

// configureInternalInterfaceAndExternalForwarding sets up the new internal interface and then creates iptables rules to forward
// traffic out the external interface
func configureInternalInterfaceAndExternalForwarding(ctx context.Context, client ssh.Client, externalIPAddr, internalPortName, internalIPAddr string, action string) error {

	log.SpanLog(ctx, log.DebugLevelMexos, "configureInternalInterfaceAndExternalForwarding", "externalIPAddr", externalIPAddr, "internalPortName", internalPortName, "internalIPAddr", internalIPAddr)

	// list the ports so we can find the internal and external port macs
	ports, err := ListPorts(ctx)
	if err != nil {
		return err
	}
	internalPortMac := ""
	externalPortMac := ""
	for _, p := range ports {
		if strings.Contains(p.FixedIPs, "'"+internalIPAddr+"'") {
			internalPortMac = p.MACAddress
		} else if strings.Contains(p.FixedIPs, "'"+externalIPAddr+"'") {
			externalPortMac = p.MACAddress
		}
	}
	log.SpanLog(ctx, log.DebugLevelMexos, "running ifconfig to list interfaces")
	// list all the interfaces
	cmd := fmt.Sprintf("sudo ifconfig -a")
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("unable to run ifconfig: %s - %v", out, err)
	}
	//                ifname        encap              mac
	matchPattern := "(\\w+)\\s+Link \\S+\\s+HWaddr\\s+(\\S+)"
	reg, err := regexp.Compile(matchPattern)
	if err != nil {
		// this is a bug if the regex does not compile
		log.SpanLog(ctx, log.DebugLevelMexos, "failed to compile regex", "pattern", matchPattern)
		return fmt.Errorf("Internal Error compiling regex for interface")
	}

	//find the interfaces matching our macs
	externalIfname := ""
	internalIfname := ""
	lines := strings.Split(out, "\n")
	for _, l := range lines {
		if reg.MatchString(l) {
			matches := reg.FindStringSubmatch(l)
			ifn := matches[1]
			mac := matches[2]
			log.SpanLog(ctx, log.DebugLevelMexos, "found interface", "ifn", ifn, "mac", mac)
			if mac == externalPortMac {
				externalIfname = ifn
			}
			if mac == internalPortMac {
				internalIfname = ifn
			}
		}
	}
	if externalIfname == "" {
		log.SpanLog(ctx, log.DebugLevelMexos, "unable to find external interface via MAC", "mac", externalPortMac)
		if action == actionAdd {
			return fmt.Errorf("unable to find interface for external port mac: %s", externalPortMac)
		}
		// keep going on delete
	}
	if internalIfname == "" {
		log.SpanLog(ctx, log.DebugLevelMexos, "unable to find internal interface via MAC", "mac", internalPortMac)
		if action == actionAdd {
			return fmt.Errorf("unable to find interface for internal port mac: %s", internalPortMac)
		}
		// keep going on delete
	}

	filename := "/etc/network/interfaces.d/" + internalPortName + ".cfg"
	contents := fmt.Sprintf("auto %s\niface %s inet static\n   address %s/24", internalIfname, internalIfname, internalIPAddr)

	if action == actionAdd {
		err = pc.WriteFile(client, filename, contents, "ifconfig", pc.SudoOn)
		// now create the file
		if err != nil {
			return fmt.Errorf("unable to write interface config file: %s -- %v", filename, err)
		}
		// now bring the new internal interface up.
		cmd = fmt.Sprintf("sudo ifdown --force %s;sudo ifup %s", internalIfname, internalIfname)
		log.SpanLog(ctx, log.DebugLevelMexos, "bringing up interface", "internalIfname", internalIfname, "cmd", cmd)
		out, err = client.Output(cmd)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelMexos, "unable to run ifup", "out", out, "err", err)
			return fmt.Errorf("unable to run ifup: %s - %v", out, err)
		}
	} else {
		cmd := fmt.Sprintf("sudo rm %s", filename)
		out, err := client.Output(cmd)
		if err != nil {
			if strings.Contains(err.Error(), "No such file") {
				log.SpanLog(ctx, log.DebugLevelMexos, "file already gone", "filename", filename)
			} else {
				return fmt.Errorf("Unexpected error removing interface file %s, %s -- %v", filename, out, err)
			}
		}
	}
	// we can get here on some error cases in which the ifname were not found
	if internalIfname != "" {
		err = persistInterfaceName(ctx, client, internalIfname, internalPortMac, action)
		if err != nil {
			return nil
		}
		if externalIfname != "" {
			err = setupForwardingIptables(ctx, client, externalIfname, internalIfname, action)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelMexos, "setupForwardingIptables failed", "err", err)
			}
		}
	}

	return err
}

// AttachAndEnableRootLBInterface attaches the interface and enables it in the OS
func AttachAndEnableRootLBInterface(ctx context.Context, client ssh.Client, rootLBName string, internalPortName, internalIPAddr string) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "AttachAndEnableRootLBInterface", "rootLBName", rootLBName, "internalPortName", internalPortName)

	err := AttachPortToServer(ctx, rootLBName, internalPortName)
	if err != nil {
		return err
	}
	rootLbIp, err := GetServerIPAddr(ctx, GetCloudletExternalNetwork(), rootLBName, InternalIPType)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelMexos, "fail to get RootLB IP address", "rootLBName", rootLBName)

		deterr := DetachPortFromServer(ctx, rootLBName, internalPortName)
		if deterr != nil {
			log.SpanLog(ctx, log.DebugLevelMexos, "fail to detach port", "err", deterr)
		}
		return err
	}

	err = configureInternalInterfaceAndExternalForwarding(ctx, client, rootLbIp, internalPortName, internalIPAddr, actionAdd)
	if err != nil {
		deterr := DetachPortFromServer(ctx, rootLBName, internalPortName)
		if deterr != nil {
			log.SpanLog(ctx, log.DebugLevelMexos, "fail to detach port", "err", deterr)
		}
		return err
	}
	return nil
}

// DetachAndDisableRootLBInterface performs some cleanup when deleting the rootLB port.
func DetachAndDisableRootLBInterface(ctx context.Context, client ssh.Client, rootLBName string, internalPortName, internalIPAddr string) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "DetachAndDisableRootLBInterface", "rootLBName", rootLBName, "internalPortName", internalPortName)
	rootLB, err := getRootLB(ctx, rootLBName)
	if err != nil {
		// this is unexpected
		return fmt.Errorf("Cannot find rootLB %s", rootLBName)
	}
	err = configureInternalInterfaceAndExternalForwarding(ctx, client, rootLB.IP, internalPortName, internalIPAddr, actionDelete)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelMexos, "error in configureInternalInterfaceAndExternalForwarding", "err", err)
	}
	err = DetachPortFromServer(ctx, rootLBName, internalPortName)
	if err != nil {
		// might already be gone
		log.SpanLog(ctx, log.DebugLevelMexos, "fail to detach port", "err", err)
	}
	return err
}
