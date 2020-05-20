package vmlayer

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"

	valid "github.com/asaskevich/govalidator"
	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/proxy"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	dme "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vmspec"

	ssh "github.com/mobiledgex/golang-ssh"
)

// InternalPortAttachPolicy is for dedicated clusters to define whether the internal port should be created when the rootlb
// is spun up, or afterwards.
type InternalPortAttachPolicy string

const AttachPortDuringCreate InternalPortAttachPolicy = "AttachPortDuringCreate"
const AttachPortAfterCreate InternalPortAttachPolicy = "AttachPortAfterCreate"

var udevRulesFile = "/etc/udev/rules.d/70-persistent-net.rules"

type InterfaceActionsOp struct {
	addInterface    bool
	deleteInterface bool
	createIptables  bool
	deleteIptables  bool
}

var RootLBPorts = []dme.AppPort{{
	PublicPort: cloudcommon.RootLBL7Port,
	Proto:      dme.LProto_L_PROTO_TCP,
}}

// creates entries in the 70-persistent-net.rules files to ensure the interface names are consistent after reboot
func persistInterfaceName(ctx context.Context, client ssh.Client, ifName, mac string, action *InterfaceActionsOp) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "persistInterfaceName", "ifName", ifName, "mac", mac)
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
			log.SpanLog(ctx, log.DebugLevelInfra, "found existing rule for mac", "line", l)
		} else {
			newFileContents = newFileContents + l + "\n"
		}
	}
	newRule := fmt.Sprintf("SUBSYSTEM==\"net\", ACTION==\"add\", DRIVERS==\"?*\", ATTR{address}==\"%s\", NAME=\"%s\"", mac, ifName)
	if action.addInterface {
		newFileContents = newFileContents + newRule + "\n"
	}
	return pc.WriteFile(client, udevRulesFile, newFileContents, "udev-rules", pc.SudoOn)
}

// run an iptables add or delete conditionally based on whether the entry already exists or not
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
func setupForwardingIptables(ctx context.Context, client ssh.Client, externalIfname, internalIfname string, action *InterfaceActionsOp) error {
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
func (v *VMPlatform) configureInternalInterfaceAndExternalForwarding(ctx context.Context, client ssh.Client, subnetName, internalPortName string, serverDetails *ServerDetail, action *InterfaceActionsOp) error {

	log.SpanLog(ctx, log.DebugLevelInfra, "configureInternalInterfaceAndExternalForwarding", "serverDetails", serverDetails, "internalPortName", internalPortName, "action", fmt.Sprintf("%+v", action))

	internalIP, err := GetIPFromServerDetails(ctx, "", internalPortName, serverDetails)
	if err != nil {
		return err
	}
	externalIP, err := GetIPFromServerDetails(ctx, v.VMProperties.GetCloudletExternalNetwork(), "", serverDetails)
	if err != nil {
		return err
	}

	err = WaitServerSSHReachable(ctx, client, externalIP.ExternalAddr, time.Minute*1)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "server not reachable", "err", err)
		return err
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "running ifconfig to list interfaces")
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
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to compile regex", "pattern", matchPattern)
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
			log.SpanLog(ctx, log.DebugLevelInfra, "found interface", "ifn", ifn, "mac", mac)
			if mac == externalIP.MacAddress {
				externalIfname = ifn
			}
			if mac == internalIP.MacAddress {
				internalIfname = ifn
			}
		}
	}
	if externalIfname == "" {
		log.SpanLog(ctx, log.DebugLevelInfra, "unable to find external interface via MAC", "mac", externalIP.MacAddress)
		if action.addInterface {
			return fmt.Errorf("unable to find interface for external port mac: %s", externalIP.MacAddress)
		}
		// keep going on delete
	}
	if internalIfname == "" {
		log.SpanLog(ctx, log.DebugLevelInfra, "unable to find internal interface via MAC", "mac", internalIP.MacAddress)
		if action.addInterface {
			return fmt.Errorf("unable to find interface for internal port mac: %s", internalIP.MacAddress)
		}
		// keep going on delete
	}
	filename := "/etc/network/interfaces.d/" + internalPortName + ".cfg"
	contents := fmt.Sprintf("auto %s\niface %s inet static\n   address %s/24", internalIfname, internalIfname, internalIP.InternalAddr)

	if action.addInterface {
		// cleanup any interfaces files that may be sitting around with our new interface, perhaps from some old failure
		cmd := fmt.Sprintf("grep -l ' %s ' /etc/network/interfaces.d/*-port.cfg", internalIfname)
		out, err = client.Output(cmd)
		log.SpanLog(ctx, log.DebugLevelInfra, "cleanup old interface files with interface", "internalIfname", internalIfname, "out", out, "err", err)
		if err == nil {
			files := strings.Split(out, "\n")
			for _, f := range files {
				log.SpanLog(ctx, log.DebugLevelInfra, "cleanup old interfaces file", "file", f)
				cmd := fmt.Sprintf("sudo rm -f %s", f)
				out, err := client.Output(cmd)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "unable to delete file", "file", f, "out", out, "err", err)
				}
			}
		}

		err = pc.WriteFile(client, filename, contents, "ifconfig", pc.SudoOn)
		// now create the file
		if err != nil {
			return fmt.Errorf("unable to write interface config file: %s -- %v", filename, err)
		}

		// in some OS the interfaces file may not refer to interfaces.d
		ifFile := "/etc/network/interfaces"
		cmd = fmt.Sprintf("grep -l interfaces.d %s", ifFile)
		out, err = client.Output(cmd)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "adding source line to interfaces file")
			cmd = fmt.Sprintf("echo '%s'|sudo tee -a %s", "source /etc/network/interfaces.d/*-port.cfg", ifFile)
			out, err = client.Output(cmd)
			if err != nil {
				return fmt.Errorf("can't add source reference to interfaces file: %v", err)
			}
		}

		// now bring the new internal interface up.
		cmd = fmt.Sprintf("sudo ifdown --force %s;sudo ifup %s", internalIfname, internalIfname)
		log.SpanLog(ctx, log.DebugLevelInfra, "bringing up interface", "internalIfname", internalIfname, "cmd", cmd)
		out, err = client.Output(cmd)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "unable to run ifup", "out", out, "err", err)
			return fmt.Errorf("unable to run ifup: %s - %v", out, err)
		}
	} else if action.deleteInterface {
		cmd := fmt.Sprintf("sudo rm %s", filename)
		out, err := client.Output(cmd)
		if err != nil {
			if strings.Contains(err.Error(), "No such file") {
				log.SpanLog(ctx, log.DebugLevelInfra, "file already gone", "filename", filename)
			} else {
				return fmt.Errorf("Unexpected error removing interface file %s, %s -- %v", filename, out, err)
			}
		}
	}
	// we can get here on some error cases in which the ifname were not found
	if internalIfname != "" {
		if action.addInterface || action.deleteInterface {
			err = persistInterfaceName(ctx, client, internalIfname, internalIP.MacAddress, action)
			if err != nil {
				return nil
			}
		}
		if action.createIptables || action.deleteIptables {
			if externalIfname != "" {
				err = setupForwardingIptables(ctx, client, externalIfname, internalIfname, action)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "setupForwardingIptables failed", "err", err)
				}
			}
		}
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "persistInterfaceName and setupForwardingIptables skipped due to empty internalIfName")
	}
	return err
}

// AttachAndEnableRootLBInterface attaches the interface and enables it in the OS
func (v *VMPlatform) AttachAndEnableRootLBInterface(ctx context.Context, client ssh.Client, rootLBName string, attachPort bool, subnetName, internalPortName, internalIPAddr string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "AttachAndEnableRootLBInterface", "rootLBName", rootLBName, "attachPort", attachPort, "subnetName", subnetName, "internalPortName", internalPortName)

	var action InterfaceActionsOp
	action.createIptables = true
	if attachPort {
		action.addInterface = true
		err := v.VMProvider.AttachPortToServer(ctx, rootLBName, subnetName, internalPortName, internalIPAddr, ActionCreate)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "fail to attach port", "err", err)
			return err
		}
	}
	sd, err := v.VMProvider.GetServerDetail(ctx, rootLBName)
	if err != nil {
		return err
	}
	err = v.configureInternalInterfaceAndExternalForwarding(ctx, client, subnetName, internalPortName, sd, &action)
	if err != nil {
		if attachPort {
			log.SpanLog(ctx, log.DebugLevelInfra, "fail to confgure internal interface, detaching port", "err", err)
			deterr := v.VMProvider.DetachPortFromServer(ctx, rootLBName, subnetName, internalPortName)
			if deterr != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "fail to detach port", "err", deterr)
			}
		}
		return err
	}
	return nil
}

func (v *VMPlatform) GetRootLBName(key *edgeproto.CloudletKey) string {
	name := cloudcommon.GetRootLBFQDN(key)
	return v.VMProvider.NameSanitize(name)
}

// DetachAndDisableRootLBInterface performs some cleanup when deleting the rootLB port.
func (v *VMPlatform) DetachAndDisableRootLBInterface(ctx context.Context, client ssh.Client, rootLBName string, detachPort bool, subnetName, internalPortName, internalIPAddr string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DetachAndDisableRootLBInterface", "rootLBName", rootLBName, "subnetName", subnetName, "internalPortName", internalPortName)

	var action InterfaceActionsOp
	action.deleteIptables = true
	if detachPort {
		action.deleteInterface = true
	}
	sd, err := v.VMProvider.GetServerDetail(ctx, rootLBName)
	if err != nil {
		return err
	}

	err = v.configureInternalInterfaceAndExternalForwarding(ctx, client, subnetName, internalPortName, sd, &action)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "error in configureInternalInterfaceAndExternalForwarding", "err", err)
	}
	if detachPort {
		err = v.VMProvider.DetachPortFromServer(ctx, rootLBName, subnetName, internalPortName)
		if err != nil {
			// might already be gone
			log.SpanLog(ctx, log.DebugLevelInfra, "fail to detach port", "err", err)
		}
	}
	return err
}

//MEXRootLB has rootLB data
type MEXRootLB struct {
	Name string
	IP   *ServerIP
}

var rootLBLock sync.Mutex
var MaxRootLBWait = 5 * time.Minute

var MEXRootLBMap = make(map[string]*MEXRootLB)

// GetVMSpecForRootLB gets the VM spec for the rootLB when it is not specified within a cluster. This is
// used for Shared RootLb and for VM app based RootLb
func (v *VMPlatform) GetVMSpecForRootLB(ctx context.Context, rootLbName string, subnetConnect string, updateCallback edgeproto.CacheUpdateCallback) (*VMRequestSpec, error) {

	log.SpanLog(ctx, log.DebugLevelInfra, "GetVMSpecForRootLB", "rootLbName", rootLbName)

	var rootlbFlavor edgeproto.Flavor
	err := v.VMProperties.GetCloudletSharedRootLBFlavor(&rootlbFlavor)
	if err != nil {
		return nil, fmt.Errorf("unable to get Shared RootLB Flavor: %v", err)
	}
	vmspec, err := vmspec.GetVMSpec(v.FlavorList, rootlbFlavor)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "RootLB GetVMSpec error", "v.FlavorList", v.FlavorList, "rootlbFlavor", rootlbFlavor, "err", err)
		return nil, fmt.Errorf("unable to find VM spec for RootLB: %v", err)
	}
	az := vmspec.AvailabilityZone
	if az == "" {
		az = v.VMProperties.GetCloudletComputeAvailabilityZone()
	}
	imgPath := v.VMProperties.CommonPf.PlatformConfig.CloudletVMImagePath
	imgVersion := v.VMProperties.CommonPf.PlatformConfig.VMImageVersion
	imageName, err := v.VMProvider.AddCloudletImageIfNotPresent(ctx, imgPath, imgVersion, updateCallback)
	if err != nil {
		return nil, err
	}
	return v.GetVMRequestSpec(ctx,
		VMTypeRootLB,
		rootLbName,
		vmspec.FlavorName,
		imageName,
		true,
		WithExternalVolume(vmspec.ExternalVolumeSize),
		WithSubnetConnection(subnetConnect))
}

// GetVMSpecForRootLBPorts get a vmspec for the purpose of creating new ports to the specified subnet
func (v *VMPlatform) GetVMSpecForRootLBPorts(ctx context.Context, rootLbName string, subnet string) (*VMRequestSpec, error) {
	rootlb, err := v.GetVMRequestSpec(
		ctx,
		VMTypeRootLB,
		rootLbName,
		"dummyflavor",
		"dummyimage",
		false, // shared RLB already has external ports
		WithCreatePortsOnly(true),
		WithSubnetConnection(subnet),
	)
	return rootlb, err
}

//NewRootLB gets a new rootLB instance
func (v *VMPlatform) NewRootLB(ctx context.Context, rootLBName string) (*MEXRootLB, error) {
	rootLBLock.Lock()
	defer rootLBLock.Unlock()
	log.SpanLog(ctx, log.DebugLevelInfra, "getting new rootLB", "rootLBName", rootLBName)
	if _, ok := MEXRootLBMap[rootLBName]; ok {
		return nil, fmt.Errorf("rootlb %s already exists", rootLBName)
	}
	newRootLB := &MEXRootLB{Name: rootLBName}
	MEXRootLBMap[rootLBName] = newRootLB
	return newRootLB, nil
}

//DeleteRootLB to be called by code that called NewRootLB
func DeleteRootLB(rootLBName string) {
	rootLBLock.Lock()
	defer rootLBLock.Unlock()
	delete(MEXRootLBMap, rootLBName)
}

func GetRootLB(ctx context.Context, name string) (*MEXRootLB, error) {
	rootLB, ok := MEXRootLBMap[name]
	if !ok {
		return nil, fmt.Errorf("can't find rootlb %s", name)
	}
	if rootLB == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetRootLB, rootLB is null")
	}
	return rootLB, nil
}

//CreateRootLB creates a rootLB.  It should not be called if the rootLB already exists, as to save time we don't check
func (v *VMPlatform) CreateRootLB(
	ctx context.Context, rootLB *MEXRootLB,
	cloudletKey *edgeproto.CloudletKey,
	imgPath, imgVersion string,
	action ActionType,
	updateCallback edgeproto.CacheUpdateCallback,
) error {

	log.SpanLog(ctx, log.DebugLevelInfra, "create rootlb", "name", rootLB.Name, "action", action)
	if rootLB == nil {
		return fmt.Errorf("cannot enable rootLB, rootLB is null")
	}
	if action == ActionCreate {
		_, err := v.VMProvider.GetServerDetail(ctx, rootLB.Name)
		if err == nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "rootlb already exists")
			return nil
		}
	}
	vmreq, err := v.GetVMSpecForRootLB(ctx, rootLB.Name, "", updateCallback)
	if err != nil {
		return err
	}
	var vms []*VMRequestSpec
	vms = append(vms, vmreq)
	_, err = v.OrchestrateVMsFromVMSpec(ctx, rootLB.Name, vms, action, updateCallback, WithNewSecurityGroup(v.GetServerSecurityGroupName(rootLB.Name)))
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "error while creating RootLB VM", "name", rootLB.Name, "error", err)
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "done creating rootlb", "name", rootLB.Name)
	return nil

}

//SetupRootLB prepares the RootLB. It will optionally create the rootlb if the createRootLBFlavor
// is not blank and no existing server found
func (v *VMPlatform) SetupRootLB(
	ctx context.Context, rootLBName string,
	cloudletKey *edgeproto.CloudletKey,
	updateCallback edgeproto.CacheUpdateCallback,
) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SetupRootLB", "rootLBName", rootLBName)
	//fqdn is that of the machine/kvm-instance running the agent
	if !valid.IsDNSName(rootLBName) {
		return fmt.Errorf("fqdn %s is not valid", rootLBName)
	}
	rootLB, err := GetRootLB(ctx, rootLBName)
	if err != nil {
		return fmt.Errorf("cannot find rootlb in map %s", rootLBName)
	}
	sd, err := v.VMProvider.GetServerDetail(ctx, rootLBName)
	if err == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "server with same name as rootLB exists", "rootLBName", rootLBName)
	}

	// setup SSH access to cloudlet for CRM.  Since we are getting the external IP here, this will only work
	// when CRM accessed via public internet.
	log.SpanLog(ctx, log.DebugLevelInfra, "setup security group for SSH access")
	groupName := v.GetServerSecurityGroupName(rootLBName)
	my_ip, err := infracommon.GetExternalPublicAddr(ctx)
	if err != nil {
		// this is not necessarily fatal
		log.InfoLog("cannot fetch public ip", "err", err)
	} else {
		err = v.VMProvider.AddSecurityRuleCIDRWithRetry(ctx, my_ip, "tcp", groupName, "22", rootLBName)
		if err != nil {
			return err
		}
	}

	err = v.WaitForRootLB(ctx, rootLB)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "timeout waiting for agent to run", "name", rootLB.Name)
		return fmt.Errorf("Error waiting for rootLB %v", err)
	}
	ip, err := GetIPFromServerDetails(ctx, v.VMProperties.GetCloudletExternalNetwork(), "", sd)
	if err != nil {
		return fmt.Errorf("cannot get rootLB IP %sv", err)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "set rootLB IP to", "ip", ip)
	rootLB.IP = ip

	client, err := v.SetupSSHUser(ctx, rootLB, infracommon.SSHUser)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "Copy resource-tracker to rootLb", "rootLb", rootLBName)
	err = CopyResourceTracker(client)
	if err != nil {
		return fmt.Errorf("cannot copy resource-tracker to rootLb %v", err)
	}
	err = v.AddRouteToServer(ctx, client, rootLBName, InternalNetworkRoute)
	if err != nil {
		return fmt.Errorf("failed to AddRouteToServer %v", err)
	}
	err = v.VMProvider.WhitelistSecurityRules(ctx, v.GetServerSecurityGroupName(rootLBName), rootLBName, GetAllowedClientCIDR(), RootLBPorts)
	if err != nil {
		return fmt.Errorf("failed to WhitelistSecurityRules %v", err)
	}

	if err = v.VMProperties.CommonPf.ActivateFQDNA(ctx, rootLBName, ip.ExternalAddr); err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "DNS A record activated", "name", rootLB.Name)
	return nil
}

//WaitForRootLB waits for the RootLB instance to be up and copies of SSH credentials for internal networks.
//  Idempotent, but don't call all the time.
func (v *VMPlatform) WaitForRootLB(ctx context.Context, rootLB *MEXRootLB) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "wait for rootlb", "name", rootLB.Name)
	if rootLB == nil {
		return fmt.Errorf("cannot wait for lb, rootLB is null")
	}
	extNet := v.VMProperties.GetCloudletExternalNetwork()
	if extNet == "" {
		return fmt.Errorf("waiting for lb, missing external network in manifest")
	}
	client, err := v.GetSSHClientForServer(ctx, rootLB.Name, v.VMProperties.GetCloudletExternalNetwork())
	if err != nil {
		return err
	}
	start := time.Now()
	running := false
	for {
		log.SpanLog(ctx, log.DebugLevelInfra, "waiting for rootlb...", "rootLB", rootLB)
		_, err := client.Output("sudo grep -i 'Finished mobiledgex init' /var/log/mobiledgex.log")
		if err == nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "rootlb is running", "name", rootLB.Name)
			running = true
			break
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "error checking if rootLB is running", "err", err)
		}
		elapsed := time.Since(start)
		if elapsed >= (MaxRootLBWait) {
			break
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "sleeping 10 seconds before retry", "elapsed", elapsed)
		time.Sleep(10 * time.Second)
	}
	if !running {
		return fmt.Errorf("timeout waiting for RootLB")
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "done waiting for rootlb", "name", rootLB.Name)

	return nil
}

// This function copies resource-tracker from crm to rootLb - we need this to provide docker metrics
func CopyResourceTracker(client ssh.Client) error {
	path, err := exec.LookPath("resource-tracker")
	if err != nil {
		return err
	}
	err = SCPFilePath(client, path, "/tmp/resource-tracker")
	if err != nil {
		return err
	}
	// copy to /usr/local/bin/resource-tracker
	cmd := fmt.Sprintf("sudo cp /tmp/resource-tracker /usr/local/bin/resource-tracker")
	_, err = client.Output(cmd)
	if err != nil {
		return err
	}
	// make it executable
	cmd = fmt.Sprintf("sudo chmod a+rx /usr/local/bin/resource-tracker")
	_, err = client.Output(cmd)
	return err
}

func (v *VMPlatform) DeleteProxySecurityGroupRules(ctx context.Context, client ssh.Client, proxyName string, secGrpName string, ports []dme.AppPort, app *edgeproto.App, serverName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteProxySecurityGroupRules", "proxyName", proxyName, "ports", ports)

	err := proxy.DeleteNginxProxy(ctx, client, proxyName)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot delete proxy", "proxyName", proxyName, "error", err)
	}
	allowedClientCIDR := GetAllowedClientCIDR()
	return v.VMProvider.RemoveWhitelistSecurityRules(ctx, secGrpName, allowedClientCIDR, ports)
}

func (v *VMPlatform) SyncSharedRootLB(ctx context.Context, caches *platform.Caches) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SyncSharedRootLB")

	err := v.CreateRootLB(ctx, v.VMProperties.sharedRootLB, v.VMProperties.CommonPf.PlatformConfig.CloudletKey, v.VMProperties.CommonPf.PlatformConfig.CloudletVMImagePath, v.VMProperties.CommonPf.PlatformConfig.VMImageVersion, ActionSync, edgeproto.DummyUpdateCallback)
	if err != nil {
		return err
	}
	// now we need to attach ports from clusters unless there is a router
	if v.VMProperties.GetCloudletExternalRouter() != NoExternalRouter {
		return nil
	}
	clusterKeys := make(map[edgeproto.ClusterInstKey]struct{})
	caches.ClusterInstCache.GetAllKeys(ctx, func(k *edgeproto.ClusterInstKey, modRev int64) {
		clusterKeys[*k] = struct{}{}
	})
	for k := range clusterKeys {
		log.SpanLog(ctx, log.DebugLevelInfra, "SyncClusterInsts found cluster", "key", k)
		var clus edgeproto.ClusterInst
		if !caches.ClusterInstCache.Get(&k, &clus) {
			return fmt.Errorf("fail to fetch cluster %s", k)
		}

		if clus.IpAccess == edgeproto.IpAccess_IP_ACCESS_SHARED && clus.State == edgeproto.TrackedState_READY {
			subnetName := GetClusterSubnetName(ctx, &clus)
			portName := GetPortName(v.VMProperties.sharedRootLBName, subnetName)
			ipaddr, err := v.GetIPFromServerName(ctx, "", subnetName, v.VMProperties.sharedRootLBName)
			if err != nil {
				return err
			}
			err = v.VMProvider.AttachPortToServer(ctx, v.VMProperties.sharedRootLBName, subnetName, portName, ipaddr.InternalAddr, ActionSync)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "fail to attach port", "err", err)
				return err
			}
		}
	}
	return nil
}
