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
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform"

	valid "github.com/asaskevich/govalidator"
	"github.com/edgexr/edge-cloud-infra/chefmgmt"
	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/edgexr/edge-cloud/cloudcommon"
	dme "github.com/edgexr/edge-cloud/d-match-engine/dme-proto"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/vmspec"

	ssh "github.com/mobiledgex/golang-ssh"
)

// InternalPortAttachPolicy is for dedicated clusters to define whether the internal port should be created when the rootlb
// is spun up, or afterwards.
type InternalPortAttachPolicy string

const AttachPortNotSupported InternalPortAttachPolicy = "AttachPortNotSupported"
const AttachPortDuringCreate InternalPortAttachPolicy = "AttachPortDuringCreate"
const AttachPortAfterCreate InternalPortAttachPolicy = "AttachPortAfterCreate"

var udevRulesFile = "/etc/udev/rules.d/70-persistent-net.rules"

var sharedRootLBPortLock sync.Mutex

var RootLBPorts = []dme.AppPort{}

// creates entries in the 70-persistent-net.rules files to ensure the interface names are consistent after reboot
func persistInterfaceName(ctx context.Context, client ssh.Client, ifName, mac string, action *infracommon.InterfaceActionsOp) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "persistInterfaceName", "ifName", ifName, "mac", mac, "action", action)
	newFileContents := ""

	cmd := fmt.Sprintf("sudo cat %s", udevRulesFile)
	out, err := client.Output(cmd)
	// if the file exists, check for old entries
	if err == nil {
		lines := strings.Split(out, "\n")
		for _, l := range lines {
			// if the mac is already there remove it, it will be appended later
			if strings.Contains(l, mac) {
				log.SpanLog(ctx, log.DebugLevelInfra, "found existing rule for mac", "line", l)
			} else {
				newFileContents = newFileContents + l + "\n"
			}
		}
	}
	newRule := fmt.Sprintf("SUBSYSTEM==\"net\", ACTION==\"add\", DRIVERS==\"?*\", ATTR{address}==\"%s\", NAME=\"%s\"", mac, ifName)
	if action.AddInterface {
		newFileContents = newFileContents + newRule + "\n"
	}
	// preexisting or not, write it
	return pc.WriteFile(client, udevRulesFile, newFileContents, "udev-rules", pc.SudoOn)
}

func (v *VMPlatform) GetInterfaceNameForMac(ctx context.Context, client ssh.Client, mac string) string {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetInterfaceNameForMac", "mac", mac)
	cmd := fmt.Sprintf("ip -br link | awk '$3 ~ /^%s/ {print $1; exit 1}'", mac)
	out, _ := client.Output(cmd)
	return out
}

// configureInternalInterfaceAndExternalForwarding sets up the new internal interface and then creates iptables rules to forward
// traffic out the external interface.  Returns the name of the internal interface
func (v *VMPlatform) configureInternalInterfaceAndExternalForwarding(ctx context.Context, client ssh.Client, subnetName, internalPortName string, serverDetails *ServerDetail, action *infracommon.InterfaceActionsOp) (string, error) {

	log.SpanLog(ctx, log.DebugLevelInfra, "configureInternalInterfaceAndExternalForwarding", "serverDetails", serverDetails, "internalPortName", internalPortName, "action", fmt.Sprintf("%+v", action))
	internalIP, err := GetIPFromServerDetails(ctx, "", internalPortName, serverDetails)
	if err != nil {
		return "", err
	}
	if internalIP.MacAddress == "" {
		return "", fmt.Errorf("No MAC address for internal interface: %s", internalPortName)
	}
	var externalIps []*ServerIP

	nets := v.VMProperties.GetNetworksByType(ctx, []NetworkType{NetworkTypeExternalPrimary, NetworkTypeExternalAdditionalRootLb})
	log.SpanLog(ctx, log.DebugLevelInfra, "external network list", "externalNetworks", nets)
	for net := range nets {
		externalIP, err := GetIPFromServerDetails(ctx, net, "", serverDetails)
		if err != nil {
			return "", err
		}
		if externalIP.MacAddress == "" {
			return "", fmt.Errorf("No MAC address for external interface: %s", externalIP.Network)
		}
		externalIps = append(externalIps, externalIP)
	}
	err = WaitServerReady(ctx, v.VMProvider, client, serverDetails.Name, MaxRootLBWait)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "server not ready", "err", err)
		return "", err
	}

	// discover the interface names matching our macs
	var externalIfnames []string
	internalIfname := v.GetInterfaceNameForMac(ctx, client, internalIP.MacAddress)
	log.SpanLog(ctx, log.DebugLevelInfra, "found interface", "ifn", internalIfname, "mac", internalIP.MacAddress)

	for _, eip := range externalIps {
		externalIfname := v.GetInterfaceNameForMac(ctx, client, eip.MacAddress)
		externalIfnames = append(externalIfnames, externalIfname)
		if externalIfname == "" {
			log.SpanLog(ctx, log.DebugLevelInfra, "unable to find external interface via MAC", "mac", eip.MacAddress)
			if action.AddInterface {
				return "", fmt.Errorf("unable to find interface for external port mac: %s", eip.MacAddress)
			}
			// keep going on delete
		}
	}
	if internalIfname == "" {
		log.SpanLog(ctx, log.DebugLevelInfra, "unable to find internal interface via MAC", "mac", internalIP.MacAddress)
		if action.AddInterface {
			return "", fmt.Errorf("unable to find interface for internal port mac: %s", internalIP.MacAddress)
		}
		// keep going on delete
	}
	netplanEnabled := infracommon.ServerIsNetplanEnabled(ctx, client)
	filename, fileMatch, contents := infracommon.GenerateNetworkFileDetailsForIP(ctx, internalPortName, internalIfname, internalIP.InternalAddr, 24, netplanEnabled)
	if action.AddInterface {
		// cleanup any interfaces files that may be sitting around with our new interface, perhaps from some old failure
		cmd := fmt.Sprintf("grep -l ' %s ' %s", fileMatch, internalIfname)
		out, err := client.Output(cmd)
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
		err = pc.WriteFile(client, filename, contents, "netconfig", pc.SudoOn)
		// now create the file
		if err != nil {
			return "", fmt.Errorf("unable to write network config file: %s -- %v", filename, err)
		}

		// now bring the new internal interface up.
		var ipcmds []string
		maskLen := 24
		if v.VMProperties.UsesCommonSharedInternalLBNetwork && serverDetails.Name == v.VMProperties.SharedRootLBName {
			ni, err := ParseNetSpec(ctx, v.VMProperties.GetCloudletNetworkScheme())
			if err != nil {
				return "", err
			}
			maskLen = ni.CommonInternalNetworkMaskBits
		}
		linkCmd := fmt.Sprintf("sudo ip link set dev %s up", internalIfname)
		ipcmds = append(ipcmds, linkCmd)
		flushCmd := fmt.Sprintf("sudo ip addr flush %s", internalIfname)
		ipcmds = append(ipcmds, flushCmd)
		addrCmd := fmt.Sprintf("sudo ip addr add %s/%d dev %s", internalIP.InternalAddr, maskLen, internalIfname)
		ipcmds = append(ipcmds, addrCmd)
		for _, c := range ipcmds {
			log.SpanLog(ctx, log.DebugLevelInfra, "bringing up interface", "internalIfname", internalIfname, "cmd", c)
			out, err = client.Output(c)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "unable to run", "cmd", c, "out", out, "err", err)
				return "", fmt.Errorf("unable to run ip command: %s - %v", out, err)
			}
		}

	} else if action.DeleteInterface {
		cmd := fmt.Sprintf("sudo rm %s", filename)
		out, err := client.Output(cmd)
		if err != nil {
			if strings.Contains(out, "No such file") {
				log.SpanLog(ctx, log.DebugLevelInfra, "file already gone", "filename", filename)
			} else {
				return "", fmt.Errorf("Unexpected error removing network config file %s, %s -- %v", filename, out, err)
			}
		}

		cmd = fmt.Sprintf("sudo ip addr flush %s", internalIfname)
		log.SpanLog(ctx, log.DebugLevelInfra, "removing ip from interface", "internalIfname", internalIfname, "cmd", internalIfname)
		out, err = client.Output(cmd)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "unable to run ", "cmd", cmd, "out", out, "err", err)
		}
	}
	// we can get here on some error cases in which the ifname were not found
	if internalIfname != "" {
		if action.AddInterface || action.DeleteInterface {
			err = persistInterfaceName(ctx, client, internalIfname, internalIP.MacAddress, action)
			if err != nil {
				return "", err
			}
		}
		if action.CreateIptables || action.DeleteIptables {
			for _, externalIfname := range externalIfnames {
				if externalIfname != "" {
					err = v.setupForwardingIptables(ctx, client, externalIfname, internalIfname, action)
					if err != nil {
						log.SpanLog(ctx, log.DebugLevelInfra, "setupForwardingIptables failed", "err", err)
					}
				}
			}
		}
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "persistInterfaceName and setupForwardingIptables skipped due to empty internalIfName")
	}
	return internalIfname, err
}

// AttachAndEnableRootLBInterface attaches the interface and enables it in the OS.  Returns the internal interface name
func (v *VMPlatform) AttachAndEnableRootLBInterface(ctx context.Context, client ssh.Client, rootLBName string, attachPort bool, subnetName, internalPortName, internalIPAddr string, vmAction ActionType) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "AttachAndEnableRootLBInterface", "rootLBName", rootLBName, "attachPort", attachPort, "subnetName", subnetName, "internalPortName", internalPortName, "internalIPAddr", internalIPAddr)

	if rootLBName == v.VMProperties.SharedRootLBName {
		sharedRootLBPortLock.Lock()
		defer sharedRootLBPortLock.Unlock()
	}
	var action infracommon.InterfaceActionsOp
	action.CreateIptables = true
	if attachPort {
		action.AddInterface = true
		err := v.VMProvider.AttachPortToServer(ctx, rootLBName, subnetName, internalPortName, internalIPAddr, vmAction)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "fail to attach port", "err", err)
			return "", err
		}
	}
	sd, err := v.VMProvider.GetServerDetail(ctx, rootLBName)
	if err != nil {
		return "", err
	}
	internalIfName, err := v.configureInternalInterfaceAndExternalForwarding(ctx, client, subnetName, internalPortName, sd, &action)
	if err != nil {
		if attachPort {
			log.SpanLog(ctx, log.DebugLevelInfra, "fail to confgure internal interface, detaching port", "err", err)
			deterr := v.VMProvider.DetachPortFromServer(ctx, rootLBName, subnetName, internalPortName)
			if deterr != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "fail to detach port", "err", deterr)
			}
		}
		return "", err
	}
	return internalIfName, nil
}

// GetRootLBName uses the old rootLB name format to ensure backwards
// compatibility. Ideally we'd have some check that could tell us
// whether to use the old name (if the VM exists), or the new
// name, but setting the VMProperties.SharedRootLBName is done
// early in Init(), and it has many dependencies, and we cannot
// actually check for VM existence until later after the
// VMProvider is initialized. So for safety we're going to keep
// the VM name the same, and only use the new RootLBFQDN name
// for the DNS registration.
func (v *VMPlatform) GetRootLBName(key *edgeproto.CloudletKey) string {
	name := cloudcommon.GetRootLBFQDNOld(key, v.VMProperties.CommonPf.PlatformConfig.AppDNSRoot)
	return v.VMProvider.NameSanitize(name)
}

// DetachAndDisableRootLBInterface performs some cleanup when deleting the rootLB port.
func (v *VMPlatform) DetachAndDisableRootLBInterface(ctx context.Context, client ssh.Client, rootLBName string, subnetName, internalPortName, internalIPAddr string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DetachAndDisableRootLBInterface", "rootLBName", rootLBName, "subnetName", subnetName, "internalPortName", internalPortName)
	if rootLBName == v.VMProperties.SharedRootLBName {
		sharedRootLBPortLock.Lock()
		defer sharedRootLBPortLock.Unlock()
	}

	var action infracommon.InterfaceActionsOp
	action.DeleteIptables = true
	action.DeleteInterface = true

	sd, err := v.VMProvider.GetServerDetail(ctx, rootLBName)
	if err != nil {
		return err
	}

	_, err = v.configureInternalInterfaceAndExternalForwarding(ctx, client, subnetName, internalPortName, sd, &action)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "error in configureInternalInterfaceAndExternalForwarding", "err", err)
	}

	err = v.VMProvider.DetachPortFromServer(ctx, rootLBName, subnetName, internalPortName)
	if err != nil {
		// might already be gone
		log.SpanLog(ctx, log.DebugLevelInfra, "fail to detach port", "err", err)
	}

	return err
}

var rootLBLock sync.Mutex
var MaxRootLBWait = 5 * time.Minute

// used by cloudlet.go currently
func (v *VMPlatform) GetDefaultRootLBFlavor(ctx context.Context) (*edgeproto.FlavorInfo, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetDefaultRootLBFlavor cloudlet flavor list empty use default")
	var rlbFlav edgeproto.Flavor
	// must be a platform with no native flavor support, use our default LB flavor from props
	err := v.VMProperties.GetCloudletSharedRootLBFlavor(&rlbFlav)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetDefaultRootLBFlavor GetCloudletSharedRootLBFlavor", "error", err)
		return nil, err
	}

	rootlbFlavorInfo := edgeproto.FlavorInfo{
		Name:  MEX_ROOTLB_FLAVOR_NAME,
		Vcpus: rlbFlav.Vcpus,
		Ram:   rlbFlav.Ram,
		Disk:  rlbFlav.Disk,
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "GetDefaultRootLBFlavor", "default", rootlbFlavorInfo)
	return &rootlbFlavorInfo, nil
}

// GetVMSpecForRootLB gets the VM spec for the rootLB when it is not specified within a cluster. This is
// used for Shared RootLb and for VM app based RootLb
func (v *VMPlatform) GetVMSpecForRootLB(ctx context.Context, rootLbName string, subnetConnect string, tags []string, addNets map[string]NetworkType, addRoutes map[string][]edgeproto.Route, updateCallback edgeproto.CacheUpdateCallback) (*VMRequestSpec, error) {

	log.SpanLog(ctx, log.DebugLevelInfra, "GetVMSpecForRootLB", "rootLbName", rootLbName)

	var rootlbFlavor edgeproto.Flavor
	err := v.VMProperties.GetCloudletSharedRootLBFlavor(&rootlbFlavor)
	if err != nil {
		return nil, fmt.Errorf("unable to get Shared RootLB Flavor: %v", err)
	}

	cli := edgeproto.CloudletInfo{}
	cli.Key = *v.VMProperties.CommonPf.PlatformConfig.CloudletKey
	cli.Flavors = v.FlavorList

	spec := &vmspec.VMCreationSpec{}
	if len(cli.Flavors) == 0 {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetVMSpecForRootLB clouldlet flavor list emtpy use default", "rootLbName", rootLbName)
		// must be a platform with no native flavor support, just use the default
		spec.FlavorName = rootlbFlavor.Key.Name
		// The platform has the definition of the name in its internal flavors list for the actual create
	} else {
		restbls := v.GetResTablesForCloudlet(ctx, &cli.Key)
		spec, err = vmspec.GetVMSpec(ctx, rootlbFlavor, cli, restbls)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "RootLB GetVMSpec error", "v.FlavorList", v.FlavorList, "rootlbFlavor", rootlbFlavor, "err", err)
			return nil, fmt.Errorf("unable to find VM spec for RootLB: %v", err)
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "GetVMSpec returned", "flavor", spec.FlavorName, "for mex flavor", rootlbFlavor)
	az := spec.AvailabilityZone
	if az == "" {
		az = v.VMProperties.GetCloudletComputeAvailabilityZone()
	}
	imageName, err := v.GetCloudletImageToUse(ctx, updateCallback)
	if err != nil {
		return nil, err
	}
	chefAttributes := make(map[string]interface{})
	chefAttributes["tags"] = tags
	clientName := v.GetChefClientName(rootLbName)
	chefParams := v.GetServerChefParams(clientName, "", chefmgmt.ChefPolicyBase, chefAttributes)

	// append the cloudlet-wide additional rootlb networks to the ones passed in
	netTypes := []NetworkType{NetworkTypeExternalAdditionalRootLb}
	cloudletAddNets := v.VMProperties.GetNetworksByType(ctx, netTypes)
	for c, n := range cloudletAddNets {
		addNets[c] = n
	}
	nodeType := cloudcommon.NodeTypeDedicatedRootLB
	if rootLbName == v.VMProperties.SharedRootLBName {
		nodeType = cloudcommon.NodeTypeSharedRootLB
	}
	return v.GetVMRequestSpec(ctx,
		nodeType,
		rootLbName,
		spec.FlavorName,
		imageName,
		true,
		WithExternalVolume(spec.ExternalVolumeSize),
		WithSubnetConnection(subnetConnect),
		WithChefParams(chefParams),
		WithAdditionalNetworks(addNets),
		WithRoutes(addRoutes))
}

// GetVMSpecForSharedRootLBPorts get a vmspec for the purpose of creating new ports to the specified subnet
func (v *VMPlatform) GetVMSpecForSharedRootLBPorts(ctx context.Context, rootLbName string, subnet string) (*VMRequestSpec, error) {
	rootlb, err := v.GetVMRequestSpec(
		ctx,
		cloudcommon.NodeTypeSharedRootLB,
		rootLbName,
		"dummyflavor",
		"dummyimage",
		false, // shared RLB already has external ports
		WithCreatePortsOnly(true),
		WithSubnetConnection(subnet),
	)
	return rootlb, err
}

// CreateRootLB creates a rootLB. It will not create it if it
// already exists.
func (v *VMPlatform) CreateRootLB(
	ctx context.Context, rootLBName string,
	cloudletKey *edgeproto.CloudletKey,
	imgPath, imgVersion string,
	action ActionType,
	tags []string,
	updateCallback edgeproto.CacheUpdateCallback,
) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "create rootlb", "name", rootLBName, "action", action)
	if action == ActionCreate {
		_, err := v.VMProvider.GetServerDetail(ctx, rootLBName)
		if err == nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "rootlb already exists")
			return nil
		}
	}
	nets := make(map[string]NetworkType)
	routes := make(map[string][]edgeproto.Route)
	vmreq, err := v.GetVMSpecForRootLB(ctx, rootLBName, "", tags, nets, routes, updateCallback)
	if err != nil {
		return err
	}
	var vms []*VMRequestSpec
	vms = append(vms, vmreq)
	_, err = v.OrchestrateVMsFromVMSpec(ctx, rootLBName, vms, action, updateCallback, WithNewSecurityGroup(infracommon.GetServerSecurityGroupName(rootLBName)))
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "error while creating RootLB VM", "name", rootLBName, "error", err)
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "done creating rootlb", "name", rootLBName)
	return nil

}

// SetupRootLB prepares the RootLB.
func (v *VMPlatform) SetupRootLB(
	ctx context.Context, rootLBName, rootLBFQDN string,
	cloudletKey *edgeproto.CloudletKey,
	TrustPolicy *edgeproto.TrustPolicy,
	updateCallback edgeproto.CacheUpdateCallback,
) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SetupRootLB", "rootLBName", rootLBName, "fqdn", rootLBFQDN)
	// ensure no entries exist in the ip cache for this rootlb
	DeleteServerIpFromCache(ctx, rootLBName)

	// fqdn is that of the machine/kvm-instance running the agent
	if !valid.IsDNSName(rootLBFQDN) {
		return fmt.Errorf("fqdn %s is not valid", rootLBFQDN)
	}
	sd, err := v.VMProvider.GetServerDetail(ctx, rootLBName)
	if err == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "server with same name as rootLB exists", "rootLBName", rootLBName)
		// if the provider needs external IP mapping to be validated, do it now. We could consider
		// doing this for all providers but need to verify it will not cause a problem with any existing
		// deployments
		if v.VMProperties.ValidateExternalIPMapping {
			ip, err := GetIPFromServerDetails(ctx, v.VMProperties.GetCloudletExternalNetwork(), "", sd)
			if err != nil {
				return err
			}
			err = v.VMProperties.CommonPf.ValidateExternalIPMapping(ctx, ip.ExternalAddr)
			if err != nil {
				return err
			}
		}
	}

	// setup SSH access to cloudlet for CRM.  Since we are getting the external IP here, this will only work
	// when CRM accessed via public internet.
	log.SpanLog(ctx, log.DebugLevelInfra, "setup rootLBName group for SSH access")
	groupName := infracommon.GetServerSecurityGroupName(rootLBName)
	client, err := v.GetSSHClientForServer(ctx, rootLBName, v.VMProperties.GetCloudletExternalNetwork(), pc.WithUser(infracommon.SSHUser), pc.WithCachedIp(true))
	if err != nil {
		return err
	}
	// TODO: this should eventually be removed when all providers use
	// cloudlet level rules (TrustPolicy) that does the whitelist at the cloudlet level
	myIp, err := infracommon.GetExternalPublicAddr(ctx)
	if err != nil {
		// this is not necessarily fatal
		log.InfoLog("cannot fetch public ip", "err", err)
	} else {
		var sshPort = []dme.AppPort{{
			PublicPort: 22,
			Proto:      dme.LProto_L_PROTO_TCP,
		}}
		wlParams := infracommon.WhiteListParams{
			ServerName:  rootLBName,
			SecGrpName:  groupName,
			Label:       "rootlb-ssh",
			AllowedCIDR: myIp + "/32",
			Ports:       sshPort,
		}
		err = v.VMProvider.WhitelistSecurityRules(ctx, client, &wlParams)
		if err != nil {
			return err
		}
		if v.VMProperties.RequiresWhitelistOwnIp {
			for _, a := range sd.Addresses {

				wlParams = infracommon.WhiteListParams{
					ServerName:  rootLBName,
					SecGrpName:  groupName,
					Label:       "own-externalip-ssh",
					AllowedCIDR: a.ExternalAddr + "/32",
					Ports:       sshPort,
				}
				err = v.VMProvider.WhitelistSecurityRules(ctx, client, &wlParams)
				if err != nil {
					return err
				}
			}
		}
	}
	err = WaitServerReady(ctx, v.VMProvider, client, rootLBName, MaxRootLBWait)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "timeout waiting for rootLB", "name", rootLBName)
		return fmt.Errorf("Error waiting for rootLB %v", err)
	}
	ip, err := GetIPFromServerDetails(ctx, v.VMProperties.GetCloudletExternalNetwork(), "", sd)
	if err != nil {
		return fmt.Errorf("cannot get rootLB IP %sv", err)
	}
	// just for test as this is taking too long
	if v.VMProperties.GetSkipInstallResourceTracker() {
		log.SpanLog(ctx, log.DebugLevelInfra, "skipping install of resource tracker")
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "Copy resource-tracker to rootLb", "rootLb", rootLBName)
		err = CopyResourceTracker(client)
		if err != nil {
			return fmt.Errorf("cannot copy resource-tracker to rootLb %v", err)
		}
	}
	commonSharedAccess := rootLBName == v.VMProperties.SharedRootLBName && v.VMProperties.UsesCommonSharedInternalLBNetwork
	route, err := v.VMProperties.GetInternalNetworkRoute(ctx, commonSharedAccess)
	if err != nil {
		return err
	}
	ni, err := ParseNetSpec(ctx, v.VMProperties.GetCloudletNetworkScheme())
	if err != nil {
		return err
	}
	if ni.FloatingIPNet != "" {
		// For now we do nothing when we have a floating IP because it means we are using the
		// openstack router to get everywhere anyway.
		log.SpanLog(ctx, log.DebugLevelInfra, "No route changes needed due to floating IP")
		return nil
	}
	rtr := v.VMProperties.GetCloudletExternalRouter()
	gatewayIP := ni.RouterGatewayIP
	if gatewayIP == "" && rtr != NoConfigExternalRouter && rtr != NoExternalRouter {
		rd, err := v.VMProvider.GetRouterDetail(ctx, v.VMProperties.GetCloudletExternalRouter())
		if err != nil {
			return err
		}
		gatewayIP = rd.ExternalIP
	}
	if gatewayIP != "" {
		externalIf := v.GetInterfaceNameForMac(ctx, client, ip.MacAddress)
		err = v.VMProperties.AddRouteToServer(ctx, client, rootLBName, route, gatewayIP, externalIf)
		if err != nil {
			return fmt.Errorf("failed to AddRouteToServer for rootlb: %s -  %v", rootLBName, err)
		}
	}
	wlParams := infracommon.WhiteListParams{
		ServerName:  rootLBName,
		SecGrpName:  groupName,
		Label:       "rootlb-ports",
		AllowedCIDR: infracommon.GetAllowedClientCIDR(),
		Ports:       RootLBPorts,
	}
	err = v.VMProvider.WhitelistSecurityRules(ctx, client, &wlParams)
	if err != nil {
		return fmt.Errorf("failed to WhitelistSecurityRules %v", err)
	}

	if err = v.VMProperties.CommonPf.ActivateFQDNA(ctx, rootLBFQDN, ip.ExternalAddr); err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "DNS A record activated", "name", rootLBName)
	// perform provider specific prep of the rootLB
	secGrpName := infracommon.GetServerSecurityGroupName(rootLBName)
	if v.VMProperties.IptablesBasedFirewall {
		// when using iptables for firewall, we use a common secgrp for cloudlet-wide and per-LB
		secGrpName = infracommon.TrustPolicySecGrpNameLabel
	}
	return v.VMProvider.PrepareRootLB(ctx, client, rootLBName, secGrpName, TrustPolicy, updateCallback)
}

// This function copies resource-tracker from crm to rootLb - we need this to provide docker metrics
func CopyResourceTracker(client ssh.Client) error {
	path, err := exec.LookPath("resource-tracker")
	if err != nil {
		return err
	}
	err = infracommon.SCPFilePath(client, path, "/tmp/resource-tracker")
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

func GetChefRootLBTags(platformConfig *platform.PlatformConfig) []string {
	return []string{
		"deploytag/" + platformConfig.DeploymentTag,
		"region/" + platformConfig.Region,
		"cloudlet/" + platformConfig.CloudletKey.Name,
		"cloudletorg/" + platformConfig.CloudletKey.Organization,
		"nodetype/" + cloudcommon.NodeTypeSharedRootLB.String(),
	}
}

// GetAllRootLBClients gets rootLb clients for both Shared and Dedicated LBs
func (v *VMPlatform) GetAllRootLBClients(ctx context.Context) (map[string]ssh.Client, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetAllRootLBClients")
	rootlbClients, err := v.GetRootLBClients(ctx)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "error getting dedicated client", "err", err)
		return nil, fmt.Errorf("Unable to get dedicated rootlb Clients - %v", err)
	}
	// GetRootLBClients gets only the dedicated rootlbs.  We need the shared one also
	sharedClient, err := v.GetNodePlatformClient(ctx, &edgeproto.CloudletMgmtNode{Name: v.VMProperties.SharedRootLBName})
	if err != nil {
		if strings.Contains(err.Error(), ServerDoesNotExistError) {
			// this can happen on startup
			log.SpanLog(ctx, log.DebugLevelInfra, "shared rootlb does not exist")
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "error getting sharedlb client", "err", err)
			return nil, fmt.Errorf("Unable to get shared rootlb Client - %v", err)
		}
	} else {
		rootlbClients[v.VMProperties.SharedRootLBName] = sharedClient
	}
	return rootlbClients, nil
}

func (v *VMPlatform) GetRootLBClientForClusterInstKey(ctx context.Context, clusterInstKey *edgeproto.ClusterInstKey) (map[string]ssh.Client, error) {
	rootLBClients := make(map[string]ssh.Client)

	var clusterInst edgeproto.ClusterInst
	found := v.Caches.ClusterInstCache.Get(clusterInstKey, &clusterInst)
	if !found {
		return nil, fmt.Errorf("Unable to get clusterInst %v", clusterInstKey.GetKeyString())
	}
	lbName := v.VMProperties.GetRootLBNameForCluster(ctx, &clusterInst)
	client, err := v.GetClusterPlatformClient(ctx, &clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to get rootLB client for dedicated cluster", "key", clusterInst.Key, "error", err)
		return nil, fmt.Errorf("Unable to get client from clusterInst %v", clusterInstKey.GetKeyString())
	}
	rootLBClients[lbName] = client
	return rootLBClients, nil
}

// GetRootLBClients gets all RootLB Clients for dedicated LBs
func (v *VMPlatform) GetRootLBClients(ctx context.Context) (map[string]ssh.Client, error) {
	if v.Caches == nil {
		return nil, fmt.Errorf("caches is nil")
	}
	ctx, result, err := v.VMProvider.InitOperationContext(ctx, OperationInitStart)
	if err != nil {
		return nil, err
	}
	if result == OperationNewlyInitialized {
		defer v.VMProvider.InitOperationContext(ctx, OperationInitComplete)
	}
	rootLBClients := make(map[string]ssh.Client)
	clusterInstKeys := []edgeproto.ClusterInstKey{}
	v.Caches.ClusterInstCache.GetAllKeys(ctx, func(k *edgeproto.ClusterInstKey, modRev int64) {
		clusterInstKeys = append(clusterInstKeys, *k)
	})
	for _, k := range clusterInstKeys {
		var clusterInst edgeproto.ClusterInst
		if v.Caches.ClusterInstCache.Get(&k, &clusterInst) {
			if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
				lbName := v.VMProperties.GetRootLBNameForCluster(ctx, &clusterInst)
				client, err := v.GetClusterPlatformClient(ctx, &clusterInst, cloudcommon.ClientTypeRootLB)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "failed to get rootLB client for dedicated cluster", "key", clusterInst.Key, "error", err)
					// set client as nil and continue, caller will generate alert accordingly
					client = nil
				}
				rootLBClients[lbName] = client
			}
		}
	}

	apps := make(map[edgeproto.AppKey]struct{})
	v.Caches.AppCache.GetAllKeys(ctx, func(k *edgeproto.AppKey, modRev int64) {
		apps[*k] = struct{}{}
	})
	for k := range apps {
		var app edgeproto.App
		if v.Caches.AppCache.Get(&k, &app) {
			if app.Deployment == cloudcommon.DeploymentTypeVM && app.AccessType != edgeproto.AccessType_ACCESS_TYPE_DIRECT {
				continue
			}
		}
		delete(apps, k)
	}

	appInstKeys := []edgeproto.AppInstKey{}
	v.Caches.AppInstCache.GetAllKeys(ctx, func(k *edgeproto.AppInstKey, modRev int64) {
		appInstKeys = append(appInstKeys, *k)
	})
	for _, k := range appInstKeys {
		if _, ok := apps[k.AppKey]; !ok {
			continue
		}
		appInst := edgeproto.AppInst{}
		if !v.Caches.AppInstCache.Get(&k, &appInst) {
			continue
		}
		lbName := appInst.Uri
		client, err := v.GetSSHClientForServer(ctx, lbName, v.VMProperties.GetCloudletExternalNetwork())
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to get rootLB client for VM app instance", "key", k, "error", err)
			client = nil
			// set client as nil and continue, caller will generate alert accordingly
		}
		rootLBClients[lbName] = client
	}
	return rootLBClients, nil
}

func (v *VMPlatform) GetRootLBFlavor(ctx context.Context) (*edgeproto.Flavor, error) {
	var rootlbFlavor edgeproto.Flavor
	err := v.VMProperties.GetCloudletSharedRootLBFlavor(&rootlbFlavor)
	if err != nil {
		return nil, fmt.Errorf("unable to get Shared RootLB Flavor: %v", err)
	}
	return &rootlbFlavor, nil
}
