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

	valid "github.com/asaskevich/govalidator"
	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/objstore"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	"github.com/edgexr/edge-cloud-platform/pkg/resspec"

	ssh "github.com/edgexr/golang-ssh"
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
var NoAccessKey string

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

type configureInternalInterface struct {
	ipversion       infracommon.IPVersion
	internalIP      *ServerIP
	externalIPs     []*ServerIP
	externalIfnames []string
}

// configureInternalInterfaceAndExternalForwarding sets up the new internal interface and then creates iptables rules to forward
// traffic out the external interface.  Returns the name of the internal interface
func (v *VMPlatform) configureInternalInterfaceAndExternalForwarding(ctx context.Context, client ssh.Client, subnetNames SubnetNames, internalPortName string, serverDetails *ServerDetail, action *infracommon.InterfaceActionsOp) (string, error) {

	log.SpanLog(ctx, log.DebugLevelInfra, "configureInternalInterfaceAndExternalForwarding", "serverDetails", serverDetails, "internalPortName", internalPortName, "action", fmt.Sprintf("%+v", action))
	internalIPs, err := GetIPFromServerDetails(ctx, "", internalPortName, serverDetails)
	if err != nil {
		return "", err
	}
	var internalAddrs infracommon.IPs
	var configs [len(internalIPs)]*configureInternalInterface
	for ii := range internalIPs {
		internalIP := internalIPs[ii]
		if internalIP == nil {
			continue
		}
		if internalIP.MacAddress == "" {
			return "", fmt.Errorf("No MAC address for %s internal interface: %s", internalIP.IPVersion, internalPortName)
		}
		configs[ii] = &configureInternalInterface{
			internalIP: internalIP,
			ipversion:  internalIP.IPVersion,
		}
		internalAddrs[ii] = internalIPs[ii].InternalAddr
	}

	nets := v.VMProperties.GetNetworksByType(ctx, []NetworkType{NetworkTypeExternalPrimary, NetworkTypeExternalSecondary, NetworkTypeExternalAdditionalRootLb})
	log.SpanLog(ctx, log.DebugLevelInfra, "external network list", "externalNetworks", nets)
	for net := range nets {
		if net == "" {
			continue
		}
		externalIPs, err := GetIPFromServerDetails(ctx, net, "", serverDetails)
		if err != nil {
			return "", err
		}
		for ipType := range externalIPs {
			if externalIPs[ipType] == nil || configs[ipType] == nil {
				continue
			}
			if externalIPs[ipType].MacAddress == "" {
				return "", fmt.Errorf("No MAC address for external interface %s on network %s", externalIPs[ipType].ExternalAddr, externalIPs[ipType].Network)
			}
			configs[ipType].externalIPs = append(configs[ipType].externalIPs, externalIPs[ipType])
		}
	}
	err = WaitServerReady(ctx, v.VMProvider, client, serverDetails.Name, MaxRootLBWait)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "server not ready", "err", err)
		return "", err
	}

	// discover the interface names matching our macs
	internalIfname := ""
	internalMacAddr := ""
	for _, config := range configs {
		if config == nil {
			continue
		}
		ifname := v.GetInterfaceNameForMac(ctx, client, config.internalIP.MacAddress)
		log.SpanLog(ctx, log.DebugLevelInfra, "found interface", "ifn", ifname, "mac", config.internalIP.MacAddress)
		if ifname == "" {
			if action.AddInterface {
				return "", fmt.Errorf("unable to find interface for internal port mac: %s", config.internalIP.MacAddress)
			}
			// keep going on delete
		}
		// if both ipv4 and ipv6 are present, they must be on the same interface
		if internalIfname == "" {
			internalIfname = ifname
			internalMacAddr = config.internalIP.MacAddress
		} else if internalIfname != ifname {
			return "", fmt.Errorf("IPv4 and IPv6 IPs must be on the same interface, but are on %s and %s", internalIfname, ifname)
		}

		for _, eip := range config.externalIPs {
			externalIfname := v.GetInterfaceNameForMac(ctx, client, eip.MacAddress)
			if externalIfname == "" {
				log.SpanLog(ctx, log.DebugLevelInfra, "unable to find external interface via MAC", "mac", eip.MacAddress)
				if action.AddInterface {
					return "", fmt.Errorf("unable to find interface for external port mac: %s", eip.MacAddress)
				}
				// keep going on delete
			} else {
				config.externalIfnames = append(config.externalIfnames, externalIfname)
			}
		}
	}

	configNetworks := map[string]struct{}{
		v.VMProperties.GetCloudletMexNetwork(): {},
	}
	defaultRouteNets := map[string]struct{}{}
	err = v.ConfigureNetworkInterfaces(ctx, client, serverDetails, configNetworks, defaultRouteNets, nil)
	if err != nil {
		return "", fmt.Errorf("failed to configure LB interface, %s", err)
	}

	// we can get here on some error cases in which the ifname were not found
	if internalIfname != "" {
		if action.AddInterface || action.DeleteInterface {
			err = persistInterfaceName(ctx, client, internalIfname, internalMacAddr, action)
			if err != nil {
				return "", err
			}
		}
		if action.CreateIptables || action.DeleteIptables {
			for _, config := range configs {
				if config == nil {
					continue
				}
				for _, externalIfname := range config.externalIfnames {
					if externalIfname != "" {
						err = v.setupForwardingIptables(ctx, client, externalIfname, internalIfname, action, config.ipversion)
						if err != nil {
							log.SpanLog(ctx, log.DebugLevelInfra, "setupForwardingIptables failed", "externalIfname", externalIfname, "internalIfname", internalIfname, "ipversion", config.ipversion, "err", err)
						}
					}
				}
			}
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "persistInterfaceName and setupForwardingIptables skipped due to empty internalIfName")
		}
	}
	return internalIfname, err
}

// AttachAndEnableRootLBInterface attaches the interface and enables it in the OS.  Returns the internal interface name
func (v *VMPlatform) AttachAndEnableRootLBInterface(ctx context.Context, client ssh.Client, rootLBName string, attachPort bool, subnetNames SubnetNames, internalPortName string, internalIPs infracommon.IPs, vmAction ActionType) (*ServerDetail, string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "AttachAndEnableRootLBInterface", "rootLBName", rootLBName, "attachPort", attachPort, "subnetNames", subnetNames, "internalPortName", internalPortName, "internalIPs", internalIPs)

	if rootLBName == v.VMProperties.SharedRootLBName {
		sharedRootLBPortLock.Lock()
		defer sharedRootLBPortLock.Unlock()
	}
	var action infracommon.InterfaceActionsOp
	action.CreateIptables = true
	if attachPort {
		action.AddInterface = true
		err := v.VMProvider.AttachPortToServer(ctx, rootLBName, subnetNames, internalPortName, internalIPs, vmAction)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "fail to attach port", "err", err)
			return nil, "", err
		}
	}

	// Get server details after port has been attached
	sd, err := v.VMProvider.GetServerDetail(ctx, rootLBName)
	if err != nil {
		return nil, "", fmt.Errorf("attach and enable root LB interface failed, %s", err)
	}
	internalIfName, err := v.configureInternalInterfaceAndExternalForwarding(ctx, client, subnetNames, internalPortName, sd, &action)
	if err != nil {
		if attachPort {
			log.SpanLog(ctx, log.DebugLevelInfra, "fail to confgure internal interface, detaching port", "err", err)
			deterr := v.VMProvider.DetachPortFromServer(ctx, rootLBName, subnetNames, internalPortName)
			if deterr != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "fail to detach port", "err", deterr)
			}
		}
		return nil, "", err
	}
	return sd, internalIfName, nil
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
	// If the appDnsRoot changes, the only way to point back
	// to the original rootLB name is manually via this env var.
	name, ok := v.VMProperties.CommonPf.Properties.GetValue("MEX_SHARED_ROOTLB_NAME")
	if !ok || name == "" {
		name = cloudcommon.GetRootLBFQDNOld(key, v.VMProperties.CommonPf.PlatformConfig.AppDNSRoot)
	}
	return v.VMProvider.NameSanitize(name)
}

// DetachAndDisableRootLBInterface performs some cleanup when deleting the rootLB port.
func (v *VMPlatform) DetachAndDisableRootLBInterface(ctx context.Context, client ssh.Client, rootLBName string, subnetNames SubnetNames, internalPortName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DetachAndDisableRootLBInterface", "rootLBName", rootLBName, "subnetNames", subnetNames, "internalPortName", internalPortName)
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

	err = v.VMProvider.DetachPortFromServer(ctx, rootLBName, subnetNames, internalPortName)
	if err != nil {
		// might already be gone
		log.SpanLog(ctx, log.DebugLevelInfra, "fail to detach port", "err", err)
	}

	_, err = v.configureInternalInterfaceAndExternalForwarding(ctx, client, subnetNames, internalPortName, sd, &action)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "error in configureInternalInterfaceAndExternalForwarding", "err", err)
	}

	return err
}

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
func (v *VMPlatform) GetVMSpecForRootLB(ctx context.Context, rootLbName string, subnetConnect SubnetNames, ownerKey objstore.ObjKey, addNets map[string]NetworkType, addRoutes map[string][]edgeproto.Route, accessKey string, nodeRole cloudcommon.NodeRole, updateCallback edgeproto.CacheUpdateCallback) (*VMRequestSpec, error) {

	log.SpanLog(ctx, log.DebugLevelInfra, "GetVMSpecForRootLB", "rootLbName", rootLbName)

	var rootlbFlavor edgeproto.Flavor
	err := v.VMProperties.GetCloudletSharedRootLBFlavor(&rootlbFlavor)
	if err != nil {
		return nil, fmt.Errorf("unable to get Shared RootLB Flavor: %v", err)
	}

	cli := edgeproto.CloudletInfo{}
	cli.Key = *v.VMProperties.CommonPf.PlatformConfig.CloudletKey
	flavors, err := v.GetCachedFlavorList(ctx)
	if err != nil {
		return nil, err
	}
	cli.Flavors = flavors

	spec := &resspec.VMCreationSpec{}
	if len(cli.Flavors) == 0 {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetVMSpecForRootLB clouldlet flavor list emtpy use default", "rootLbName", rootLbName)
		// must be a platform with no native flavor support, just use the default
		spec.FlavorName = rootlbFlavor.Key.Name
		// The platform has the definition of the name in its internal flavors list for the actual create
	} else {
		restbls := v.GetResTablesForCloudlet(ctx, &cli.Key)
		spec, err = resspec.GetVMSpec(ctx, rootlbFlavor.ToNodeResources(), cli, restbls)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "RootLB GetVMSpec error", "v.FlavorList", flavors, "rootlbFlavor", rootlbFlavor, "err", err)
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
	ops := []VMReqOp{
		WithExternalVolume(spec.ExternalVolumeSize),
		WithSubnetConnection(subnetConnect),
		WithConfigureNodeVars(v, nodeRole, &cli.Key, ownerKey),
		WithAdditionalNetworks(addNets),
		WithRoutes(addRoutes),
	}
	if accessKey != NoAccessKey {
		ops = append(ops, WithAccessKey(accessKey))
	}
	return v.GetVMRequestSpec(ctx,
		nodeType,
		rootLbName,
		spec.FlavorName,
		imageName,
		true,
		ops...)
}

// GetVMSpecForSharedRootLBPorts get a vmspec for the purpose of creating new ports to the specified subnet
func (v *VMPlatform) GetVMSpecForSharedRootLBPorts(ctx context.Context, rootLbName string, subnets SubnetNames) (*VMRequestSpec, error) {
	rootlb, err := v.GetVMRequestSpec(
		ctx,
		cloudcommon.NodeTypeSharedRootLB,
		rootLbName,
		"dummyflavor",
		"dummyimage",
		false, // shared RLB already has external ports
		WithCreatePortsOnly(true),
		WithSubnetConnection(subnets),
	)
	return rootlb, err
}

// CreateOrUpdateRootLB creates or updates the rootLB
func (v *VMPlatform) CreateRootLB(
	ctx context.Context, rootLBName string,
	cloudletKey *edgeproto.CloudletKey,
	action ActionType,
	accessKey string, // accessKey is set if LB hosts Shepherd
	nodeRole cloudcommon.NodeRole,
	updateCallback edgeproto.CacheUpdateCallback,
) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "create or update rootlb", "name", rootLBName, "action", action)

	nets := make(map[string]NetworkType)
	routes := make(map[string][]edgeproto.Route)
	vmreq, err := v.GetVMSpecForRootLB(ctx, rootLBName, NoSubnets, cloudletKey, nets, routes, accessKey, nodeRole, updateCallback)
	if err != nil {
		return err
	}
	var vms []*VMRequestSpec
	vms = append(vms, vmreq)
	gp, err := v.OrchestrateVMsFromVMSpec(ctx,
		rootLBName,
		v.VMProperties.CommonPf.PlatformConfig.CloudletObjID,
		vms,
		action,
		updateCallback,
		WithNewSecurityGroup(infracommon.GetServerSecurityGroupName(rootLBName)),
		WithEnableIPV6(v.VMProperties.CloudletEnableIPV6),
		WithUseExistingVMs(true), // avoid destroying the rootLB if it already exists
	)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "error while creating RootLB VM", "name", rootLBName, "error", err)
		return err
	}
	if action == ActionUpdate {
		// new ports created due to new networks may not have been added to the
		// rootLB since we use the existing VMs. Make sure all rootLB ports
		// are attached here. Note this does not include ports to connect to
		// ClusterInsts, as those ports as defined as part of the ClusterInst
		// orchestration group.
		err = v.attachRootLBExternalPorts(ctx, rootLBName, gp, action)
		if err != nil {
			return err
		}
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "done creating rootlb", "name", rootLBName)
	return nil

}

func (v *VMPlatform) attachRootLBExternalPorts(ctx context.Context, rootLBName string, gp *VMGroupOrchestrationParams, action ActionType) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "attachRootLBExternalPorts", "rootLBName", rootLBName)
	rootLBPorts := make(map[string]struct{})
	for _, vm := range gp.VMs {
		if vm.Name != rootLBName {
			continue
		}
		for _, port := range vm.Ports {
			rootLBPorts[port.Name] = struct{}{}
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "ensuring ports are attached to rootLB", "server", rootLBName, "ports", rootLBPorts)
	for _, port := range gp.Ports {
		if _, found := rootLBPorts[port.Name]; !found {
			continue
		}
		ips := infracommon.IPs{}
		for _, fixedip := range port.FixedIPs {
			ips[infracommon.IPIndexOf(fixedip.IPVersion)] = fixedip.Address
		}
		err := v.VMProvider.AttachPortToServer(ctx, rootLBName, port.SubnetIds, port.Name, ips, action)
		if err != nil {
			return err
		}
	}
	return nil
}

// SetupRootLB prepares the RootLB.
func (v *VMPlatform) SetupRootLB(
	ctx context.Context, rootLBName, rootLBFQDN string,
	cloudletKey *edgeproto.CloudletKey,
	TrustPolicy *edgeproto.TrustPolicy,
	sd *ServerDetail,
	enableIPV6 bool,
	updateCallback edgeproto.CacheUpdateCallback,
) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SetupRootLB", "rootLBName", rootLBName, "fqdn", rootLBFQDN, "enableIPV6", enableIPV6)
	// ensure no entries exist in the ip cache for this rootlb
	DeleteServerIpFromCache(ctx, rootLBName)

	// fqdn is that of the machine/kvm-instance running the agent
	if !valid.IsDNSName(rootLBFQDN) {
		return fmt.Errorf("fqdn %s is not valid", rootLBFQDN)
	}

	// if the provider needs external IP mapping to be validated, do it now. We could consider
	// doing this for all providers but need to verify it will not cause a problem with any existing
	// deployments
	if v.VMProperties.ValidateExternalIPMapping {
		ips, err := v.GetExternalIPFromServerName(ctx, rootLBName, WithServerDetail(sd))
		if err != nil {
			return err
		}
		for _, ip := range ips {
			if ip == nil {
				continue
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
	iptypes := []infracommon.IPVersion{
		infracommon.IPV4,
	}
	if enableIPV6 {
		iptypes = append(iptypes, infracommon.IPV6)
	}
	myIPs, err := infracommon.GetExternalPublicAddr(ctx, iptypes...)
	if err != nil {
		// this is not necessarily fatal
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot fetch public ip", "err", err)
	} else {
		var sshPort = []dme.AppPort{{
			PublicPort: 22,
			Proto:      dme.LProto_L_PROTO_TCP,
		}}
		allowedCIDR := infracommon.IPs{}
		if myIPs.IPV4() != "" {
			allowedCIDR[infracommon.IndexIPV4] = myIPs.IPV4() + "/32"
		}
		if myIPs.IPV6() != "" {
			allowedCIDR[infracommon.IndexIPV6] = myIPs.IPV6() + "/128"
		}
		wlParams := infracommon.WhiteListParams{
			ServerName:  rootLBName,
			SecGrpName:  groupName,
			Label:       "rootlb-ssh",
			AllowedCIDR: allowedCIDR,
			Ports:       sshPort,
		}
		err = v.VMProvider.WhitelistSecurityRules(ctx, client, &wlParams)
		if err != nil {
			return err
		}
		if v.VMProperties.RequiresWhitelistOwnIp {
			for _, a := range sd.Addresses {
				// address is a single IP type, but wlParams expects an IP array
				idx := infracommon.IPIndexOf(a.IPVersion)
				mask := "/32"
				if a.IPVersion == infracommon.IPV6 {
					mask = "/128"
				}
				externalAddr := infracommon.IPs{}
				externalAddr[idx] = a.ExternalAddr + mask

				wlParams = infracommon.WhiteListParams{
					ServerName:  rootLBName,
					SecGrpName:  groupName,
					Label:       "own-externalip-ssh",
					AllowedCIDR: externalAddr,
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
	rootLBIPs, err := v.GetExternalIPFromServerName(ctx, rootLBName, WithServerDetail(sd))
	if err != nil {
		return fmt.Errorf("cannot get rootLB IP %sv", err)
	}
	// just for test as this is taking too long
	if v.VMProperties.GetSkipInstallResourceTracker() {
		log.SpanLog(ctx, log.DebugLevelInfra, "skipping install of resource tracker")
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "Copy resource-tracker to rootLb", "rootLb", rootLBName)
		err = CopyResourceTracker(ctx, client)
		if err != nil {
			return fmt.Errorf("cannot copy resource-tracker to rootLb %v", err)
		}
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
	gatewayIPV6 := ni.IPV6RouterGatewayIP
	if rtr != NoConfigExternalRouter && rtr != NoExternalRouter {
		rd, err := v.VMProvider.GetRouterDetail(ctx, v.VMProperties.GetCloudletExternalRouter())
		if err != nil {
			return err
		}
		if gatewayIP == "" {
			gatewayIP = rd.ExternalIP
		}
		if gatewayIPV6 == "" {
			gatewayIPV6 = rd.ExternalIPV6
		}
	}
	gatewayIPs := infracommon.IPs{}
	gatewayIPs[infracommon.IndexIPV4] = gatewayIP
	gatewayIPs[infracommon.IndexIPV6] = gatewayIPV6

	v.SetExternalGateways(ctx, sd, gatewayIPs)
	configNetworks := map[string]struct{}{
		v.VMProperties.GetCloudletExternalNetwork():          {},
		v.VMProperties.GetCloudletExternalNetworkSecondary(): {},
	}
	defaultRouteNets := configNetworks
	err = v.ConfigureNetworkInterfaces(ctx, client, sd, configNetworks, defaultRouteNets, nil)
	if err != nil {
		return err
	}

	if enableIPV6 {
		if err := setupDockerIPV6(ctx, client); err != nil {
			return err
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

	if err = v.ActivateFQDNs(ctx, rootLBFQDN, rootLBIPs.IPV4(), rootLBIPs.IPV6()); err != nil {
		return err
	}
	err = v.proxyCerts.SetupTLSCerts(ctx, rootLBFQDN, rootLBName, client)
	if err != nil {
		return err
	}
	// perform provider specific prep of the rootLB
	secGrpName := infracommon.GetServerSecurityGroupName(rootLBName)
	if v.VMProperties.IptablesBasedFirewall {
		// when using iptables for firewall, we use a common secgrp for cloudlet-wide and per-LB
		secGrpName = infracommon.TrustPolicySecGrpNameLabel
	}
	return v.VMProvider.PrepareRootLB(ctx, client, rootLBName, secGrpName, TrustPolicy, updateCallback)
}

// This function copies resource-tracker from crm to rootLb - we need this to provide docker metrics
func CopyResourceTracker(ctx context.Context, client ssh.Client) error {
	path, err := exec.LookPath("resource-tracker")
	if err != nil {
		return err
	}
	out, err := client.Output("md5sum /usr/local/bin/resource-tracker")
	if err == nil {
		sum, err := cloudcommon.Md5SumFile(path)
		if err == nil && sum == strings.Fields(out)[0] {
			log.SpanLog(ctx, log.DebugLevelInfra, "resource-tracker already present on remote", "md5sum", sum)
			return nil
		}
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

// GetRootLBClients gets rootLb clients for both Shared and Dedicated LBs
func (v *VMPlatform) GetRootLBClients(ctx context.Context) (map[string]platform.RootLBClient, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetAllRootLBClients")
	rootlbClients, err := v.GetDedicatedRootLBClients(ctx)
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
		rootlbClients[v.VMProperties.SharedRootLBName] = platform.RootLBClient{
			Client: sharedClient,
			FQDN:   v.VMProperties.CommonPf.PlatformConfig.RootLBFQDN,
		}
	}
	return rootlbClients, nil
}

func (v *VMPlatform) GetRootLBClientForClusterKey(ctx context.Context, clusterKey *edgeproto.ClusterKey) (map[string]platform.RootLBClient, error) {
	rootLBClients := make(map[string]platform.RootLBClient)

	var clusterInst edgeproto.ClusterInst
	found := v.Caches.ClusterInstCache.Get(clusterKey, &clusterInst)
	if !found {
		return nil, fmt.Errorf("Unable to get clusterInst %v", clusterKey.GetKeyString())
	}
	lbName := v.VMProperties.GetRootLBNameForCluster(ctx, &clusterInst)
	client, err := v.GetClusterPlatformClient(ctx, &clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to get rootLB client for dedicated cluster", "key", clusterInst.Key, "error", err)
		return nil, fmt.Errorf("Unable to get client from clusterInst %v", clusterKey.GetKeyString())
	}
	rootLBClients[lbName] = platform.RootLBClient{
		Client: client,
		FQDN:   clusterInst.StaticFqdn,
	}
	return rootLBClients, nil
}

// GetDedicatedRootLBClients gets all RootLB Clients for dedicated LBs and
// mapping of lbnames to FQDN.
func (v *VMPlatform) GetDedicatedRootLBClients(ctx context.Context) (map[string]platform.RootLBClient, error) {
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
	rootLBClients := make(map[string]platform.RootLBClient)
	clusterKeys := []edgeproto.ClusterKey{}
	v.Caches.ClusterInstCache.GetAllKeys(ctx, func(k *edgeproto.ClusterKey, modRev int64) {
		clusterKeys = append(clusterKeys, *k)
	})
	for _, k := range clusterKeys {
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
				rootLBClients[lbName] = platform.RootLBClient{
					Client: client,
					FQDN:   clusterInst.StaticFqdn,
				}
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
		appInst := edgeproto.AppInst{}
		if !v.Caches.AppInstCache.Get(&k, &appInst) {
			continue
		}
		if _, ok := apps[appInst.AppKey]; !ok {
			continue
		}
		lbName := appInst.StaticUri
		client, err := v.GetSSHClientForServer(ctx, lbName, v.VMProperties.GetCloudletExternalNetwork())
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to get rootLB client for VM app instance", "key", k, "error", err)
			client = nil
			// set client as nil and continue, caller will generate alert accordingly
		}
		rootLBClients[lbName] = platform.RootLBClient{
			Client: client,
			FQDN:   appInst.StaticUri,
		}
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
