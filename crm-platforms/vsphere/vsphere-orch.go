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

package vsphere

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
)

var orchVmLock sync.Mutex

const VLAN_START uint32 = 1000

func getResourcePoolName(groupName, domain string) string {
	return groupName + "-pool" + "-" + domain
}

// user data is encoded as base64
func vmsphereUserDataFormatter(instring string) string {
	// despite the use of paravirtualized drivers, vSphere gets get name sda, sdb
	instring = strings.ReplaceAll(instring, "/dev/vd", "/dev/sd")
	return base64.StdEncoding.EncodeToString([]byte(instring))
}

// meta data needs to have an extra layer "meta" for vsphere
func vmsphereMetaDataFormatter(instring string) string {
	indented := ""
	for _, v := range strings.Split(instring, "\n") {
		indented += strings.Repeat(" ", 4) + v + "\n"
	}
	withMeta := fmt.Sprintf("meta:\n%s", indented)
	return base64.StdEncoding.EncodeToString([]byte(withMeta))
}

// DeleteResourcesForGroup deletes all VMs, tags, and pools for a given resource group
func (v *VSpherePlatform) DeleteResourcesForGroup(ctx context.Context, groupName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteResourcesForGroup", "groupName", groupName)

	// get all vm names
	vmtags, err := v.GetTagsMatchingField(ctx, TagFieldGroup, groupName, v.GetVMDomainTagCategory(ctx))
	if err != nil {
		return err
	}
	// default the domain to the platform domain, override if we find
	// a tag with a different domain. This can happen when the controller directly
	// runs platform code with the domain set to "platform" and deletes the compute VMs
	domain := string(v.vmProperties.Domain)
	for _, vmtag := range vmtags {
		vmDomainTagContents, err := v.ParseVMDomainTag(ctx, vmtag.Name)
		if err != nil {
			return err
		}
		domain = vmDomainTagContents.Domain
		err = v.DeleteVM(ctx, vmDomainTagContents.Vmname)
		if err != nil {
			return err
		}
		err = v.DeleteTag(ctx, vmtag.Name)
		if err != nil {
			return err
		}
	}

	// delete subnet tags
	subTags, err := v.GetTagsMatchingField(ctx, TagFieldGroup, groupName, v.GetSubnetTagCategory(ctx))
	if err != nil {
		return err
	}
	for _, subTag := range subTags {
		err = v.DeleteTag(ctx, subTag.Name)
		if err != nil {
			return err
		}
	}

	// delete vmip tags
	ipTags, err := v.GetTagsMatchingField(ctx, TagFieldGroup, groupName, v.GetVmIpTagCategory(ctx))
	if err != nil {
		return err
	}
	for _, ipTag := range ipTags {
		err = v.DeleteTag(ctx, ipTag.Name)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "DeleteTag error", "err", err)
		}
	}

	// delete resource pool
	poolName := getResourcePoolName(groupName, domain)
	return v.DeletePool(ctx, poolName)
}

func getPortGroupNameForVlan(vlan uint32) string {
	return fmt.Sprintf("VLAN-%d", vlan)
}

// CreatePortGroup creates a portgroup on a DVS for a particular VLAN.  Since Govc does not currently support
// deleting port groups, we use a generic name "VLAN-x" and re-use the port groups when subnets are deleted/added
func (v *VSpherePlatform) CreatePortGroup(ctx context.Context, dvs string, pgName string, vlan uint32) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreatePortGroup", "dvs", dvs, "vlan", vlan)
	dcName := v.GetDatacenterName(ctx)
	out, err := v.TimedGovcCommand(ctx, "govc", "dvs.portgroup.add", "-dc", dcName, "-dvs", dvs, "-vlan", fmt.Sprintf("%d", vlan), "-nports", "100", pgName)
	if err != nil {
		if strings.Contains(string(out), "already exists") {
			log.SpanLog(ctx, log.DebugLevelInfra, "CreatePortGroup already exists", "pgName", pgName)
			return nil
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "Error in CreatePortGroup", "portGroupName", pgName, "out", out, "err", err)
		return fmt.Errorf("Failed to create port group: %s - %v", pgName, err)
	}
	return nil

}

// DeletePool deletes a resource pool
func (v *VSpherePlatform) DeletePool(ctx context.Context, poolName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeletePool", "poolName", poolName)
	dcName := v.GetDatacenterName(ctx)
	computeCluster := v.GetHostCluster()
	pathPrefix := fmt.Sprintf("/%s/host/%s/Resources/", dcName, computeCluster)
	poolPath := pathPrefix + poolName
	out, err := v.TimedGovcCommand(ctx, "govc", "pool.destroy", "-dc", dcName, poolPath)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Error in delete pool", "poolName", poolName, "out", out, "err", err)
		return fmt.Errorf("Failed to delete pool: %s - %v", poolName, err)
	}
	return nil
}

// CreatePool creates a resource pool
func (v *VSpherePlatform) CreatePool(ctx context.Context, poolName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreatePool", "poolName", poolName)

	dcName := v.GetDatacenterName(ctx)
	computeCluster := v.GetHostCluster()
	pathPrefix := fmt.Sprintf("/%s/host/%s/Resources/", dcName, computeCluster)
	poolPath := pathPrefix + poolName
	out, err := v.TimedGovcCommand(ctx, "govc", "pool.create", "-dc", dcName, poolPath)
	if err != nil {
		if strings.Contains(string(out), "already exists") {
			log.SpanLog(ctx, log.DebugLevelInfra, "Pool already exists", "poolName", poolName)
			return nil
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "Error in create pool", "poolName", poolName, "out", out, "err", err)
		return fmt.Errorf("Failed to create pool: %s - %v", poolName, err)
	}
	return nil
}

func (v *VSpherePlatform) populateOrchestrationParams(ctx context.Context, vmgp *vmlayer.VMGroupOrchestrationParams, action vmlayer.ActionType) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "populateOrchestrationParams", "SkipInfraSpecificCheck", vmgp.SkipInfraSpecificCheck)

	subnetToVlan := make(map[string]uint32)
	masterIP := ""
	var flavors []*edgeproto.FlavorInfo
	var err error
	flavors, err = v.vmProperties.GetFlavorListInternal(ctx, v.caches)
	if err != nil {
		return err
	}

	var usedCidrs map[string]string
	if !vmgp.SkipInfraSpecificCheck {
		usedCidrs, err = v.GetUsedSubnetCIDRs(ctx)
		if err != nil {
			return nil
		}
	}
	currentSubnetName := ""
	if action != vmlayer.ActionCreate {
		currentSubnetName = vmlayer.MexSubnetPrefix + vmgp.GroupName
	}

	// find an available subnet or the current subnet for update and delete
	for i, s := range vmgp.Subnets {
		if s.CIDR != vmlayer.NextAvailableResource || vmgp.SkipInfraSpecificCheck {
			// no need to compute the CIDR
			continue
		}
		found := false
		for octet := 0; octet <= 255; octet++ {
			subnet := fmt.Sprintf("%s.%s.%d.%d/%s", vmgp.Netspec.Octets[0], vmgp.Netspec.Octets[1], octet, 0, vmgp.Netspec.NetmaskBits)
			// either look for an unused one (create) or the current one (update)
			newSubnet := action == vmlayer.ActionCreate
			if (newSubnet && usedCidrs[subnet] == "") || (!newSubnet && usedCidrs[subnet] == currentSubnetName) {
				found = true
				vlan := VLAN_START + uint32(octet)
				vmgp.Subnets[i].CIDR = subnet
				vmgp.Subnets[i].GatewayIP = fmt.Sprintf("%s.%s.%d.%d", vmgp.Netspec.Octets[0], vmgp.Netspec.Octets[1], octet, 1)
				vmgp.Subnets[i].NodeIPPrefix = fmt.Sprintf("%s.%s.%d", vmgp.Netspec.Octets[0], vmgp.Netspec.Octets[1], octet)
				vmgp.Subnets[i].Vlan = vlan
				subnetToVlan[s.Name] = vlan
				masterIP = fmt.Sprintf("%s.%s.%d.%d", vmgp.Netspec.Octets[0], vmgp.Netspec.Octets[1], octet, 10)
				tagname := v.GetSubnetTag(ctx, vmgp.GroupName, s.Name, subnet, vlan)
				tagid := v.IdSanitize(tagname)
				vmgp.Tags = append(vmgp.Tags, vmlayer.TagOrchestrationParams{Category: v.GetSubnetTagCategory(ctx), Id: tagid, Name: tagname})
				break
			}
		}
		if !found {
			return fmt.Errorf("cannot find subnet cidr")
		}
	}

	// populate vm fields
	for vmidx, vm := range vmgp.VMs {
		vmHasExternalIp := false
		vmgp.VMs[vmidx].MetaData = vmlayer.GetVMMetaData(vm.Role, masterIP, vmsphereMetaDataFormatter)
		userdata, err := vmlayer.GetVMUserData(vm.Name, vm.SharedVolume, vm.DeploymentManifest, vm.Command, &vm.CloudConfigParams, vmsphereUserDataFormatter)
		if err != nil {
			return err
		}
		vmgp.VMs[vmidx].UserData = userdata
		flavormatch := false
		for _, f := range flavors {
			if f.Name == vm.FlavorName {
				vmgp.VMs[vmidx].Vcpus = f.Vcpus
				vmgp.VMs[vmidx].Disk = f.Disk
				vmgp.VMs[vmidx].Ram = f.Ram
				flavormatch = true
				break
			}
		}
		if !flavormatch {
			return fmt.Errorf("No match in flavor cache for flavor name: %s", vm.FlavorName)
		}
		if vm.AttachExternalDisk {
			// AppVMs use a generic template with the disk attached separately
			var vol vmlayer.VolumeOrchestrationParams
			vol = vmlayer.VolumeOrchestrationParams{
				Name:               "disk0",
				ImageName:          vmgp.VMs[vmidx].ImageFolder + "/" + vmgp.VMs[vmidx].ImageName + ".vmdk",
				AttachExternalDisk: true,
			}
			vmgp.VMs[vmidx].Volumes = append(vmgp.VMs[vmidx].Volumes, vol)
			vmgp.VMs[vmidx].ImageName = ""
		} else {
			vol := vmlayer.VolumeOrchestrationParams{
				Name:               "disk0",
				Size:               vmgp.VMs[vmidx].Disk,
				AttachExternalDisk: false,
			}
			vmgp.VMs[vmidx].Volumes = append(vmgp.VMs[vmidx].Volumes, vol)
		}

		// populate external ips
		if !vmgp.SkipInfraSpecificCheck {
			for pi, portref := range vm.Ports {
				log.SpanLog(ctx, log.DebugLevelInfra, "updating VM port", "portref", portref)
				if portref.NetworkId == v.IdSanitize(v.vmProperties.GetCloudletExternalNetwork()) {
					vmHasExternalIp = true
					var eip string
					if action == vmlayer.ActionUpdate {
						eip, err = v.GetExternalIPForServer(ctx, vm.Name)
						log.SpanLog(ctx, log.DebugLevelInfra, "using current ip for action", "eip", eip, "action", action, "server", vm.Name)
					} else {
						eip, err = v.GetFreeExternalIP(ctx)
					}
					if err != nil {
						return err
					}

					gw, err := v.GetExternalGateway(ctx, "")
					if err != nil {
						return err
					}
					fip := vmlayer.FixedIPOrchestrationParams{
						Subnet:  vmlayer.NewResourceReference(portref.Name, portref.Id, false),
						Mask:    v.GetExternalNetmask(),
						Address: eip,
						Gateway: gw,
					}
					vmgp.VMs[vmidx].FixedIPs = append(vmgp.VMs[vmidx].FixedIPs, fip)
					tagname := v.GetVmIpTag(ctx, vmgp.GroupName, vm.Name, portref.NetworkId, eip)
					tagid := v.IdSanitize(tagname)
					vmgp.Tags = append(vmgp.Tags, vmlayer.TagOrchestrationParams{Category: v.GetVmIpTagCategory(ctx), Id: tagid, Name: tagname})
				} else {
					vlan, ok := subnetToVlan[portref.SubnetId]
					if !ok {
						return fmt.Errorf("cannot find vlan for subnet: %s", portref.SubnetId)
					}
					vm.Ports[pi].PortGroup = getPortGroupNameForVlan(vlan)
				}
			}

			// update fixedips from subnet found
			for fipidx, fip := range vm.FixedIPs {
				if fip.Address == vmlayer.NextAvailableResource {
					found := false
					for _, s := range vmgp.Subnets {
						if s.Name == fip.Subnet.Name {
							found = true
							vmgp.VMs[vmidx].FixedIPs[fipidx].Address = fmt.Sprintf("%s.%d", s.NodeIPPrefix, fip.LastIPOctet)
							vmgp.VMs[vmidx].FixedIPs[fipidx].Mask = v.GetInternalNetmask()

							if !vmHasExternalIp {
								vm.FixedIPs[fipidx].Gateway = s.GatewayIP
							}
							tagname := v.GetVmIpTag(ctx, vmgp.GroupName, vm.Name, s.Id, vmgp.VMs[vmidx].FixedIPs[fipidx].Address)
							tagid := v.IdSanitize(tagname)
							vmgp.Tags = append(vmgp.Tags, vmlayer.TagOrchestrationParams{Category: v.GetVmIpTagCategory(ctx), Id: tagid, Name: tagname})
							log.SpanLog(ctx, log.DebugLevelInfra, "updating address for VM", "vmname", vmgp.VMs[vmidx].Name, "address", vmgp.VMs[vmidx].FixedIPs[fipidx].Address)
							break
						}
					}
					if !found {
						return fmt.Errorf("subnet for vm %s not found", vm.Name)
					}
				}
			}
		}

		// we need to put the fip with the GW in first, so re-sort the fixed ips accordingly
		var sortedFips []vmlayer.FixedIPOrchestrationParams
		for f, fip := range vmgp.VMs[vmidx].FixedIPs {
			if fip.Gateway != "" {
				sortedFips = append([]vmlayer.FixedIPOrchestrationParams{vmgp.VMs[vmidx].FixedIPs[f]}, sortedFips...)
			} else {
				sortedFips = append(sortedFips, vmgp.VMs[vmidx].FixedIPs[f])
			}
		}
		vmgp.VMs[vmidx].FixedIPs = sortedFips

		// we need to put the interface with the external ip first
		var sortedPorts []vmlayer.PortResourceReference
		for p, port := range vmgp.VMs[vmidx].Ports {
			if port.NetworkId == v.vmProperties.GetCloudletExternalNetwork() {
				sortedPorts = append([]vmlayer.PortResourceReference{vmgp.VMs[vmidx].Ports[p]}, sortedPorts...)
			} else {
				sortedPorts = append(sortedPorts, vmgp.VMs[vmidx].Ports[p])
			}
		}
		vmgp.VMs[vmidx].Ports = sortedPorts
		log.SpanLog(ctx, log.DebugLevelInfra, "Interfaces after sorting", "vmname", vmgp.VMs[vmidx].Name, "FixedIPs", vmgp.VMs[vmidx].FixedIPs, "Ports", sortedPorts)

		tagname := v.GetVmDomainTag(ctx, vmgp.GroupName, vm.Name, string(vm.Role), vm.FlavorName)
		tagid := v.IdSanitize(tagname)
		vmgp.Tags = append(vmgp.Tags, vmlayer.TagOrchestrationParams{Category: v.GetVMDomainTagCategory(ctx), Id: tagid, Name: tagname})

	} //for vm

	return nil
}

func (v *VSpherePlatform) DeleteVM(ctx context.Context, vmName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVM", "vmName", vmName)
	dcName := v.GetDatacenterName(ctx)
	out, err := v.TimedGovcCommand(ctx, "govc", "vm.destroy", "-dc", dcName, vmName)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Error in vm.destroy", "vmName", vmName, "out", string(out), "err", err)
		if strings.Contains(string(out), "not found") {
			log.SpanLog(ctx, log.DebugLevelInfra, "VM already gone", "vmName", vmName)
			return fmt.Errorf(vmlayer.ServerDoesNotExistError)
		} else {
			return fmt.Errorf("Error in deleting VM: %s", vmName)
		}
	}
	return nil
}

// CreateVM create a VM in the given pool
func (v *VSpherePlatform) CreateVM(ctx context.Context, vm *vmlayer.VMOrchestrationParams, poolName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateVM", "vmName", vm.Name, "poolName", poolName)

	dcName := v.GetDatacenterName(ctx)
	dsName := v.GetDataStore()
	computeCluster := v.GetHostCluster()
	pathPrefix := fmt.Sprintf("/%s/host/%s/Resources/", dcName, computeCluster)
	poolPath := pathPrefix + poolName
	vmVersion := v.GetVMVersion()

	if len(vm.Ports) == 0 {
		return fmt.Errorf("No networks assigned to VM")
	}
	if len(vm.Volumes) == 0 {
		return fmt.Errorf("No volumes assigned to VM")
	}
	if vm.Volumes[0].AttachExternalDisk {
		// create the VM using an existing disk rather than a clone.  We only support one network being connected currently for this case
		ds := v.GetDataStore()
		netname := vm.Ports[0].NetworkId
		if vm.Ports[0].PortGroup != "" {
			netname = vm.Ports[0].PortGroup
		}
		image := vm.Volumes[0].ImageName
		mappedGuestType, err := vmlayer.GetVmwareMappedOsType(vm.VmAppOsType)
		if err != nil {
			return err
		}
		out, err := v.TimedGovcCommand(ctx, "govc", "vm.create", "-version", vmVersion, "-g", mappedGuestType, "-pool", poolName, "-ds", ds, "-dc", dcName, "-disk", image, "-net", netname, vm.Name)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "Failed to create template VM", "out", string(out), "err", err)
			return fmt.Errorf("Failed to create template VM: %s - %v", string(out), err)
		}
		return nil
	} else {
		// clone from template
		firstNet := vm.Ports[0].NetworkId
		if vm.Ports[0].PortGroup != "" {
			firstNet = vm.Ports[0].PortGroup
		}
		out, err := v.TimedGovcCommand(ctx, "govc", "vm.clone",
			"-dc", dcName,
			"-ds", dsName,
			"-on=false",
			"-vm", vm.ImageName,
			"-pool", poolPath,
			"-c", fmt.Sprintf("%d", vm.Vcpus),
			"-m", fmt.Sprintf("%d", vm.Ram),
			"-net", firstNet,
			vm.Name)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "Error in clone VM", "vmName", vm.Name, "out", string(out), "err", err)
			return fmt.Errorf("Failed to clone VM from template: %s - %s %v", vm.Name, string(out), err)
		}
		// clone only supports 1 network interface, add others here
		for i := range vm.Ports {
			if i >= 1 {
				net := vm.Ports[i].NetworkId
				if vm.Ports[i].PortGroup != "" {
					net = vm.Ports[i].PortGroup
				}
				out, err := v.TimedGovcCommand(ctx, "govc", "vm.network.add", "-dc", dcName, "-vm", vm.Name, "-net", net)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "Error in adding network", "vmName", vm.Name, "net", net, "out", string(out), "err", err)
					return fmt.Errorf("Failed to add network: %s to VM: %s", net, vm.Name)
				}
			}
		}
	}

	// update the disk
	out, err := v.TimedGovcCommand(ctx, "govc", "vm.disk.change", "-dc", dcName, "-vm", vm.Name, "-size", fmt.Sprintf("%dG", vm.Disk))
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Error in change disk size", "vmName", vm.Name, "out", string(out), "err", err)
		return fmt.Errorf("Failed to set disk size: %s - %v", vm.Name, err)
	}
	// customize it
	custArgs := []string{"vm.customize",
		"-vm", vm.Name,
		"-name", vm.HostName,
		"-dc", dcName}

	if len(vm.FixedIPs) == 0 {
		return fmt.Errorf("No IP for VM: %s", vm.Name)
	}

	for _, ip := range vm.FixedIPs {
		netmask, err := vmlayer.MaskLenToMask(ip.Mask)
		if err != nil {
			return err
		}
		dnsServers := []string{vm.CloudConfigParams.PrimaryDNS}
		if vm.CloudConfigParams.FallbackDNS != "" {
			dnsServers = append(dnsServers, vm.CloudConfigParams.FallbackDNS)
		}
		custArgs = append(custArgs, []string{"-ip", ip.Address}...)
		custArgs = append(custArgs, []string{"-netmask", netmask}...)
		custArgs = append(custArgs, []string{"-dns-server", strings.Join(dnsServers, ",")}...)
		if ip.Gateway != "" {
			custArgs = append(custArgs, []string{"-gateway", ip.Gateway}...)
		}
	}
	out, err = v.TimedGovcCommand(ctx, "govc", custArgs...)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Error in customize VM", "vmName", vm.Name, "out", string(out), "err", err)
		return fmt.Errorf("Failed to customize VM: %s - %v", vm.Name, err)
	}
	// if there is a second disk, attach it
	if len(vm.Volumes) > 1 {
		for _, vol := range vm.Volumes {
			if vol.UnitNumber > 0 {
				out, err = v.TimedGovcCommand(ctx, "govc", "vm.disk.create",
					"-dc", dcName,
					"-vm", vm.Name,
					"-size", fmt.Sprintf("%dGB", vol.Size),
					"-name", vol.Name)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "Error in vm.disk.create", "vmName", vm.Name, "out", string(out), "err", err)
					return fmt.Errorf("Failed to attach disk to VM")
				}
			}
		}
	}

	// update guestinfo
	out, err = v.TimedGovcCommand(ctx, "govc", "vm.change",
		"-dc", dcName,
		"-e", "guestinfo.metadata="+vm.MetaData,
		"-e", "guestinfo.metadata.encoding=base64",
		"-e", "guestinfo.userdata="+vm.UserData,
		"-e", "guestinfo.userdata.encoding=base64",
		"-vm", vm.Name)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Error in change VM", "vmName", vm.Name, "out", string(out), "err", err)
		return fmt.Errorf("Failed to set guestinfo for for VM: %s - %v", vm.Name, err)
	}
	// in 1804 we need to ensure the interfaces are connected as the guest tools will not reliably do this
	err = v.ConnectNetworksForVM(ctx, vm.Name)
	if err != nil {
		return err
	}
	return v.SetPowerState(ctx, vm.Name, vmlayer.ActionStart)
}

func (v *VSpherePlatform) createTagsForVMs(ctx context.Context, vmgp *vmlayer.VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "createTagsForVMs")

	// lock until all the tags are created, meaning we have the IPs picked
	orchVmLock.Lock()
	defer orchVmLock.Unlock()
	err := v.populateOrchestrationParams(ctx, vmgp, vmlayer.ActionCreate)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "Updated Group Orch Parms", "vmgp", vmgp)
	updateCallback(edgeproto.UpdateTask, "Creating vCenter Tags")
	for _, t := range vmgp.Tags {
		err := v.CreateTag(ctx, &t)
		if err != nil {
			return err
		}
	}
	return nil
}

func (v *VSpherePlatform) CreateVMs(ctx context.Context, vmgp *vmlayer.VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateVMs")
	err := v.createTagsForVMs(ctx, vmgp, updateCallback)
	if err != nil {
		return err
	}
	updateCallback(edgeproto.UpdateTask, "Creating Distributed Port Groups")
	for _, s := range vmgp.Subnets {
		pgName := getPortGroupNameForVlan(s.Vlan)
		err := v.CreatePortGroup(ctx, v.GetInternalVSwitch(), pgName, s.Vlan)
		if err != nil {
			return err
		}
	}

	poolName := getResourcePoolName(vmgp.GroupName, string(v.vmProperties.Domain))
	err = v.CreatePool(ctx, poolName)
	if err != nil {
		return err
	}
	vmCreateResults := make(chan string, len(vmgp.VMs))
	updateCallback(edgeproto.UpdateTask, "Creating VMs")
	for vmidx := range vmgp.VMs {
		log.SpanLog(ctx, log.DebugLevelInfra, "Creating VM", "vmName", vmgp.VMs[vmidx].Name)
		go func(idx int) {
			err := v.CreateVM(ctx, &vmgp.VMs[idx], poolName)
			if err == nil {
				vmCreateResults <- ""
			} else {
				vmCreateResults <- err.Error()
			}
		}(vmidx)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "Waiting for VM create results")

	errFound := ""
	for range vmgp.VMs {
		result := <-vmCreateResults
		if result != "" {
			errFound = result
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "All VMs finished, checking results")
	if errFound != "" {
		if !vmgp.SkipCleanupOnFailure {
			updateCallback(edgeproto.UpdateTask, "Cleaning up after failure")
			err := v.DeleteResourcesForGroup(ctx, vmgp.GroupName)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "cleanup failed", "err", err)
			}
		}
		return fmt.Errorf("CreateVMs failed: %s", errFound)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateVMs complete")
	return nil
}

func (v *VSpherePlatform) DeleteVMs(ctx context.Context, vmGroupName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVMs", "vmGroupName", vmGroupName)
	return v.DeleteResourcesForGroup(ctx, vmGroupName)
}

// DeleteVMAndTags deletes VM and any tags associated with it. This is used for deleting
// a single VM from a group without deleting the group
func (v *VSpherePlatform) DeleteVMAndTags(ctx context.Context, vmName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteVMAndTags", "vmName", vmName)

	err := v.DeleteVM(ctx, vmName)
	if err != nil {
		return err
	}
	vmTags, err := v.GetTagsMatchingField(ctx, TagFieldVmName, vmName, v.GetVMDomainTagCategory(ctx))
	if err != nil {
		return err
	}
	for _, vmtag := range vmTags {
		err := v.DeleteTag(ctx, vmtag.Name)
		if err != nil {
			return err
		}
	}
	vipTags, err := v.GetTagsMatchingField(ctx, TagFieldVmName, vmName, v.GetVmIpTagCategory(ctx))
	if err != nil {
		return err
	}
	for _, viptag := range vipTags {
		v.DeleteTag(ctx, viptag.Name)
		if err != nil {
			return err
		}
	}
	return nil
}

func (v *VSpherePlatform) GetServerGroupResources(ctx context.Context, name string) (*edgeproto.InfraResources, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetServerGroupResources", "name", name)
	var resources edgeproto.InfraResources
	vmTags, err := v.GetTagsMatchingField(ctx, TagFieldGroup, name, v.GetVMDomainTagCategory(ctx))
	if err != nil {
		return nil, err
	}
	vmips, err := v.GetAllVmIpsFromTags(ctx)
	if err != nil {
		return nil, err
	}
	for _, vt := range vmTags {
		vmDomainTagContents, err := v.ParseVMDomainTag(ctx, vt.Name)
		if err != nil {
			return nil, err
		}
		vminfo := edgeproto.VmInfo{
			Name:        vmDomainTagContents.Vmname,
			InfraFlavor: vmDomainTagContents.Flavor,
			Type:        string(v.vmProperties.GetNodeTypeForVmNameAndRole(vmDomainTagContents.Vmname, vmDomainTagContents.Role).String()),
		}
		ips, ok := vmips[vmDomainTagContents.Vmname]
		if ok {
			for _, ip := range ips {
				var vmip edgeproto.IpAddr
				vmip.ExternalIp = ip
				vminfo.Ipaddresses = append(vminfo.Ipaddresses, vmip)
			}
		}
		resources.Vms = append(resources.Vms, vminfo)
	}
	return &resources, nil
}

func (v *VSpherePlatform) getVMListsForUpdate(ctx context.Context, vmgp *vmlayer.VMGroupOrchestrationParams, vmLists *vmlayer.VMUpdateList, updateCallback edgeproto.CacheUpdateCallback) error {
	orchVmLock.Lock()
	defer orchVmLock.Unlock()
	err := v.populateOrchestrationParams(ctx, vmgp, vmlayer.ActionUpdate)
	if err != nil {
		return err
	}
	// Get existing VMs
	vmTags, err := v.GetTagsMatchingField(ctx, TagFieldGroup, vmgp.GroupName, v.GetVMDomainTagCategory(ctx))
	if err != nil {
		return err
	}
	for _, vt := range vmTags {
		vmDomainTagContents, err := v.ParseVMDomainTag(ctx, vt.Name)
		if err != nil {
			return err
		}
		vmLists.CurrentVMs[vmDomainTagContents.Vmname] = vmDomainTagContents.Vmname
	}
	// Get new VMs
	for i := range vmgp.VMs {
		vmLists.NewVMs[vmgp.VMs[i].Name] = &vmgp.VMs[i]
	}
	// find VMs in new list missing in current list
	for vmname, vmorch := range vmLists.NewVMs {
		_, exists := vmLists.CurrentVMs[vmname]
		if !exists {
			vmLists.VmsToCreate[vmname] = vmorch
		}
	}
	// find VMs in current list missing in new list
	for oldvm, _ := range vmLists.CurrentVMs {
		_, exists := vmLists.NewVMs[oldvm]
		if !exists {
			vmLists.VmsToDelete[oldvm] = oldvm
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "getVMListsForUpdate", "num VMs to create", len(vmLists.VmsToCreate), "num VMs to delete", len(vmLists.VmsToDelete), "VMS", vmLists.VmsToCreate)
	for _, tag := range vmgp.Tags {
		// apply any tags that relate to a new vm
		vmname, err := v.GetValueForTagField(tag.Name, TagFieldVmName)
		if err == nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "getVMListsForUpdate found tag", "tag", tag.Name, "vmname", vmname)
			_, isnew := vmLists.VmsToCreate[vmname]
			if isnew {
				err := v.CreateTag(ctx, &tag)
				if err != nil {
					return err
				}
			}
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "error in GetValueForTagField", "tag", tag.Name, "err", err)
		}
	}
	return nil
}

// UpdateVMs calculates which VMs need to be added or removed from the given group and then does so.  It also
// deletes and removes tags as needed.
func (v *VSpherePlatform) UpdateVMs(ctx context.Context, vmgp *vmlayer.VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMs", "vmGroupName", vmgp.GroupName)

	var vmLists vmlayer.VMUpdateList
	vmLists.CurrentVMs = make(map[string]string)
	vmLists.NewVMs = make(map[string]*vmlayer.VMOrchestrationParams)
	vmLists.VmsToCreate = make(map[string]*vmlayer.VMOrchestrationParams)
	vmLists.VmsToDelete = make(map[string]string)
	err := v.getVMListsForUpdate(ctx, vmgp, &vmLists, updateCallback)
	if err != nil {
		return err
	}

	if len(vmLists.VmsToDelete) > 0 {
		updateCallback(edgeproto.UpdateTask, "Deleting VMs")
	}
	for _, vmname := range vmLists.VmsToDelete {
		err := v.DeleteVMAndTags(ctx, vmname)
		if err != nil {
			return err
		}
	}

	poolName := getResourcePoolName(vmgp.GroupName, string(v.vmProperties.Domain))
	if len(vmLists.VmsToCreate) > 0 {
		updateCallback(edgeproto.UpdateTask, "Creating VMs")
	}
	vmCreateResults := make(chan string, len(vmLists.VmsToCreate))
	for vmn := range vmLists.VmsToCreate {
		go func(vmname string) {
			err := v.CreateVM(ctx, vmLists.VmsToCreate[vmname], poolName)
			if err == nil {
				vmCreateResults <- ""
			} else {
				vmCreateResults <- err.Error()
			}
		}(vmn)
	}
	errFound := false
	for range vmLists.VmsToCreate {
		result := <-vmCreateResults
		if result != "" {
			errFound = true
		}
	}
	if errFound {
		return fmt.Errorf("Error in Creating VMs for update")
	}
	return nil
}

// AttachPortToServer adds a port to the server with the given ipaddr
func (v *VSpherePlatform) AttachPortToServer(ctx context.Context, serverName, subnetName, portName, ipaddr string, action vmlayer.ActionType) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "AttachPortToServer", "serverName", serverName, "subnetName", subnetName)

	portGrp, err := v.GetPortGroup(ctx, serverName, subnetName)
	if err != nil {
		return err
	}
	attached, err := v.IsPortGrpAttached(ctx, serverName, portGrp)
	if err != nil {
		return err
	}
	if attached {
		log.SpanLog(ctx, log.DebugLevelInfra, "AttachPortToServer port already attached")
	} else {
		dcName := v.GetDatacenterName(ctx)
		out, err := v.TimedGovcCommand(ctx, "govc", "vm.network.add", "-dc", dcName, "-vm", serverName, "-net", portGrp)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "vm.network.add failed", "out", out, "err", err)
			return fmt.Errorf("AttachPortToServer failed")
		}
	}
	// now create the tag
	tagName := v.GetVmIpTag(ctx, serverName, serverName, subnetName, ipaddr)
	tagId := v.IdSanitize(tagName)
	tag := vmlayer.TagOrchestrationParams{
		Name:     tagName,
		Id:       tagId,
		Category: v.GetVmIpTagCategory(ctx),
	}
	return v.CreateTag(ctx, &tag)
}

// DetachPortFromServer does not actually detach the port (not supported in govc), but removes the tags
func (v *VSpherePlatform) DetachPortFromServer(ctx context.Context, serverName, subnetName string, portName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DetachPortFromServer", "subnetName", subnetName, "portName", portName)
	// get all the ip tags for this server
	tags, err := v.GetTagsMatchingField(ctx, TagFieldVmName, serverName, v.GetVmIpTagCategory(ctx))
	if err != nil {
		return err
	}
	// delete the tag matching this subnet
	for _, t := range tags {
		vmipTagContents, err := v.ParseVMIpTag(ctx, t.Name)
		if err != nil {
			return err
		}
		if vmipTagContents.Network == subnetName {
			return v.DeleteTag(ctx, t.Name)
		}
	}
	return fmt.Errorf("DetachPortFromServer failed: no IP tag found")
}

// CreateTemplateFromImage creates a vm template from the image file
func (v *VSpherePlatform) CreateTemplateFromImage(ctx context.Context, imageFolder string, imageFile string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateTemplateFromImage", "imageFolder", imageFolder, "imageFile", imageFile)
	ds := v.GetDataStore()
	dcName := v.GetDatacenterName(ctx)
	templateName := imageFile
	folder := v.GetTemplateFolder()
	extNet := v.vmProperties.GetCloudletExternalNetwork()
	pool := fmt.Sprintf("/%s/host/%s/Resources", v.GetDatacenterName(ctx), v.GetHostCluster())
	vmVersion := v.GetVMVersion()

	// create the VM which will become our template
	out, err := v.TimedGovcCommand(ctx, "govc", "vm.create", "-version", vmVersion, "-g", "ubuntu64Guest", "-pool", pool, "-ds", ds, "-dc", dcName, "-folder", folder, "-disk", imageFolder+"/"+imageFile+".vmdk", "-net", extNet, templateName)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Failed to create template VM", "out", string(out), "err", err)
		return fmt.Errorf("Failed to create template VM: %s - %v", string(out), err)
	}

	// try to wait for tools to start. This update the VM so vSphere knows the tools are installed
	log.SpanLog(ctx, log.DebugLevelInfra, "Wait for guest tools to run", "templateName", templateName)
	start := time.Now()
	for {
		vm, err := v.GetGovcVm(ctx, folder+"/"+templateName)
		if err != nil {
			return err
		}
		if vm.Guest.ToolsStatus == "toolsOk" {
			break
		}
		elapsed := time.Since(start)
		if elapsed > maxGuestWait {
			return fmt.Errorf("timed out waiting for VM tools %s", templateName)
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "Sleep and check guest tools again", "templateName", templateName, "ToolsStatus", vm.Guest.ToolsStatus)
		time.Sleep(5 * time.Second)
	}

	// shut off the VM
	err = v.SetPowerState(ctx, folder+"/"+templateName, vmlayer.ActionStop)
	if err != nil {
		return err
	}
	// mark the VM as a template
	out, err = v.TimedGovcCommand(ctx, "govc", "vm.markastemplate", "-dc", dcName, templateName)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Failed to mark VM as template", "out", string(out), "err", err)
		return fmt.Errorf("Failed to mark VM as template: %v", err)
	}
	return nil
}

// ImportImage imports the image file into the datastore
func (v *VSpherePlatform) ImportImage(ctx context.Context, folder, imageFile string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ImportImage", "folder", folder, "imageFile", imageFile)
	ds := v.GetDataStore()
	dcName := v.GetDatacenterName(ctx)

	pool := fmt.Sprintf("/%s/host/%s/Resources", v.GetDatacenterName(ctx), v.GetHostCluster())
	out, err := v.TimedGovcCommand(ctx, "govc", "import.vmdk", "-force", "-pool", pool, "-ds", ds, "-dc", dcName, imageFile, folder)

	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "ImportImage fail", "out", string(out), "err", err)
		return fmt.Errorf("Import Image Fail: %v", err)
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "ImportImage OK", "out", string(out))
	}
	return nil
}
