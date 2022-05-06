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

package awsec2

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

type VmGroupResources struct {
	VpcId         string
	SecGrpMap     map[string]*AwsEc2SecGrp
	SubnetMap     map[string]*AwsEc2Subnet
	imageNameToId map[string]string
}

// meta data needs to have an extra layer "meta" for vsphere
func awsMetaDataFormatter(instring string) string {
	indented := ""
	for _, v := range strings.Split(instring, "\n") {
		indented += strings.Repeat(" ", 4) + v + "\n"
	}
	withMeta := fmt.Sprintf("meta:\n%s", indented)
	return base64.StdEncoding.EncodeToString([]byte(withMeta))
}

// meta data needs to have an extra layer "meta" for vsphere
func awsUserDataFormatter(instring string) string {
	// aws ec2 needs to leave as raw text
	return instring
}

// createVmGroupResources creates subnets, secgrps ahead of VMs.  returns a VmGroupResource struct to be used in VM create
func (a *AwsEc2Platform) getVmGroupResources(ctx context.Context, vmgp *vmlayer.VMGroupOrchestrationParams, action vmlayer.ActionType, updateCallback edgeproto.CacheUpdateCallback) (*VmGroupResources, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "getVmGroupResources", "action", action)

	var resources VmGroupResources
	vpc, err := a.GetVPC(ctx, a.GetVpcName())
	if err != nil {
		return nil, err
	}
	// populate image map
	resources.imageNameToId = make(map[string]string)
	for _, vm := range vmgp.VMs {
		_, ok := resources.imageNameToId[vm.ImageName]
		if !ok {
			imgId, err := a.GetImageId(ctx, vm.ImageName, a.AmiIamAccountId)
			if err != nil {
				return nil, err
			}
			resources.imageNameToId[vm.ImageName] = imgId
		}
	}
	resources.VpcId = vpc.VpcId
	mexNet := a.VMProperties.GetCloudletMexNetwork()
	internalRouteTableId := ""
	if !a.awsGenPf.IsAwsOutpost() {
		internalRouteTableId, err = a.GetRouteTableId(ctx, vpc.VpcId, SearchForRouteTableByName, mexNet)
		if err != nil {
			return nil, err
		}
	}

	// lock around the rest of this function which gets and creates subnets, secgrps
	orchVmLock.Lock()
	defer orchVmLock.Unlock()

	err = a.populateOrchestrationParams(ctx, vmgp, action)
	if err != nil {
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "Orchestration Params after populate", "vmgp", vmgp)
	secGrpMap, err := a.GetSecurityGroups(ctx, vpc.VpcId)
	if err != nil {
		return nil, err
	}
	resources.SecGrpMap = secGrpMap

	if action == vmlayer.ActionCreate {
		updateCallback(edgeproto.UpdateTask, "Creating Security Group")
		for _, sg := range vmgp.SecurityGroups {
			_, ok := secGrpMap[sg.Name]
			if !ok {
				newgrp, err := a.CreateSecurityGroup(ctx, sg.Name, vpc.VpcId, vmgp.GroupName)
				if err != nil {
					if strings.Contains(err.Error(), SecGrpAlreadyExistsError) {
						log.SpanLog(ctx, log.DebugLevelInfra, "security group already exists", "vmgp", vmgp)
					} else {
						return nil, err
					}
				}
				secGrpMap[sg.Name] = newgrp
			}
		}
	}
	if action == vmlayer.ActionCreate {
		updateCallback(edgeproto.UpdateTask, "Creating Subnets")
		for _, sn := range vmgp.Subnets {
			if sn.ReservedName != "" {
				log.SpanLog(ctx, log.DebugLevelInfra, "assign reserved subnet", "ReservedName", sn.ReservedName)
				snMap, err := a.GetSubnets(ctx)
				if err != nil {
					return nil, err
				}
				subn, ok := snMap[sn.ReservedName]
				if !ok {
					return nil, fmt.Errorf("Cannot find reserved subnet in list: %s", sn.ReservedName)
				}
				err = a.AssignFreePrecreatedSubnet(ctx, subn.SubnetId, vmgp.GroupName, sn.Name)
				if err != nil {
					return nil, err
				}
			} else {
				routeTableId := MainRouteTable
				if sn.NetworkName == mexNet {
					routeTableId = internalRouteTableId
				}
				_, err := a.CreateSubnet(ctx, vmgp.GroupName, sn.Name, sn.CIDR, routeTableId)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	snMap, err := a.GetSubnets(ctx)
	if err != nil {
		return nil, err
	}
	resources.SubnetMap = snMap
	return &resources, nil
}

func (a *AwsEc2Platform) populateOrchestrationParams(ctx context.Context, vmgp *vmlayer.VMGroupOrchestrationParams, action vmlayer.ActionType) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "populateOrchestrationParams", "action", action)
	usedCidrs := make(map[string]string)
	if !vmgp.SkipInfraSpecificCheck {
		subs, err := a.GetSubnets(ctx)
		if err != nil {
			return nil
		}
		for _, s := range subs {
			usedCidrs[s.CidrBlock] = s.Name
		}
	}
	var flavors []*edgeproto.FlavorInfo
	var err error
	flavors, err = a.GetFlavorList(ctx)
	if err != nil {
		return err
	}

	masterIP := ""
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
			match := false

			if a.awsGenPf.IsAwsOutpost() {
				_, ok := usedCidrs[subnet]
				if !ok {
					continue
				}
				// find a free one rather than creating one
				if (strings.Contains(usedCidrs[subnet], FreeInternalSubnetType)) || (!newSubnet && usedCidrs[subnet] == currentSubnetName) {
					vmgp.Subnets[i].ReservedName = usedCidrs[subnet]
					match = true
				}
			} else {
				if (newSubnet && usedCidrs[subnet] == "") || (!newSubnet && usedCidrs[subnet] == currentSubnetName) {
					match = true
				}
			}
			if match {
				found = true
				vmgp.Subnets[i].CIDR = subnet
				vmgp.Subnets[i].GatewayIP = fmt.Sprintf("%s.%s.%d.%d", vmgp.Netspec.Octets[0], vmgp.Netspec.Octets[1], octet, 1)
				vmgp.Subnets[i].NodeIPPrefix = fmt.Sprintf("%s.%s.%d", vmgp.Netspec.Octets[0], vmgp.Netspec.Octets[1], octet)
				masterIP = fmt.Sprintf("%s.%s.%d.%d", vmgp.Netspec.Octets[0], vmgp.Netspec.Octets[1], octet, 10)
				break
			}
		}
		if !found {
			return fmt.Errorf("cannot find subnet cidr")
		}
	}
	metaDir := "/mnt/mobiledgex-config/openstack/latest/"
	for vmidx, vm := range vmgp.VMs {
		flavormatch := false
		for _, f := range flavors {
			if f.Name == vm.FlavorName {
				// only the disk needs to be specified
				vmgp.VMs[vmidx].Disk = f.Disk
				flavormatch = true
				break
			}
		}
		if !flavormatch {
			return fmt.Errorf("No match in flavor cache for flavor name: %s", vm.FlavorName)
		}

		// metadata for AWS EC2 is embedded in the user data and then extracted within cloud-init
		metaData := vmlayer.GetVMMetaData(vm.Role, masterIP, awsMetaDataFormatter)
		vm.CloudConfigParams.ExtraBootCommands = append(vm.CloudConfigParams.ExtraBootCommands, "mkdir -p "+metaDir)
		vm.CloudConfigParams.ExtraBootCommands = append(vm.CloudConfigParams.ExtraBootCommands,
			fmt.Sprintf("echo %s |base64 -d|python3 -c \"import sys, yaml, json; json.dump(yaml.load(sys.stdin), sys.stdout)\" > "+metaDir+"meta_data.json", metaData))
		userdata, err := vmlayer.GetVMUserData(vm.Name, vm.SharedVolume, vm.DeploymentManifest, vm.Command, &vm.CloudConfigParams, awsUserDataFormatter)
		if err != nil {
			return err
		}
		vmgp.VMs[vmidx].UserData = userdata
		if len(vm.Volumes) == 0 {
			vol := vmlayer.VolumeOrchestrationParams{
				DeviceName:         "/dev/sda1",
				Name:               "root disk",
				Size:               vmgp.VMs[vmidx].Disk,
				AttachExternalDisk: false,
			}
			vmgp.VMs[vmidx].Volumes = append(vmgp.VMs[vmidx].Volumes, vol)
		}

		for f, fip := range vm.FixedIPs {
			if fip.Address == vmlayer.NextAvailableResource && fip.LastIPOctet != 0 {
				log.SpanLog(ctx, log.DebugLevelInfra, "updating fixed ip", "fixedip", fip)
				for _, s := range vmgp.Subnets {
					if s.Name == fip.Subnet.Name {
						addr := fmt.Sprintf("%s.%d", s.NodeIPPrefix, fip.LastIPOctet)
						log.SpanLog(ctx, log.DebugLevelInfra, "populating fixed ip based on subnet", "addr", addr, "subnet", s)
						vmgp.VMs[vmidx].FixedIPs[f].Address = addr
						break
					}
				}
			}
		}
	}
	return nil
}

func (a *AwsEc2Platform) getVMListsForUpdate(ctx context.Context, vmgp *vmlayer.VMGroupOrchestrationParams, vmLists *vmlayer.VMUpdateList, updateCallback edgeproto.CacheUpdateCallback) error {
	// get current VMs
	vms, err := a.getEc2Instances(ctx, MatchAnyVmName, vmgp.GroupName)
	if err != nil {
		return err
	}
	for _, res := range vms.Reservations {
		for _, vm := range res.Instances {
			for _, tag := range vm.Tags {
				if tag.Key == NameTag {
					vmLists.CurrentVMs[tag.Value] = vm.InstanceId
				}
			}
		}
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
	for oldvm, instanceId := range vmLists.CurrentVMs {
		_, exists := vmLists.NewVMs[oldvm]
		if !exists {
			vmLists.VmsToDelete[oldvm] = instanceId
		}
	}
	return nil
}

// CreateVMs creates the VMs and associated resources provided in the group orch params.  For AWS, VM creation is done in serial
// because it returns almost instantly.  After creation VMs are polled to see that they are all running.
func (a *AwsEc2Platform) CreateVMs(ctx context.Context, vmgp *vmlayer.VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateVMs", "vmgp", vmgp)
	resources, err := a.getVmGroupResources(ctx, vmgp, vmlayer.ActionCreate, updateCallback)
	if err != nil {
		return err
	}
	updateCallback(edgeproto.UpdateTask, "Creating VMs")
	// AWS VM creation into pending state is very fast so no need to do this in multiple threads.
	for _, vm := range vmgp.VMs {
		err := a.CreateVM(ctx, vmgp.GroupName, &vm, vmgp.Ports, resources)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "CreateVM failed", "err", err)
			if !vmgp.SkipCleanupOnFailure {
				a.DeleteVMs(ctx, vmgp.GroupName)
			}
			return err
		}
	}
	// VMs take some time to actually start after create, poll for this
	err = a.WaitForVMsToBeInState(ctx, vmgp.GroupName, "running", maxVMRunningWait)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Waiting for VMs to run failed", "err", err, "GroupName", vmgp.GroupName)
		if !vmgp.SkipCleanupOnFailure {
			a.DeleteVMs(ctx, vmgp.GroupName)
		}
		return err
	}
	return nil
}

func (a *AwsEc2Platform) DeleteVMs(ctx context.Context, vmGroupName string) error {
	return a.DeleteAllResourcesForGroup(ctx, vmGroupName)
}

// UpdateVMs calculates which VMs need to be added or removed from the given group and then does so.
func (a *AwsEc2Platform) UpdateVMs(ctx context.Context, vmgp *vmlayer.VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "UpdateVMs", "vmGroupName", vmgp.GroupName)

	var vmLists vmlayer.VMUpdateList
	vmLists.CurrentVMs = make(map[string]string)
	vmLists.NewVMs = make(map[string]*vmlayer.VMOrchestrationParams)
	vmLists.VmsToCreate = make(map[string]*vmlayer.VMOrchestrationParams)
	vmLists.VmsToDelete = make(map[string]string)
	resources, err := a.getVmGroupResources(ctx, vmgp, vmlayer.ActionUpdate, updateCallback)
	if err != nil {
		return err
	}
	err = a.getVMListsForUpdate(ctx, vmgp, &vmLists, updateCallback)
	if err != nil {
		return err
	}
	if len(vmLists.VmsToDelete) > 0 {
		updateCallback(edgeproto.UpdateTask, "Deleting VMs")
		var instancesIdsToDelete []string
		for _, instanceId := range vmLists.VmsToDelete {
			instancesIdsToDelete = append(instancesIdsToDelete, instanceId)
		}
		err = a.DeleteInstances(ctx, instancesIdsToDelete)
		if err != nil {
			return err
		}
	}
	if len(vmLists.VmsToCreate) > 0 {
		updateCallback(edgeproto.UpdateTask, "Creating VMs")
		for _, vmorch := range vmLists.VmsToCreate {
			err := a.CreateVM(ctx, vmgp.GroupName, vmorch, vmgp.Ports, resources)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *AwsEc2Platform) DeleteAllResourcesForGroup(ctx context.Context, vmGroupName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteAllResourcesForGroup", "vmGroupName", vmGroupName)
	ec2Instances, err := a.getEc2Instances(ctx, MatchAnyVmName, vmGroupName)
	if err != nil {
		return err
	}
	vpc, err := a.GetVPC(ctx, a.GetVpcName())
	if err != nil {
		return err
	}
	var instanceIdList []string
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "Delete vms for group", "vmGroupName", vmGroupName)

	for _, res := range ec2Instances.Reservations {
		for _, inst := range res.Instances {
			if inst.State.Name != "terminated" {
				instanceIdList = append(instanceIdList, inst.InstanceId)
			}
		}
	}
	if len(instanceIdList) == 0 {
		log.SpanLog(ctx, log.DebugLevelInfra, "No instances to delete", "vmGroupName", vmGroupName)
	} else {
		err = a.DeleteInstances(ctx, instanceIdList)
		if err != nil {
			return err
		}

		err = a.WaitForVMsToBeInState(ctx, vmGroupName, "terminated", maxVMTerminateWait)
		if err != nil {
			return err
		}
		// we cannot delete subnets, etc until the VMs are gone.  Wait for this to happen
		log.SpanLog(ctx, log.DebugLevelInfra, "Waiting for VMs to be terminated", "instanceIdList", instanceIdList)
		start := time.Now()
		for {
			numRemaining := 0
			remainingInstances, err := a.getEc2Instances(ctx, MatchAnyVmName, vmGroupName)
			if err != nil {
				return err
			}
			for _, res := range remainingInstances.Reservations {
				for _, inst := range res.Instances {
					if inst.State.Name != "terminated" {
						numRemaining++
					}
				}
			}
			if numRemaining == 0 {
				break
			}
			elapsed := time.Since(start)
			if elapsed > maxVMTerminateWait {
				return fmt.Errorf("timed out waiting for VMs to terminate")
			}
			log.SpanLog(ctx, log.DebugLevelInfra, "Sleep and check VMs again", "numRemaining", numRemaining)
			time.Sleep(5 * time.Second)
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "Delete subnets for group", "vmGroupName", vmGroupName)
	subNets, err := a.GetSubnets(ctx)
	for _, s := range subNets {
		for _, tag := range s.Tags {
			// currently we never delete external subnets as this is created with the cloudlet.  This
			// will need to be revisited when supporting create and delete cloudlet for outpost
			subnetType := FreeInternalSubnetType
			if tag.Key == VMGroupNameTag && tag.Value == vmGroupName {
				if a.awsGenPf.IsAwsOutpost() {
					err = a.ReleasePrecreatedSubnet(ctx, s.SubnetId, vmGroupName, subnetType)
				} else {
					err = a.DeleteSubnet(ctx, s.SubnetId)
				}
				if err != nil {
					return err
				}
			}
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "Delete security groups for VM group", "vmGroupName", vmGroupName)

	sgMap, err := a.GetSecurityGroups(ctx, vpc.VpcId)
	for _, sg := range sgMap {
		for _, tag := range sg.Tags {
			if tag.Key == VMGroupNameTag && tag.Value == vmGroupName {
				err = a.DeleteSecurityGroup(ctx, sg.GroupId, vpc.VpcId)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}
