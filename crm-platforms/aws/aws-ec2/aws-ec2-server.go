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
	"encoding/json"
	"fmt"
	"os"
	"time"

	awsgen "github.com/edgexr/edge-cloud-infra/crm-platforms/aws/aws-generic"
	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

func (a *AwsEc2Platform) WaitForVMsToBeInState(ctx context.Context, vmGroupName, state string, maxTime time.Duration) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "WaitForVMsToBeInState", "vmGroupName", vmGroupName, "state", state, "maxTime", maxTime)

	start := time.Now()
	for {
		numRemaining := 0
		remainingInstances, err := a.getEc2Instances(ctx, MatchAnyVmName, vmGroupName)
		if err != nil {
			return err
		}
		for _, res := range remainingInstances.Reservations {
			for _, inst := range res.Instances {
				if inst.State.Name != state {
					numRemaining++
				}
			}
		}
		if numRemaining == 0 {
			break
		}
		elapsed := time.Since(start)
		if elapsed > maxTime {
			return fmt.Errorf("timed out waiting for VMs")
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "Sleep and check VMs again", "numRemaining", numRemaining)
		time.Sleep(5 * time.Second)
	}
	return nil
}

func (a *AwsEc2Platform) DeleteInstances(ctx context.Context, instancesIds []string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteInstances", "instancesIds", instancesIds)

	cmdArgs := []string{
		"ec2",
		"terminate-instances",
		"--region", a.awsGenPf.GetAwsRegion(),
		"--instance-ids",
	}
	cmdArgs = append(cmdArgs, instancesIds...)
	out, err := a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws", cmdArgs...)
	log.SpanLog(ctx, log.DebugLevelInfra, "terminate-instances result", "out", string(out), "err", err)
	if err != nil {
		return fmt.Errorf("terminate ec2 instances failed: %s - %v", string(out), err)
	}
	return nil
}

func (a *AwsEc2Platform) GetServerDetail(ctx context.Context, vmname string) (*vmlayer.ServerDetail, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetServerDetail", "vmname", vmname)

	var sd vmlayer.ServerDetail
	snMap, err := a.GetSubnets(ctx)
	if err != nil {
		return nil, err
	}
	ec2Instances, err := a.getEc2Instances(ctx, vmname, MatchAnyGroupName)
	if err != nil {
		return nil, err
	}
	for _, res := range ec2Instances.Reservations {
		for _, inst := range res.Instances {
			log.SpanLog(ctx, log.DebugLevelInfra, "found server", "vmname", vmname, "state", inst.State)

			switch inst.State.Name {
			case "running":
				sd.Status = vmlayer.ServerActive
			case "stopped":
				fallthrough
			case "stopping":
				fallthrough
			case "pending":
				fallthrough
			case "shutting-down":
				sd.Status = vmlayer.ServerShutoff
			default:
				return nil, fmt.Errorf("unexpected server state: %s server: %s", inst.State.Name, vmname)
			}
			sd.Name = vmname
			sd.ID = inst.InstanceId
			for _, netif := range inst.NetworkInterfaces {
				var sip vmlayer.ServerIP

				log.SpanLog(ctx, log.DebugLevelInfra, "found network interface", "vmname", vmname, "netif", netif)

				if len(netif.PrivateIpAddresses) != 1 {
					log.SpanLog(ctx, log.DebugLevelInfra, "unexpected number of private ips", "netif.PrivateIpAddresses", netif.PrivateIpAddresses)
					continue
				}
				sip.InternalAddr = netif.PrivateIpAddresses[0].PrivateIpAddress
				if netif.PrivateIpAddresses[0].Association.PublicIp != "" {
					sip.ExternalAddr = netif.PrivateIpAddresses[0].Association.PublicIp
					sip.ExternalAddrIsFloating = true
				} else {
					sip.ExternalAddr = sip.InternalAddr
				}
				for sname, sn := range snMap {
					if sn.SubnetId == netif.SubnetId {
						sip.Network = sname
						break
					}
				}
				if sip.Network == "" {
					log.SpanLog(ctx, log.DebugLevelInfra, "Could not find subnet for network interface", "netif.SubnetId", netif.SubnetId, "snMap", snMap)
					return nil, fmt.Errorf("Could not find subnet for network interface subnetid: %s", netif.SubnetId)
				}
				sip.PortName = vmlayer.GetPortName(vmname, sip.Network)
				sip.MacAddress = netif.MacAddress
				sd.Addresses = append(sd.Addresses, sip)

			}
			log.SpanLog(ctx, log.DebugLevelInfra, "active server", "vmname", vmname, "state", inst.State, "sd", sd)
			return &sd, nil
		}
	}
	return &sd, fmt.Errorf(vmlayer.ServerDoesNotExistError)
}

func (a *AwsEc2Platform) AttachPortToServer(ctx context.Context, serverName, subnetName, portName, ipaddr string, action vmlayer.ActionType) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "AttachPortToServer", "serverName", serverName, "subnetName", subnetName, "portName", portName, "ipaddr", ipaddr)

	sn, err := a.GetSubnet(ctx, subnetName)
	if err != nil {
		return err
	}
	sd, err := a.GetServerDetail(ctx, serverName)
	if err != nil {
		return err
	}

	vpc, err := a.GetVPC(ctx, a.GetVpcName())
	if err != nil {
		return err
	}

	secGrpName := infracommon.GetServerSecurityGroupName(serverName)
	sgrp, err := a.GetSecurityGroup(ctx, secGrpName, vpc.VpcId)
	if err != nil {
		return err
	}
	out, err := a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
		"ec2",
		"create-network-interface",
		"--subnet-id", sn.SubnetId,
		"--description", "port "+portName,
		"--private-ip-address", ipaddr,
		"--groups", sgrp.GroupId,
		"--region", a.awsGenPf.GetAwsRegion())
	log.SpanLog(ctx, log.DebugLevelInfra, "create-network-interface result", "out", string(out), "err", err)
	if err != nil {
		return fmt.Errorf("AttachPortToServer create interface failed: %s - %v", string(out), err)
	}
	var createdIf AwsEc2NetworkInterfaceCreateResult
	err = json.Unmarshal(out, &createdIf)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "aws attach-network-interface unmarshal fail", "out", string(out), "err", err)
		return fmt.Errorf("cannot unmarshal, %v", err)
	}
	deviceIndex := len(sd.Addresses)
	log.SpanLog(ctx, log.DebugLevelInfra, "created interface", "interface", createdIf)

	// Attach the interface
	out, err = a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
		"ec2",
		"attach-network-interface",
		"--instance-id", sd.ID,
		"--network-interface-id", createdIf.NetworkInterface.NetworkInterfaceId,
		"--device-index", fmt.Sprintf("%d", deviceIndex),
		"--region", a.awsGenPf.GetAwsRegion())
	log.SpanLog(ctx, log.DebugLevelInfra, "attach-network-interface result", "out", string(out), "err", err)
	if err != nil {
		return fmt.Errorf("AttachPortToServer attach interface failed: %s - %v", string(out), err)
	}

	// Disable SourceDestCheck to allow NAT
	out, err = a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
		"ec2",
		"modify-network-interface-attribute",
		"--no-source-dest-check",
		"--network-interface-id", createdIf.NetworkInterface.NetworkInterfaceId,
		"--region", a.awsGenPf.GetAwsRegion())
	log.SpanLog(ctx, log.DebugLevelInfra, "modify-network-interface-attribute result", "out", string(out), "err", err)
	if err != nil {
		return fmt.Errorf("AttachPortToServer modify interface failed: %s - %v", string(out), err)
	}

	return nil
}

func (a *AwsEc2Platform) CheckServerReady(ctx context.Context, client ssh.Client, serverName string) error {
	// no special checks to be done
	return nil
}

func (a *AwsEc2Platform) CreateVM(ctx context.Context, groupName string, vm *vmlayer.VMOrchestrationParams, groupPorts []vmlayer.PortOrchestrationParams, resources *VmGroupResources) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateVM", "vm", vm, "resources", resources)

	udFileName := "/var/tmp/" + vm.Name + "-userdata.txt"
	udFile, err := os.Create(udFileName)
	defer udFile.Close()
	defer os.Remove(udFileName)
	_, err = udFile.WriteString(vm.UserData)
	if err != nil {
		return fmt.Errorf("Unable to write userdata file for vm: %s - %v", vm.Name, err)
	}

	if len(vm.Ports) == 0 {
		return fmt.Errorf("No ports specified in VM: %s", vm.Name)
	}
	extNet := a.VMProperties.GetCloudletExternalNetwork()
	tagspec := fmt.Sprintf("ResourceType=instance,Tags=[{Key=%s,Value=%s},{Key=%s,Value=%s}]", NameTag, vm.Name, VMGroupNameTag, groupName)
	var networkInterfaces []AwsEc2NetworkInterfaceCreateSpec
	for i, p := range vm.Ports {
		var ni AwsEc2NetworkInterfaceCreateSpec
		ni.DeviceIndex = i
		snName := ""
		if p.NetworkId == extNet {
			snName = p.NetworkId
			ni.AssociatePublicIpAddress = true
		} else {
			// for internal interface allow masquerading
			snName = p.SubnetId
			for _, f := range vm.FixedIPs {
				if f.Subnet.Name == snName {
					ni.PrivateIpAddress = f.Address
				}
			}
		}
		snId, ok := resources.SubnetMap[snName]
		if !ok {
			log.SpanLog(ctx, log.DebugLevelInfra, "subnet not in map", "snId", snId, "subnets", resources.SubnetMap)
			return fmt.Errorf("Could not find subnet: %s", snName)
		}
		ni.SubnetId = snId.SubnetId
		for _, gp := range groupPorts {
			if gp.Name == p.Name {
				for _, s := range gp.SecurityGroups {
					sg, ok := resources.SecGrpMap[s.Name]
					if !ok {
						return fmt.Errorf("Cannot find EC2 security group: %s in vpc: %s", s.Name, resources.VpcId)
					}
					ni.Groups = append(ni.Groups, sg.GroupId)
				}
			}

		}
		networkInterfaces = append(networkInterfaces, ni)
	}
	niParms, err := json.Marshal(networkInterfaces)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Failed to marshal network interfaces", "networkInterfaces", networkInterfaces, "err", err)
		return fmt.Errorf("Failed to marshal network interfaces: %v", err)
	}
	var blockDevices []AwsEc2BlockDeviceMapping
	for _, v := range vm.Volumes {
		blockDevice := AwsEc2BlockDeviceMapping{
			DeviceName: v.DeviceName,
			Ebs: AwsEc2Ebs{
				DeleteOnTermination: true,
				VolumeSize:          vm.Disk,
			},
		}
		blockDevices = append(blockDevices, blockDevice)
	}
	ebsParams, err := json.Marshal(blockDevices)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Failed to marshal ebs block devices", "blockDevices", blockDevices, "err", err)
		return fmt.Errorf("Failed to marshal ec2 ebs disks: %v", err)
	}

	imgId, ok := resources.imageNameToId[vm.ImageName]
	if !ok {
		// should not happen, we should have failed earlier
		return fmt.Errorf("Image not found: %s", imgId)
	}
	createArgs := []string{
		"ec2",
		"run-instances",
		"--image-id", imgId,
		"--count", fmt.Sprintf("%d", 1),
		"--instance-type", vm.FlavorName,
		"--region", a.awsGenPf.GetAwsRegion(),
		"--tag-specifications", tagspec,
		"--user-data", "file://" + udFileName,
		"--network-interfaces", string(niParms),
		"--block-device-mappings", string(ebsParams),
	}
	out, err := a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws", createArgs...)
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateVM result", "out", string(out), "err", err)
	if err != nil {
		return fmt.Errorf("run-instances error: %s - %v", string(out), err)
	}
	return nil
}

func (a *AwsEc2Platform) GetImageId(ctx context.Context, imageName, accountId string) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetImageId", "imageName", imageName, "accountId", accountId)

	out, err := a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
		"ec2",
		"describe-images",
		"--region", a.awsGenPf.GetAwsRegion(),
		"--owners", accountId)

	log.SpanLog(ctx, log.DebugLevelInfra, "describe-images result", "out", string(out), "err", err)
	if err != nil {
		return "", fmt.Errorf("GetImageId failed: %s - %v", string(out), err)
	}

	var images AwsEc2ImageList
	err = json.Unmarshal(out, &images)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "aws describe-images unmarshal fail", "out", string(out), "err", err)
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return "", err
	}
	for _, img := range images.Images {
		if img.Name == imageName {
			if img.State != "available" {
				return "", fmt.Errorf("%s:%s", ImageNotAvailableError, img.State)
			}
			return img.ImageId, nil
		}
	}
	return "", fmt.Errorf(ImageDoesNotExistError)
}

func (a *AwsEc2Platform) getEc2Instances(ctx context.Context, vmNameFilter, groupNameFilter string) (*AwsEc2Instances, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "getEc2Instances", "vmNameFilter", vmNameFilter, "groupNameFilter", groupNameFilter)
	var ec2insts AwsEc2Instances

	// look for instances in any state except terminated
	filters := []string{"--filters", "Name=instance-state-name,Values=pending,running,shutting-down,stopping,stopped"}

	if vmNameFilter != MatchAnyVmName {
		filters = append(filters, "Name=tag-key,Values=Name")
		filters = append(filters, fmt.Sprintf("Name=tag-value,Values=%s", vmNameFilter))
		if groupNameFilter != MatchAnyGroupName {
			return nil, fmt.Errorf("Cannot search for ec2 instances based on both vm and group name")
		}
	}
	if groupNameFilter != MatchAnyGroupName {
		filters = append(filters, fmt.Sprintf("Name=tag-key,Values=%s", VMGroupNameTag))
		filters = append(filters, fmt.Sprintf("Name=tag-value,Values=%s", groupNameFilter))
	}
	cmdArgs := []string{
		"ec2",
		"describe-instances",
		"--region", a.awsGenPf.GetAwsRegion(),
	}
	cmdArgs = append(cmdArgs, filters...)

	out, err := a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws", cmdArgs...)
	if err != nil {
		return nil, fmt.Errorf("Error in describe-instances: %v", err)
	}
	err = json.Unmarshal(out, &ec2insts)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "aws describe-instances unmarshal fail", "out", string(out), "err", err)
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	return &ec2insts, nil
}

func (a *AwsEc2Platform) DetachPortFromServer(ctx context.Context, serverName, subnetName string, portName string) error {
	return fmt.Errorf("DetachPortFromServer not implemented")
}

func (a *AwsEc2Platform) GetVMStats(ctx context.Context, appInst *edgeproto.AppInst) (*vmlayer.VMMetrics, error) {
	log.SpanLog(ctx, log.DebugLevelMetrics, "GetVMStats not supported")
	return &vmlayer.VMMetrics{}, nil
}

func (a *AwsEc2Platform) VmAppChangedCallback(ctx context.Context, appInst *edgeproto.AppInst, newState edgeproto.TrackedState) {
}

func (a *AwsEc2Platform) SetPowerState(ctx context.Context, serverName, serverAction string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SetPowerState not supported")
	return nil
}

func (a *AwsEc2Platform) GetNetworkInterfaces(ctx context.Context) (*AwsEc2NetworkInterfaceList, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetNetworkInterfaces")
	// now add the natgw as the default route
	out, err := a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
		"ec2",
		"describe-network-interfaces",
		"--region", a.awsGenPf.GetAwsRegion())

	if err != nil {
		return nil, fmt.Errorf("Error in describe-network-interfaces : %s - %v", string(out), err)
	}
	var ifList AwsEc2NetworkInterfaceList
	err = json.Unmarshal(out, &ifList)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "aws describe-network-interfaces unmarshal fail", "out", string(out), "err", err)
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	return &ifList, nil
}

func (a *AwsEc2Platform) GetConsoleUrl(ctx context.Context, serverName string) (string, error) {
	return "", fmt.Errorf("GetConsoleUrl not implemented")
}

func (a *AwsEc2Platform) AddImageIfNotPresent(ctx context.Context, imageInfo *infracommon.ImageInfo, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("AddImageIfNotPresent not implemented")
}

func (a *AwsEc2Platform) GetServerGroupResources(ctx context.Context, name string) (*edgeproto.InfraResources, error) {
	return nil, fmt.Errorf("GetServerGroupResources not implemented for AWS EC2")
}
