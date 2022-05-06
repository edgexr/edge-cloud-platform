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

package vmpool

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

func (s *VMPoolPlatform) GetFlavorList(ctx context.Context) ([]*edgeproto.FlavorInfo, error) {
	var flavors []*edgeproto.FlavorInfo
	if s.caches == nil || s.caches.VMPool == nil {
		return nil, fmt.Errorf("cache is nil")
	}

	accessIP := ""
	// find one of the VM with external IP
	// we'll use this VM to access VMs with just internal network access
	for _, poolVM := range s.caches.VMPool.Vms {
		if poolVM.NetInfo.ExternalIp != "" {
			accessIP = poolVM.NetInfo.ExternalIp
			break
		}
	}
	if accessIP == "" {
		return nil, fmt.Errorf("At least one VM should have access to external network")
	}
	accessClient, err := s.VMProperties.CommonPf.GetSSHClientFromIPAddr(ctx, accessIP)
	if err != nil {
		return nil, fmt.Errorf("can't get ssh client for %s, %v", accessIP, err)
	}

	flavorMap := make(map[string]struct{})
	updatedVMs := []edgeproto.VM{}

	for _, vm := range s.caches.VMPool.Vms {
		var client ssh.Client
		if vm.NetInfo.ExternalIp != "" {
			client, err = s.VMProperties.CommonPf.GetSSHClientFromIPAddr(ctx, vm.NetInfo.ExternalIp)
			if err != nil {
				return nil, fmt.Errorf("failed to verify vm %s, can't get ssh client for %s, %v", vm.Name, vm.NetInfo.ExternalIp, err)
			}
		} else if vm.NetInfo.InternalIp != "" {
			client, err = accessClient.AddHop(vm.NetInfo.InternalIp, 22)
			if err != nil {
				return nil, fmt.Errorf("failed to verify vm %s, can't get ssh client for %s, %v", vm.Name, vm.NetInfo.InternalIp, err)
			}
		} else {
			return nil, fmt.Errorf("VM %s is missing network info", vm.Name)
		}
		out, err := client.Output("sudo bash /etc/mobiledgex/get-flavor.sh")
		if err != nil {
			return nil, fmt.Errorf("failed to get flavor info for %s: %s - %v", vm.Name, out, err)
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "GetFlavorList, found resource", "vm", vm.Name, "resource info", out)

		parts := strings.Split(out, ",")
		if len(parts) != 3 {
			return nil, fmt.Errorf("invalid flavor info for %s: %s", vm.Name, out)
		}

		memMb, err := strconv.Atoi(parts[0])
		if err != nil || memMb <= 0 {
			return nil, fmt.Errorf("invalid memory info %s for %s: %v", parts[0], vm.Name, err)
		}

		vcpus, err := strconv.Atoi(parts[1])
		if err != nil || vcpus <= 0 {
			return nil, fmt.Errorf("invalid vcpu info %s for %s: %v", parts[1], vm.Name, err)
		}

		diskGb, err := strconv.Atoi(parts[2])
		if err != nil || diskGb <= 0 {
			return nil, fmt.Errorf("invalid disk info %s for %s: %v", parts[2], vm.Name, err)
		}

		flavorName := fmt.Sprintf("vcpu/%d-ram/%d-disk/%d", uint64(vcpus), uint64(memMb), uint64(diskGb))
		vm.Flavor = &edgeproto.FlavorInfo{
			Name:  vm.Name + "-flavor",
			Vcpus: uint64(vcpus),
			Ram:   uint64(memMb),
			Disk:  uint64(diskGb),
		}

		updatedVMs = append(updatedVMs, vm)
		if _, ok := flavorMap[flavorName]; ok {
			continue
		}
		flavorMap[flavorName] = struct{}{}

		var flavInfo edgeproto.FlavorInfo
		flavInfo.Name = flavorName
		flavInfo.Ram = uint64(memMb)
		flavInfo.Vcpus = uint64(vcpus)
		flavInfo.Disk = uint64(diskGb)
		flavors = append(flavors, &flavInfo)
	}

	if len(updatedVMs) > 0 {
		// Update VMs with updated flavor details
		s.caches.VMPoolMux.Lock()
		defer s.caches.VMPoolMux.Unlock()
		s.caches.VMPool.Vms = updatedVMs
		s.UpdateVMPoolInfo(ctx)
	}

	s.FlavorList = flavors

	return flavors, nil
}

func (s *VMPoolPlatform) SetPowerState(ctx context.Context, serverName, serverAction string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SetPowerState not supported")
	return nil
}

func (s *VMPoolPlatform) GetCloudletImageSuffix(ctx context.Context) string {
	return ".qcow2"
}

func (s *VMPoolPlatform) DeleteImage(ctx context.Context, folder, imageName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteImage not supported")
	return nil
}

func (s *VMPoolPlatform) AttachPortToServer(ctx context.Context, serverName, subnetName, portName, ipaddr string, action vmlayer.ActionType) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "AttachPortToServer not supported")
	return nil
}

func (s *VMPoolPlatform) DetachPortFromServer(ctx context.Context, serverName, subnetName string, portName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DetachPortFromServer not supported")
	return nil
}

func (s *VMPoolPlatform) GetNetworkList(ctx context.Context) ([]string, error) {
	return []string{}, nil
}
