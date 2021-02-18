package vmpool

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
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

	wgError := make(chan error)
	wgDone := make(chan bool)
	var mux sync.Mutex
	var wg sync.WaitGroup
	for _, vm := range s.caches.VMPool.Vms {
		var client ssh.Client
		if vm.NetInfo.ExternalIp != "" {
			client, err = s.VMProperties.CommonPf.GetSSHClientFromIPAddr(ctx, accessIP)
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
		wg.Add(1)
		go func(clientIn ssh.Client, vmIn edgeproto.VM, wg *sync.WaitGroup) {
			out, err := clientIn.Output("sudo bash /etc/mobiledgex/get-flavor.sh")
			if err != nil {
				wgError <- fmt.Errorf("failed to get flavor info for %s: %s - %v", vmIn.Name, out, err)
				return
			}
			log.SpanLog(ctx, log.DebugLevelInfra, "GetFlavorList, found resource", "vm", vmIn.Name, "resource info", out)

			parts := strings.Split(out, ",")
			if len(parts) != 3 {
				wgError <- fmt.Errorf("invalid flavor info for %s: %s", vmIn.Name, out)
				return
			}

			memMb, err := strconv.Atoi(parts[0])
			if err != nil || memMb <= 0 {
				wgError <- fmt.Errorf("invalid memory info %s for %s: %v", parts[0], vmIn.Name, err)
				return
			}

			vcpus, err := strconv.Atoi(parts[1])
			if err != nil || vcpus <= 0 {
				wgError <- fmt.Errorf("invalid vcpu info %s for %s: %v", parts[1], vmIn.Name, err)
				return
			}

			diskGb, err := strconv.Atoi(parts[2])
			if err != nil || diskGb <= 0 {
				wgError <- fmt.Errorf("invalid disk info %s for %s: %v", parts[2], vmIn.Name, err)
				return
			}

			defer wg.Done()

			flavorName := fmt.Sprintf("vcpu/%d-ram/%d-disk/%d", uint64(vcpus), uint64(memMb), uint64(diskGb))
			vmIn.Flavor = &edgeproto.FlavorInfo{
				Name:  vmIn.Name + "-flavor",
				Vcpus: uint64(vcpus),
				Ram:   uint64(memMb),
				Disk:  uint64(diskGb),
			}

			mux.Lock()
			updatedVMs = append(updatedVMs, vmIn)
			if _, ok := flavorMap[flavorName]; ok {
				mux.Unlock()
				return
			}
			flavorMap[flavorName] = struct{}{}

			var flavInfo edgeproto.FlavorInfo
			flavInfo.Name = flavorName
			flavInfo.Ram = uint64(memMb)
			flavInfo.Vcpus = uint64(vcpus)
			flavInfo.Disk = uint64(diskGb)
			flavors = append(flavors, &flavInfo)
			mux.Unlock()
		}(client, vm, &wg)
	}

	go func() {
		wg.Wait()
		close(wgDone)
	}()

	// Wait until either WaitGroup is done or an error is received through the channel
	select {
	case <-wgDone:
		break
	case err := <-wgError:
		close(wgError)
		return nil, err
	case <-time.After(AllVMAccessTimeout):
		return nil, fmt.Errorf("Timed out fetching flavor list from VMs")
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

func (s *VMPoolPlatform) AddCloudletImageIfNotPresent(ctx context.Context, imgPathPrefix, imgVersion string, updateCallback edgeproto.CacheUpdateCallback) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddCloudletImageIfNotPresent not supported")
	imgPath := vmlayer.GetCloudletVMImagePath(imgPathPrefix, imgVersion, s.GetCloudletImageSuffix(ctx))

	// Fetch platform base image name
	pfImageName, err := cloudcommon.GetFileName(imgPath)
	if err != nil {
		return "", err
	}
	return pfImageName, nil
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
