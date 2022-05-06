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

package shepherd_vmprovider

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

// Default Ceilometer granularity is 300 secs(5 mins)
var sharedRootLBWait = time.Minute * 5

var caches *platform.Caches

// ChangeSinceLastCloudletStats means a VM appinst changed since last VM App stats collection
var ChangeSinceLastVmAppStats bool

type ShepherdPlatform struct {
	rootLbName      string
	SharedClient    ssh.Client
	VMPlatform      *vmlayer.VMPlatform
	collectInterval time.Duration
	platformConfig  *platform.PlatformConfig
	appDNSRoot      string
}

func (s *ShepherdPlatform) setPlatformActiveFromCloudletInfo(ctx context.Context, cloudletInternal *edgeproto.CloudletInternal) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "getPlatformActiveFromCloudletInfo", "cloudletInternal", cloudletInternal)
	activeStr, ok := cloudletInternal.Props[infracommon.CloudletPlatformActive]
	if !ok {
		return nil
	}
	active, err := strconv.ParseBool(activeStr)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "unable to parse CloudletPlatformActive as bool", "activeStr", activeStr, "err", err)
		return fmt.Errorf("unable to parse CloudletPlatformActive as bool")
	} else {
		log.ForceLogSpan(log.SpanFromContext(ctx))
		log.SpanLog(ctx, log.DebugLevelInfra, "ShepherdPlatformActive", "active", active)
		shepherd_common.ShepherdPlatformActive = active
	}
	return nil
}

func (s *ShepherdPlatform) vmProviderCloudletCb(ctx context.Context, old *edgeproto.CloudletInternal, new *edgeproto.CloudletInternal) {
	log.SpanLog(ctx, log.DebugLevelInfra, "vmProviderCloudletCb", "new cloudlet internal", new)
	err := s.setPlatformActiveFromCloudletInfo(ctx, new)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "setPlatformActiveFromCloudletInfo returned error", "err", err)
	}
	s.VMPlatform.VMProvider.InternalCloudletUpdatedCallback(ctx, old, new)
}

func (s *ShepherdPlatform) Init(ctx context.Context, pc *platform.PlatformConfig, platformCaches *platform.Caches) error {
	s.platformConfig = pc
	s.appDNSRoot = pc.AppDNSRoot

	err := s.VMPlatform.VMProperties.CommonPf.InitCloudletSSHKeys(ctx, pc.AccessApi)
	if err != nil {
		return err
	}

	go s.VMPlatform.VMProperties.CommonPf.RefreshCloudletSSHKeys(pc.AccessApi)

	if err = s.VMPlatform.InitProps(ctx, pc); err != nil {
		return err
	}

	s.VMPlatform.Caches = platformCaches
	s.VMPlatform.VMProvider.InitData(ctx, platformCaches)
	// Override cloudlet internal updated callback so CloudletAccessToken updates from the CRM can be stored
	platformCaches.CloudletInternalCache.SetUpdatedCb(s.vmProviderCloudletCb)

	if err = s.VMPlatform.VMProvider.InitApiAccessProperties(ctx, pc.AccessApi, pc.EnvVars); err != nil {
		return err
	}
	if err = s.VMPlatform.VMProvider.InitProvider(ctx, platformCaches, vmlayer.ProviderInitPlatformStartShepherd, edgeproto.DummyUpdateCallback); err != nil {
		return err
	}
	var result vmlayer.OperationInitResult
	ctx, result, err = s.VMPlatform.VMProvider.InitOperationContext(ctx, vmlayer.OperationInitStart)
	if err != nil {
		log.FatalLog("Failed to InitOperationContext", "err", err)
	}
	if result == vmlayer.OperationNewlyInitialized {
		defer s.VMPlatform.VMProvider.InitOperationContext(ctx, vmlayer.OperationInitComplete)
	}
	//need to have a separate one for dedicated rootlbs, see openstack.go line 111,
	s.rootLbName = s.VMPlatform.GetRootLBName(pc.CloudletKey)

	start := time.Now()
	// first wait for the rootlb to exist so we can get a client
	for {
		s.SharedClient, err = s.VMPlatform.GetNodePlatformClient(ctx, &edgeproto.CloudletMgmtNode{Name: s.rootLbName})
		if err == nil {
			break
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "Error getting rootlb client", "rootLB", s.rootLbName, "err", err)
		elapsed := time.Since(start)
		if elapsed > sharedRootLBWait {
			return fmt.Errorf("timed out waiting for shared rootlb %s -- %v", s.rootLbName, err)
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "sleeping 10 seconds before retry", "elapsed", elapsed, "SharedRootLBWait", sharedRootLBWait)
		time.Sleep(10 * time.Second)
	}
	// now wait for the client to be reachable
	err = vmlayer.WaitServerReady(ctx, s.VMPlatform.VMProvider, s.SharedClient, s.rootLbName, vmlayer.MaxRootLBWait)
	if err != nil {
		return err
	}

	// Reuse the same ssh connection whever possible
	err = s.SharedClient.StartPersistentConn(shepherd_common.ShepherdSshConnectTimeout)
	if err != nil {
		return err
	}

	intervalMins, err := s.VMPlatform.VMProperties.GetVmAppMetricsCollectInterval()
	if err != nil {
		return fmt.Errorf("Unable to get VM app collection interval - %v", err)
	}
	s.collectInterval = time.Minute * time.Duration(intervalMins)
	log.SpanLog(ctx, log.DebugLevelInfra, "init shepherd done", "rootLB", s.rootLbName, "physicalName", pc.PhysicalName, "VM App collect interval", s.collectInterval)

	var cloudletInternal edgeproto.CloudletInternal
	if !platformCaches.CloudletInternalCache.Get(pc.CloudletKey, &cloudletInternal) {
		log.SpanLog(ctx, log.DebugLevelInfra, "cloudletInternal not found", "key", pc.CloudletKey)
	} else {
		err = s.setPlatformActiveFromCloudletInfo(ctx, &cloudletInternal)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *ShepherdPlatform) SetVMPool(ctx context.Context, vmPool *edgeproto.VMPool) {
	log.SpanLog(ctx, log.DebugLevelInfra, "set vmpool", "vmpool", vmPool)
	if s.VMPlatform != nil {
		if caches == nil {
			var vmPoolMux sync.Mutex
			caches = &platform.Caches{}
			caches.VMPoolMux = &vmPoolMux
		}
		caches.VMPoolMux.Lock()
		defer caches.VMPoolMux.Unlock()
		caches.VMPool = vmPool
		s.VMPlatform.VMProvider.InitData(ctx, caches)
	}
}

func (s *ShepherdPlatform) GetMetricsCollectInterval() time.Duration {
	return s.collectInterval
}

func (s *ShepherdPlatform) GetClusterIP(ctx context.Context, clusterInst *edgeproto.ClusterInst) (string, error) {
	var err error
	var result vmlayer.OperationInitResult
	ctx, result, err = s.VMPlatform.VMProvider.InitOperationContext(ctx, vmlayer.OperationInitStart)
	if err != nil {
		return "", err
	}
	if result == vmlayer.OperationNewlyInitialized {
		defer s.VMPlatform.VMProvider.InitOperationContext(ctx, vmlayer.OperationInitComplete)
	}
	return s.VMPlatform.GetClusterAccessIP(ctx, clusterInst)
}

func (s *ShepherdPlatform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	var err error
	var result vmlayer.OperationInitResult
	ctx, result, err = s.VMPlatform.VMProvider.InitOperationContext(ctx, vmlayer.OperationInitStart)
	if err != nil {
		return nil, err
	}
	if result == vmlayer.OperationNewlyInitialized {
		defer s.VMPlatform.VMProvider.InitOperationContext(ctx, vmlayer.OperationInitComplete)
	}
	client, err := s.VMPlatform.GetClusterPlatformClientInternal(ctx, clusterInst, clientType, pc.WithCachedIp(false))
	if err != nil {
		return nil, err
	}
	err = client.StartPersistentConn(shepherd_common.ShepherdSshConnectTimeout)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (s *ShepherdPlatform) GetVmAppRootLbClient(ctx context.Context, appInst *edgeproto.AppInst) (ssh.Client, error) {
	var err error
	var result vmlayer.OperationInitResult
	ctx, result, err = s.VMPlatform.VMProvider.InitOperationContext(ctx, vmlayer.OperationInitStart)
	if err != nil {
		return nil, err
	}
	if result == vmlayer.OperationNewlyInitialized {
		defer s.VMPlatform.VMProvider.InitOperationContext(ctx, vmlayer.OperationInitComplete)
	}
	rootLBName := appInst.Uri
	client, err := s.VMPlatform.GetNodePlatformClient(ctx, &edgeproto.CloudletMgmtNode{Name: rootLBName}, pc.WithCachedIp(false))
	if err != nil {
		return nil, err
	}
	err = client.StartPersistentConn(shepherd_common.ShepherdSshConnectTimeout)
	if err != nil {
		return nil, err
	}
	return client, err
}

func (s *ShepherdPlatform) GetPlatformStats(ctx context.Context) (shepherd_common.CloudletMetrics, error) {
	var err error

	cloudletMetric := shepherd_common.CloudletMetrics{}
	if !shepherd_common.ShepherdPlatformActive {
		log.SpanLog(ctx, log.DebugLevelMetrics, "skipping GetPlatformStats for inactive platform")
		return cloudletMetric, nil
	}
	var result vmlayer.OperationInitResult
	ctx, result, err = s.VMPlatform.VMProvider.InitOperationContext(ctx, vmlayer.OperationInitStart)
	if err != nil {
		return cloudletMetric, err
	}
	if result == vmlayer.OperationNewlyInitialized {
		defer s.VMPlatform.VMProvider.InitOperationContext(ctx, vmlayer.OperationInitComplete)
	}
	platformResources, err := s.VMPlatform.VMProvider.GetPlatformResourceInfo(ctx)
	if err != nil {
		return cloudletMetric, err
	}
	log.SpanLog(ctx, log.DebugLevelMetrics, "Got PlatformStats", "platformResources", platformResources, "err", err)
	cloudletMetric = shepherd_common.CloudletMetrics(*platformResources)
	return cloudletMetric, nil
}

func (s *ShepherdPlatform) GetVmStats(ctx context.Context, key *edgeproto.AppInstKey) (shepherd_common.AppMetrics, error) {
	var err error
	appMetrics := shepherd_common.AppMetrics{}
	if !shepherd_common.ShepherdPlatformActive {
		log.SpanLog(ctx, log.DebugLevelMetrics, "skipping GetVmStats for inactive platform")
		return appMetrics, nil
	}
	var result vmlayer.OperationInitResult
	ctx, result, err = s.VMPlatform.VMProvider.InitOperationContext(ctx, vmlayer.OperationInitStart)
	if err != nil {
		return appMetrics, err
	}
	if result == vmlayer.OperationNewlyInitialized {
		defer s.VMPlatform.VMProvider.InitOperationContext(ctx, vmlayer.OperationInitComplete)
	}
	appInst := edgeproto.AppInst{}
	if !s.VMPlatform.Caches.AppInstCache.Get(key, &appInst) {
		return appMetrics, key.NotFoundError()
	}
	vmMetrics, err := s.VMPlatform.VMProvider.GetVMStats(ctx, &appInst)
	if err != nil {
		return appMetrics, err
	}
	appMetrics = shepherd_common.AppMetrics{}
	appMetrics.Cpu = vmMetrics.Cpu
	appMetrics.CpuTS = vmMetrics.CpuTS
	appMetrics.Mem = vmMetrics.Mem
	appMetrics.MemTS = vmMetrics.MemTS
	appMetrics.Disk = vmMetrics.Disk
	appMetrics.DiskTS = vmMetrics.DiskTS
	return appMetrics, nil
}

func (s *ShepherdPlatform) VmAppChangedCallback(ctx context.Context, appInst *edgeproto.AppInst, newState edgeproto.TrackedState) {
	s.VMPlatform.VMProvider.VmAppChangedCallback(ctx, appInst, newState)
}

func (s *ShepherdPlatform) SetUsageAccessArgs(ctx context.Context, addr string, client ssh.Client) error {
	// Nothing to do for vmprovider
	return nil
}

func (s *ShepherdPlatform) IsPlatformLocal(ctx context.Context) bool {
	return false
}
