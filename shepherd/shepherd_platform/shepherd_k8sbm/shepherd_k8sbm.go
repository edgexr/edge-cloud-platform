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

package shepherd_k8sbm

import (
	"context"
	"fmt"
	"strconv"
	"time"

	k8sbm "github.com/edgexr/edge-cloud-infra/crm-platforms/k8s-baremetal"
	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud-infra/promutils"
	"github.com/edgexr/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

const K8sBareMetalStatsCollectionInterval = 1 * time.Minute

var caches *platform.Caches

type ShepherdPlatform struct {
	Pf             *k8sbm.K8sBareMetalPlatform
	platformConfig *platform.PlatformConfig
	promAddr       string
	client         ssh.Client
}

func (s *ShepherdPlatform) Init(ctx context.Context, pc *platform.PlatformConfig, platformCaches *platform.Caches) error {
	s.platformConfig = pc
	return s.Pf.InitCommon(ctx, pc, caches, nil, edgeproto.DummyUpdateCallback)
}

func (s *ShepherdPlatform) SetVMPool(ctx context.Context, vmPool *edgeproto.VMPool) {
	log.SpanLog(ctx, log.DebugLevelMetrics, "unsupported function for bare-metal k8s")
}

func (s *ShepherdPlatform) GetMetricsCollectInterval() time.Duration {
	return K8sBareMetalStatsCollectionInterval
}

func (s *ShepherdPlatform) GetClusterIP(ctx context.Context, clusterInst *edgeproto.ClusterInst) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfo, "no clusterIP for bare-metal k8s")
	return "", nil
}

func (s *ShepherdPlatform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	return s.Pf.GetClusterPlatformClient(ctx, clusterInst, clientType)
}

func (s *ShepherdPlatform) GetVmAppRootLbClient(ctx context.Context, appInst *edgeproto.AppInst) (ssh.Client, error) {
	log.SpanLog(ctx, log.DebugLevelInfo, "VMs are unsupported on k8sbm")
	return nil, fmt.Errorf("VMs are unsupported on k8sbm")
}

func (s *ShepherdPlatform) GetPlatformStats(ctx context.Context) (shepherd_common.CloudletMetrics, error) {
	log.SpanLog(ctx, log.DebugLevelMetrics, "Platform Stats for bare metal k8s")
	if s.promAddr == "" || s.client == nil {
		return shepherd_common.CloudletMetrics{}, fmt.Errorf("Prometheus was not detected on the cluster")
	}

	cloudletMetrics := shepherd_common.CloudletMetrics{}
	// Get Cloudlet CPU Max
	resp, err := promutils.GetPromMetrics(ctx, s.promAddr, promutils.PromQCloudletCpuTotalEncoded, s.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			cloudletMetrics.CollectTime = promutils.ParseTime(metric.Values[0].(float64))
			// copy only if we can parse the value
			if val, err := strconv.ParseUint(metric.Values[1].(string), 10, 64); err == nil {
				cloudletMetrics.VCpuMax = val
				// We should have only one value here
				break
			}
		}
	}
	// Get Cloudlet CPU usage
	if cloudletMetrics.VCpuMax != 0 {
		resp, err = promutils.GetPromMetrics(ctx, s.promAddr, promutils.PromQCpuClustUrlEncoded, s.client)
		if err == nil && resp.Status == "success" {
			for _, metric := range resp.Data.Result {
				if cloudletMetrics.CollectTime == nil {
					cloudletMetrics.CollectTime = promutils.ParseTime(metric.Values[0].(float64))
				}
				// copy only if we can parse the value
				if val, err := strconv.ParseFloat(metric.Values[1].(string), 64); err == nil {
					// from the percentage, figure out number of vcpus used
					cloudletMetrics.VCpuUsed = uint64(float64(cloudletMetrics.VCpuMax) * val / 100)
					// Should be at least one cpu used
					if cloudletMetrics.VCpuUsed == 0 {
						cloudletMetrics.VCpuUsed = 1
					}
					// We should have only one value here
					break
				}
			}
		}
	}
	// Get max mem - in MBs
	resp, err = promutils.GetPromMetrics(ctx, s.promAddr, promutils.PromQCloudletMemTotalEncoded, s.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			cloudletMetrics.CollectTime = promutils.ParseTime(metric.Values[0].(float64))
			// copy only if we can parse the value
			if val, err := strconv.ParseUint(metric.Values[1].(string), 10, 64); err == nil {
				cloudletMetrics.MemMax = uint64(val / (1024 * 1024))
				// We should have only one value here
				break
			}
		}
	}
	// Get mem used - in MBs
	resp, err = promutils.GetPromMetrics(ctx, s.promAddr, promutils.PromQCloudletMemUseEncoded, s.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			if cloudletMetrics.CollectTime == nil {
				cloudletMetrics.CollectTime = promutils.ParseTime(metric.Values[0].(float64))
			}
			// copy only if we can parse the value
			if val, err := strconv.ParseUint(metric.Values[1].(string), 10, 64); err == nil {
				cloudletMetrics.MemUsed = uint64(val / (1024 * 1024))
				// We should have only one value here
				break
			}
		}
	}
	// Get fs usage - in GBs
	resp, err = promutils.GetPromMetrics(ctx, s.promAddr, promutils.PromQCloudletDiskUseEncoded, s.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			if cloudletMetrics.CollectTime == nil {
				cloudletMetrics.CollectTime = promutils.ParseTime(metric.Values[0].(float64))
			}
			// copy only if we can parse the value
			if val, err := strconv.ParseUint(metric.Values[1].(string), 10, 64); err == nil {
				cloudletMetrics.DiskUsed = uint64(val / (1024 * 1024 * 1024))
				// We should have only one value here
				break
			}
		}
	}
	// In GBs
	resp, err = promutils.GetPromMetrics(ctx, s.promAddr, promutils.PromQCloudletDiskTotalEncoded, s.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			if cloudletMetrics.CollectTime == nil {
				cloudletMetrics.CollectTime = promutils.ParseTime(metric.Values[0].(float64))
			}
			// copy only if we can parse the value
			if val, err := strconv.ParseUint(metric.Values[1].(string), 10, 64); err == nil {
				cloudletMetrics.DiskMax = uint64(val / (1024 * 1024 * 1024))
				// We should have only one value here
				break
			}
		}
	}
	// Get IPs range usage
	externalIps, err := infracommon.ParseIpRanges(s.Pf.GetExternalIpRanges())
	if err == nil {
		cloudletMetrics.Ipv4Max = uint64(len(externalIps))
	}
	usedIps, err := s.Pf.GetUsedSecondaryIpAddresses(ctx, s.client, s.Pf.GetExternalEthernetInterface())
	if err == nil {
		cloudletMetrics.Ipv4Used = uint64(len(usedIps))
	}
	return cloudletMetrics, nil
}

func (s *ShepherdPlatform) GetVmStats(ctx context.Context, key *edgeproto.AppInstKey) (shepherd_common.AppMetrics, error) {
	log.SpanLog(ctx, log.DebugLevelInfo, "VMs are unsupported for bare metal k8s")
	return shepherd_common.AppMetrics{}, fmt.Errorf("VMs are unsupported for bare metals k8s")
}

func (s *ShepherdPlatform) VmAppChangedCallback(ctx context.Context, appInst *edgeproto.AppInst, newState edgeproto.TrackedState) {
}

func (s *ShepherdPlatform) SetUsageAccessArgs(ctx context.Context, addr string, client ssh.Client) error {
	if addr == "" {
		return fmt.Errorf("Address cannot be empty")
	}
	s.promAddr = addr
	s.client = client
	return nil
}

func (s *ShepherdPlatform) IsPlatformLocal(ctx context.Context) bool {
	return false
}
