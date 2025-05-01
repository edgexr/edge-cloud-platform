// Copyright 2025 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sitenodepool

import (
	"context"
	"errors"
	"fmt"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	certscache "github.com/edgexr/edge-cloud-platform/pkg/proxy/certs-cache"
)

func (s *SiteNodePool) PerformUpgrades(ctx context.Context, caches *platform.Caches, cloudletState dme.CloudletState) error {
	return nil
}

func (s *SiteNodePool) GetCloudletManifest(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfInitConfig *platform.PlatformInitConfig, accessApi platform.AccessApi, flavor *edgeproto.Flavor, caches *platform.Caches) (*edgeproto.CloudletManifest, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "Get cloudlet manifest not supported", "cloudletName", cloudlet.Key.Name)
	return nil, fmt.Errorf("GetCloudletManifest not supported")
}

func (s *SiteNodePool) VerifyVMs(ctx context.Context, vms []edgeproto.VM) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "VerifyVMs nothing to do")
	return nil
}

func (s *SiteNodePool) GetCloudletInfraResources(ctx context.Context) (*edgeproto.InfraResourcesSnapshot, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetCloudletInfraResources")
	// TODO
	return &edgeproto.InfraResourcesSnapshot{}, nil
}

func (s *SiteNodePool) CreateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfInitConfig *platform.PlatformInitConfig, flavor *edgeproto.Flavor, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) (bool, error) {
	// nothing to do, cloudlet is just a bunch of site nodes
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateCloudlet", "cloudlet", cloudlet)

	// just do init to catch any configuration errors
	platConfig := infracommon.GetPlatformConfig(cloudlet, pfConfig, pfInitConfig)
	err := s.InitCommon(ctx, platConfig, caches, nil, updateCallback)
	if err != nil {
		return false, err
	}
	return false, nil
}

func (s *SiteNodePool) UpdateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (s *SiteNodePool) ChangeCloudletDNS(ctx context.Context, cloudlet *edgeproto.Cloudlet, oldFqdn string, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (s *SiteNodePool) DeleteCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfInitConfig *platform.PlatformInitConfig, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteCloudlet", "cloudlet", cloudlet)
	return nil
}

func (s *SiteNodePool) UpdateTrustPolicy(ctx context.Context, TrustPolicy *edgeproto.TrustPolicy) error {
	log.DebugLog(log.DebugLevelInfra, "update ManagedK8sPlatform TrustPolicy", "policy", TrustPolicy)
	return fmt.Errorf("UpdateTrustPolicy not supported")
}
func (s *SiteNodePool) UpdateTrustPolicyException(ctx context.Context, TrustPolicyException *edgeproto.TrustPolicyException, clusterKey *edgeproto.ClusterKey) error {
	return fmt.Errorf("UpdateTrustPolicyException TODO")
}

func (s *SiteNodePool) DeleteTrustPolicyException(ctx context.Context, TrustPolicyExceptionKey *edgeproto.TrustPolicyExceptionKey, clusterKey *edgeproto.ClusterKey) error {
	return fmt.Errorf("DeleteTrustPolicyException TODO")
}

func (s *SiteNodePool) GetRestrictedCloudletStatus(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (s *SiteNodePool) GetRootLBClients(ctx context.Context) (map[string]platform.RootLBClient, error) {
	return nil, nil
}

func (s *SiteNodePool) GetRootLBFlavor(ctx context.Context) (*edgeproto.Flavor, error) {
	return &edgeproto.Flavor{}, nil
}

func (s *SiteNodePool) ActiveChanged(ctx context.Context, platformActive bool) error {
	return nil
}

func (s *SiteNodePool) RefreshCerts(ctx context.Context, certsCache *certscache.ProxyCertsCache) error {
	return errors.New("TODO")
}
