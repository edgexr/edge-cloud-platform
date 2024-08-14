// Copyright 2024 EdgeXR, Inc
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

package k8sop

import (
	"context"
	"fmt"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
)

func (s *K8sOperator) PerformUpgrades(ctx context.Context, caches *platform.Caches, cloudletState dme.CloudletState) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "PerformUpgrades", "cloudletState", cloudletState)
	return nil
}

func (s *K8sOperator) GetCloudletManifest(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfInitConfig *platform.PlatformInitConfig, accessApi platform.AccessApi, flavor *edgeproto.Flavor, caches *platform.Caches) (*edgeproto.CloudletManifest, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "Get cloudlet manifest not supported", "cloudletName", cloudlet.Key.Name)
	return nil, fmt.Errorf("GetCloudletManifest not supported for managed k8s provider")
}

func (s *K8sOperator) VerifyVMs(ctx context.Context, vms []edgeproto.VM) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "VerifyVMs nothing to do")
	return nil
}

func (s *K8sOperator) GetCloudletInfraResources(ctx context.Context) (*edgeproto.InfraResourcesSnapshot, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetCloudletInfraResources")
	// TODO
	return &edgeproto.InfraResourcesSnapshot{}, nil
}

func (s *K8sOperator) CreateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfInitConfig *platform.PlatformInitConfig, flavor *edgeproto.Flavor, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) (bool, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateCloudlet", "cloudlet", cloudlet)
	if cloudlet.InfraApiAccess == edgeproto.InfraApiAccess_RESTRICTED_ACCESS {
		updateCallback(edgeproto.UpdateTask, "Please continue to set up cloudlet-operator manually")
		return false, nil
	}
	return false, fmt.Errorf("Create of single kubernetes cluster from controller is not supported yet, use restricted access for manual setup")
}

func (s *K8sOperator) UpdateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (s *K8sOperator) UpdateTrustPolicy(ctx context.Context, TrustPolicy *edgeproto.TrustPolicy) error {
	log.DebugLog(log.DebugLevelInfra, "update ManagedK8sPlatform TrustPolicy", "policy", TrustPolicy)
	return fmt.Errorf("UpdateTrustPolicy not supported on managed k8s platform: %s", s.Type)
}
func (s *K8sOperator) UpdateTrustPolicyException(ctx context.Context, TrustPolicyException *edgeproto.TrustPolicyException, clusterKey *edgeproto.ClusterKey) error {
	return fmt.Errorf("UpdateTrustPolicyException TODO")
}

func (s *K8sOperator) DeleteTrustPolicyException(ctx context.Context, TrustPolicyExceptionKey *edgeproto.TrustPolicyExceptionKey, clusterKey *edgeproto.ClusterKey) error {
	return fmt.Errorf("DeleteTrustPolicyException TODO")
}

func (s *K8sOperator) DeleteCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfInitConfig *platform.PlatformInitConfig, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteCloudlet", "cloudlet", cloudlet)
	return nil
}

func (s *K8sOperator) GetRestrictedCloudletStatus(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (s *K8sOperator) GetRootLBClients(ctx context.Context) (map[string]platform.RootLBClient, error) {
	return nil, nil
}

func (s *K8sOperator) GetRootLBFlavor(ctx context.Context) (*edgeproto.Flavor, error) {
	return nil, nil
}

func (s *K8sOperator) ActiveChanged(ctx context.Context, platformActive bool) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ActiveChanged")
	return nil
}
