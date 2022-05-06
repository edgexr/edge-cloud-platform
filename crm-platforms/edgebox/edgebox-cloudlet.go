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

package edgebox

import (
	"context"

	"github.com/edgexr/edge-cloud-infra/crm-platforms/fakeinfra"
	intprocess "github.com/edgexr/edge-cloud-infra/e2e-tests/int-process"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	pf "github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	dme "github.com/edgexr/edge-cloud/d-match-engine/dme-proto"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/vault"
)

func (e *EdgeboxPlatform) CreateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, flavor *edgeproto.Flavor, caches *pf.Caches, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) (bool, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "create cloudlet for edgebox")
	cloudletResourcesCreated, err := e.generic.CreateCloudlet(ctx, cloudlet, pfConfig, flavor, nil, accessApi, updateCallback)
	if err != nil {
		return cloudletResourcesCreated, err
	}
	if err = fakeinfra.ShepherdStartup(ctx, cloudlet, pfConfig, updateCallback); err != nil {
		return cloudletResourcesCreated, err
	}

	return cloudletResourcesCreated, fakeinfra.CloudletPrometheusStartup(ctx, cloudlet, pfConfig, caches, updateCallback)
}

func (e *EdgeboxPlatform) UpdateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "update cloudlet for edgebox")
	// Update envvars
	e.commonPf.Properties.UpdatePropsFromVars(ctx, cloudlet.EnvVar)
	return nil
}

func (e *EdgeboxPlatform) UpdateTrustPolicy(ctx context.Context, TrustPolicy *edgeproto.TrustPolicy) error {
	log.DebugLog(log.DebugLevelInfra, "update edgebox TrustPolicy", "policy", TrustPolicy)
	return nil
}

func (e *EdgeboxPlatform) UpdateTrustPolicyException(ctx context.Context, TrustPolicyException *edgeproto.TrustPolicyException, clusterInstKey *edgeproto.ClusterInstKey) error {
	log.DebugLog(log.DebugLevelInfra, "update edgebox TrustPolicyException", "policy", TrustPolicyException)
	return nil
}

func (e *EdgeboxPlatform) DeleteTrustPolicyException(ctx context.Context, TrustPolicyExceptionKey *edgeproto.TrustPolicyExceptionKey, clusterInstKey *edgeproto.ClusterInstKey) error {
	log.DebugLog(log.DebugLevelInfra, "delete edgebox TrustPolicyException", "policyKey", TrustPolicyExceptionKey)
	return nil
}

func (e *EdgeboxPlatform) DeleteCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, caches *pf.Caches, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "delete cloudlet for edgebox")
	err := e.generic.DeleteCloudlet(ctx, cloudlet, pfConfig, caches, accessApi, updateCallback)
	if err != nil {
		return err
	}
	updateCallback(edgeproto.UpdateTask, "Stopping Cloudlet Monitoring")
	if err := intprocess.StopCloudletPrometheus(ctx); err != nil {
		return err
	}
	updateCallback(edgeproto.UpdateTask, "Stopping Shepherd")
	return intprocess.StopShepherdService(ctx, cloudlet)
}

func (e *EdgeboxPlatform) SaveCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, accessVarsIn map[string]string, pfConfig *edgeproto.PlatformConfig, vaultConfig *vault.Config, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Saving cloudlet access vars", "cloudletName", cloudlet.Key.Name)
	return nil
}

func (e *EdgeboxPlatform) DeleteCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, vaultConfig *vault.Config, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Deleting cloudlet access vars", "cloudletName", cloudlet.Key.Name)
	return nil
}

func (e *EdgeboxPlatform) PerformUpgrades(ctx context.Context, caches *pf.Caches, cloudletState dme.CloudletState) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "PerformUpgrades", "cloudletState", cloudletState)
	return nil
}

func (e *EdgeboxPlatform) GetCloudletManifest(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, accessApi platform.AccessApi, flavor *edgeproto.Flavor, caches *pf.Caches) (*edgeproto.CloudletManifest, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "Get cloudlet manifest", "cloudletName", cloudlet.Key.Name)
	return e.generic.GetCloudletManifest(ctx, cloudlet, pfConfig, accessApi, flavor, caches)
}

func (e *EdgeboxPlatform) VerifyVMs(ctx context.Context, vms []edgeproto.VM) error {
	return e.generic.VerifyVMs(ctx, vms)
}

func (e *EdgeboxPlatform) GetRestrictedCloudletStatus(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	return e.generic.GetRestrictedCloudletStatus(ctx, cloudlet, pfConfig, accessApi, updateCallback)
}

func (e *EdgeboxPlatform) GetCloudletResourceQuotaProps(ctx context.Context) (*edgeproto.CloudletResourceQuotaProps, error) {
	return e.generic.GetCloudletResourceQuotaProps(ctx)
}

func (e *EdgeboxPlatform) GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource, infraResMap map[string]edgeproto.InfraResource) map[string]edgeproto.InfraResource {
	return e.generic.GetClusterAdditionalResources(ctx, cloudlet, vmResources, infraResMap)
}

func (e *EdgeboxPlatform) GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error {
	return e.generic.GetClusterAdditionalResourceMetric(ctx, cloudlet, resMetric, resources)
}

func (e *EdgeboxPlatform) GetRootLBFlavor(ctx context.Context) (*edgeproto.Flavor, error) {
	return e.generic.GetRootLBFlavor(ctx)
}
