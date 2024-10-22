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

package managedk8s

import (
	"context"
	"errors"
	"fmt"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
)

func (m *ManagedK8sPlatform) PerformUpgrades(ctx context.Context, caches *platform.Caches, cloudletState dme.CloudletState) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "PerformUpgrades", "cloudletState", cloudletState)
	return nil
}

func (m *ManagedK8sPlatform) GetCloudletManifest(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfInitConfig *platform.PlatformInitConfig, accessApi platform.AccessApi, flavor *edgeproto.Flavor, caches *platform.Caches) (*edgeproto.CloudletManifest, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "Get cloudlet manifest not supported", "cloudletName", cloudlet.Key.Name)
	return nil, fmt.Errorf("GetCloudletManifest not supported for managed k8s provider")
}

func (m *ManagedK8sPlatform) VerifyVMs(ctx context.Context, vms []edgeproto.VM) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "VerifyVMs nothing to do")
	return nil
}

func (m *ManagedK8sPlatform) getCloudletClusterName(cloudlet *edgeproto.Cloudlet) string {
	return m.Provider.NameSanitize(cloudlet.Key.Name + "-pf")
}

func (m *ManagedK8sPlatform) CreateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfInitConfig *platform.PlatformInitConfig, flavor *edgeproto.Flavor, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) (bool, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateCloudlet", "cloudlet", cloudlet)
	cloudletResourcesCreated := false
	if cloudlet.Deployment != cloudcommon.DeploymentTypeKubernetes && cloudlet.CrmOnEdge {
		return cloudletResourcesCreated, fmt.Errorf("Only kubernetes deployment supported for cloudlet platform: %s", m.Type)
	}
	platCfg := infracommon.GetPlatformConfig(cloudlet, pfConfig, pfInitConfig)
	props := m.Provider.GetFeatures().Properties
	err := m.Provider.InitApiAccessProperties(ctx, platCfg.AccessApi, cloudlet.EnvVar)
	if err != nil {
		return cloudletResourcesCreated, err
	}
	if err := m.CommonPf.InitInfraCommon(ctx, platCfg, props); err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "InitInfraCommon failed", "err", err)
		return cloudletResourcesCreated, err
	}

	err = m.Provider.SetProperties(&m.CommonPf.Properties)
	if err != nil {
		return cloudletResourcesCreated, err
	}

	// find available flavors
	var info edgeproto.CloudletInfo
	err = m.Provider.GatherCloudletInfo(ctx, &info)
	if err != nil {
		return cloudletResourcesCreated, err
	}
	if cloudlet.CrmOnEdge {
		return false, errors.New("managed Kubernetes platforms do not support CRM on edge")
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateCloudlet success")
	return cloudletResourcesCreated, nil
}

func (m *ManagedK8sPlatform) UpdateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (s *ManagedK8sPlatform) ChangeCloudletDNS(ctx context.Context, cloudlet *edgeproto.Cloudlet, oldFqdn string, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (m *ManagedK8sPlatform) UpdateTrustPolicy(ctx context.Context, TrustPolicy *edgeproto.TrustPolicy) error {
	log.DebugLog(log.DebugLevelInfra, "update ManagedK8sPlatform TrustPolicy", "policy", TrustPolicy)
	return fmt.Errorf("UpdateTrustPolicy not supported on managed k8s platform: %s", m.Type)
}
func (m *ManagedK8sPlatform) UpdateTrustPolicyException(ctx context.Context, TrustPolicyException *edgeproto.TrustPolicyException, clusterKey *edgeproto.ClusterKey) error {
	return fmt.Errorf("UpdateTrustPolicyException TODO")
}

func (m *ManagedK8sPlatform) DeleteTrustPolicyException(ctx context.Context, TrustPolicyExceptionKey *edgeproto.TrustPolicyExceptionKey, clusterKey *edgeproto.ClusterKey) error {
	return fmt.Errorf("DeleteTrustPolicyException TODO")
}

func (m *ManagedK8sPlatform) DeleteCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, pfInitConfig *platform.PlatformInitConfig, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteCloudlet", "cloudlet", cloudlet)
	platCfg := infracommon.GetPlatformConfig(cloudlet, pfConfig, pfInitConfig)
	props := m.Provider.GetFeatures().Properties
	err := m.Provider.InitApiAccessProperties(ctx, platCfg.AccessApi, cloudlet.EnvVar)
	if err != nil {
		return err
	}
	if err := m.CommonPf.InitInfraCommon(ctx, platCfg, props); err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "InitInfraCommon failed", "err", err)
		return err
	}
	err = m.Provider.SetProperties(&m.CommonPf.Properties)
	if err != nil {
		return err
	}
	return nil
}

func (v *ManagedK8sPlatform) GetRestrictedCloudletStatus(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (v *ManagedK8sPlatform) GetRootLBClients(ctx context.Context) (map[string]platform.RootLBClient, error) {
	return nil, nil
}

func (m *ManagedK8sPlatform) ActiveChanged(ctx context.Context, platformActive bool) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ActiveChanged")
	return nil
}

func (m *ManagedK8sPlatform) NameSanitize(name string) string {
	return m.Provider.NameSanitize(name)
}
