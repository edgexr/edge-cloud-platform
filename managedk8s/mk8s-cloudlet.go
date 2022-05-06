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
	"fmt"

	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/edgexr/edge-cloud/cloudcommon"
	dme "github.com/edgexr/edge-cloud/d-match-engine/dme-proto"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/vault"
	"github.com/edgexr/edge-cloud/vmspec"
	ssh "github.com/mobiledgex/golang-ssh"
)

func (m *ManagedK8sPlatform) SaveCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, accessVarsIn map[string]string, pfConfig *edgeproto.PlatformConfig, vaultConfig *vault.Config, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SaveCloudletAccessVars", "cloudletName", cloudlet.Key.Name)
	return nil
}

func (m *ManagedK8sPlatform) DeleteCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, vaultConfig *vault.Config, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteCloudletAccessVars", "cloudletName", cloudlet.Key.Name)
	return nil
}

func (m *ManagedK8sPlatform) PerformUpgrades(ctx context.Context, caches *platform.Caches, cloudletState dme.CloudletState) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "PerformUpgrades", "cloudletState", cloudletState)
	return nil
}

func (m *ManagedK8sPlatform) GetCloudletManifest(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, accessApi platform.AccessApi, flavor *edgeproto.Flavor, caches *platform.Caches) (*edgeproto.CloudletManifest, error) {
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

func (m *ManagedK8sPlatform) CreateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, flavor *edgeproto.Flavor, caches *platform.Caches, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) (bool, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateCloudlet", "cloudlet", cloudlet)
	cloudletResourcesCreated := false
	if cloudlet.Deployment != cloudcommon.DeploymentTypeKubernetes {
		return cloudletResourcesCreated, fmt.Errorf("Only kubernetes deployment supported for cloudlet platform: %s", m.Type)
	}
	platCfg := infracommon.GetPlatformConfig(cloudlet, pfConfig, accessApi)
	props, err := m.Provider.GetProviderSpecificProps(ctx)
	if err != nil {
		return cloudletResourcesCreated, err
	}
	err = m.Provider.InitApiAccessProperties(ctx, accessApi, cloudlet.EnvVar)
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
	cloudletClusterName := m.getCloudletClusterName(cloudlet)

	// find available flavors
	var info edgeproto.CloudletInfo
	err = m.Provider.GatherCloudletInfo(ctx, &info)
	if err != nil {
		return cloudletResourcesCreated, err
	}
	// at this point we can communicate to the cloudlet so ensure full delete happens on error
	cloudletResourcesCreated = true

	// Find the closest matching vmspec
	cli := edgeproto.CloudletInfo{}
	cli.Key = cloudlet.Key
	cli.Flavors = info.Flavors
	vmsp, err := vmspec.GetVMSpec(ctx, *flavor, cli, nil)
	if err != nil {
		return cloudletResourcesCreated, err
	}
	// create the cluster to run the platform
	kconf := fmt.Sprintf("%s.%s.kubeconfig", cloudlet.Key.Name, "platform")
	client := &pc.LocalClient{}
	err = m.createClusterInstInternal(ctx, client, cloudletClusterName, kconf, 1, vmsp.FlavorName, updateCallback)
	if err != nil {
		return cloudletResourcesCreated, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateCloudlet success")
	return cloudletResourcesCreated, m.CreatePlatformApp(ctx, "crm-"+cloudletClusterName, kconf, accessApi, pfConfig)
}

func (m *ManagedK8sPlatform) UpdateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (m *ManagedK8sPlatform) UpdateTrustPolicy(ctx context.Context, TrustPolicy *edgeproto.TrustPolicy) error {
	log.DebugLog(log.DebugLevelInfra, "update ManagedK8sPlatform TrustPolicy", "policy", TrustPolicy)
	return fmt.Errorf("UpdateTrustPolicy not supported on managed k8s platform: %s", m.Type)
}
func (m *ManagedK8sPlatform) UpdateTrustPolicyException(ctx context.Context, TrustPolicyException *edgeproto.TrustPolicyException, clusterInstKey *edgeproto.ClusterInstKey) error {
	return fmt.Errorf("UpdateTrustPolicyException TODO")
}

func (m *ManagedK8sPlatform) DeleteTrustPolicyException(ctx context.Context, TrustPolicyExceptionKey *edgeproto.TrustPolicyExceptionKey, clusterInstKey *edgeproto.ClusterInstKey) error {
	return fmt.Errorf("DeleteTrustPolicyException TODO")
}

func (m *ManagedK8sPlatform) DeleteCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, caches *platform.Caches, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteCloudlet", "cloudlet", cloudlet)
	platCfg := infracommon.GetPlatformConfig(cloudlet, pfConfig, accessApi)
	props, err := m.Provider.GetProviderSpecificProps(ctx)
	if err != nil {
		return err
	}
	err = m.Provider.InitApiAccessProperties(ctx, accessApi, cloudlet.EnvVar)
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
	cloudletClusterName := m.getCloudletClusterName(cloudlet)
	return m.deleteClusterInstInternal(ctx, cloudletClusterName, updateCallback)
}

func (v *ManagedK8sPlatform) GetRestrictedCloudletStatus(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (v *ManagedK8sPlatform) GetRootLBClients(ctx context.Context) (map[string]ssh.Client, error) {
	return nil, nil
}

func (m *ManagedK8sPlatform) ActiveChanged(ctx context.Context, platformActive bool) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ActiveChanged")
	return nil
}

func (m *ManagedK8sPlatform) NameSanitize(name string) string {
	return m.Provider.NameSanitize(name)
}
