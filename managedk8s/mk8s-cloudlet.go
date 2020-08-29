package managedk8s

import (
	"context"
	"fmt"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
	"github.com/mobiledgex/edge-cloud/vmspec"
)

func (m *ManagedK8sPlatform) SaveCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, accessVarsIn map[string]string, pfConfig *edgeproto.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SaveCloudletAccessVars", "cloudletName", cloudlet.Key.Name)
	return nil
}

func (m *ManagedK8sPlatform) DeleteCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteCloudletAccessVars", "cloudletName", cloudlet.Key.Name)
	return nil
}

func (m *ManagedK8sPlatform) SyncControllerCache(ctx context.Context, caches *platform.Caches, cloudletState edgeproto.CloudletState) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SyncControllerCache", "cloudletState", cloudletState)
	return nil
}

func (m *ManagedK8sPlatform) GetCloudletManifest(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, flavor *edgeproto.Flavor, caches *platform.Caches) (*edgeproto.CloudletManifest, error) {
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

func (m *ManagedK8sPlatform) CreateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, flavor *edgeproto.Flavor, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateCloudlet", "cloudlet", cloudlet)

	if cloudlet.Deployment != cloudcommon.DeploymentTypeKubernetes {
		return fmt.Errorf("Only kubernetes deployment supported for cloudlet platform: %s", m.Type)
	}
	vaultConfig, err := vault.BestConfig(pfConfig.VaultAddr)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Failed to get vault configs", "vaultAddr", pfConfig.VaultAddr, "err", err)
		return err
	}
	platCfg := infracommon.GetPlatformConfig(cloudlet, pfConfig)
	props := m.Provider.GetK8sProviderSpecificProps()
	err = m.Provider.InitApiAccessProperties(ctx, platCfg.Region, vaultConfig, platCfg.EnvVars)
	if err != nil {
		return err
	}
	if err := m.CommonPf.InitInfraCommon(ctx, platCfg, props, vaultConfig); err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "InitInfraCommon failed", "err", err)
		return err
	}
	m.Provider.SetCommonPlatform(&m.CommonPf)
	cloudletClusterName := m.getCloudletClusterName(cloudlet)

	// find available flavors
	var info edgeproto.CloudletInfo
	err = m.Provider.GatherCloudletInfo(ctx, &info)
	if err != nil {
		return err
	}
	// Find the closest matching vmspec
	cli := edgeproto.CloudletInfo{}
	cli.Key = cloudlet.Key
	cli.Flavors = info.Flavors
	vmsp, err := vmspec.GetVMSpec(ctx, *flavor, cli, nil)
	if err != nil {
		return err
	}
	// create the cluster to run the platform
	kconf := fmt.Sprintf("%s.%s.kubeconfig", cloudlet.Key.Name, "platform")
	client := &pc.LocalClient{}
	err = m.createClusterInstInternal(ctx, client, cloudletClusterName, kconf, 1, vmsp.FlavorName, updateCallback)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateCloudlet success")
	return m.CreatePlatformApp(ctx, "crm-"+cloudletClusterName, kconf, vaultConfig, pfConfig)
}

func (m *ManagedK8sPlatform) UpdateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (m *ManagedK8sPlatform) DeleteCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteCloudlet", "cloudlet", cloudlet)
	vaultConfig, err := vault.BestConfig(pfConfig.VaultAddr)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Failed to get vault configs", "vaultAddr", pfConfig.VaultAddr, "err", err)
		return err
	}
	platCfg := infracommon.GetPlatformConfig(cloudlet, pfConfig)
	props := m.Provider.GetK8sProviderSpecificProps()
	err = m.Provider.InitApiAccessProperties(ctx, platCfg.Region, vaultConfig, platCfg.EnvVars)
	if err != nil {
		return err
	}
	if err := m.CommonPf.InitInfraCommon(ctx, platCfg, props, vaultConfig); err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "InitInfraCommon failed", "err", err)
		return err
	}
	m.Provider.SetCommonPlatform(&m.CommonPf)
	cloudletClusterName := m.getCloudletClusterName(cloudlet)
	return m.deleteClusterInstInternal(ctx, cloudletClusterName)
}
