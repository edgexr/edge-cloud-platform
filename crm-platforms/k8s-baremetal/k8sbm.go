package k8sbm

import (
	"context"
	"fmt"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	dme "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
	ssh "github.com/mobiledgex/golang-ssh"
)

type K8sBareMetalPlatform struct {
	commonPf           infracommon.CommonPlatform
	caches             *platform.Caches
	FlavorList         []*edgeproto.FlavorInfo
	sharedLBName       string
	cloudletKubeConfig string
	externalIps        []string
	internalIps        []string
}

func (k *K8sBareMetalPlatform) GetCloudletKubeConfig(cloudletKey *edgeproto.CloudletKey) string {
	return fmt.Sprintf("%s-%s", cloudletKey.Name, "cloudlet-kubeconfig")
}

func (k *K8sBareMetalPlatform) IsCloudletServicesLocal() bool {
	return false
}

func (k *K8sBareMetalPlatform) Init(ctx context.Context, platformConfig *platform.PlatformConfig, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Init start")
	k.caches = caches
	if err := k.commonPf.InitInfraCommon(ctx, platformConfig, k8sbmProps); err != nil {
		return err
	}
	externalIps, err := infracommon.ParseIpRanges(k.GetExternalIpRanges())
	if err != nil {
		return err
	}
	k.externalIps = externalIps
	internalIps, err := infracommon.ParseIpRanges(k.GetInternalIpRanges())
	if err != nil {
		return err
	}
	if len(externalIps) > len(internalIps) {
		log.SpanLog(ctx, log.DebugLevelInfra, "Not enough internal IPs", "numexternal", len(externalIps), "numinternal", len(internalIps))
		return fmt.Errorf("Number of internal IPs defined in K8S_INTERNAL_IP_RANGES must be at least as many as K8S_EXTERNAL_IP_RANGES")
	}
	k.internalIps = internalIps
	k.sharedLBName = k.GetSharedLBName(ctx, platformConfig.CloudletKey)
	k.cloudletKubeConfig = k.GetCloudletKubeConfig(platformConfig.CloudletKey)

	if !platformConfig.TestMode {
		err := k.commonPf.InitCloudletSSHKeys(ctx, platformConfig.AccessApi)
		if err != nil {
			return err
		}
		go k.commonPf.RefreshCloudletSSHKeys(platformConfig.AccessApi)
	}

	client, err := k.GetNodePlatformClient(ctx, &edgeproto.CloudletMgmtNode{Name: platformConfig.CloudletKey.String(), Type: "k8sbmcontrolhost"})
	if err != nil {
		return err
	}
	err = k.SetupLb(ctx, client, k.sharedLBName)
	if err != nil {
		return err
	}
	return nil
}

func (k *K8sBareMetalPlatform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "GatherCloudletInfo")
	var err error
	info.Flavors, err = k.GetFlavorList(ctx)
	return err
}

// TODO
func (k *K8sBareMetalPlatform) GetCloudletInfraResources(ctx context.Context) (*edgeproto.InfraResourcesSnapshot, error) {
	var resources edgeproto.InfraResourcesSnapshot
	return &resources, nil
}

// TODO
func (k *K8sBareMetalPlatform) GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource, infraResMap map[string]edgeproto.InfraResource) map[string]edgeproto.InfraResource {
	resInfo := make(map[string]edgeproto.InfraResource)
	return resInfo
}

// TODO
func (k *K8sBareMetalPlatform) GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error {
	externalIpsUsed := uint64(0)
	for _, vmRes := range resources {
		if vmRes.Type == cloudcommon.VMTypeRootLB {
			externalIpsUsed += 1
		}
	}
	resMetric.AddIntVal("externalIpsUsed", externalIpsUsed)
	return nil
}

// TODO
func (k *K8sBareMetalPlatform) GetClusterInfraResources(ctx context.Context, clusterKey *edgeproto.ClusterInstKey) (*edgeproto.InfraResources, error) {
	var resources edgeproto.InfraResources
	return &resources, nil
}

// TODO
func (k *K8sBareMetalPlatform) GetAppInstRuntime(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) (*edgeproto.AppInstRuntime, error) {
	return &edgeproto.AppInstRuntime{}, nil
}

// GetClusterPlatformClient is not needed presently for bare metal
func (k *K8sBareMetalPlatform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	return nil, fmt.Errorf("GetClusterPlatformClient not supported")
}

func (k *K8sBareMetalPlatform) GetNodePlatformClient(ctx context.Context, node *edgeproto.CloudletMgmtNode, ops ...pc.SSHClientOp) (ssh.Client, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetNodePlatformClient", "node", node)
	if node == nil || node.Name == "" {
		return nil, fmt.Errorf("cannot GetNodePlatformClient, node details are empty")
	}
	controlIp := k.GetControlAccessIp()
	return k.commonPf.GetSSHClientFromIPAddr(ctx, controlIp, ops...)
}

// TODO
func (k *K8sBareMetalPlatform) ListCloudletMgmtNodes(ctx context.Context, clusterInsts []edgeproto.ClusterInst) ([]edgeproto.CloudletMgmtNode, error) {
	return []edgeproto.CloudletMgmtNode{}, nil
}

// TODO
func (k *K8sBareMetalPlatform) GetContainerCommand(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, req *edgeproto.ExecRequest) (string, error) {
	return "", fmt.Errorf("GetContainerCommand TODO")
}

func (k *K8sBareMetalPlatform) GetConsoleUrl(ctx context.Context, app *edgeproto.App) (string, error) {
	return "", fmt.Errorf("GetConsoleUrl not supported on BareMetal")
}

func (k *K8sBareMetalPlatform) SaveCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, accessVarsIn map[string]string, pfConfig *edgeproto.PlatformConfig, vaultConfig *vault.Config, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SaveCloudletAccessVars", "cloudletName", cloudlet.Key.Name)
	return nil
}

func (k *K8sBareMetalPlatform) GetCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, vaultConfig *vault.Config) (map[string]string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetCloudletAccessVars", "cloudletName", cloudlet.Key.Name)
	return map[string]string{}, nil
}

func (k *K8sBareMetalPlatform) DeleteCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, vaultConfig *vault.Config, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteCloudletAccessVars", "cloudletName", cloudlet.Key.Name)
	return nil
}

func (k *K8sBareMetalPlatform) SetPowerState(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("SetPowerState not supported on BareMetal")
}

func (k *K8sBareMetalPlatform) runDebug(ctx context.Context, req *edgeproto.DebugRequest) string {
	return "runDebug TODO on bare metal"
}

func (k *K8sBareMetalPlatform) SyncControllerCache(ctx context.Context, caches *platform.Caches, cloudletState dme.CloudletState) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SyncControllerCache", "state", cloudletState)
	return nil
}

func (k *K8sBareMetalPlatform) GetCloudletManifest(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, accessApi platform.AccessApi, flavor *edgeproto.Flavor, caches *platform.Caches) (*edgeproto.CloudletManifest, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "Get cloudlet manifest", "cloudletName", cloudlet.Key.Name)
	return &edgeproto.CloudletManifest{Manifest: "GetCloudletManifest TODO\n" + pfConfig.CrmAccessPrivateKey}, nil
}

func (k *K8sBareMetalPlatform) VerifyVMs(ctx context.Context, vms []edgeproto.VM) error {
	return nil
}

func (k *K8sBareMetalPlatform) GetAccessData(ctx context.Context, cloudlet *edgeproto.Cloudlet, region string, vaultConfig *vault.Config, dataType string, arg []byte) (map[string]string, error) {
	return nil, fmt.Errorf("GetAccessData not implemented")
}

func (k *K8sBareMetalPlatform) GetRestrictedCloudletStatus(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (k *K8sBareMetalPlatform) GetRootLBClients(ctx context.Context) (map[string]ssh.Client, error) {
	return nil, nil
}

func (k *K8sBareMetalPlatform) GetVersionProperties() map[string]string {
	return map[string]string{}
}
