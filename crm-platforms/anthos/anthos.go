package anthos

import (
	"context"
	"fmt"
	"time"

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

type AnthosPlatform struct {
	commonPf   infracommon.CommonPlatform
	caches     *platform.Caches
	FlavorList []*edgeproto.FlavorInfo
}

var RootLBFlavor = edgeproto.Flavor{
	Key:   edgeproto.FlavorKey{Name: "rootlb-flavor"},
	Vcpus: uint64(2),
	Ram:   uint64(4096),
	Disk:  uint64(40),
}

func (a *AnthosPlatform) Init(ctx context.Context, platformConfig *platform.PlatformConfig, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Init")

	if err := a.commonPf.InitInfraCommon(ctx, platformConfig, anthosProps); err != nil {
		return err
	}
	return nil
}

func (a *AnthosPlatform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	return nil
}

func (a *AnthosPlatform) CreateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) error {
	return fmt.Errorf("CreateClusterInst todo")
}

func (a *AnthosPlatform) UpdateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("UpdateClusterInst todo")
}

func (a *AnthosPlatform) DeleteClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("UpdateClusterInst todo")
}

func (a *AnthosPlatform) GetCloudletInfraResources(ctx context.Context) (*edgeproto.InfraResourcesSnapshot, error) {
	var resources edgeproto.InfraResourcesSnapshot
	return &resources, nil
}

// called by controller, make sure it doesn't make any calls to infra API
func (a *AnthosPlatform) GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource, infraResMap map[string]edgeproto.InfraResource) map[string]edgeproto.InfraResource {
	resInfo := make(map[string]edgeproto.InfraResource)
	return resInfo
}

func (a *AnthosPlatform) GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error {
	externalIpsUsed := uint64(0)
	for _, vmRes := range resources {
		if vmRes.Type == cloudcommon.VMTypeRootLB {
			externalIpsUsed += 1
		}
	}
	resMetric.AddIntVal("externalIpsUsed", externalIpsUsed)
	return nil
}

func (a *AnthosPlatform) GetClusterInfraResources(ctx context.Context, clusterKey *edgeproto.ClusterInstKey) (*edgeproto.InfraResources, error) {
	var resources edgeproto.InfraResources
	return &resources, nil
}

func (a *AnthosPlatform) CreateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("CreateAppInst TODO")
}

func (a *AnthosPlatform) DeleteAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("DeleteAppInst TODO")
}

func (a *AnthosPlatform) UpdateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("UpdateAppInst TODO")
}

func (a *AnthosPlatform) GetAppInstRuntime(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) (*edgeproto.AppInstRuntime, error) {
	return &edgeproto.AppInstRuntime{}, nil
}

func (a *AnthosPlatform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	return nil, fmt.Errorf("GetClusterPlatformClient TODO")
}

func (a *AnthosPlatform) GetNodePlatformClient(ctx context.Context, node *edgeproto.CloudletMgmtNode, ops ...pc.SSHClientOp) (ssh.Client, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetNodePlatformClient", "node", node)

	if node == nil || node.Name == "" {
		return nil, fmt.Errorf("cannot GetNodePlatformClient, as node details are empty")
	}
	controlVip := a.GetControlVip()
	return a.commonPf.GetSSHClientFromIPAddr(ctx, controlVip, ops...)
}

func (a *AnthosPlatform) ListCloudletMgmtNodes(ctx context.Context, clusterInsts []edgeproto.ClusterInst) ([]edgeproto.CloudletMgmtNode, error) {
	return []edgeproto.CloudletMgmtNode{}, nil
}

func (a *AnthosPlatform) GetContainerCommand(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, req *edgeproto.ExecRequest) (string, error) {
	return "", fmt.Errorf("GetContainerCommand TODO")
}

func (a *AnthosPlatform) GetConsoleUrl(ctx context.Context, app *edgeproto.App) (string, error) {
	return "", fmt.Errorf("GetConsoleUrl not supported on Anthos")
}

func (a *AnthosPlatform) CreateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, flavor *edgeproto.Flavor, caches *platform.Caches, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("CreateCloudlet TODO")
}

func (a *AnthosPlatform) UpdateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("UpdateCloudlet TODO")
}

func (a *AnthosPlatform) UpdateTrustPolicy(ctx context.Context, TrustPolicy *edgeproto.TrustPolicy) error {
	return fmt.Errorf("UpdateTrustPolicy TODO")
}

func (a *AnthosPlatform) DeleteCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, caches *platform.Caches, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("DeleteCloudlet TODO")
}

func (a *AnthosPlatform) SaveCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, accessVarsIn map[string]string, pfConfig *edgeproto.PlatformConfig, vaultConfig *vault.Config, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SaveCloudletAccessVars", "cloudletName", cloudlet.Key.Name)
	return nil
}

func (a *AnthosPlatform) GetCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, vaultConfig *vault.Config) (map[string]string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetCloudletAccessVars", "cloudletName", cloudlet.Key.Name)
	return map[string]string{}, nil
}

func (a *AnthosPlatform) DeleteCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, vaultConfig *vault.Config, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteCloudletAccessVars", "cloudletName", cloudlet.Key.Name)
	return nil
}

func (a *AnthosPlatform) SetPowerState(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("SetPowerState not supported on Anthos")
}

func (a *AnthosPlatform) runDebug(ctx context.Context, req *edgeproto.DebugRequest) string {
	return "runDebug todo"
}

func (a *AnthosPlatform) SyncControllerCache(ctx context.Context, caches *platform.Caches, cloudletState dme.CloudletState) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SyncControllerCache", "state", cloudletState)
	return nil
}

func (a *AnthosPlatform) GetCloudletManifest(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, accessApi platform.AccessApi, flavor *edgeproto.Flavor, caches *platform.Caches) (*edgeproto.CloudletManifest, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "Get cloudlet manifest", "cloudletName", cloudlet.Key.Name)
	return &edgeproto.CloudletManifest{Manifest: "fake manifest\n" + pfConfig.CrmAccessPrivateKey}, nil
}

func (a *AnthosPlatform) VerifyVMs(ctx context.Context, vms []edgeproto.VM) error {
	return nil
}

func (a *AnthosPlatform) GetAccessData(ctx context.Context, cloudlet *edgeproto.Cloudlet, region string, vaultConfig *vault.Config, dataType string, arg []byte) (map[string]string, error) {
	return nil, fmt.Errorf("GetAccessData TODO")
}

func (a *AnthosPlatform) GetRestrictedCloudletStatus(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	updateCallback(edgeproto.UpdateTask, "Setting up cloudlet")
	return nil
}

func (a *AnthosPlatform) GetRootLBClients(ctx context.Context) (map[string]ssh.Client, error) {
	return nil, nil
}

func (a *AnthosPlatform) GetVersionProperties() map[string]string {
	return map[string]string{}
}

func (a *AnthosPlatform) GetRootLBFlavor(ctx context.Context) (*edgeproto.Flavor, error) {
	return &RootLBFlavor, nil
}
