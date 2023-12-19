package mock

import (
	"context"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/dme-proto"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/fakecommon"
	k8scommon "github.com/edgexr/edge-cloud-platform/pkg/platform/k8s-common"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	"github.com/edgexr/edge-cloud-platform/pkg/process"
	"github.com/edgexr/edge-cloud-platform/pkg/rediscache"
	"github.com/edgexr/edge-cloud-platform/pkg/redundancy"
	ssh "github.com/edgexr/golang-ssh"
)

// Mock cloudlet provides a cloudlet with near infinite
// resources but no real backing, for developer/regression
// testing.

var (
	MockRamMax         = uint64(4096000)
	MockVcpusMax       = uint64(5000)
	MockDiskMax        = uint64(500000)
	MockExternalIpsMax = uint64(3000)
)

type Platform struct {
	caches    *platform.Caches
	resources fakecommon.Resources
}

func NewPlatform() platform.Platform {
	return &Platform{}
}

func (s *Platform) GetFeatures() *edgeproto.PlatformFeatures {
	return &edgeproto.PlatformFeatures{
		PlatformType:                             platform.PlatformTypeMock,
		SupportsMultiTenantCluster:               true,
		SupportsSharedVolume:                     true,
		SupportsTrustPolicy:                      true,
		CloudletServicesLocal:                    true,
		SupportsAdditionalNetworks:               true,
		SupportsPlatformHighAvailabilityOnDocker: true,
		SupportsPlatformHighAvailabilityOnK8S:    true,
		IsMock:                                   true,
	}
}

func (s *Platform) InitCommon(ctx context.Context, platformConfig *platform.PlatformConfig, caches *platform.Caches, haMgr *redundancy.HighAvailabilityManager, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "init Mock cloudlet")
	s.caches = caches
	s.resources.Init()
	s.resources.SetMaxResources(MockRamMax, MockVcpusMax, MockDiskMax, MockExternalIpsMax)
	return nil
}

func (s *Platform) InitHAConditional(ctx context.Context, platformConfig *platform.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (s *Platform) GetInitHAConditionalCompatibilityVersion(ctx context.Context) string {
	return "Mock-1.0"
}

func (s *Platform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	info.OsMaxRam = MockRamMax
	info.OsMaxVcores = MockVcpusMax
	info.OsMaxVolGb = MockDiskMax
	var err error
	info.Flavors, err = k8scommon.GetFlavorList(ctx, s.caches)
	if err != nil {
		return err
	}
	s.resources.SetCloudletFlavors(info.Flavors, info.Flavors[0].Name)
	return nil
}

func (s *Platform) CreateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) error {
	s.resources.AddClusterResources(clusterInst)
	return nil
}

func (s *Platform) UpdateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	s.resources.RemoveClusterResources(&clusterInst.Key)
	s.resources.AddClusterResources(clusterInst)
	return nil
}

func (s *Platform) DeleteClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	s.resources.RemoveClusterResources(&clusterInst.Key)
	return nil
}

func (s *Platform) GetCloudletInfraResources(ctx context.Context) (*edgeproto.InfraResourcesSnapshot, error) {
	return s.resources.GetSnapshot(), nil
}

func (s *Platform) GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource, infraResMap map[string]edgeproto.InfraResource) map[string]edgeproto.InfraResource {
	return map[string]edgeproto.InfraResource{}
}

func (s *Platform) GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error {
	return nil
}

func (s *Platform) GetClusterInfraResources(ctx context.Context, clusterKey *edgeproto.ClusterInstKey) (*edgeproto.InfraResources, error) {
	return s.resources.GetClusterResources(clusterKey), nil
}

func (s *Platform) CreateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	s.resources.AddVmAppResCount(ctx, app, appInst)
	return nil
}

func (s *Platform) DeleteAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	s.resources.RemoveVmAppResCount(ctx, app, appInst)
	return nil
}

func (s *Platform) UpdateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (s *Platform) GetAppInstRuntime(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) (*edgeproto.AppInstRuntime, error) {
	return &edgeproto.AppInstRuntime{}, nil
}

func (s *Platform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	return &pc.LocalClient{}, nil
}

func (s *Platform) GetNodePlatformClient(ctx context.Context, node *edgeproto.CloudletMgmtNode, ops ...pc.SSHClientOp) (ssh.Client, error) {
	return &pc.LocalClient{}, nil
}

func (s *Platform) ListCloudletMgmtNodes(ctx context.Context, clusterInsts []edgeproto.ClusterInst, vmAppInsts []edgeproto.AppInst) ([]edgeproto.CloudletMgmtNode, error) {
	return []edgeproto.CloudletMgmtNode{}, nil
}

func (s *Platform) GetContainerCommand(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, req *edgeproto.ExecRequest) (string, error) {
	return "", nil
}

func (s *Platform) GetConsoleUrl(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst) (string, error) {
	return "", nil
}

func (s *Platform) CreateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, flavor *edgeproto.Flavor, caches *platform.Caches, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) (bool, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "create Mock cloudlet", "key", cloudlet.Key)
	var redisCfg rediscache.RedisConfig
	err := process.StartCRMService(ctx, cloudlet, pfConfig, process.HARolePrimary, &redisCfg)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Mock cloudlet create failed to start CRM", "err", err)
		return true, err
	}
	return true, nil
}

func (s *Platform) UpdateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (s *Platform) DeleteCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, caches *platform.Caches, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "delete Mock cloudlet", "key", cloudlet.Key)
	updateCallback(edgeproto.UpdateTask, "Deleting Cloudlet")
	updateCallback(edgeproto.UpdateTask, "Stopping CRMServer")
	err := process.StopCRMService(ctx, cloudlet, process.HARoleAll)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "fake cloudlet delete failed", "err", err)
		return err
	}
	return nil
}

func (s *Platform) GetCloudletManifest(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, accessApi platform.AccessApi, flavor *edgeproto.Flavor, caches *platform.Caches) (*edgeproto.CloudletManifest, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "Get cloudlet manifest", "cloudletName", cloudlet.Key.Name)
	return &edgeproto.CloudletManifest{Manifest: "Mock manifest\n"}, nil
}

func (s *Platform) UpdateTrustPolicy(ctx context.Context, TrustPolicy *edgeproto.TrustPolicy) error {
	log.DebugLog(log.DebugLevelInfra, "fake UpdateTrustPolicy begin", "policy", TrustPolicy)
	return nil
}

func (s *Platform) UpdateTrustPolicyException(ctx context.Context, tpe *edgeproto.TrustPolicyException, clusterInstKey *edgeproto.ClusterInstKey) error {
	return nil
}

func (s *Platform) DeleteTrustPolicyException(ctx context.Context, tpeKey *edgeproto.TrustPolicyExceptionKey, clusterInstKey *edgeproto.ClusterInstKey) error {
	return nil
}

func (s *Platform) SetPowerState(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Setting power state", "state", appInst.PowerState)
	return nil
}

func (s *Platform) PerformUpgrades(ctx context.Context, caches *platform.Caches, cloudletState dme.CloudletState) error {
	return nil
}

func (s *Platform) VerifyVMs(ctx context.Context, vms []edgeproto.VM) error {
	return nil
}

func (s *Platform) GetRestrictedCloudletStatus(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	updateCallback(edgeproto.UpdateTask, "Setting up cloudlet")
	return nil
}

func (s *Platform) GetRootLBClients(ctx context.Context) (map[string]platform.RootLBClient, error) {
	return nil, nil
}

func (s *Platform) GetVersionProperties(ctx context.Context) map[string]string {
	return map[string]string{}
}

func (s *Platform) GetRootLBFlavor(ctx context.Context) (*edgeproto.Flavor, error) {
	return &edgeproto.Flavor{}, nil
}

func (s *Platform) ActiveChanged(ctx context.Context, platformActive bool) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ActiveChanged", "platformActive", platformActive)
	return nil
}

func (s *Platform) NameSanitize(name string) string {
	return name
}
