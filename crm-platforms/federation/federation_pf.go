package federation

import (
	"context"
	"time"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	dme "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
	ssh "github.com/mobiledgex/golang-ssh"
)

type FederationPlatform struct{}

// GetVersionProperties returns properties related to the platform version
func (f *FederationPlatform) GetVersionProperties() map[string]string {
	return map[string]string{}
}

// Get platform features
func (f *FederationPlatform) GetFeatures() *platform.Features {
	return &platform.Features{}
}

// Init is called once during CRM startup.
func (f *FederationPlatform) Init(ctx context.Context, platformConfig *platform.PlatformConfig, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

// Gather information about the cloudlet platform.
// This includes available resources, flavors, etc.
// Returns true if sync with controller is required
func (f *FederationPlatform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	return nil
}

// Create a Kubernetes Cluster on the cloudlet.
func (f *FederationPlatform) CreateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) error {
	return nil
}

// Delete a Kuberentes Cluster on the cloudlet.
func (f *FederationPlatform) DeleteClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

// Update the cluster
func (f *FederationPlatform) UpdateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

// Get resources used by the cloudlet
func (f *FederationPlatform) GetCloudletInfraResources(ctx context.Context) (*edgeproto.InfraResourcesSnapshot, error) {
	return &edgeproto.InfraResourcesSnapshot{}, nil
}

// Get cluster additional resources used by the vms specific to the platform
func (f *FederationPlatform) GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource, infraResMap map[string]edgeproto.InfraResource) map[string]edgeproto.InfraResource {
	return nil
}

// Get Cloudlet Resource Properties
func (f *FederationPlatform) GetCloudletResourceQuotaProps(ctx context.Context) (*edgeproto.CloudletResourceQuotaProps, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetCloudletResourceQuotaProps")

	return &edgeproto.CloudletResourceQuotaProps{
		Properties: []edgeproto.InfraResource{
			{
				Name:        cloudcommon.ResourceDisk,
				Description: cloudcommon.ResourceQuotaDesc[cloudcommon.ResourceDisk],
			},
		},
	}, nil
}

// Get cluster additional resource metric
func (f *FederationPlatform) GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error {
	return nil
}

// Get resources used by the cluster
func (f *FederationPlatform) GetClusterInfraResources(ctx context.Context, clusterKey *edgeproto.ClusterInstKey) (*edgeproto.InfraResources, error) {
	return &edgeproto.InfraResources{}, nil
}

// Create an AppInst on a Cluster
func (f *FederationPlatform) CreateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

// Delete an AppInst on a Cluster
func (f *FederationPlatform) DeleteAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

// Update an AppInst
func (f *FederationPlatform) UpdateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

// Get AppInst runtime information
func (f *FederationPlatform) GetAppInstRuntime(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) (*edgeproto.AppInstRuntime, error) {
	return &edgeproto.AppInstRuntime{}, nil
}

// Get the client to manage the ClusterInst
func (f *FederationPlatform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	return nil, nil
}

// Get the client to manage the specified platform management node
func (f *FederationPlatform) GetNodePlatformClient(ctx context.Context, node *edgeproto.CloudletMgmtNode, ops ...pc.SSHClientOp) (ssh.Client, error) {
	return nil, nil
}

// List the cloudlet management nodes used by this platform
func (f *FederationPlatform) ListCloudletMgmtNodes(ctx context.Context, clusterInsts []edgeproto.ClusterInst, vmAppInsts []edgeproto.AppInst) ([]edgeproto.CloudletMgmtNode, error) {
	return nil, nil
}

// Get the command to pass to PlatformClient for the container command
func (f *FederationPlatform) GetContainerCommand(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, req *edgeproto.ExecRequest) (string, error) {
	return "", nil
}

// Get the console URL of the VM app
func (f *FederationPlatform) GetConsoleUrl(ctx context.Context, app *edgeproto.App) (string, error) {
	return "", nil
}

// Set power state of the AppInst
func (f *FederationPlatform) SetPowerState(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

// Create Cloudlet returns cloudletResourcesCreated, error
func (f *FederationPlatform) CreateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, flavor *edgeproto.Flavor, caches *platform.Caches, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) (bool, error) {
	// nothing to be done
	return false, nil
}

func (f *FederationPlatform) UpdateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

// Delete Cloudlet
func (f *FederationPlatform) DeleteCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, caches *platform.Caches, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

// Save Cloudlet AccessVars
func (f *FederationPlatform) SaveCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, accessVarsIn map[string]string, pfConfig *edgeproto.PlatformConfig, vaultConfig *vault.Config, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

// Delete Cloudlet AccessVars
func (f *FederationPlatform) DeleteCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, vaultConfig *vault.Config, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

// Sync data with controller
func (f *FederationPlatform) SyncControllerCache(ctx context.Context, caches *platform.Caches, cloudletState dme.CloudletState) error {
	return nil
}

// Get Cloudlet Manifest Config
func (f *FederationPlatform) GetCloudletManifest(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, accessApi platform.AccessApi, flavor *edgeproto.Flavor, caches *platform.Caches) (*edgeproto.CloudletManifest, error) {
	return &edgeproto.CloudletManifest{}, nil
}

// Verify VM
func (f *FederationPlatform) VerifyVMs(ctx context.Context, vms []edgeproto.VM) error {
	return nil
}

// Get Cloudlet Properties
func (f *FederationPlatform) GetCloudletProps(ctx context.Context) (*edgeproto.CloudletProps, error) {
	return &edgeproto.CloudletProps{}, nil
}

// Platform-sepcific access data lookup (only called from Controller context)
func (f *FederationPlatform) GetAccessData(ctx context.Context, cloudlet *edgeproto.Cloudlet, region string, vaultConfig *vault.Config, dataType string, arg []byte) (map[string]string, error) {
	return nil, nil
}

// Update the cloudlet's Trust Policy
func (f *FederationPlatform) UpdateTrustPolicy(ctx context.Context, TrustPolicy *edgeproto.TrustPolicy) error {
	return nil
}

//  Create and Update TrustPolicyException
func (f *FederationPlatform) UpdateTrustPolicyException(ctx context.Context, TrustPolicyException *edgeproto.TrustPolicyException) error {
	return nil
}

// Delete TrustPolicyException
func (f *FederationPlatform) DeleteTrustPolicyException(ctx context.Context, TrustPolicyExceptionKey *edgeproto.TrustPolicyExceptionKey) error {
	return nil
}

// Get restricted cloudlet create status
func (f *FederationPlatform) GetRestrictedCloudletStatus(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, accessApi platform.AccessApi, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

// Get ssh clients of all root LBs
func (f *FederationPlatform) GetRootLBClients(ctx context.Context) (map[string]ssh.Client, error) {
	return nil, nil
}

// Get RootLB Flavor
func (f *FederationPlatform) GetRootLBFlavor(ctx context.Context) (*edgeproto.Flavor, error) {
	return &edgeproto.Flavor{}, nil
}
