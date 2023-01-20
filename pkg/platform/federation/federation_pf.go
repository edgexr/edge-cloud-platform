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

package federation

import (
	"context"
	"fmt"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/dme-proto"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/federationmgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/fedewapi"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	"github.com/edgexr/edge-cloud-platform/pkg/redundancy"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
	ssh "github.com/edgexr/golang-ssh"
)

const (
	AppDeploymentTimeout = 20 * time.Minute
)

var DisableFedAppInsts = true

// NOTE: This object is shared by all FRM-based cloudlets and hence it can't
//       hold fields just for a specific cloudlet
type FederationPlatform struct {
	tokenSources *federationmgmt.TokenSourceCache
	caches       *platform.Caches
	commonPf     *infracommon.CommonPlatform
}

// GetVersionProperties returns properties related to the platform version
func (f *FederationPlatform) GetVersionProperties(ctx context.Context) map[string]string {
	return map[string]string{}
}

// Get platform features
func (f *FederationPlatform) GetFeatures() *edgeproto.PlatformFeatures {
	return &edgeproto.PlatformFeatures{
		SupportsKubernetesOnly:        true,
		KubernetesRequiresWorkerNodes: true,
	}
}

// Get federation config for cloudlet
func (f *FederationPlatform) GetFederationConfig(ctx context.Context, cloudletKey *edgeproto.CloudletKey) (*edgeproto.FederationConfig, error) {
	cloudlet := edgeproto.Cloudlet{}
	if !f.caches.CloudletCache.Get(cloudletKey, &cloudlet) {
		return nil, fmt.Errorf("Cloudlet not found in cache %s", cloudletKey.String())
	}
	if cloudlet.FederationConfig.FederationContextId == "" {
		return nil, fmt.Errorf("Unable to find federation config for %s", cloudletKey.String())
	}
	return &cloudlet.FederationConfig, nil
}

// Init is called once during FRM startup.
func (f *FederationPlatform) InitCommon(ctx context.Context, platformConfig *platform.PlatformConfig, caches *platform.Caches, haMgr *redundancy.HighAvailabilityManager, updateCallback edgeproto.CacheUpdateCallback) error {
	f.tokenSources = federationmgmt.NewTokenSourceCache(platformConfig.AccessApi)
	f.caches = caches
	f.commonPf = &infracommon.CommonPlatform{
		PlatformConfig: platformConfig,
	}
	return nil
}

// InitHAConditional is optional init steps for the active unit, if applicable
func (f *FederationPlatform) InitHAConditional(ctx context.Context, platformConfig *platform.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (f *FederationPlatform) GetInitHAConditionalCompatibilityVersion(ctx context.Context) string {
	return "federation-1.0"
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

	return &edgeproto.CloudletResourceQuotaProps{}, nil
}

// Get cluster additional resource metric
func (f *FederationPlatform) GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error {
	return nil
}

// Get resources used by the cluster
func (f *FederationPlatform) GetClusterInfraResources(ctx context.Context, clusterKey *edgeproto.ClusterInstKey) (*edgeproto.InfraResources, error) {
	return &edgeproto.InfraResources{}, nil
}

func (f *FederationPlatform) fedClient(ctx context.Context, cloudletKey *edgeproto.CloudletKey, fedConfig *edgeproto.FederationConfig) (*federationmgmt.Client, error) {
	fedKey := federationmgmt.FedKey{
		OperatorId: cloudletKey.Organization,
		Name:       cloudletKey.Name,
		FedType:    federationmgmt.FederationTypeConsumer,
		ID:         uint(fedConfig.FederationDbId),
	}
	return f.tokenSources.Client(ctx, fedConfig.PartnerFederationAddr, &fedKey)
}

// Create an appInst. This runs on the Consumer.
func (f *FederationPlatform) CreateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	if DisableFedAppInsts {
		return nil
	}
	// helm not supported yet
	if app.Deployment == cloudcommon.DeploymentTypeHelm {
		return fmt.Errorf("Helm deployment not supported yet")
	}
	if appInst.FedKey.AppInstId != "" {
		return fmt.Errorf("Error, AppInst already has a federation AppInstId set")
	}

	cloudletKey := &clusterInst.Key.CloudletKey
	fedConfig, err := f.GetFederationConfig(ctx, cloudletKey)
	if err != nil {
		return err
	}
	fedClient, err := f.fedClient(ctx, cloudletKey, fedConfig)
	if err != nil {
		return err
	}

	req := fedewapi.InstallAppRequest{
		AppId:         app.GlobalId,
		AppVersion:    app.Key.Version,
		AppProviderId: app.Key.Organization,
		ZoneInfo: fedewapi.InstallAppRequestZoneInfo{
			ZoneId:    cloudletKey.Name,
			FlavourId: "TBD",
		},
		AppInstCallbackLink: f.commonPf.PlatformConfig.FedExternalAddr + "/" + federationmgmt.PartnerInstanceStatusEventPath,
	}
	updateCallback(edgeproto.UpdateTask, "Sending app instance create request to federation partner")
	res := fedewapi.InstallApp202Response{}
	_, _, err = fedClient.SendRequest(ctx, "POST", "/"+federationmgmt.ApiRoot+"/application/lcm", &req, &res, nil)
	if err != nil {
		return err
	}
	if res.AppInstIdentifier == "" {
		return fmt.Errorf("App instance created succeeded but no ID in response")
	}
	appInst.FedKey.FederationName = fedConfig.FederationName
	appInst.FedKey.AppInstId = res.AppInstIdentifier
	log.SpanLog(ctx, log.DebugLevelApi, "Got FedAppInstId", "appInstKey", appInst.Key, "fedAppInstId", res.AppInstIdentifier)

	// Partner returns immediately with 202, and will call the callback link
	// to denote the result.
	// The callback link goes to MC. MC will then call the
	// AppInst.FedAppInstEvent API with an AppInstInfo, which then follows
	// the same path as FRM sending back an AppInstInfo.
	updateCallback(edgeproto.UpdateTask, "Waiting for federation partner callbacks for FedAppInstId "+res.AppInstIdentifier)
	return nil
}

// Delete an AppInst on a Cluster
func (f *FederationPlatform) DeleteAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("not supported yet")
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
func (f *FederationPlatform) GetConsoleUrl(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst) (string, error) {
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
func (f *FederationPlatform) PerformUpgrades(ctx context.Context, caches *platform.Caches, cloudletState dme.CloudletState) error {
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
func (f *FederationPlatform) UpdateTrustPolicyException(ctx context.Context, TrustPolicyException *edgeproto.TrustPolicyException, clusterInstKey *edgeproto.ClusterInstKey) error {
	return nil
}

// Delete TrustPolicyException
func (f *FederationPlatform) DeleteTrustPolicyException(ctx context.Context, TrustPolicyExceptionKey *edgeproto.TrustPolicyExceptionKey, clusterInstKey *edgeproto.ClusterInstKey) error {
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

func (k *FederationPlatform) ActiveChanged(ctx context.Context, platformActive bool) error {
	return nil
}

func (k *FederationPlatform) NameSanitize(name string) string {
	return name
}
