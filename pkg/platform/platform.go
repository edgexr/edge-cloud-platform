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

package platform

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	cloudflare "github.com/cloudflare/cloudflare-go"
	dme "github.com/edgexr/edge-cloud-platform/api/dme-proto"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/chefauth"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/federationmgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	"github.com/edgexr/edge-cloud-platform/pkg/redundancy"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
	ssh "github.com/edgexr/golang-ssh"
)

type PlatformConfig struct {
	CloudletKey         *edgeproto.CloudletKey
	PhysicalName        string
	Region              string
	TestMode            bool
	CloudletVMImagePath string
	VMImageVersion      string
	PackageVersion      string
	EnvVars             map[string]string
	NodeMgr             *node.NodeMgr
	AppDNSRoot          string
	RootLBFQDN          string
	ChefServerPath      string
	DeploymentTag       string
	Upgrade             bool
	AccessApi           AccessApi
	TrustPolicy         string
	CacheDir            string
	GPUConfig           *edgeproto.GPUConfig
	FedExternalAddr     string
}

type Caches struct {
	SettingsCache             *edgeproto.SettingsCache
	FlavorCache               *edgeproto.FlavorCache
	TrustPolicyCache          *edgeproto.TrustPolicyCache
	TrustPolicyExceptionCache *edgeproto.TrustPolicyExceptionCache
	CloudletPoolCache         *edgeproto.CloudletPoolCache
	ClusterInstCache          *edgeproto.ClusterInstCache
	ClusterInstInfoCache      *edgeproto.ClusterInstInfoCache
	AppInstCache              *edgeproto.AppInstCache
	AppInstInfoCache          *edgeproto.AppInstInfoCache
	AppCache                  *edgeproto.AppCache
	ResTagTableCache          *edgeproto.ResTagTableCache
	CloudletCache             *edgeproto.CloudletCache
	CloudletInternalCache     *edgeproto.CloudletInternalCache
	VMPoolCache               *edgeproto.VMPoolCache
	VMPoolInfoCache           *edgeproto.VMPoolInfoCache
	GPUDriverCache            *edgeproto.GPUDriverCache
	NetworkCache              *edgeproto.NetworkCache
	CloudletInfoCache         *edgeproto.CloudletInfoCache
	// VMPool object managed by CRM
	VMPool    *edgeproto.VMPool
	VMPoolMux *sync.Mutex
}

// Used by federation to redirect FRM to finish CreateAppInst via the controller
var ErrContinueViaController = errors.New("continue operation via controller")

// Platform abstracts the underlying cloudlet platform.
type Platform interface {
	// GetVersionProperties returns properties related to the platform version
	GetVersionProperties(ctx context.Context) map[string]string
	// GetFeatures returns static features, attributes, and
	// properties of the platform.
	GetFeatures() *edgeproto.PlatformFeatures
	// InitCommon is called once during CRM startup to do steps needed for both active or standby. If the platform does not support
	// H/A and does not need separate steps for the active unit, then just this func can be implemented and InitHAConditional can be left empty
	InitCommon(ctx context.Context, platformConfig *PlatformConfig, caches *Caches, haMgr *redundancy.HighAvailabilityManager, updateCallback edgeproto.CacheUpdateCallback) error
	// InitHAConditional is only needed for platforms which support H/A. It is called in the following cases: 1) when platform initially starts in a non-switchover case
	// 2) in a switchover case if the previouly-active unit is running a different version as specified by GetInitHAConditionalCompatibilityVersion
	InitHAConditional(ctx context.Context, platformConfig *PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error
	// GetInitializationCompatibilityVersion returns a version as a string. When doing switchovers, if the new version matches the previous version, then InitHAConditional
	// is not called again. If there is a mismatch, then InitHAConditional will be called again.
	GetInitHAConditionalCompatibilityVersion(ctx context.Context) string
	// Gather information about the cloudlet platform.
	// This includes available resources, flavors, etc.
	// Returns true if sync with controller is required
	GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error
	// Create a Kubernetes Cluster on the cloudlet.
	CreateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) error
	// Delete a Kuberentes Cluster on the cloudlet.
	DeleteClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error
	// Update the cluster
	UpdateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error
	// Get resources used by the cloudlet
	GetCloudletInfraResources(ctx context.Context) (*edgeproto.InfraResourcesSnapshot, error)
	// Get cluster additional resources used by the vms specific to the platform
	GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource, infraResMap map[string]edgeproto.InfraResource) map[string]edgeproto.InfraResource
	// Get cluster additional resource metric
	GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error
	// Get resources used by the cluster
	GetClusterInfraResources(ctx context.Context, clusterKey *edgeproto.ClusterInstKey) (*edgeproto.InfraResources, error)
	// Create an AppInst on a Cluster
	CreateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error
	// Delete an AppInst on a Cluster
	DeleteAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error
	// Update an AppInst
	UpdateAppInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error
	// Get AppInst runtime information
	GetAppInstRuntime(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) (*edgeproto.AppInstRuntime, error)
	// Get the client to manage the ClusterInst
	GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error)
	// Get the client to manage the specified platform management node
	GetNodePlatformClient(ctx context.Context, node *edgeproto.CloudletMgmtNode, ops ...pc.SSHClientOp) (ssh.Client, error)
	// List the cloudlet management nodes used by this platform
	ListCloudletMgmtNodes(ctx context.Context, clusterInsts []edgeproto.ClusterInst, vmAppInsts []edgeproto.AppInst) ([]edgeproto.CloudletMgmtNode, error)
	// Get the command to pass to PlatformClient for the container command
	GetContainerCommand(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, req *edgeproto.ExecRequest) (string, error)
	// Get the console URL of the VM appInst
	GetConsoleUrl(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst) (string, error)
	// Set power state of the AppInst
	SetPowerState(ctx context.Context, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error
	// Create Cloudlet returns cloudletResourcesCreated, error
	CreateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, flavor *edgeproto.Flavor, caches *Caches, accessApi AccessApi, updateCallback edgeproto.CacheUpdateCallback) (bool, error)
	UpdateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, updateCallback edgeproto.CacheUpdateCallback) error
	// Delete Cloudlet
	DeleteCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, caches *Caches, accessApi AccessApi, updateCallback edgeproto.CacheUpdateCallback) error
	// Performs Upgrades for things like k8s config
	PerformUpgrades(ctx context.Context, caches *Caches, cloudletState dme.CloudletState) error
	// Get Cloudlet Manifest Config
	GetCloudletManifest(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, accessApi AccessApi, flavor *edgeproto.Flavor, caches *Caches) (*edgeproto.CloudletManifest, error)
	// Verify VM
	VerifyVMs(ctx context.Context, vms []edgeproto.VM) error
	// Update the cloudlet's Trust Policy
	UpdateTrustPolicy(ctx context.Context, TrustPolicy *edgeproto.TrustPolicy) error
	//  Create and Update TrustPolicyException
	UpdateTrustPolicyException(ctx context.Context, TrustPolicyException *edgeproto.TrustPolicyException, clusterInstKey *edgeproto.ClusterInstKey) error
	// Delete TrustPolicyException
	DeleteTrustPolicyException(ctx context.Context, TrustPolicyExceptionKey *edgeproto.TrustPolicyExceptionKey, clusterInstKey *edgeproto.ClusterInstKey) error
	// Get restricted cloudlet create status
	GetRestrictedCloudletStatus(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, accessApi AccessApi, updateCallback edgeproto.CacheUpdateCallback) error
	// Get ssh clients of all root LBs
	GetRootLBClients(ctx context.Context) (map[string]ssh.Client, error)
	// Get RootLB Flavor
	GetRootLBFlavor(ctx context.Context) (*edgeproto.Flavor, error)
	// Called when the platform instance switches activity. Currently only transition from Standby to Active is allowed.
	ActiveChanged(ctx context.Context, platformActive bool) error
	// Sanitizes the name to make it conform to platform requirements.
	NameSanitize(name string) string
}

type ClusterSvc interface {
	// GetVersionProperties returns properties related to the platform version
	GetVersionProperties(ctx context.Context) map[string]string
	// Get AppInst Configs
	GetAppInstConfigs(ctx context.Context, clusterInst *edgeproto.ClusterInst, appInst *edgeproto.AppInst,
		autoScalePolicy *edgeproto.AutoScalePolicy, settings *edgeproto.Settings,
		userAlerts []edgeproto.AlertPolicy) ([]*edgeproto.ConfigFile, error)
}

// AccessApi handles functions that require secrets access, but
// may be run from either the Controller or CRM context, so may either
// use Vault directly (Controller) or may go indirectly via Controller (CRM).
type AccessApi interface {
	cloudcommon.RegistryAuthApi
	cloudcommon.GetPublicCertApi
	GetCloudletAccessVars(ctx context.Context) (map[string]string, error)
	SignSSHKey(ctx context.Context, publicKey string) (string, error)
	GetSSHPublicKey(ctx context.Context) (string, error)
	GetOldSSHKey(ctx context.Context) (*vault.MEXKey, error)
	GetChefAuthKey(ctx context.Context) (*chefauth.ChefAuthKey, error)
	CreateOrUpdateDNSRecord(ctx context.Context, name, rtype, content string, ttl int, proxy bool) error
	GetDNSRecords(ctx context.Context, fqdn string) ([]cloudflare.DNSRecord, error)
	DeleteDNSRecord(ctx context.Context, recordID string) error
	GetSessionTokens(ctx context.Context, secretName string) (string, error)
	GetKafkaCreds(ctx context.Context) (*node.KafkaCreds, error)
	GetGCSCreds(ctx context.Context) ([]byte, error)
	GetFederationAPIKey(ctx context.Context, fedKey *federationmgmt.FedKey) (*federationmgmt.ApiKey, error)
}

// AccessData types
const (
	GetCloudletAccessVars   = "get-cloudlet-access-vars"
	GetRegistryAuth         = "get-registry-auth"
	SignSSHKey              = "sign-ssh-key"
	GetSSHPublicKey         = "get-ssh-public-key"
	GetOldSSHKey            = "get-old-ssh-key"
	GetChefAuthKey          = "get-chef-auth-key"
	CreateOrUpdateDNSRecord = "create-or-update-dns-record"
	GetDNSRecords           = "get-dns-records"
	DeleteDNSRecord         = "delete-dns-record"
	GetSessionTokens        = "get-session-tokens"
	GetPublicCert           = "get-public-cert"
	GetKafkaCreds           = "get-kafka-creds"
	GetGCSCreds             = "get-gcs-creds"
	GetFederationAPIKey     = "get-federation-apikey"
)

type DNSRequest struct {
	Name    string
	RType   string
	Content string
	TTL     int
	Proxy   bool
}

// GetTypeBC converts the old enum-based name into the
// standard platform type name, if needed. Otherwise it
// just returns the standard platform name as is.
// This is necessary to convert the old platform strings
// set in Chef as the command line args for existing CRM
// and Shepherd instances.
func GetTypeBC(pfType string) string {
	out := strings.TrimPrefix(pfType, "PLATFORM_TYPE_")
	out = strings.ToLower(out)
	out = strings.Replace(out, "_", "", -1)
	return out
}

// Track K8s AppInstances for resource management only if platform supports K8s deployments only
func TrackK8sAppInst(ctx context.Context, app *edgeproto.App, features *edgeproto.PlatformFeatures) bool {
	if features.SupportsKubernetesOnly &&
		(app.Deployment == cloudcommon.DeploymentTypeKubernetes ||
			app.Deployment == cloudcommon.DeploymentTypeHelm) {
		return true
	}
	return false
}

type PlatformBuilder func() Platform
