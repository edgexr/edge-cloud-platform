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

package vmlayer

import (
	"context"
	"fmt"
	"os"

	"github.com/gogo/protobuf/types"
	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/accessapi"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/redundancy"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/cloudcommon/node"
	dme "github.com/edgexr/edge-cloud/d-match-engine/dme-proto"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/vault"
	ssh "github.com/mobiledgex/golang-ssh"
)

// VMProvider is an interface that platforms implement to perform the details of interfacing with the orchestration layer

type VMProvider interface {
	NameSanitize(string) string
	IdSanitize(string) string
	GetProviderSpecificProps(ctx context.Context) (map[string]*edgeproto.PropertyInfo, error)
	SetVMProperties(vmProperties *VMProperties)
	GetFeatures() *platform.Features
	InitData(ctx context.Context, caches *platform.Caches)
	InitProvider(ctx context.Context, caches *platform.Caches, stage ProviderInitStage, updateCallback edgeproto.CacheUpdateCallback) error
	GetFlavorList(ctx context.Context) ([]*edgeproto.FlavorInfo, error)
	GetNetworkList(ctx context.Context) ([]string, error)
	AddImageIfNotPresent(ctx context.Context, imageInfo *infracommon.ImageInfo, updateCallback edgeproto.CacheUpdateCallback) error
	GetCloudletImageSuffix(ctx context.Context) string
	DeleteImage(ctx context.Context, folder, image string) error
	GetServerDetail(ctx context.Context, serverName string) (*ServerDetail, error)
	GetConsoleUrl(ctx context.Context, serverName string) (string, error)
	GetInternalPortPolicy() InternalPortAttachPolicy
	AttachPortToServer(ctx context.Context, serverName, subnetName, portName, ipaddr string, action ActionType) error
	DetachPortFromServer(ctx context.Context, serverName, subnetName, portName string) error
	PrepareRootLB(ctx context.Context, client ssh.Client, rootLBName string, secGrpName string, TrustPolicy *edgeproto.TrustPolicy, updateCallback edgeproto.CacheUpdateCallback) error
	WhitelistSecurityRules(ctx context.Context, client ssh.Client, wlParams *infracommon.WhiteListParams) error
	RemoveWhitelistSecurityRules(ctx context.Context, client ssh.Client, wlParams *infracommon.WhiteListParams) error
	GetResourceID(ctx context.Context, resourceType ResourceType, resourceName string) (string, error)
	GetVaultCloudletAccessPath(key *edgeproto.CloudletKey, region, physicalName string) string
	InitApiAccessProperties(ctx context.Context, accessApi platform.AccessApi, vars map[string]string) error
	GetApiEndpointAddr(ctx context.Context) (string, error)
	GetExternalGateway(ctx context.Context, extNetName string) (string, error)
	SaveCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, accessVarsIn map[string]string, pfConfig *edgeproto.PlatformConfig, vaultConfig *vault.Config, updateCallback edgeproto.CacheUpdateCallback) error
	SetPowerState(ctx context.Context, serverName, serverAction string) error
	GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error
	GetCloudletManifest(ctx context.Context, name string, cloudletImagePath string, VMGroupOrchestrationParams *VMGroupOrchestrationParams) (string, error)
	GetRouterDetail(ctx context.Context, routerName string) (*RouterDetail, error)
	CreateVMs(ctx context.Context, vmGroupOrchestrationParams *VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error
	UpdateVMs(ctx context.Context, vmGroupOrchestrationParams *VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error
	DeleteVMs(ctx context.Context, vmGroupName string) error
	GetVMStats(ctx context.Context, appInst *edgeproto.AppInst) (*VMMetrics, error)
	GetPlatformResourceInfo(ctx context.Context) (*PlatformResources, error)
	VerifyVMs(ctx context.Context, vms []edgeproto.VM) error
	CheckServerReady(ctx context.Context, client ssh.Client, serverName string) error
	GetServerGroupResources(ctx context.Context, name string) (*edgeproto.InfraResources, error)
	ValidateAdditionalNetworks(ctx context.Context, additionalNets map[string]NetworkType) error
	GetSessionTokens(ctx context.Context, vaultConfig *vault.Config, account string) (map[string]string, error)
	ConfigureCloudletSecurityRules(ctx context.Context, egressRestricted bool, TrustPolicy *edgeproto.TrustPolicy, rootlbClients map[string]ssh.Client, action ActionType, updateCallback edgeproto.CacheUpdateCallback) error
	ConfigureTrustPolicyExceptionSecurityRules(ctx context.Context, TrustPolicyException *edgeproto.TrustPolicyException, rootLbClients map[string]ssh.Client, action ActionType, updateCallback edgeproto.CacheUpdateCallback) error
	InitOperationContext(ctx context.Context, operationStage OperationInitStage) (context.Context, OperationInitResult, error)
	GetCloudletInfraResourcesInfo(ctx context.Context) ([]edgeproto.InfraResource, error)
	GetCloudletResourceQuotaProps(ctx context.Context) (*edgeproto.CloudletResourceQuotaProps, error)
	GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource, infraResMap map[string]edgeproto.InfraResource) map[string]edgeproto.InfraResource
	GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error
	InternalCloudletUpdatedCallback(ctx context.Context, old *edgeproto.CloudletInternal, new *edgeproto.CloudletInternal)
	VmAppChangedCallback(ctx context.Context, appInst *edgeproto.AppInst, newState edgeproto.TrackedState)
	GetGPUSetupStage(ctx context.Context) GPUSetupStage
	ActiveChanged(ctx context.Context, platformActive bool) error
}

// VMPlatform contains the needed by all VM based platforms
type VMPlatform struct {
	Type         string
	VMProvider   VMProvider
	VMProperties VMProperties
	FlavorList   []*edgeproto.FlavorInfo
	Caches       *platform.Caches
	GPUConfig    edgeproto.GPUConfig
	CacheDir     string
	infracommon.CommonEmbedded
	HAManager *redundancy.HighAvailabilityManager
}

// VMMetrics contains stats and timestamp
type VMMetrics struct {
	// Cpu is a percentage
	Cpu   float64
	CpuTS *types.Timestamp
	// Mem is bytes used
	Mem   uint64
	MemTS *types.Timestamp
	// Disk is bytes used
	Disk   uint64
	DiskTS *types.Timestamp
	// NetSent is bytes/second average
	NetSent   uint64
	NetSentTS *types.Timestamp
	// NetRecv is bytes/second average
	NetRecv   uint64
	NetRecvTS *types.Timestamp
}

type PlatformResources struct {
	// Timestamp when this was collected
	CollectTime *types.Timestamp
	// Total number of CPUs
	VCpuMax uint64
	// Current number of CPUs used
	VCpuUsed uint64
	// Total amount of RAM(in MB)
	MemMax uint64
	// Currently used RAM(in MB)
	MemUsed uint64
	// Total amount of Storage(in GB)
	DiskUsed uint64
	// Currently used Storage(in GB)
	DiskMax uint64
	// Total number of Floating IPs available
	FloatingIpsMax uint64
	// Currently used number of Floating IPs
	FloatingIpsUsed uint64
	// Total KBytes received
	NetRecv uint64
	// Total KBytes sent
	NetSent uint64
	// Total available IP addresses
	Ipv4Max uint64
	// Currently used IP addrs
	Ipv4Used uint64
}

// ResourceType is not exhaustive list, currently only ResourceTypeSecurityGroup is needed
type ResourceType string

const (
	ResourceTypeVM            ResourceType = "VM"
	ResourceTypeSubnet        ResourceType = "Subnet"
	ResourceTypeSecurityGroup ResourceType = "SecGrp"
)

type ProviderInitStage string

const (
	ProviderInitCreateCloudletDirect        ProviderInitStage = "CreateCloudletDirect"
	ProviderInitCreateCloudletRestricted    ProviderInitStage = "CreateCloudletRestricted"
	ProviderInitPlatformStartCrmConditional ProviderInitStage = "ProviderInitPlatformStartCrmConditional"
	ProviderInitPlatformStartCrmCommon      ProviderInitStage = "ProviderInitPlatformStartCrmCommon"
	ProviderInitPlatformStartShepherd       ProviderInitStage = "PlatformStartShepherd"
	ProviderInitDeleteCloudlet              ProviderInitStage = "DeleteCloudlet"
	ProviderInitGetVmSpec                   ProviderInitStage = "GetVmSpec"
)

// OperationInitStage is used to perform any common functions needed when starting and finishing an operation on the provider
type OperationInitStage string

const (
	OperationInitStart    OperationInitStage = "OperationStart"
	OperationInitComplete OperationInitStage = "OperationComplete"
)

// OperationInitResult indicates whether the initialization was newly done or previously done for
// the context.  It is necessary because there are some flows in which an initialization could
// be done multiple times.  If OperationAlreadyInitialized is returned, cleanup should be skipped
type OperationInitResult string

const (
	OperationNewlyInitialized   OperationInitResult = "OperationNewlyInitialized"
	OperationInitFailed         OperationInitResult = "OperationInitFailed"
	OperationAlreadyInitialized OperationInitResult = "OperationAlreadyInitialized"
)

// Some platforms like VCD needs an additional step to setup GPU driver.
// Hence, GPU drivers should only be setup as part of AppInst bringup.
// For other platforms like Openstack, GPU driver can be setup as part
// of ClusterInst bringup
type GPUSetupStage string

const (
	ClusterInstStage GPUSetupStage = "clusterinst"
	AppInstStage     GPUSetupStage = "appinst"
)

type StringSanitizer func(value string) string

type ResTagTables map[string]*edgeproto.ResTagTable

var pCaches *platform.Caches

// VMPlatform embeds Platform and VMProvider

func (v *VMPlatform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	var err error
	var result OperationInitResult
	ctx, result, err = v.VMProvider.InitOperationContext(ctx, OperationInitStart)
	if err != nil {
		return nil, err
	}
	if result == OperationNewlyInitialized {
		defer v.VMProvider.InitOperationContext(ctx, OperationInitComplete)
	}
	return v.GetClusterPlatformClientInternal(ctx, clusterInst, clientType, pc.WithCachedIp(true))
}

func (v *VMPlatform) GetClusterPlatformClientInternal(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string, ops ...pc.SSHClientOp) (ssh.Client, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetClusterPlatformClientInternal", "clientType", clientType, "IpAccess", clusterInst.IpAccess)
	rootLBName := v.VMProperties.SharedRootLBName
	if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		rootLBName = clusterInst.Fqdn
	}
	client, err := v.GetNodePlatformClient(ctx, &edgeproto.CloudletMgmtNode{Name: rootLBName}, ops...)
	if err != nil {
		return nil, err
	}
	if clientType == cloudcommon.ClientTypeClusterVM {
		vmIP, err := v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletMexNetwork(), GetClusterSubnetName(ctx, clusterInst), GetClusterMasterName(ctx, clusterInst))
		if err != nil {
			return nil, err
		}

		client, err = client.AddHop(vmIP.ExternalAddr, 22)
		if err != nil {
			return nil, err
		}
	}
	return client, nil
}

func (v *VMPlatform) GetNodePlatformClient(ctx context.Context, node *edgeproto.CloudletMgmtNode, ops ...pc.SSHClientOp) (ssh.Client, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetNodePlatformClient", "node", node)
	if node == nil {
		return nil, fmt.Errorf("cannot GetNodePlatformClient, as node details are empty")
	}
	nodeName := node.Name
	if nodeName == "" && node.Type == cloudcommon.NodeTypeSharedRootLB.String() {
		nodeName = v.VMProperties.SharedRootLBName
	}
	if nodeName == "" {
		return nil, fmt.Errorf("cannot GetNodePlatformClient, must specify node name")
	}
	var extNetName string
	if cloudcommon.IsPlatformNode(node.Type) && v.VMProperties.PlatformExternalNetwork != "" {
		extNetName = v.VMProperties.PlatformExternalNetwork
	} else {
		extNetName = v.VMProperties.GetCloudletExternalNetwork()
	}
	if extNetName == "" {
		return nil, fmt.Errorf("GetNodePlatformClient, missing external network in platform config")
	}
	var err error
	var result OperationInitResult
	ctx, result, err = v.VMProvider.InitOperationContext(ctx, OperationInitStart)
	if err != nil {
		return nil, err
	}
	if result == OperationNewlyInitialized {
		defer v.VMProvider.InitOperationContext(ctx, OperationInitComplete)
	}
	return v.GetSSHClientForServer(ctx, nodeName, extNetName, ops...)
}

func (v *VMPlatform) ListCloudletMgmtNodes(ctx context.Context, clusterInsts []edgeproto.ClusterInst, vmAppInsts []edgeproto.AppInst) ([]edgeproto.CloudletMgmtNode, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "ListCloudletMgmtNodes", "clusterInsts", clusterInsts, "vmAppInsts", vmAppInsts)
	mgmt_nodes := []edgeproto.CloudletMgmtNode{
		edgeproto.CloudletMgmtNode{
			Type: cloudcommon.NodeTypeSharedRootLB.String(),
			Name: v.VMProperties.SharedRootLBName,
		},
	}
	var cloudlet edgeproto.Cloudlet
	if !v.Caches.CloudletCache.Get(v.VMProperties.CommonPf.PlatformConfig.CloudletKey, &cloudlet) {
		return mgmt_nodes, fmt.Errorf("unable to find cloudlet key in cache")
	}
	if cloudlet.Deployment == cloudcommon.DeploymentTypeKubernetes {
		nodes := v.GetPlatformNodes(&cloudlet)
		for _, n := range nodes {
			mgmt_nodes = append(mgmt_nodes, edgeproto.CloudletMgmtNode{
				Type: n.NodeType.String(),
				Name: n.NodeName,
			})
			log.SpanLog(ctx, log.DebugLevelInfra, "added mgmt node", "name", n.NodeName, "type", n.NodeType)
		}
	} else {
		mgmt_nodes = append(mgmt_nodes, edgeproto.CloudletMgmtNode{
			Type: cloudcommon.NodeTypePlatformVM.String(),
			Name: v.GetPlatformVMName(v.VMProperties.CommonPf.PlatformConfig.CloudletKey),
		})
	}
	for _, clusterInst := range clusterInsts {
		if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
			mgmt_nodes = append(mgmt_nodes, edgeproto.CloudletMgmtNode{
				Type: cloudcommon.NodeTypeDedicatedRootLB.String(),
				Name: clusterInst.Fqdn,
			})
		}
	}
	for _, vmAppInst := range vmAppInsts {
		mgmt_nodes = append(mgmt_nodes, edgeproto.CloudletMgmtNode{
			Type: cloudcommon.NodeTypeDedicatedRootLB.String(),
			Name: vmAppInst.Uri,
		})
	}
	return mgmt_nodes, nil
}

func (v *VMPlatform) GetResTablesForCloudlet(ctx context.Context, ckey *edgeproto.CloudletKey) ResTagTables {

	if v.Caches == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "nil caches")
		return nil
	}
	var tbls = make(ResTagTables)
	cl := edgeproto.Cloudlet{}
	if !v.Caches.CloudletCache.Get(ckey, &cl) {
		log.SpanLog(ctx, log.DebugLevelInfra, "Not found in cache", "cloudlet", ckey.Name)
		return nil
	}
	for res, resKey := range cl.ResTagMap {
		var tbl edgeproto.ResTagTable
		if v.Caches.ResTagTableCache == nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "Caches.ResTagTableCache nil")
			return nil
		}
		if !v.Caches.ResTagTableCache.Get(resKey, &tbl) {
			continue
		}
		tbls[res] = &tbl
	}
	return tbls
}

func (v *VMPlatform) InitProps(ctx context.Context, platformConfig *platform.PlatformConfig) error {
	props := make(map[string]*edgeproto.PropertyInfo)
	for k, v := range VMProviderProps {
		props[k] = v
	}
	providerProps, err := v.VMProvider.GetProviderSpecificProps(ctx)
	if err != nil {
		return err
	}
	for k, v := range providerProps {
		props[k] = v
	}
	err = v.VMProperties.CommonPf.InitInfraCommon(ctx, platformConfig, props)
	if err != nil {
		return err
	}
	v.VMProvider.SetVMProperties(&v.VMProperties)
	v.VMProperties.SharedRootLBName = v.GetRootLBName(v.VMProperties.CommonPf.PlatformConfig.CloudletKey)
	v.VMProperties.PlatformSecgrpName = infracommon.GetServerSecurityGroupName(v.GetPlatformVMName(v.VMProperties.CommonPf.PlatformConfig.CloudletKey))
	v.VMProperties.CloudletSecgrpName = v.getCloudletSecurityGroupName()
	return nil
}

func (v *VMPlatform) initDebug(nodeMgr *node.NodeMgr) {
	nodeMgr.Debug.AddDebugFunc("crmrefreshsshkeys",
		func(ctx context.Context, req *edgeproto.DebugRequest) string {
			infracommon.TriggerRefreshCloudletSSHKeys(&v.VMProperties.CommonPf.SshKey)
			return "triggered refresh"
		})

	nodeMgr.Debug.AddDebugFunc("crmupgradecmd", v.crmUpgradeCmd)
}

func (v *VMPlatform) crmUpgradeCmd(ctx context.Context, req *edgeproto.DebugRequest) string {
	results, err := v.UpgradeFuncHandleSSHKeys(ctx, v.VMProperties.CommonPf.PlatformConfig.AccessApi, v.Caches)
	if err != nil {
		return fmt.Sprintf("failed to upgrade vms to vault ssh keys: %v", err)
	}
	return fmt.Sprintf("%v", results)
}

func (v *VMPlatform) InitCommon(ctx context.Context, platformConfig *platform.PlatformConfig, caches *platform.Caches, haMgr *redundancy.HighAvailabilityManager, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "InitCommon", "physicalName", platformConfig.PhysicalName, "type", v.Type)
	// setup the internal cloudlet cache which does not come from the controller
	cloudletInternal := edgeproto.CloudletInternal{
		Key:   *platformConfig.CloudletKey,
		Props: make(map[string]string),
	}
	cloudletInternal.Props[infracommon.CloudletPlatformActive] = fmt.Sprintf("%t", haMgr.PlatformInstanceActive)
	caches.CloudletInternalCache.Update(ctx, &cloudletInternal, 0)
	v.Caches = caches
	v.VMProperties.Domain = VMDomainCompute
	if platformConfig.GPUConfig != nil {
		v.GPUConfig = *platformConfig.GPUConfig
	}
	v.CacheDir = platformConfig.CacheDir
	if _, err := os.Stat(v.CacheDir); os.IsNotExist(err) {
		return fmt.Errorf("CacheDir doesn't exist, please create one")
	}
	v.HAManager = haMgr

	if !platformConfig.TestMode {
		err := v.VMProperties.CommonPf.InitCloudletSSHKeys(ctx, platformConfig.AccessApi)
		if err != nil {
			return err
		}
		go v.VMProperties.CommonPf.RefreshCloudletSSHKeys(platformConfig.AccessApi)
	}

	var err error
	if err = v.InitProps(ctx, platformConfig); err != nil {
		return err
	}
	v.initDebug(v.VMProperties.CommonPf.PlatformConfig.NodeMgr)

	v.VMProvider.InitData(ctx, caches)

	updateCallback(edgeproto.UpdateTask, "Fetching API access credentials")
	if err = v.VMProvider.InitApiAccessProperties(ctx, platformConfig.AccessApi, platformConfig.EnvVars); err != nil {
		return err
	}
	v.FlavorList, err = v.VMProvider.GetFlavorList(ctx)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetFlavorList failed", "err", err)
		return err
	}
	var cloudlet edgeproto.Cloudlet
	if !v.Caches.CloudletCache.Get(v.VMProperties.CommonPf.PlatformConfig.CloudletKey, &cloudlet) {
		return fmt.Errorf("unable to find cloudlet key in cache")
	}
	v.VMProperties.PlatformExternalNetwork = cloudlet.InfraConfig.ExternalNetworkName

	if err = v.VMProvider.InitProvider(ctx, caches, ProviderInitPlatformStartCrmCommon, updateCallback); err != nil {
		return err
	}
	return nil

}

func (v *VMPlatform) InitHAConditional(ctx context.Context, platformConfig *platform.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "InitHAConditional")

	if err := v.VMProvider.InitProvider(ctx, v.Caches, ProviderInitPlatformStartCrmConditional, updateCallback); err != nil {
		return err
	}
	var result OperationInitResult
	ctx, result, err := v.VMProvider.InitOperationContext(ctx, OperationInitStart)
	if err != nil {
		return err
	}
	if result == OperationNewlyInitialized {
		defer v.VMProvider.InitOperationContext(ctx, OperationInitComplete)
	}

	if err := v.ConfigureCloudletSecurityRules(ctx, ActionCreate); err != nil {
		if v.VMProperties.IptablesBasedFirewall {
			// iptables based security rules can fail on one clusterInst LB, but we cannot treat
			// this as a fatal error or it can cause the CRM to never initialize
			log.SpanLog(ctx, log.DebugLevelInfra, "Warning: error in ConfigureCloudletSecurityRules", "err", err)
		} else {
			return err
		}
	}

	tags := GetChefRootLBTags(platformConfig)
	err = v.CreateRootLB(ctx, v.VMProperties.SharedRootLBName, v.VMProperties.CommonPf.PlatformConfig.CloudletKey, v.VMProperties.CommonPf.PlatformConfig.CloudletVMImagePath, v.VMProperties.CommonPf.PlatformConfig.VMImageVersion, ActionCreate, tags, updateCallback)
	if err != nil {
		return fmt.Errorf("Error creating rootLB: %v", err)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "created shared rootLB", "name", v.VMProperties.SharedRootLBName)

	if platformConfig.Upgrade {
		v.VMProperties.Upgrade = true
		// Pull private key from Vault
		log.SpanLog(ctx, log.DebugLevelInfra, "Fetch private key from vault")
		mexKey, err := platformConfig.AccessApi.GetOldSSHKey(ctx)
		if err != nil {
			return err
		}
		v.VMProperties.CommonPf.SshKey.MEXPrivateKey = mexKey.PrivateKey

		log.SpanLog(ctx, log.DebugLevelInfra, "Upgrade shared rootlb to use vault SSH")

		// Upgrade Shared RootLB to use Vault SSH
		// Set SSH client to use mex private key
		v.VMProperties.CommonPf.SshKey.UseMEXPrivateKey = true
		sharedRootLBClient, err := v.GetSSHClientForServer(ctx, v.VMProperties.SharedRootLBName, v.VMProperties.GetCloudletExternalNetwork())
		if err != nil {
			return err
		}
		publicSSHKey, err := platformConfig.AccessApi.GetSSHPublicKey(ctx)
		if err != nil {
			return err
		}
		upgradeScript := GetVaultCAScript(publicSSHKey)
		ExecuteUpgradeScript(ctx, v.VMProperties.SharedRootLBName, sharedRootLBClient, upgradeScript)
		// Verify if shared rootlb is reachable using vault SSH
		// Set SSH client to use vault signed Keys
		v.VMProperties.CommonPf.SshKey.UseMEXPrivateKey = false
		sharedRootLBClient, err = v.GetSSHClientForServer(ctx, v.VMProperties.SharedRootLBName, v.VMProperties.GetCloudletExternalNetwork())
		if err != nil {
			return err
		}
		_, err = sharedRootLBClient.Output("hostname")
		if err != nil {
			return fmt.Errorf("failed to access shared rootlb: %v", err)
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "successfully upgraded shared rootlb to use Vault SSH")
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "calling SetupRootLB")
	updateCallback(edgeproto.UpdateTask, "Setting up RootLB")
	rootLBFQDN := platformConfig.RootLBFQDN
	err = v.SetupRootLB(ctx, v.VMProperties.SharedRootLBName, rootLBFQDN, v.VMProperties.CommonPf.PlatformConfig.CloudletKey, nil, updateCallback)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "ok, SetupRootLB")
	return nil
}

//  for now there is only only HA Conditional compat version for all providers. This could be
// changed if needed, but if a  provider specific version is defined it should be appended to
// the VMPlatform version in place of v.Type in case the VMPlatform init sequence changes
func (v *VMPlatform) GetInitHAConditionalCompatibilityVersion(ctx context.Context) string {
	return "VMPlatform-1.0-" + v.Type
}

func (v *VMPlatform) PerformUpgrades(ctx context.Context, caches *platform.Caches, cloudletState dme.CloudletState) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "PerformUpgrades", "cloudletState", cloudletState)

	if v.VMProperties.Upgrade {
		_, err := v.UpgradeFuncHandleSSHKeys(ctx, v.VMProperties.CommonPf.PlatformConfig.AccessApi, caches)
		if err != nil {
			return err
		}
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "Upgrade CRM Config")
	// upgrade k8s config on each rootLB
	sharedRootLBClient, err := v.GetNodePlatformClient(ctx, &edgeproto.CloudletMgmtNode{Name: v.VMProperties.SharedRootLBName}, pc.WithCachedIp(true))
	if err != nil {
		return err
	}
	err = k8smgmt.UpgradeConfig(ctx, caches, sharedRootLBClient, v.GetClusterPlatformClient)
	if err != nil {
		return err
	}
	return nil
}

func (v *VMPlatform) GetCloudletInfraResources(ctx context.Context) (*edgeproto.InfraResourcesSnapshot, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetCloudletInfraResources")

	var err error
	var result OperationInitResult
	ctx, result, err = v.VMProvider.InitOperationContext(ctx, OperationInitStart)
	if err != nil {
		return nil, err
	}
	if result == OperationNewlyInitialized {
		defer v.VMProvider.InitOperationContext(ctx, OperationInitComplete)
	}
	var resources edgeproto.InfraResourcesSnapshot
	platResources, err := v.VMProvider.GetServerGroupResources(ctx, v.GetPlatformVMName(&v.VMProperties.CommonPf.PlatformConfig.NodeMgr.MyNode.Key.CloudletKey))
	if err == nil {
		for ii := range platResources.Vms {
			platResources.Vms[ii].Type = cloudcommon.NodeTypePlatformVM.String()
		}
		resources.PlatformVms = append(resources.PlatformVms, platResources.Vms...)
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "Failed to get platform VM resources", "err", err)
	}
	rootlbResources, err := v.VMProvider.GetServerGroupResources(ctx, v.VMProperties.SharedRootLBName)
	if err == nil {
		resources.PlatformVms = append(resources.PlatformVms, rootlbResources.Vms...)
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "Failed to get root lb resources", "err", err)
	}
	resourcesInfo, err := v.VMProvider.GetCloudletInfraResourcesInfo(ctx)
	if err == nil {
		resources.Info = resourcesInfo
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "Failed to get cloudlet infra resources info", "err", err)
	}
	return &resources, nil
}

func (v *VMPlatform) GetCloudletResourceQuotaProps(ctx context.Context) (*edgeproto.CloudletResourceQuotaProps, error) {
	return v.VMProvider.GetCloudletResourceQuotaProps(ctx)
}

// called by controller, make sure it doesn't make any calls to infra API
func (v *VMPlatform) GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource, infraResMap map[string]edgeproto.InfraResource) map[string]edgeproto.InfraResource {
	return v.VMProvider.GetClusterAdditionalResources(ctx, cloudlet, vmResources, infraResMap)
}

func (v *VMPlatform) GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error {
	return v.VMProvider.GetClusterAdditionalResourceMetric(ctx, cloudlet, resMetric, resources)
}

func (v *VMPlatform) GetClusterInfraResources(ctx context.Context, clusterKey *edgeproto.ClusterInstKey) (*edgeproto.InfraResources, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetClusterInfraResources")

	var err error
	var result OperationInitResult
	ctx, result, err = v.VMProvider.InitOperationContext(ctx, OperationInitStart)
	if err != nil {
		return nil, err
	}
	if result == OperationNewlyInitialized {
		defer v.VMProvider.InitOperationContext(ctx, OperationInitComplete)
	}

	clusterName := v.VMProvider.NameSanitize(k8smgmt.GetCloudletClusterName(clusterKey))
	return v.VMProvider.GetServerGroupResources(ctx, clusterName)
}

func (v *VMPlatform) GetAccessData(ctx context.Context, cloudlet *edgeproto.Cloudlet, region string, vaultConfig *vault.Config, dataType string, arg []byte) (map[string]string, error) {
	log.SpanLog(ctx, log.DebugLevelApi, "VMProvider GetAccessData", "dataType", dataType)
	switch dataType {
	case accessapi.GetCloudletAccessVars:
		path := v.VMProvider.GetVaultCloudletAccessPath(&cloudlet.Key, region, cloudlet.PhysicalName)
		if path == "" {
			log.SpanLog(ctx, log.DebugLevelApi, "No access vars path, returning empty map")
			vars := make(map[string]string, 1)
			return vars, nil
		}
		vars, err := infracommon.GetEnvVarsFromVault(ctx, vaultConfig, path)
		log.SpanLog(ctx, log.DebugLevelApi, "VMProvider GetAccessData", "dataType", dataType, "path", path, "err", err)
		if err != nil {
			return nil, err
		}
		return vars, nil
	case accessapi.GetSessionTokens:
		return v.VMProvider.GetSessionTokens(ctx, vaultConfig, string(arg))
	}
	return nil, fmt.Errorf("VMPlatform unhandled GetAccessData type %s", dataType)
}
