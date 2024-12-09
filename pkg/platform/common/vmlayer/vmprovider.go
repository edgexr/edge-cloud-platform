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

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	"github.com/edgexr/edge-cloud-platform/pkg/proxy/certs"
	certscache "github.com/edgexr/edge-cloud-platform/pkg/proxy/certs-cache"
	"github.com/edgexr/edge-cloud-platform/pkg/redundancy"
	ssh "github.com/edgexr/golang-ssh"
	"github.com/gogo/protobuf/types"
)

// VMProvider is an interface that platforms implement to perform the details of interfacing with the orchestration layer

type VMProvider interface {
	NameSanitize(string) string
	IdSanitize(string) string
	SetVMProperties(vmProperties *VMProperties)
	GetFeatures() *edgeproto.PlatformFeatures
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
	AttachPortToServer(ctx context.Context, serverName string, subnetNames SubnetNames, portName string, ips infracommon.IPs, action ActionType) error
	DetachPortFromServer(ctx context.Context, serverName string, subnetNames SubnetNames, portName string) error
	PrepareRootLB(ctx context.Context, client ssh.Client, rootLBName string, secGrpName string, TrustPolicy *edgeproto.TrustPolicy, updateCallback edgeproto.CacheUpdateCallback) error
	WhitelistSecurityRules(ctx context.Context, client ssh.Client, wlParams *infracommon.WhiteListParams) error
	RemoveWhitelistSecurityRules(ctx context.Context, client ssh.Client, wlParams *infracommon.WhiteListParams) error
	GetResourceID(ctx context.Context, resourceType ResourceType, resourceName string) (string, error)
	InitApiAccessProperties(ctx context.Context, accessApi platform.AccessApi, vars map[string]string) error
	GetApiEndpointAddr(ctx context.Context) (string, error)
	GetExternalGateway(ctx context.Context, extNetName string) (string, error)
	SetPowerState(ctx context.Context, serverName, serverAction string) error
	GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error
	GetCloudletManifest(ctx context.Context, name string, cloudletImagePath string, VMGroupOrchestrationParams *VMGroupOrchestrationParams) (string, error)
	GetRouterDetail(ctx context.Context, routerName string) (*RouterDetail, error)
	CreateVMs(ctx context.Context, vmGroupOrchestrationParams *VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error
	UpdateVMs(ctx context.Context, vmGroupOrchestrationParams *VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error
	DeleteVMs(ctx context.Context, vmGroupName, ownerID string) error
	GetVMStats(ctx context.Context, appInst *edgeproto.AppInst) (*VMMetrics, error)
	GetPlatformResourceInfo(ctx context.Context) (*PlatformResources, error)
	VerifyVMs(ctx context.Context, vms []edgeproto.VM) error
	CheckServerReady(ctx context.Context, client ssh.Client, serverName string) error
	GetServerGroupResources(ctx context.Context, name string) (*edgeproto.InfraResources, error)
	ValidateAdditionalNetworks(ctx context.Context, additionalNets map[string]NetworkType) error
	ConfigureCloudletSecurityRules(ctx context.Context, egressRestricted bool, TrustPolicy *edgeproto.TrustPolicy, rootlbClients map[string]platform.RootLBClient, action ActionType, updateCallback edgeproto.CacheUpdateCallback) error
	ConfigureTrustPolicyExceptionSecurityRules(ctx context.Context, TrustPolicyException *edgeproto.TrustPolicyException, rootLbClients map[string]platform.RootLBClient, action ActionType, updateCallback edgeproto.CacheUpdateCallback) error
	InitOperationContext(ctx context.Context, operationStage OperationInitStage) (context.Context, OperationInitResult, error)
	GetCloudletInfraResourcesInfo(ctx context.Context) ([]edgeproto.InfraResource, error)
	GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource) map[string]edgeproto.InfraResource
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
	flavorList   []*edgeproto.FlavorInfo
	Caches       *platform.Caches
	GPUConfig    edgeproto.GPUConfig
	CacheDir     string
	infracommon.CommonEmbedded
	HAManager  *redundancy.HighAvailabilityManager
	proxyCerts *certs.ProxyCerts
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
		rootLBName = clusterInst.StaticFqdn
	}
	client, err := v.GetNodePlatformClient(ctx, &edgeproto.CloudletMgmtNode{Name: rootLBName}, ops...)
	if err != nil {
		return nil, err
	}
	if clientType == cloudcommon.ClientTypeClusterVM {
		vmIPs, err := v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletMexNetwork(), v.GetClusterSubnetName(ctx, clusterInst), GetClusterMasterName(ctx, clusterInst))
		if err != nil {
			return nil, err
		}

		client, err = client.AddHop(vmIPs.IPV4ExternalAddr(), 22)
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
				Name: clusterInst.StaticFqdn,
			})
		}
	}
	for _, vmAppInst := range vmAppInsts {
		mgmt_nodes = append(mgmt_nodes, edgeproto.CloudletMgmtNode{
			Type: cloudcommon.NodeTypeDedicatedRootLB.String(),
			Name: vmAppInst.StaticUri,
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

func (v *VMPlatform) InitProps(ctx context.Context, platformConfig *platform.PlatformConfig, ops ...infracommon.InitOp) error {
	props := make(map[string]*edgeproto.PropertyInfo)
	for k, v := range VMProviderProps {
		props[k] = v
	}
	features := v.GetFeatures()
	for k, v := range features.Properties {
		props[k] = v
	}
	err := v.VMProperties.CommonPf.InitInfraCommon(ctx, platformConfig, props, ops...)
	if err != nil {
		return err
	}
	v.VMProvider.SetVMProperties(&v.VMProperties)
	v.VMProperties.SharedRootLBName = v.GetRootLBName(v.VMProperties.CommonPf.PlatformConfig.CloudletKey)
	v.VMProperties.PlatformSecgrpName = infracommon.GetServerSecurityGroupName(v.GetPlatformVMName(v.VMProperties.CommonPf.PlatformConfig.CloudletKey))
	v.VMProperties.CloudletSecgrpName = v.getCloudletSecurityGroupName()
	v.VMProperties.CloudletEnableIPV6 = features.SupportsIpv6
	return nil
}

func (v *VMPlatform) initDebug(nodeMgr *node.NodeMgr) {
	nodeMgr.Debug.AddDebugFunc("refresh-rootlb-certs", func(ctx context.Context, req *edgeproto.DebugRequest) string {
		v.proxyCerts.TriggerRootLBCertsRefresh()
		return "triggered refresh of rootlb certs"
	})
}

func (v *VMPlatform) InitCommon(ctx context.Context, platformConfig *platform.PlatformConfig, caches *platform.Caches, haMgr *redundancy.HighAvailabilityManager, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "InitCommon", "physicalName", platformConfig.PhysicalName, "type", v.Type)
	if platformConfig.CrmOnEdge && haMgr != nil {
		// setup the internal cloudlet cache which does not come from the controller
		cloudletInternal := edgeproto.CloudletInternal{
			Key:   *platformConfig.CloudletKey,
			Props: make(map[string]string),
		}
		cloudletInternal.Props[infracommon.CloudletPlatformActive] = fmt.Sprintf("%t", haMgr.PlatformInstanceActive)
		caches.CloudletInternalCache.Update(ctx, &cloudletInternal, 0)
	}
	v.Caches = caches
	if platformConfig.CrmOnEdge {
		v.VMProperties.Domain = VMDomainCompute
	} else {
		v.VMProperties.Domain = VMDomainPlatform
	}
	if platformConfig.GPUConfig != nil {
		v.GPUConfig = *platformConfig.GPUConfig
	}
	v.CacheDir = platformConfig.CacheDir
	if _, err := os.Stat(v.CacheDir); os.IsNotExist(err) {
		return fmt.Errorf("CacheDir doesn't exist, please create one")
	}
	v.HAManager = haMgr

	var err error
	if err = v.InitProps(ctx, platformConfig); err != nil {
		return err
	}
	if platformConfig.CrmOnEdge {
		v.initDebug(v.VMProperties.CommonPf.PlatformConfig.NodeMgr)
	}
	v.VMProvider.InitData(ctx, caches)

	updateCallback(edgeproto.UpdateTask, "Fetching API access credentials")
	if err = v.VMProvider.InitApiAccessProperties(ctx, platformConfig.AccessApi, platformConfig.EnvVars); err != nil {
		return err
	}
	var cloudlet edgeproto.Cloudlet
	if !v.Caches.CloudletCache.Get(v.VMProperties.CommonPf.PlatformConfig.CloudletKey, &cloudlet) {
		return fmt.Errorf("unable to find cloudlet key in cache")
	}
	// TODO: resolve why there are two ways to store/use the external network name
	v.VMProperties.PlatformExternalNetwork = cloudlet.InfraConfig.ExternalNetworkName
	if cloudlet.InfraConfig.ExternalNetworkName != "" {
		v.VMProperties.SetCloudletExternalNetwork(cloudlet.InfraConfig.ExternalNetworkName)
	}

	v.proxyCerts = certs.NewProxyCerts(ctx, platformConfig.CloudletKey, v, platformConfig.NodeMgr, haMgr, v.GetFeatures(), platformConfig.CommercialCerts, platformConfig.EnvoyWithCurlImage, platformConfig.ProxyCertsCache)
	v.proxyCerts.Start(ctx)

	if err = v.VMProvider.InitProvider(ctx, caches, ProviderInitPlatformStartCrmCommon, updateCallback); err != nil {
		return err
	}
	return nil

}

func (v *VMPlatform) InitHAConditional(ctx context.Context, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "InitHAConditional")

	platformConfig := v.VMProperties.CommonPf.PlatformConfig
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

	_, err = v.VMProvider.GetServerDetail(ctx, v.VMProperties.SharedRootLBName)
	if err == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "rootlb already exists, updating ports")
		// avoid downtime during crm upgrades by running rootLB update in the background. Most of the time nothing will change.
		go func() {
			cspan, cctx := log.ChildSpan(ctx, log.DebugLevelInfra, "update rootLB")
			err := v.initRootLB(cctx, platformConfig, ActionUpdate, updateCallback)
			log.SpanLog(cctx, log.DebugLevelApi, "update rootLB finished", "err", err)
			cspan.Finish()
			if err != nil {
				log.FatalLog("rootLB update failed", "err", err)
			}
		}()
	} else {
		err := v.initRootLB(ctx, platformConfig, ActionCreate, updateCallback)
		if err != nil {
			return err
		}
		v.checkRebuildRootLb(ctx, v.Caches, updateCallback)
	}
	v.proxyCerts.TriggerRootLBCertsRefresh()
	return nil
}

func (v *VMPlatform) GetCachedFlavorList(ctx context.Context) ([]*edgeproto.FlavorInfo, error) {
	if v.flavorList == nil {
		flavorList, err := v.VMProvider.GetFlavorList(ctx)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "GetFlavorList failed", "err", err)
			return nil, fmt.Errorf("get cached flavor list failed, %s", err)
		}
		v.flavorList = flavorList
	}
	return v.flavorList, nil
}

func (v *VMPlatform) initRootLB(ctx context.Context, platformConfig *platform.PlatformConfig, action ActionType, updateCallback edgeproto.CacheUpdateCallback) error {
	var rootLBNodeRole cloudcommon.NodeRole
	if platformConfig.CrmOnEdge {
		// Shepherd runs on platform VM with CRM
		rootLBNodeRole = cloudcommon.NodeRoleBase
	} else {
		// No platform VM, Shepherd runs on rootLB
		rootLBNodeRole = cloudcommon.NodeRoleDockerShepherdLB
	}
	err := v.CreateRootLB(ctx, v.VMProperties.SharedRootLBName, v.VMProperties.CommonPf.PlatformConfig.CloudletKey, action, platformConfig.RootLBAccessKey, rootLBNodeRole, updateCallback)
	if err != nil {
		return fmt.Errorf("Error creating rootLB: %v", err)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "created rootLB", "name", v.VMProperties.SharedRootLBName)

	log.SpanLog(ctx, log.DebugLevelInfra, "calling SetupRootLB")
	updateCallback(edgeproto.UpdateTask, "Setting up RootLB")
	rootLBFQDN := platformConfig.RootLBFQDN
	// get server detail again in case it was changed by CreateOrUpdateRootLB
	sd, err := v.VMProvider.GetServerDetail(ctx, v.VMProperties.SharedRootLBName)
	if err == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "rootlb already exists, updating it")
		action = ActionUpdate
	}
	err = v.SetupRootLB(ctx, v.VMProperties.SharedRootLBName, rootLBFQDN, v.VMProperties.CommonPf.PlatformConfig.CloudletKey, nil, sd, v.VMProperties.CloudletEnableIPV6, updateCallback)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "ok, SetupRootLB")
	return nil
}

// updateAppInstConfigForLb
func (v *VMPlatform) updateAppInstConfigForLb(ctx context.Context, caches *platform.Caches, appInst *edgeproto.AppInst) {
	log.SpanLog(ctx, log.DebugLevelInfra, "Update rootLb for appInst", "AppInst", appInst.Key)
	app := edgeproto.App{}
	if !caches.AppCache.Get(&appInst.AppKey, &app) {
		log.SpanLog(ctx, log.DebugLevelInfra, "upgrade version single cluster config dir, App not found", "AppInst", appInst.Key)
		return
	}
	cinst := edgeproto.ClusterInst{}
	if !caches.ClusterInstCache.Get(appInst.GetClusterKey(), &cinst) {
		log.SpanLog(ctx, log.DebugLevelInfra, "clusterInstNot found", "AppInst", appInst.Key)
		return
	}
	// Only update shared access appInsts
	if cinst.IpAccess != edgeproto.IpAccess_IP_ACCESS_SHARED {
		log.SpanLog(ctx, log.DebugLevelInfra, "appinst uses dedicated ip access", "AppInst", appInst.Key)
		return
	}

	names, err := k8smgmt.GetKubeNames(&cinst, &app, appInst)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "update appinst data for lb, names failed", "AppInst", appInst.Key, "err", err)
		return
	}
	client, err := v.GetClusterPlatformClient(ctx, &cinst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "update appinst data for lb, get client failed", "AppInst", appInst.Key, "err", err)
		return
	}
	if app.Deployment == cloudcommon.DeploymentTypeKubernetes ||
		app.Deployment == cloudcommon.DeploymentTypeHelm {
		// Update appinst manifests on the rootLb
		err = k8smgmt.WriteDeploymentManifestToFile(ctx, v.VMProperties.CommonPf.PlatformConfig.AccessApi, client, names, &app, appInst)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to write deployment manifest to rootLb", "AppInst", appInst.Key, "err", err)
		}
	}

	// Create proxy container for app
	err = v.setupDnsForAppInst(ctx, &cinst, &app, appInst, client, app.Deployment)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to set up proxy and update dns names", "AppInst", appInst.Key, "err", err)
	}
}

// CheckRebuildRootLb gets called when we created rootLb and we need to check
// if there are any clusters that need to be re-connected to this rootLb
// Also check if any appInst states need syncing
func (v *VMPlatform) checkRebuildRootLb(ctx context.Context, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CheckRebuildRootLb")

	// Update clusters
	clusters := make([]*edgeproto.ClusterInst, 0)
	caches.ClusterInstCache.Mux.Lock()
	for _, data := range caches.ClusterInstCache.Objs {
		if data.Obj.IpAccess == edgeproto.IpAccess_IP_ACCESS_SHARED {
			inst := edgeproto.ClusterInst{}
			inst.DeepCopyIn(data.Obj)
			clusters = append(clusters, &inst)
		}
	}
	caches.ClusterInstCache.Mux.Unlock()

	// No shared access clusters, just return
	if len(clusters) == 0 {
		log.SpanLog(ctx, log.DebugLevelInfra, "No clusters to update")
		return nil
	}
	for _, cluster := range clusters {
		log.SpanLog(ctx, log.DebugLevelInfra, "Update rootLb for cluster", "cluster", cluster)
		// Add cluster config to the rootLb as well as patch rootLB VM with k8s network for this cluster
		if _, err := v.UpdateClusterInst(ctx, cluster, updateCallback); err != nil {
			// The whole process is best effort, so try to update config for every cluster that we can
			log.SpanLog(ctx, log.DebugLevelInfra, "Failed to update cluster", "cluster", cluster, "err", err)
		}
	}

	// Update AppInsts
	appInsts := make([]*edgeproto.AppInst, 0)
	caches.AppInstCache.Mux.Lock()
	for _, data := range caches.AppInstCache.Objs {
		inst := edgeproto.AppInst{}
		inst.DeepCopyIn(data.Obj)
		appInsts = append(appInsts, &inst)
	}
	caches.AppInstCache.Mux.Unlock()

	for _, appInst := range appInsts {
		v.updateAppInstConfigForLb(ctx, caches, appInst)
	}

	return nil
}

// for now there is only only HA Conditional compat version for all providers. This could be
// changed if needed, but if a  provider specific version is defined it should be appended to
// the VMPlatform version in place of v.Type in case the VMPlatform init sequence changes
func (v *VMPlatform) GetInitHAConditionalCompatibilityVersion(ctx context.Context) string {
	return "VMPlatform-1.0-" + v.Type
}

func (v *VMPlatform) PerformUpgrades(ctx context.Context, caches *platform.Caches, cloudletState dme.CloudletState) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "PerformUpgrades", "cloudletState", cloudletState)

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

// called by controller, make sure it doesn't make any calls to infra API
func (v *VMPlatform) GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource) map[string]edgeproto.InfraResource {
	return v.VMProvider.GetClusterAdditionalResources(ctx, cloudlet, vmResources)
}

func (v *VMPlatform) GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error {
	return v.VMProvider.GetClusterAdditionalResourceMetric(ctx, cloudlet, resMetric, resources)
}

func (v *VMPlatform) GetClusterInfraResources(ctx context.Context, cluster *edgeproto.ClusterInst) (*edgeproto.InfraResources, error) {
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

	clusterName := v.VMProvider.NameSanitize(k8smgmt.GetCloudletClusterName(cluster))
	return v.VMProvider.GetServerGroupResources(ctx, clusterName)
}

func (v *VMPlatform) RefreshCerts(ctx context.Context, certsCache *certscache.ProxyCertsCache) error {
	return nil
}
