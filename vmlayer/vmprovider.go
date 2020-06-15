package vmlayer

import (
	"context"
	"fmt"

	"github.com/gogo/protobuf/types"
	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/proxy"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	dme "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"

	ssh "github.com/mobiledgex/golang-ssh"
)

// VMProvider is an interface that platforms implement to perform the details of interfacing with the orchestration layer

type VMProvider interface {
	NameSanitize(string) string
	IdSanitize(string) string
	GetProviderSpecificProps() map[string]*infracommon.PropertyInfo
	SetVMProperties(vmProperties *VMProperties)
	SetCaches(ctx context.Context, caches *platform.Caches)
	InitProvider(ctx context.Context, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) error
	ImportDataFromInfra(ctx context.Context) error
	GetFlavorList(ctx context.Context) ([]*edgeproto.FlavorInfo, error)
	GetNetworkList(ctx context.Context) ([]string, error)
	AddCloudletImageIfNotPresent(ctx context.Context, imgPathPrefix, imgVersion string, updateCallback edgeproto.CacheUpdateCallback) (string, error)
	AddAppImageIfNotPresent(ctx context.Context, app *edgeproto.App, flavor string, updateCallback edgeproto.CacheUpdateCallback) error
	DeleteImage(ctx context.Context, folder, image string) error
	GetServerDetail(ctx context.Context, serverName string) (*ServerDetail, error)
	GetConsoleUrl(ctx context.Context, serverName string) (string, error)
	GetInternalPortPolicy() InternalPortAttachPolicy
	AttachPortToServer(ctx context.Context, serverName, subnetName, portName, ipaddr string, action ActionType) error
	DetachPortFromServer(ctx context.Context, serverName, subnetName, portName string) error
	AddSecurityRuleCIDRWithRetry(ctx context.Context, cidr string, proto string, group string, port string, serverName string) error
	WhitelistSecurityRules(ctx context.Context, secGrpName string, serverName string, allowedCIDR string, ports []dme.AppPort) error
	RemoveWhitelistSecurityRules(ctx context.Context, secGrpName string, allowedCIDR string, ports []dme.AppPort) error
	GetResourceID(ctx context.Context, resourceType ResourceType, resourceName string) (string, error)
	GetApiAccessFilename() string
	InitApiAccessProperties(ctx context.Context, key *edgeproto.CloudletKey, region, physicalName string, vaultConfig *vault.Config, vars map[string]string) error
	GetApiEndpointAddr(ctx context.Context) (string, error)
	GetExternalGateway(ctx context.Context, extNetName string) (string, error)
	SaveCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, accessVarsIn map[string]string, pfConfig *edgeproto.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error
	SetPowerState(ctx context.Context, serverName, serverAction string) error
	GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error
	GetCloudletManifest(ctx context.Context, name string, VMGroupOrchestrationParams *VMGroupOrchestrationParams) (string, error)
	GetRouterDetail(ctx context.Context, routerName string) (*RouterDetail, error)
	CreateVMs(ctx context.Context, vmGroupOrchestrationParams *VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error
	UpdateVMs(ctx context.Context, vmGroupOrchestrationParams *VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error
	SyncVMs(ctx context.Context, vmGroupOrchestrationParams *VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error
	DeleteVMs(ctx context.Context, vmGroupName string) error
	GetVMStats(ctx context.Context, key *edgeproto.AppInstKey) (*VMMetrics, error)
	GetPlatformResourceInfo(ctx context.Context) (*PlatformResources, error)
}

// VMPlatform contains the needed by all VM based platforms
type VMPlatform struct {
	Type         string
	VMProvider   VMProvider
	VMProperties VMProperties
	FlavorList   []*edgeproto.FlavorInfo
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

const (
	VMProviderOpenstack string = "openstack"
	VMProviderVSphere   string = "vsphere"
)

type StringSanitizer func(value string) string

// VMPlatform embeds Platform and VMProvider

func (v *VMPlatform) GetType() string {
	return v.Type
}

func (v *VMPlatform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst) (ssh.Client, error) {
	rootLBName := v.VMProperties.sharedRootLBName
	if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		rootLBName = cloudcommon.GetDedicatedLBFQDN(v.VMProperties.CommonPf.PlatformConfig.CloudletKey, &clusterInst.Key.ClusterKey, v.VMProperties.CommonPf.PlatformConfig.AppDNSRoot)
	}
	return v.GetNodePlatformClient(ctx, &edgeproto.CloudletMgmtNode{Name: rootLBName})
}

func (v *VMPlatform) GetNodePlatformClient(ctx context.Context, node *edgeproto.CloudletMgmtNode) (ssh.Client, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetNodePlatformClient", "node", node)

	if node == nil || node.Name == "" {
		return nil, fmt.Errorf("cannot GetNodePlatformClient, as node details are empty")
	}
	if v.VMProperties.GetCloudletExternalNetwork() == "" {
		return nil, fmt.Errorf("GetNodePlatformClient, missing external network in platform config")
	}
	return v.GetSSHClientForServer(ctx, node.Name, v.VMProperties.GetCloudletExternalNetwork())
}

func (v *VMPlatform) ListCloudletMgmtNodes(ctx context.Context, clusterInsts []edgeproto.ClusterInst) ([]edgeproto.CloudletMgmtNode, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "ListCloudletMgmtNodes", "clusterInsts", clusterInsts)
	mgmt_nodes := []edgeproto.CloudletMgmtNode{
		edgeproto.CloudletMgmtNode{
			Type: "platformvm",
			Name: v.GetPlatformVMName(v.VMProperties.CommonPf.PlatformConfig.CloudletKey),
		},
		edgeproto.CloudletMgmtNode{
			Type: "sharedrootlb",
			Name: v.VMProperties.sharedRootLBName,
		},
	}
	for _, clusterInst := range clusterInsts {
		if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
			mgmt_nodes = append(mgmt_nodes, edgeproto.CloudletMgmtNode{
				Type: "dedicatedrootlb",
				Name: cloudcommon.GetDedicatedLBFQDN(v.VMProperties.CommonPf.PlatformConfig.CloudletKey, &clusterInst.Key.ClusterKey, v.VMProperties.CommonPf.PlatformConfig.AppDNSRoot),
			})
		}
	}
	return mgmt_nodes, nil
}

func (v *VMPlatform) InitProps(ctx context.Context, platformConfig *platform.PlatformConfig, vaultConfig *vault.Config) error {
	providerProps := v.VMProvider.GetProviderSpecificProps()
	for k, v := range VMProviderProps {
		providerProps[k] = v
	}
	err := v.VMProperties.CommonPf.InitInfraCommon(ctx, platformConfig, providerProps, vaultConfig)
	if err != nil {
		return err
	}
	v.VMProvider.SetVMProperties(&v.VMProperties)
	return nil
}

func (v *VMPlatform) Init(ctx context.Context, platformConfig *platform.PlatformConfig, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx,
		log.DebugLevelInfra, "Init VMPlatform",
		"physicalName", platformConfig.PhysicalName,
		"vaultAddr", platformConfig.VaultAddr,
		"type",
		v.Type)

	updateCallback(edgeproto.UpdateTask, "Initializing VM platform type: "+v.Type)

	vaultConfig, err := vault.BestConfig(platformConfig.VaultAddr)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "vault auth", "type", vaultConfig.Auth.Type())

	if err := v.InitProps(ctx, platformConfig, vaultConfig); err != nil {
		return err
	}

	updateCallback(edgeproto.UpdateTask, "Fetching API Access access credentials")
	if err := v.VMProvider.InitApiAccessProperties(ctx, platformConfig.CloudletKey, platformConfig.Region, platformConfig.PhysicalName, vaultConfig, platformConfig.EnvVars); err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "doing init provider")
	if err := v.VMProvider.InitProvider(ctx, caches, updateCallback); err != nil {
		return err
	}
	v.FlavorList, err = v.VMProvider.GetFlavorList(ctx)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "got flavor list", "flavorList", v.FlavorList)

	v.VMProperties.sharedRootLBName = v.GetRootLBName(v.VMProperties.CommonPf.PlatformConfig.CloudletKey)

	// create rootLB
	crmRootLB, cerr := v.NewRootLB(ctx, v.VMProperties.sharedRootLBName)
	if cerr != nil {
		return cerr
	}
	if crmRootLB == nil {
		return fmt.Errorf("rootLB is not initialized")
	}
	v.VMProperties.sharedRootLB = crmRootLB
	log.SpanLog(ctx, log.DebugLevelInfra, "created shared rootLB", "name", v.VMProperties.sharedRootLBName)

	tags := GetChefRootLBTags(platformConfig)
	err = v.CreateRootLB(ctx, crmRootLB, v.VMProperties.CommonPf.PlatformConfig.CloudletKey, v.VMProperties.CommonPf.PlatformConfig.CloudletVMImagePath, v.VMProperties.CommonPf.PlatformConfig.VMImageVersion, ActionCreate, tags, updateCallback)
	if err != nil {
		return fmt.Errorf("Error creating rootLB: %v", err)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "calling SetupRootLB")
	updateCallback(edgeproto.UpdateTask, "Setting up RootLB")
	err = v.SetupRootLB(ctx, v.VMProperties.sharedRootLBName, v.VMProperties.CommonPf.PlatformConfig.CloudletKey, updateCallback)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "ok, SetupRootLB")

	// set up L7 load balancer
	client, err := v.GetNodePlatformClient(ctx, &edgeproto.CloudletMgmtNode{Name: v.VMProperties.sharedRootLBName})
	if err != nil {
		return err
	}

	updateCallback(edgeproto.UpdateTask, "Setting up Proxy")
	err = proxy.InitL7Proxy(ctx, client, proxy.WithDockerNetwork("host"))
	if err != nil {
		return err
	}
	return nil
}

func (v *VMPlatform) SyncControllerCache(ctx context.Context, caches *platform.Caches, cloudletState edgeproto.CloudletState) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SyncControllerCache", "cloudletState", cloudletState)

	err := v.SyncClusterInsts(ctx, caches, edgeproto.DummyUpdateCallback)
	if err != nil {
		return err
	}
	// TODO v.SyncAppInsts
	err = v.SyncSharedRootLB(ctx, caches)
	if err != nil {
		return err
	}
	err = v.SyncAppInsts(ctx, caches, edgeproto.DummyUpdateCallback)
	if err != nil {
		return err
	}
	return v.VMProvider.ImportDataFromInfra(ctx)

}
