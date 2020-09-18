package vmlayer

import (
	"context"
	"fmt"

	"github.com/gogo/protobuf/types"
	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/proxy"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/cloudcommon/node"
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
	GetProviderSpecificProps() map[string]*edgeproto.PropertyInfo
	SetVMProperties(vmProperties *VMProperties)
	SetCaches(ctx context.Context, caches *platform.Caches)
	InitProvider(ctx context.Context, caches *platform.Caches, stage ProviderInitStage, updateCallback edgeproto.CacheUpdateCallback) error
	GetFlavorList(ctx context.Context) ([]*edgeproto.FlavorInfo, error)
	GetNetworkList(ctx context.Context) ([]string, error)
	AddCloudletImageIfNotPresent(ctx context.Context, imgPathPrefix, imgVersion string, updateCallback edgeproto.CacheUpdateCallback) (string, error)
	AddAppImageIfNotPresent(ctx context.Context, app *edgeproto.App, flavor string, updateCallback edgeproto.CacheUpdateCallback) error
	GetCloudletImageSuffix(ctx context.Context) string
	DeleteImage(ctx context.Context, folder, image string) error
	GetServerDetail(ctx context.Context, serverName string) (*ServerDetail, error)
	GetConsoleUrl(ctx context.Context, serverName string) (string, error)
	GetInternalPortPolicy() InternalPortAttachPolicy
	AttachPortToServer(ctx context.Context, serverName, subnetName, portName, ipaddr string, action ActionType) error
	DetachPortFromServer(ctx context.Context, serverName, subnetName, portName string) error
	PrepareRootLB(ctx context.Context, client ssh.Client, rootLBName string, secGrpName string, privacyPolicy *edgeproto.PrivacyPolicy) error
	WhitelistSecurityRules(ctx context.Context, client ssh.Client, secGrpName string, serverName, label, allowedCIDR string, ports []dme.AppPort) error
	RemoveWhitelistSecurityRules(ctx context.Context, client ssh.Client, secGrpName, label string, allowedCIDR string, ports []dme.AppPort) error
	GetResourceID(ctx context.Context, resourceType ResourceType, resourceName string) (string, error)
	GetApiAccessFilename() string
	InitApiAccessProperties(ctx context.Context, key *edgeproto.CloudletKey, region, physicalName string, vaultConfig *vault.Config, vars map[string]string) error
	GetApiEndpointAddr(ctx context.Context) (string, error)
	GetExternalGateway(ctx context.Context, extNetName string) (string, error)
	SaveCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, accessVarsIn map[string]string, pfConfig *edgeproto.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error
	SetPowerState(ctx context.Context, serverName, serverAction string) error
	GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error
	GetCloudletManifest(ctx context.Context, name string, cloudletImagePath string, VMGroupOrchestrationParams *VMGroupOrchestrationParams) (string, error)
	GetRouterDetail(ctx context.Context, routerName string) (*RouterDetail, error)
	CreateVMs(ctx context.Context, vmGroupOrchestrationParams *VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error
	UpdateVMs(ctx context.Context, vmGroupOrchestrationParams *VMGroupOrchestrationParams, updateCallback edgeproto.CacheUpdateCallback) error
	DeleteVMs(ctx context.Context, vmGroupName string) error
	GetVMStats(ctx context.Context, key *edgeproto.AppInstKey) (*VMMetrics, error)
	GetPlatformResourceInfo(ctx context.Context) (*PlatformResources, error)
	VerifyVMs(ctx context.Context, vms []edgeproto.VM) error
	CheckServerReady(ctx context.Context, client ssh.Client, serverName string) error
}

// VMPlatform contains the needed by all VM based platforms
type VMPlatform struct {
	Type         string
	VMProvider   VMProvider
	VMProperties VMProperties
	FlavorList   []*edgeproto.FlavorInfo
	Caches       *platform.Caches
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
	VMProviderVMPool    string = "vmpool"
)

type ProviderInitStage string

const (
	ProviderInitCreateCloudletDirect     ProviderInitStage = "CreateCloudletDirect"
	ProviderInitCreateCloudletRestricted ProviderInitStage = "CreateCloudletRestricted"
	ProviderInitPlatformStart            ProviderInitStage = "PlatformStart"
	ProviderInitDeleteCloudlet           ProviderInitStage = "DeleteCloudlet"
)

type StringSanitizer func(value string) string

type ResTagTables map[string]*edgeproto.ResTagTable

var pCaches *platform.Caches

// VMPlatform embeds Platform and VMProvider

func (v *VMPlatform) GetType() string {
	return v.Type
}

func (v *VMPlatform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	rootLBName := v.VMProperties.SharedRootLBName
	if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		rootLBName = cloudcommon.GetDedicatedLBFQDN(v.VMProperties.CommonPf.PlatformConfig.CloudletKey, &clusterInst.Key.ClusterKey, v.VMProperties.CommonPf.PlatformConfig.AppDNSRoot)
	}
	client, err := v.GetNodePlatformClient(ctx, &edgeproto.CloudletMgmtNode{Name: rootLBName})
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
			Name: v.VMProperties.SharedRootLBName,
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

func (v *VMPlatform) InitProps(ctx context.Context, platformConfig *platform.PlatformConfig, vaultConfig *vault.Config) error {
	props := make(map[string]*edgeproto.PropertyInfo)
	for k, v := range VMProviderProps {
		props[k] = v
	}
	providerProps := v.VMProvider.GetProviderSpecificProps()
	for k, v := range providerProps {
		props[k] = v
	}
	err := v.VMProperties.CommonPf.InitInfraCommon(ctx, platformConfig, props, vaultConfig)
	if err != nil {
		return err
	}
	v.VMProvider.SetVMProperties(&v.VMProperties)
	v.VMProperties.SharedRootLBName = v.GetRootLBName(v.VMProperties.CommonPf.PlatformConfig.CloudletKey)
	v.VMProperties.PlatformSecgrpName = v.GetServerSecurityGroupName(v.GetPlatformVMName(v.VMProperties.CommonPf.PlatformConfig.CloudletKey))
	return nil
}

func (v *VMPlatform) initDebug(nodeMgr *node.NodeMgr) {
	nodeMgr.Debug.AddDebugFunc("crmrefreshsshkeys",
		func(ctx context.Context, req *edgeproto.DebugRequest) string {
			v.triggerRefreshCloudletSSHKeys()
			return "triggered refresh"
		})

	nodeMgr.Debug.AddDebugFunc("crmupgradecmd", v.crmUpgradeCmd)
}

func (v *VMPlatform) crmUpgradeCmd(ctx context.Context, req *edgeproto.DebugRequest) string {
	results, err := v.UpgradeFuncHandleSSHKeys(ctx, v.VMProperties.CommonPf.VaultConfig, v.Caches)
	if err != nil {
		return fmt.Sprintf("failed to upgrade vms to vault ssh keys: %v", err)
	}
	return fmt.Sprintf("%v", results)
}

func (v *VMPlatform) Init(ctx context.Context, platformConfig *platform.PlatformConfig, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx,
		log.DebugLevelInfra, "Init VMPlatform",
		"physicalName", platformConfig.PhysicalName,
		"vaultAddr", platformConfig.VaultAddr,
		"type",
		v.Type)

	updateCallback(edgeproto.UpdateTask, "Initializing VM platform type: "+v.Type)
	v.Caches = caches
	v.VMProperties.Domain = VMDomainCompute
	vaultConfig, err := vault.BestConfig(platformConfig.VaultAddr)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "vault auth", "type", vaultConfig.Auth.Type())

	err = v.InitCloudletSSHKeys(ctx, vaultConfig)
	if err != nil {
		return err
	}

	go v.RefreshCloudletSSHKeys(vaultConfig)

	if err := v.InitProps(ctx, platformConfig, vaultConfig); err != nil {
		return err
	}

	updateCallback(edgeproto.UpdateTask, "Fetching API Access access credentials")
	if err := v.VMProvider.InitApiAccessProperties(ctx, platformConfig.CloudletKey, platformConfig.Region, platformConfig.PhysicalName, vaultConfig, platformConfig.EnvVars); err != nil {
		return err
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "doing init provider")
	if err := v.VMProvider.InitProvider(ctx, caches, ProviderInitPlatformStart, updateCallback); err != nil {
		return err
	}

	// Set debug command to start crm upgrade
	v.initDebug(v.VMProperties.CommonPf.PlatformConfig.NodeMgr)

	v.FlavorList, err = v.VMProvider.GetFlavorList(ctx)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "got flavor list", "flavorList", v.FlavorList)

	// create rootLB
	crmRootLB, cerr := v.NewRootLB(ctx, v.VMProperties.SharedRootLBName)
	if cerr != nil {
		return cerr
	}
	if crmRootLB == nil {
		return fmt.Errorf("rootLB is not initialized")
	}
	v.VMProperties.sharedRootLB = crmRootLB
	log.SpanLog(ctx, log.DebugLevelInfra, "created shared rootLB", "name", v.VMProperties.SharedRootLBName)

	tags := GetChefRootLBTags(platformConfig)
	err = v.CreateRootLB(ctx, crmRootLB, v.VMProperties.CommonPf.PlatformConfig.CloudletKey, v.VMProperties.CommonPf.PlatformConfig.CloudletVMImagePath, v.VMProperties.CommonPf.PlatformConfig.VMImageVersion, ActionCreate, tags, updateCallback)
	if err != nil {
		return fmt.Errorf("Error creating rootLB: %v", err)
	}

	if platformConfig.Upgrade {
		v.VMProperties.Upgrade = true
		// Pull private key from Vault
		log.SpanLog(ctx, log.DebugLevelInfra, "Fetch private key from vault")
		mexKey, err := infracommon.GetMEXKeyFromVault(vaultConfig)
		if err != nil {
			return err
		}
		v.VMProperties.sshKey.MEXPrivateKey = mexKey.PrivateKey

		log.SpanLog(ctx, log.DebugLevelInfra, "Upgrade shared rootlb to use vault SSH")

		// Upgrade Shared RootLB to use Vault SSH
		// Set SSH client to use mex private key
		v.VMProperties.sshKey.UseMEXPrivateKey = true
		sharedRootLBClient, err := v.GetSSHClientForServer(ctx, v.VMProperties.SharedRootLBName, v.VMProperties.GetCloudletExternalNetwork())
		if err != nil {
			return err
		}
		upgradeScript := GetVaultCAScript(vaultConfig)
		ExecuteUpgradeScript(ctx, v.VMProperties.SharedRootLBName, sharedRootLBClient, upgradeScript)
		// Verify if shared rootlb is reachable using vault SSH
		// Set SSH client to use vault signed Keys
		v.VMProperties.sshKey.UseMEXPrivateKey = false
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
	err = v.SetupRootLB(ctx, v.VMProperties.SharedRootLBName, v.VMProperties.CommonPf.PlatformConfig.CloudletKey, nil, updateCallback)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "ok, SetupRootLB")

	// deletes exisitng l7 proxies for backwards compatibility, since we got rid of http. can be removed later
	client, err := v.GetNodePlatformClient(ctx, &edgeproto.CloudletMgmtNode{Name: v.VMProperties.SharedRootLBName})
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
	// no sync needed right now

	if v.VMProperties.Upgrade {
		_, err := v.UpgradeFuncHandleSSHKeys(ctx, v.VMProperties.CommonPf.VaultConfig, caches)
		if err != nil {
			return err
		}
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "Upgrade CRM Config")
	// upgrade k8s config on each rootLB
	sharedRootLBClient, err := v.GetNodePlatformClient(ctx, &edgeproto.CloudletMgmtNode{Name: v.VMProperties.SharedRootLBName})
	if err != nil {
		return err
	}
	err = k8smgmt.UpgradeConfig(ctx, caches, sharedRootLBClient, v.GetClusterPlatformClient)
	if err != nil {
		return err
	}
	return nil
}
