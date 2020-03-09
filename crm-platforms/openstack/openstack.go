package openstack

import (
	"context"
	"fmt"
	"os"

	"github.com/mobiledgex/edge-cloud-infra/mexos"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/proxy"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/util"
	"github.com/mobiledgex/edge-cloud/vault"
	"github.com/mobiledgex/edge-cloud/vmspec"
	ssh "github.com/mobiledgex/golang-ssh"
)

const MINIMUM_DISK_SIZE uint64 = 20

type Platform struct {
	rootLBName  string
	rootLB      *mexos.MEXRootLB
	cloudletKey *edgeproto.CloudletKey
	flavorList  []*edgeproto.FlavorInfo
	config      platform.PlatformConfig
	vaultConfig *vault.Config
}

func (s *Platform) GetType() string {
	return "openstack"
}

// GetVMSpecForRootLB gets the VM spec for the rootLB when it is not specified within a cluster. This is
// used for Shared RootLb and for VM app based RootLb
func (s *Platform) GetVMSpecForRootLB() (*vmspec.VMCreationSpec, error) {

	var rootlbFlavor edgeproto.Flavor
	err := mexos.GetCloudletSharedRootLBFlavor(&rootlbFlavor)
	if err != nil {
		return nil, fmt.Errorf("unable to get Shared RootLB Flavor: %v", err)
	}
	vmspec, err := vmspec.GetVMSpec(s.flavorList, rootlbFlavor)
	if err != nil {
		return nil, fmt.Errorf("unable to find VM spec for Shared RootLB: %v", err)
	}
	if vmspec.AvailabilityZone == "" {
		vmspec.AvailabilityZone = mexos.GetCloudletComputeAvailabilityZone()
	}
	return vmspec, nil
}

func (s *Platform) Init(ctx context.Context, platformConfig *platform.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error {
	rootLBName := getRootLBName(platformConfig.CloudletKey)
	s.cloudletKey = platformConfig.CloudletKey
	s.config = *platformConfig
	log.SpanLog(ctx,
		log.DebugLevelMexos, "init openstack",
		"rootLB", rootLBName,
		"physicalName", platformConfig.PhysicalName,
		"vaultAddr", platformConfig.VaultAddr)

	updateCallback(edgeproto.UpdateTask, "Initializing Openstack platform")

	vaultConfig, err := vault.BestConfig(platformConfig.VaultAddr)
	if err != nil {
		return err
	}
	s.vaultConfig = vaultConfig
	log.SpanLog(ctx, log.DebugLevelMexos, "vault auth", "type", vaultConfig.Auth.Type())

	updateCallback(edgeproto.UpdateTask, "Fetching Openstack access credentials")
	if err := mexos.InitInfraCommon(ctx, vaultConfig); err != nil {
		return err
	}
	if err := mexos.InitOpenstackProps(ctx, platformConfig.CloudletKey, platformConfig.Region, platformConfig.PhysicalName, vaultConfig); err != nil {
		return err
	}
	mexos.CloudletInfraCommon.NetworkScheme = os.Getenv("MEX_NETWORK_SCHEME")
	if mexos.CloudletInfraCommon.NetworkScheme == "" {
		mexos.CloudletInfraCommon.NetworkScheme = "name=mex-k8s-net-1,cidr=10.101.X.0/24"
	}
	s.flavorList, _, _, err = mexos.GetFlavorInfo(ctx)
	if err != nil {
		return err
	}

	// create rootLB
	updateCallback(edgeproto.UpdateTask, "Creating RootLB")
	crmRootLB, cerr := mexos.NewRootLB(ctx, rootLBName)
	if cerr != nil {
		return cerr
	}
	if crmRootLB == nil {
		return fmt.Errorf("rootLB is not initialized")
	}
	log.SpanLog(ctx, log.DebugLevelMexos, "created rootLB", "rootlb", crmRootLB.Name)
	s.rootLB = crmRootLB
	s.rootLBName = rootLBName

	vmspec, err := s.GetVMSpecForRootLB()
	if err != nil {
		return err
	}

	log.SpanLog(ctx, log.DebugLevelMexos, "calling SetupRootLB")
	updateCallback(edgeproto.UpdateTask, "Setting up RootLB")
	err = mexos.SetupRootLB(ctx, rootLBName, vmspec, platformConfig.CloudletKey, platformConfig.CloudletVMImagePath, platformConfig.VMImageVersion, edgeproto.DummyUpdateCallback)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelMexos, "ok, SetupRootLB")

	// set up L7 load balancer
	client, err := s.GetPlatformClientRootLB(ctx, rootLBName)
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

func (s *Platform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	return mexos.OSGetLimits(ctx, info)
}

func (s *Platform) GetPlatformClientRootLB(ctx context.Context, rootLBName string) (ssh.Client, error) {
	log.SpanLog(ctx, log.DebugLevelMexos, "GetPlatformClientRootLB", "rootLBName", rootLBName)

	if rootLBName == "" {
		return nil, fmt.Errorf("cannot GetPlatformClientRootLB, rootLB is empty")
	}
	if mexos.GetCloudletExternalNetwork() == "" {
		return nil, fmt.Errorf("GetPlatformClientRootLB, missing external network in platform config")
	}
	return mexos.GetSSHClient(ctx, rootLBName, mexos.GetCloudletExternalNetwork(), mexos.SSHUser)
}

func (s *Platform) GetPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst) (ssh.Client, error) {
	rootLBName := s.rootLBName
	if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		rootLBName = cloudcommon.GetDedicatedLBFQDN(s.cloudletKey, &clusterInst.Key.ClusterKey)
	}
	return s.GetPlatformClientRootLB(ctx, rootLBName)
}

func getRootLBName(key *edgeproto.CloudletKey) string {
	name := cloudcommon.GetRootLBFQDN(key)
	return util.HeatSanitize(name)
}
