package openstack

import (
	"fmt"
	"os"

	"github.com/mobiledgex/edge-cloud-infra/mexos"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/nginx"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/flavor"
	"github.com/mobiledgex/edge-cloud/log"
)

const MINIMUM_DISK_SIZE uint64 = 20

type Platform struct {
	rootLBName  string
	rootLB      *mexos.MEXRootLB
	cloudletKey *edgeproto.CloudletKey
	flavorList  []*edgeproto.FlavorInfo
}

func (s *Platform) GetType() string {
	return "openstack"
}

func (s *Platform) Init(key *edgeproto.CloudletKey, physicalName, vaultAddr string) error {
	rootLBName := cloudcommon.GetRootLBFQDN(key)
	s.cloudletKey = key
	log.DebugLog(
		log.DebugLevelMexos, "init openstack",
		"rootLB", rootLBName,
		"physicalName", physicalName,
		"vaultAddr", vaultAddr,
	)

	if err := mexos.InitInfraCommon(vaultAddr); err != nil {
		return err
	}
	if err := mexos.InitOpenstackProps(key.OperatorKey.Name, physicalName, vaultAddr); err != nil {
		return err
	}
	mexos.CloudletInfraCommon.NetworkScheme = os.Getenv("MEX_NETWORK_SCHEME")
	if mexos.CloudletInfraCommon.NetworkScheme == "" {
		mexos.CloudletInfraCommon.NetworkScheme = "priv-subnet,mex-k8s-net-1,10.101.X.0/24"
	}
	var err error
	s.flavorList, err = mexos.GetFlavorInfo()
	if err != nil {
		return err
	}

	// create rootLB
	crmRootLB, cerr := mexos.NewRootLB(rootLBName)
	if cerr != nil {
		return cerr
	}
	if crmRootLB == nil {
		return fmt.Errorf("rootLB is not initialized")
	}
	log.DebugLog(log.DebugLevelMexos, "created rootLB", "rootlb", crmRootLB.Name)
	s.rootLB = crmRootLB
	s.rootLBName = rootLBName

	var sharedRootLBFlavor edgeproto.Flavor
	err = mexos.GetCloudletSharedRootLBFlavor(&sharedRootLBFlavor)
	if err != nil {
		return fmt.Errorf("unable to get Shared RootLB Flavor: %v", err)
	}
	flavorName, err := flavor.GetClosestFlavor(s.flavorList, sharedRootLBFlavor)
	if err != nil {
		return fmt.Errorf("unable to find closest flavor for Shared RootLB: %v", err)
	}

	log.DebugLog(log.DebugLevelMexos, "calling SetupRootLB")
	err = mexos.SetupRootLB(rootLBName, flavorName)
	if err != nil {
		return err
	}
	log.DebugLog(log.DebugLevelMexos, "ok, SetupRootLB")

	// set up L7 load balancer
	client, err := s.GetPlatformClientRootLB(rootLBName)
	if err != nil {
		return err
	}
	err = nginx.InitL7Proxy(client, nginx.WithDockerNetwork("host"))
	if err != nil {
		return err
	}
	return nil
}

func (s *Platform) GatherCloudletInfo(info *edgeproto.CloudletInfo) error {
	return mexos.OSGetLimits(info)
}

func (s *Platform) GetPlatformClientRootLB(rootLBName string) (pc.PlatformClient, error) {
	log.DebugLog(log.DebugLevelMexos, "GetPlatformClientRootLB", "rootLBName", rootLBName)

	if rootLBName == "" {
		return nil, fmt.Errorf("cannot GetPlatformClientRootLB, rootLB is empty")
	}
	if mexos.GetCloudletExternalNetwork() == "" {
		return nil, fmt.Errorf("GetPlatformClientRootLB, missing external network in platform config")
	}
	return mexos.GetSSHClient(rootLBName, mexos.GetCloudletExternalNetwork(), mexos.SSHUser)
}

func (s *Platform) GetPlatformClient(clusterInst *edgeproto.ClusterInst) (pc.PlatformClient, error) {
	rootLBName := s.rootLBName
	if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		rootLBName = cloudcommon.GetDedicatedLBFQDN(s.cloudletKey, &clusterInst.Key.ClusterKey)
	}
	return s.GetPlatformClientRootLB(rootLBName)
}
