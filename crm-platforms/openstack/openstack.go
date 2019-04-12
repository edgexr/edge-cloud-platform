package openstack

import (
	"fmt"
	"os"

	"github.com/mobiledgex/edge-cloud-infra/mexos"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/flavor"
	"github.com/mobiledgex/edge-cloud/log"
)

type Platform struct {
	rootLBName  string
	rootLB      *mexos.MEXRootLB
	cloudletKey *edgeproto.CloudletKey
}

func (s *Platform) GetType() string {
	return "openstack"
}

func (s *Platform) Init(key *edgeproto.CloudletKey) error {
	rootLBName := cloudcommon.GetRootLBFQDN(key)
	s.cloudletKey = key
	log.DebugLog(log.DebugLevelMexos, "init openstack", "rootLB", rootLBName)

	// OPENRC_URL is required for OpenStack, but optional in InitInfraCommon
	if os.Getenv("OPENRC_URL") == "" {
		return fmt.Errorf("Env OPENRC_URL not set")
	}
	if err := mexos.InitInfraCommon(); err != nil {
		return err
	}
	if err := mexos.InitOpenstackProps(); err != nil {
		return err
	}
	mexos.CloudletInfraCommon.NetworkScheme = os.Getenv("MEX_NETWORK_SCHEME")
	if mexos.CloudletInfraCommon.NetworkScheme == "" {
		mexos.CloudletInfraCommon.NetworkScheme = "priv-subnet,mex-k8s-net-1,10.101.X.0/24"
	}

	osflavors, err := mexos.ListFlavors()
	if err != nil || len(osflavors) == 0 {
		return fmt.Errorf("failed to get flavors, %s", err.Error())
	}
	var finfo []*edgeproto.FlavorInfo
	for _, f := range osflavors {
		finfo = append(
			finfo,
			&edgeproto.FlavorInfo{
				Name:  f.Name,
				Vcpus: uint64(f.VCPUs),
				Ram:   uint64(f.RAM),
				Disk:  uint64(f.Disk)},
		)
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
	flavorName, err := flavor.GetClosestFlavor(finfo, sharedRootLBFlavor)
	if err != nil {
		return fmt.Errorf("unable to find closest flavor for Shared RootLB: %v", err)
	}

	log.DebugLog(log.DebugLevelMexos, "calling SetupRootLB")
	err = mexos.SetupRootLB(rootLBName, flavorName)
	if err != nil {
		return err
	}
	log.DebugLog(log.DebugLevelMexos, "ok, SetupRootLB")
	return nil
}

func (s *Platform) GatherCloudletInfo(info *edgeproto.CloudletInfo) error {
	return mexos.OSGetLimits(info)
}

func (s *Platform) GetPlatformClient(rootLBName string) (pc.PlatformClient, error) {
	if rootLBName == "" {
		return nil, fmt.Errorf("cannot validate kubernetes parameters, rootLB is empty")
	}
	if mexos.GetCloudletExternalNetwork() == "" {
		return nil, fmt.Errorf("validate kubernetes parameters, missing external network in platform config")
	}
	return mexos.GetSSHClient(rootLBName, mexos.GetCloudletExternalNetwork(), mexos.SSHUser)
}
