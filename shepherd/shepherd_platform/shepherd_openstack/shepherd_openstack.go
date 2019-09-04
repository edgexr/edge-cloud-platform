package shepherd_openstack

import (
	"context"

	"github.com/mobiledgex/edge-cloud-infra/crm-platforms/openstack"
	"github.com/mobiledgex/edge-cloud-infra/mexos"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

type Platform struct {
	rootLbName   string
	SharedClient pc.PlatformClient
	pf           openstack.Platform
}

func (s *Platform) GetType() string {
	return "openstack"
}

func (s *Platform) Init(ctx context.Context, key *edgeproto.CloudletKey, physicalName, vaultAddr string) error {
	//get the platform client so we can ssh in to make curl commands to the prometheus apps
	var err error
	if err = mexos.InitOpenstackProps(ctx, key.OperatorKey.Name, physicalName, vaultAddr); err != nil {
		return err
	}
	//need to have a separate one for dedicated rootlbs, see openstack.go line 111,
	s.rootLbName = cloudcommon.GetRootLBFQDN(key)
	s.SharedClient, err = s.pf.GetPlatformClientRootLB(ctx, s.rootLbName)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelMexos, "init openstack", "rootLB", s.rootLbName,
		"physicalName", physicalName, "vaultAddr", vaultAddr)
	return nil
}

func (s *Platform) GetClusterIP(ctx context.Context, clusterInst *edgeproto.ClusterInst) (string, error) {
	_, ip, err := mexos.GetMasterNameAndIP(ctx, clusterInst)
	return ip, err
}

func (s *Platform) GetPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst) (pc.PlatformClient, error) {
	if clusterInst != nil && clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		rootLb := cloudcommon.GetDedicatedLBFQDN(&clusterInst.Key.CloudletKey, &clusterInst.Key.ClusterKey)
		pc, err := s.pf.GetPlatformClientRootLB(ctx, rootLb)
		return pc, err
	} else {
		return s.SharedClient, nil
	}
}
