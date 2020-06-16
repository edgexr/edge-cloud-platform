package shepherd_vmprovider

import (
	"context"
	"time"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"

	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
	ssh "github.com/mobiledgex/golang-ssh"
)

// Default Ceilometer granularity is 300 secs(5 mins)
var VmScrapeInterval = time.Minute * 5

type ShepherdPlatform struct {
	rootLbName      string
	SharedClient    ssh.Client
	VMPlatform      *vmlayer.VMPlatform
	collectInterval time.Duration
	vaultConfig     *vault.Config
	appDNSRoot      string
}

func (s *ShepherdPlatform) GetType() string {
	return s.VMPlatform.Type
}

func (s *ShepherdPlatform) Init(ctx context.Context, pc *platform.PlatformConfig) error {
	vaultConfig, err := vault.BestConfig(pc.VaultAddr)
	if err != nil {
		return err
	}
	s.vaultConfig = vaultConfig
	s.appDNSRoot = pc.AppDNSRoot

	if err = s.VMPlatform.InitProps(ctx, pc, vaultConfig); err != nil {
		return err
	}
	if err = s.VMPlatform.VMProvider.InitApiAccessProperties(ctx, pc.CloudletKey, pc.Region, pc.PhysicalName, vaultConfig, pc.EnvVars); err != nil {
		return err
	}

	//need to have a separate one for dedicated rootlbs, see openstack.go line 111,
	s.rootLbName = cloudcommon.GetRootLBFQDN(pc.CloudletKey, s.appDNSRoot)
	s.SharedClient, err = s.VMPlatform.GetNodePlatformClient(ctx, &edgeproto.CloudletMgmtNode{Name: s.rootLbName})
	if err != nil {
		return err
	}
	// Reuse the same ssh connection whever possible
	err = s.SharedClient.StartPersistentConn(shepherd_common.ShepherdSshConnectTimeout)
	if err != nil {
		return err
	}

	s.collectInterval = VmScrapeInterval
	log.SpanLog(ctx, log.DebugLevelInfra, "init openstack", "rootLB", s.rootLbName,
		"physicalName", pc.PhysicalName, "vaultAddr", pc.VaultAddr)
	return nil
}

func (s *ShepherdPlatform) GetMetricsCollectInterval() time.Duration {
	return s.collectInterval
}

func (s *ShepherdPlatform) GetClusterIP(ctx context.Context, clusterInst *edgeproto.ClusterInst) (string, error) {
	sd, err := s.VMPlatform.VMProvider.GetServerDetail(ctx, vmlayer.GetClusterMasterName(ctx, clusterInst))
	if err != nil {
		return "", err
	}
	mexNet := s.VMPlatform.VMProperties.GetCloudletMexNetwork()
	subnetName := vmlayer.GetClusterSubnetName(ctx, clusterInst)
	sip, err := vmlayer.GetIPFromServerDetails(ctx, mexNet, subnetName, sd)
	if err != nil {
		return "", err
	}
	return sip.ExternalAddr, nil
}

func (s *ShepherdPlatform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst) (ssh.Client, error) {
	if clusterInst != nil && clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		rootLb := cloudcommon.GetDedicatedLBFQDN(&clusterInst.Key.CloudletKey, &clusterInst.Key.ClusterKey, s.appDNSRoot)
		pc, err := s.VMPlatform.GetNodePlatformClient(ctx, &edgeproto.CloudletMgmtNode{Name: rootLb})
		if err != nil {
			return nil, err
		}
		err = pc.StartPersistentConn(shepherd_common.ShepherdSshConnectTimeout)
		if err != nil {
			return nil, err
		}
		return pc, err
	} else {
		return s.SharedClient, nil
	}
}

func (s *ShepherdPlatform) GetPlatformStats(ctx context.Context) (shepherd_common.CloudletMetrics, error) {
	cloudletMetric := shepherd_common.CloudletMetrics{}
	platformResources, err := s.VMPlatform.VMProvider.GetPlatformResourceInfo(ctx)
	if err != nil {
		return cloudletMetric, err
	}
	cloudletMetric = shepherd_common.CloudletMetrics(*platformResources)
	return cloudletMetric, nil
}

func (s *ShepherdPlatform) GetVmStats(ctx context.Context, key *edgeproto.AppInstKey) (shepherd_common.AppMetrics, error) {
	appMetrics := shepherd_common.AppMetrics{}
	vmMetrics, err := s.VMPlatform.VMProvider.GetVMStats(ctx, key)
	if err != nil {
		return appMetrics, err
	}
	appMetrics = shepherd_common.AppMetrics(*vmMetrics)
	return appMetrics, nil
}
