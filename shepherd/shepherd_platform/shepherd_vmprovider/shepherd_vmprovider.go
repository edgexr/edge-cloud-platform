package shepherd_vmprovider

import (
	"context"
	"sync"
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

var caches *platform.Caches

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

	err = s.VMPlatform.InitCloudletSSHKeys(ctx, vaultConfig)
	if err != nil {
		return err
	}

	go s.VMPlatform.RefreshCloudletSSHKeys(vaultConfig)

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

func (s *ShepherdPlatform) SetVMPool(ctx context.Context, vmPool *edgeproto.VMPool) {
	log.SpanLog(ctx, log.DebugLevelInfra, "set vmpool", "vmpool", vmPool)
	if s.VMPlatform != nil {
		if caches == nil {
			var vmPoolMux sync.Mutex
			caches = &platform.Caches{}
			caches.VMPoolMux = &vmPoolMux
		}
		caches.VMPoolMux.Lock()
		defer caches.VMPoolMux.Unlock()
		caches.VMPool = vmPool
		s.VMPlatform.VMProvider.InitData(ctx, caches)
	}
}

func (s *ShepherdPlatform) GetMetricsCollectInterval() time.Duration {
	return s.collectInterval
}

func (s *ShepherdPlatform) GetClusterIP(ctx context.Context, clusterInst *edgeproto.ClusterInst) (string, error) {
	return s.VMPlatform.GetClusterAccessIP(ctx, clusterInst)
}

func (s *ShepherdPlatform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	pc, err := s.VMPlatform.GetClusterPlatformClient(ctx, clusterInst, clientType)
	if err != nil {
		return nil, err
	}
	err = pc.StartPersistentConn(shepherd_common.ShepherdSshConnectTimeout)
	if err != nil {
		return nil, err
	}
	return pc, nil
}

func (s *ShepherdPlatform) GetVmAppRootLbClient(ctx context.Context, app *edgeproto.AppInstKey) (ssh.Client, error) {
	rootLBName := cloudcommon.GetVMAppFQDN(app, s.VMPlatform.VMProperties.CommonPf.PlatformConfig.CloudletKey, s.VMPlatform.VMProperties.CommonPf.PlatformConfig.AppDNSRoot)
	client, err := s.VMPlatform.GetNodePlatformClient(ctx, &edgeproto.CloudletMgmtNode{Name: rootLBName})
	if err != nil {
		return nil, err
	}
	err = client.StartPersistentConn(shepherd_common.ShepherdSshConnectTimeout)
	if err != nil {
		return nil, err
	}
	return client, err
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
