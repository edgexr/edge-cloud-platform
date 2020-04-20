package edgebox

import (
	"context"
	"fmt"

	"github.com/mobiledgex/edge-cloud-infra/mexos"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/dind"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
	ssh "github.com/mobiledgex/golang-ssh"
)

// edgebox wraps the generic dind implementation with
// mex-specific behavior, such as setting up DNS and
// registry.mobiledgex.net access secrets.

type Platform struct {
	generic       dind.Platform
	config        platform.PlatformConfig
	vaultConfig   *vault.Config
	NetworkScheme string
	commonPf      mexos.CommonPlatform
	envVars       map[string]*mexos.PropertyInfo
}

var edgeboxProps = map[string]*mexos.PropertyInfo{
	"MEX_NETWORK_SCHEME": &mexos.PropertyInfo{
		Value: cloudcommon.NetworkSchemePrivateIP,
	},
}

func (s *Platform) GetType() string {
	return "edgebox"
}

func (s *Platform) Init(ctx context.Context, platformConfig *platform.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error {
	err := s.generic.Init(ctx, platformConfig, updateCallback)
	s.config = *platformConfig
	if err != nil {
		return err
	}

	// Set the test Mode based on what is in PlatformConfig
	mexos.SetTestMode(platformConfig.TestMode)

	vaultConfig, err := vault.BestConfig(platformConfig.VaultAddr)
	if err != nil {
		return err
	}
	s.vaultConfig = vaultConfig

	if err := s.commonPf.InitInfraCommon(ctx, vaultConfig, platformConfig.EnvVars); err != nil {
		return err
	}

	s.envVars = edgeboxProps
	mexos.SetPropsFromVars(ctx, s.envVars, platformConfig.EnvVars)

	s.NetworkScheme = s.GetCloudletNetworkScheme()
	if s.NetworkScheme != cloudcommon.NetworkSchemePrivateIP &&
		s.NetworkScheme != cloudcommon.NetworkSchemePublicIP {
		return fmt.Errorf("Unsupported network scheme for DIND: %s", s.NetworkScheme)
	}

	fqdn := cloudcommon.GetRootLBFQDN(platformConfig.CloudletKey)
	ipaddr, err := s.GetDINDServiceIP(ctx)
	if err != nil {
		return fmt.Errorf("init cannot get service ip, %s", err.Error())
	}
	if err := s.commonPf.ActivateFQDNA(ctx, fqdn, ipaddr); err != nil {
		log.SpanLog(ctx, log.DebugLevelMexos, "error in ActivateFQDNA", "err", err)
		return err
	}
	log.SpanLog(ctx, log.DebugLevelMexos, "done init edgebox")
	return nil
}

func (s *Platform) GetCloudletNetworkScheme() string {
	return s.envVars["MEX_NETWORK_SCHEME"].Value
}

func (s *Platform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	return s.generic.GatherCloudletInfo(ctx, info)
}

func (s *Platform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst) (ssh.Client, error) {
	return s.generic.GetClusterPlatformClient(ctx, clusterInst)
}

func (s *Platform) GetNodePlatformClient(ctx context.Context, node *edgeproto.CloudletMgmtNode) (ssh.Client, error) {
	return s.generic.GetNodePlatformClient(ctx, node)
}

func (s *Platform) ListCloudletMgmtNodes(ctx context.Context, clusterInsts []edgeproto.ClusterInst) ([]edgeproto.CloudletMgmtNode, error) {
	return s.generic.ListCloudletMgmtNodes(ctx, clusterInsts)
}
