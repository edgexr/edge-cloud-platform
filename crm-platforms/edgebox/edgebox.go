package edgebox

import (
	"context"
	"fmt"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
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

type EdgeboxPlatform struct {
	generic       dind.Platform
	NetworkScheme string
	commonPf      infracommon.CommonPlatform
}

var edgeboxProps = map[string]*edgeproto.PropertyInfo{
	"MEX_EDGEBOX_NETWORK_SCHEME": &edgeproto.PropertyInfo{
		Name:        "EdgeBox Network Scheme",
		Description: vmlayer.GetSupportedSchemesStr(),
		Value:       cloudcommon.NetworkSchemePrivateIP,
	},
}

func (e *EdgeboxPlatform) GetType() string {
	return "edgebox"
}

func (e *EdgeboxPlatform) Init(ctx context.Context, platformConfig *platform.PlatformConfig, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) error {
	err := e.generic.Init(ctx, platformConfig, caches, updateCallback)
	// Set the test Mode based on what is in PlatformConfig
	infracommon.SetTestMode(platformConfig.TestMode)

	vaultConfig, err := vault.BestConfig(platformConfig.VaultAddr)
	if err != nil {
		return err
	}

	if err := e.commonPf.InitInfraCommon(ctx, platformConfig, edgeboxProps, vaultConfig); err != nil {
		return err
	}

	e.NetworkScheme = e.GetEdgeboxNetworkScheme()
	if e.NetworkScheme != cloudcommon.NetworkSchemePrivateIP &&
		e.NetworkScheme != cloudcommon.NetworkSchemePublicIP {
		return fmt.Errorf("Unsupported network scheme for DIND: %s", e.NetworkScheme)
	}

	fqdn := cloudcommon.GetRootLBFQDN(platformConfig.CloudletKey, platformConfig.AppDNSRoot)
	ipaddr, err := e.GetDINDServiceIP(ctx)
	if err != nil {
		return fmt.Errorf("init cannot get service ip, %s", err.Error())
	}
	if err := e.commonPf.ActivateFQDNA(ctx, fqdn, ipaddr); err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "error in ActivateFQDNA", "err", err)
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "done init edgebox")
	return nil

}

func (e *EdgeboxPlatform) GetEdgeboxNetworkScheme() string {
	return e.commonPf.Properties["MEX_EDGEBOX_NETWORK_SCHEME"].Value
}

func (e *EdgeboxPlatform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	return e.generic.GatherCloudletInfo(ctx, info)
}

func (s *EdgeboxPlatform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	return s.generic.GetClusterPlatformClient(ctx, clusterInst, clientType)
}

func (s *EdgeboxPlatform) GetNodePlatformClient(ctx context.Context, node *edgeproto.CloudletMgmtNode) (ssh.Client, error) {
	return s.generic.GetNodePlatformClient(ctx, node)
}

func (s *EdgeboxPlatform) ListCloudletMgmtNodes(ctx context.Context, clusterInsts []edgeproto.ClusterInst) ([]edgeproto.CloudletMgmtNode, error) {
	return s.generic.ListCloudletMgmtNodes(ctx, clusterInsts)
}

func (s *EdgeboxPlatform) GetCloudletProps(ctx context.Context) (*edgeproto.CloudletProps, error) {
	return &edgeproto.CloudletProps{Properties: edgeboxProps}, nil
}
