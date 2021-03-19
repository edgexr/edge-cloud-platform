package edgebox

import (
	"context"
	"fmt"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/dind"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
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
	infracommon.CommonEmbedded
}

var edgeboxProps = map[string]*edgeproto.PropertyInfo{
	"MEX_EDGEBOX_NETWORK_SCHEME": &edgeproto.PropertyInfo{
		Name:        "EdgeBox Network Scheme",
		Description: vmlayer.GetSupportedSchemesStr(),
		Value:       cloudcommon.NetworkSchemePrivateIP,
	},
}

func (e *EdgeboxPlatform) Init(ctx context.Context, platformConfig *platform.PlatformConfig, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) error {
	err := e.generic.Init(ctx, platformConfig, caches, updateCallback)
	// Set the test Mode based on what is in PlatformConfig
	infracommon.SetTestMode(platformConfig.TestMode)

	if err := e.commonPf.InitInfraCommon(ctx, platformConfig, edgeboxProps); err != nil {
		return err
	}

	e.NetworkScheme = e.GetEdgeboxNetworkScheme()
	if e.NetworkScheme != cloudcommon.NetworkSchemePrivateIP &&
		e.NetworkScheme != cloudcommon.NetworkSchemePublicIP {
		return fmt.Errorf("Unsupported network scheme for DIND: %s", e.NetworkScheme)
	}
	// ensure service ip exists
	_, err = e.GetDINDServiceIP(ctx)
	if err != nil {
		return fmt.Errorf("init cannot get service ip, %s", err.Error())
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "done init edgebox")
	return nil

}

func (e *EdgeboxPlatform) GetEdgeboxNetworkScheme() string {
	val, _ := e.commonPf.Properties.GetValue("MEX_EDGEBOX_NETWORK_SCHEME")
	return val
}

func (e *EdgeboxPlatform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	return e.generic.GatherCloudletInfo(ctx, info)
}

func (s *EdgeboxPlatform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	return s.generic.GetClusterPlatformClient(ctx, clusterInst, clientType)
}

func (s *EdgeboxPlatform) GetNodePlatformClient(ctx context.Context, node *edgeproto.CloudletMgmtNode, ops ...pc.SSHClientOp) (ssh.Client, error) {
	return s.generic.GetNodePlatformClient(ctx, node)
}

func (s *EdgeboxPlatform) ListCloudletMgmtNodes(ctx context.Context, clusterInsts []edgeproto.ClusterInst) ([]edgeproto.CloudletMgmtNode, error) {
	return s.generic.ListCloudletMgmtNodes(ctx, clusterInsts)
}

func (s *EdgeboxPlatform) GetCloudletProps(ctx context.Context) (*edgeproto.CloudletProps, error) {
	return &edgeproto.CloudletProps{Properties: edgeboxProps}, nil
}

func (s *EdgeboxPlatform) GetAccessData(ctx context.Context, cloudlet *edgeproto.Cloudlet, region string, vaultConfig *vault.Config, dataType string, arg []byte) (map[string]string, error) {
	return nil, nil
}

func (s *EdgeboxPlatform) GetRootLBClients(ctx context.Context) (map[string]ssh.Client, error) {
	return s.generic.GetRootLBClients(ctx)
}
