package shepherd_fake

import (
	"context"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	ssh "github.com/mobiledgex/golang-ssh"
)

type Platform struct {
	promStarted bool
}

func (s *Platform) Init(ctx context.Context, pfConfig *platform.PlatformConfig, caches *platform.Caches) error {
	return nil
}

func (s *Platform) SetVMPool(ctx context.Context, vmPool *edgeproto.VMPool) {
}

func (s *Platform) GetClusterIP(ctx context.Context, clusterInst *edgeproto.ClusterInst) (string, error) {
	return "localhost", nil
}

func (s *Platform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	return &pc.LocalClient{}, nil
}

func (s *Platform) GetVmAppRootLbClient(ctx context.Context, app *edgeproto.AppInstKey) (ssh.Client, error) {
	return &pc.LocalClient{}, nil
}

func (s *Platform) GetPlatformStats(ctx context.Context) (shepherd_common.CloudletMetrics, error) {
	return shepherd_common.CloudletMetrics{}, nil
}

func (s *Platform) GetVmStats(ctx context.Context, key *edgeproto.AppInstKey) (shepherd_common.AppMetrics, error) {
	return shepherd_common.AppMetrics{}, nil
}

func (s *Platform) VmAppChangedCallback(ctx context.Context) {
}

func (s *Platform) GetMetricsCollectInterval() time.Duration {
	return 0
}
