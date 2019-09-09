package shepherd_fake

import (
	"context"

	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

type Platform struct {
}

func (s *Platform) GetType() string {
	return "fake"
}

func (s *Platform) Init(ctx context.Context, key *edgeproto.CloudletKey, physicalName, vaultAddr string) error {
	return nil
}

func (s *Platform) GetClusterIP(ctx context.Context, clusterInst *edgeproto.ClusterInst) (string, error) {
	return "localhost", nil
}

func (s *Platform) GetPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst) (pc.PlatformClient, error) {
	return &pc.LocalClient{}, nil
}

func (s *Platform) GetPlatformStats(ctx context.Context) (shepherd_common.CloudletMetrics, error) {
	return shepherd_common.CloudletMetrics{}, nil
}
