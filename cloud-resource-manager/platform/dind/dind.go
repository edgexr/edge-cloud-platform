package dind

import (
	"context"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/proxy"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

type Platform struct {
}

func (s *Platform) GetType() string {
	return "dind"
}

func (s *Platform) Init(ctx context.Context, platformConfig *platform.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error {
	// set up L7 load balancer
	client, err := s.GetPlatformClient(ctx, nil)
	if err != nil {
		return err
	}
	updateCallback(edgeproto.UpdateTask, "Setting up Nginx L7 Proxy")
	err = proxy.InitL7Proxy(ctx, client, proxy.WithDockerPublishPorts())
	if err != nil {
		return err
	}
	return nil
}

func (s *Platform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	err := GetLimits(info)
	if err != nil {
		return err
	}
	info.Flavors = []*edgeproto.FlavorInfo{
		&edgeproto.FlavorInfo{
			Name:  "DINDFlavor",
			Vcpus: uint64(info.OsMaxVcores),
			Ram:   uint64(info.OsMaxRam),
			Disk:  uint64(500),
		},
	}
	return nil
}

func (s *Platform) GetPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst) (pc.PlatformClient, error) {
	return &pc.LocalClient{}, nil
}
