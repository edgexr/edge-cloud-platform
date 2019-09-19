package azure

import (
	"context"

	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

func (s *Platform) CreateCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "create cloudlet for azure")
	return nil
}

func (s *Platform) DeleteCloudlet(ctx context.Context, cloudlet *edgeproto.Cloudlet, pfConfig *edgeproto.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "delete cloudlet for azure")
	return nil
}
