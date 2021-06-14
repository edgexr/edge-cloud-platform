package vmpool

import (
	"context"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

func (o *VMPoolPlatform) GetConsoleUrl(ctx context.Context, serverName string) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetConsoleUrl not supported")
	return "", nil
}

func (o *VMPoolPlatform) AddImageIfNotPresent(ctx context.Context, imageInfo *infracommon.ImageInfo, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddImageIfNotPresent not supported")
	return nil
}
