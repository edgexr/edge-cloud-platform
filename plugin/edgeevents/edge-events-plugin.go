package main

import (
	"context"
	"time"

	edgeevents "github.com/mobiledgex/edge-cloud-infra/edge-events"
	dmecommon "github.com/mobiledgex/edge-cloud/d-match-engine/dme-common"
	"github.com/mobiledgex/edge-cloud/log"
)

func GetEdgeEventsHandler(ctx context.Context, edgeEventsCookieExpiration time.Duration) (dmecommon.EdgeEventsHandler, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetEdgeEventHandler")
	edgeEventsHandlerPlugin := new(edgeevents.EdgeEventsHandlerPlugin)
	edgeEventsHandlerPlugin.EdgeEventsCookieExpiration = edgeEventsCookieExpiration
	return edgeEventsHandlerPlugin, nil
}

func main() {}
