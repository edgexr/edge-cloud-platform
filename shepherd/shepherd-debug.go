package main

import (
	"context"
	"time"

	"github.com/mobiledgex/edge-cloud/cloudcommon/node"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

const defaultScrapeInterval = 15 * time.Second

func InitDebug(nodeMgr *node.NodeMgr) {
	nodeMgr.Debug.AddDebugFunc("set-scrape-interval", setScrapeInterval)
	nodeMgr.Debug.AddDebugFunc("reset-scrape-interval", resetScrapeInterval)
	nodeMgr.Debug.AddDebugFunc("show-scrape-interval", showScrapeInterval)
}

func showScrapeInterval(ctx context.Context, req *edgeproto.DebugRequest) string {
	return "shepherd scraping metrics every " + promScrapeInterval.String()
}

func setScrapeInterval(ctx context.Context, req *edgeproto.DebugRequest) string {
	var err error
	if req.Args == "" {
		return "please specify shepherd metrics scrape interval"
	}
	metricsScrapingInterval, err = time.ParseDuration(req.Args)
	if err != nil {
		return "cannot parse scrape interval duration(example: 15s)"
	}
	updateClusterWorkers(ctx, settings.ShepherdMetricsCollectionInterval)
	return "set prometheus scrape interval to " + promScrapeInterval.String()

}

func resetScrapeInterval(ctx context.Context, req *edgeproto.DebugRequest) string {
	if req.Args != "" {
		return "reset command doesn't take any arguments"
	}
	metricsScrapingInterval = *promScrapeInterval
	updateClusterWorkers(ctx, settings.ShepherdMetricsCollectionInterval)
	return "reset promScrapeInterval for all workers"
}
