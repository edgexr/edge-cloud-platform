package main

import (
	"context"
	"fmt"
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
	return "shepherd scraping metrics every " + metricsScrapingInterval.String()
}

func setIntervalFromDbg(ctx context.Context, scrapeInterval *time.Duration) error {
	if settings.ShepherdAlertEvaluationInterval.TimeDuration() < *scrapeInterval {
		return fmt.Errorf("evaluation interval %s cannot be less than scrape interval %s", settings.ShepherdAlertEvaluationInterval.TimeDuration().String(), scrapeInterval.String())
	}
	// update cloudletPrometheus config file
	err := updateCloudletPrometheusConfig(ctx, &metricsScrapingInterval, &settings.ShepherdAlertEvaluationInterval)
	if err != nil {
		return fmt.Errorf("unable to update cloudlet prometheus config: %s", err.Error())
	}
	updateClusterWorkers(ctx, settings.ShepherdMetricsCollectionInterval)
	return nil
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
	err = setIntervalFromDbg(ctx, &metricsScrapingInterval)
	if err != nil {
		return err.Error()
	}
	return "set prometheus scrape interval to " + metricsScrapingInterval.String()
}

func resetScrapeInterval(ctx context.Context, req *edgeproto.DebugRequest) string {
	if req.Args != "" {
		return "reset command doesn't take any arguments"
	}
	metricsScrapingInterval = *promScrapeInterval
	err := setIntervalFromDbg(ctx, &metricsScrapingInterval)
	if err != nil {
		return err.Error()
	}
	return "reset promScrapeInterval for all workers"
}
