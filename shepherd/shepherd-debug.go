// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/edgexr/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/edgexr/edge-cloud/cloudcommon/node"
	"github.com/edgexr/edge-cloud/edgeproto"
)

const defaultScrapeInterval = 15 * time.Second

func InitDebug(nodeMgr *node.NodeMgr) {
	nodeMgr.Debug.AddDebugFunc("set-scrape-interval", setScrapeInterval)
	nodeMgr.Debug.AddDebugFunc("reset-scrape-interval", resetScrapeInterval)
	nodeMgr.Debug.AddDebugFunc("show-scrape-interval", showScrapeInterval)
	nodeMgr.Debug.AddDebugFunc("show-platform-active", showPlatformActive)

}

func showScrapeInterval(ctx context.Context, req *edgeproto.DebugRequest) string {
	return "shepherd scraping metrics every " + metricsScrapingInterval.String()
}

func showPlatformActive(ctx context.Context, req *edgeproto.DebugRequest) string {
	return fmt.Sprintf("PlatformActive: %t", shepherd_common.ShepherdPlatformActive)
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
