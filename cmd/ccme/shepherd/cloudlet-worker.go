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
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	intprocess "github.com/edgexr/edge-cloud-platform/pkg/process"
	"github.com/edgexr/edge-cloud-platform/pkg/promutils"
	"github.com/edgexr/edge-cloud-platform/pkg/shepherd_common"
)

var cloudletMetrics shepherd_common.CloudletMetrics

// ChangeSinceLastCloudletStats means some cluster or appinst changed since last platform stats collection
var ChangeSinceLastPlatformStats bool
var LastPlatformCollectionTime time.Time

// Don't need to do much, just spin up a metrics collection thread
func InitPlatformMetrics(done chan bool) {
	go CloudletScraper(done)
	go CloudletPrometheusScraper(done)
}

func CloudletScraper(done chan bool) {
	var metrics []*edgeproto.Metric
	m, err := infraProps.GetPlatformStatsMaxCacheTime()
	if err != nil {
		log.FatalLog(err.Error())
	}
	maxCacheTime := time.Second * time.Duration(m)
	for {
		// check if there are any new apps we need to start/stop scraping for
		select {
		case <-time.After(3 * settings.ShepherdMetricsCollectionInterval.TimeDuration()):
			span := log.StartSpan(log.DebugLevelSampled, "send-cloudlet-metric")
			log.SetTags(span, cloudletKey.GetTags())
			ctx := log.ContextWithSpan(context.Background(), span)
			if !shepherd_common.ShepherdPlatformActive {
				log.SpanLog(ctx, log.DebugLevelMetrics, "skiping cloudlet metrics as shepherd is not active")
				continue
			}
			// if nothing has changed since the last collection, used cached stats up until MaxCachedPlatformStatsTime
			elapsed := time.Since(LastPlatformCollectionTime)
			if ChangeSinceLastPlatformStats || elapsed > maxCacheTime {
				cloudletStats, err := myPlatform.GetPlatformStats(ctx)
				ChangeSinceLastPlatformStats = false
				LastPlatformCollectionTime = time.Now()
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelMetrics, "Error retrieving platform metrics", "Platform", myPlatform, "error", err.Error())
					continue
				} else {
					metrics = MarshalCloudletMetrics(&cloudletStats)
				}
			} else {
				log.SpanLog(ctx, log.DebugLevelMetrics, "Using cached metrics due to no changes", "elapsed", elapsed)
			}
			for _, metric := range metrics {
				MetricSender.Update(context.Background(), metric)
			}

			span.Finish()
		case <-done:
			// process killed/interrupted, so quit
			return
		}
	}
}

func CloudletPrometheusScraper(done chan bool) {
	for {
		// check if there are any new apps we need to start/stop scraping for
		select {
		case <-time.After(settings.ShepherdMetricsCollectionInterval.TimeDuration()):
			//TODO  - cloudletEnvoyStats, err := getEnvoyStats

			aspan := log.StartSpan(log.DebugLevelMetrics, "send-cloudlet-alerts", log.WithSuppressWithoutLogs{})
			log.SetTags(aspan, cloudletKey.GetTags())
			actx := log.ContextWithSpan(context.Background(), aspan)
			if shepherd_common.ShepherdPlatformActive {
				// platform client is a local ssh
				client := promutils.NewCurlClient(CloudletPrometheusAddr, &pc.LocalClient{})
				alerts, err := shepherd_common.GetPromAlerts(actx, client)
				if err != nil {
					log.SpanLog(actx, log.DebugLevelMetrics, "Could not collect alerts",
						"prometheus port", intprocess.CloudletPrometheusPort, "err", err)
				}
				// key is nil, since we just check against the predefined set of rules
				cloudletAlertPruner := shepherd_common.NewCloudletAlertPruner(cloudletKey)
				count := shepherd_common.UpdateAlertsCache(actx, alerts, &AlertCache, cloudletAlertPruner)
				if count == 0 {
					// suppress span log since nothing logged
					log.NoLogSpan(aspan)
				}
				// query stats
				getCloudletPrometheusStats(actx, client)
			} else {
				log.SpanLog(actx, log.DebugLevelMetrics, "skipping cloudlet alerts due as shepherd is not active")
			}
			aspan.Finish()
		case <-done:
			// process killed/interrupted, so quit
			return
		}
	}
}

func getCloudletPrometheusStats(ctx context.Context, client promutils.PromClient) {
	autoScalers := make(map[edgeproto.ClusterKey]*ClusterAutoScaler)
	workerMapMutex.Lock()
	for _, worker := range workerMap {
		if worker.autoScaler.policyName != "" {
			autoScalers[worker.clusterKey] = &worker.autoScaler
		}
	}
	workerMapMutex.Unlock()

	for key, autoScaler := range autoScalers {
		policy := edgeproto.AutoScalePolicy{}
		policy.Key.Name = autoScaler.policyName
		policy.Key.Organization = key.Organization
		found := AutoScalePoliciesCache.Get(&policy.Key, &policy)
		if !found {
			log.SpanLog(ctx, log.DebugLevelMetrics, "cloudlet-worker autoscale policy not found", "policyKey", policy.Key)
			continue
		}
		tags := make([]string, 0)
		for k, v := range key.GetTags() {
			tags = append(tags, k+`="`+v+`"`)
		}
		q := "max_over_time(envoy_cluster_upstream_cx_active_total:avg{" + strings.Join(tags, ",") + "}[" + fmt.Sprintf("%d", policy.StabilizationWindowSec) + "s])"
		q = url.QueryEscape(q)
		resp, err := promutils.GetPromMetrics(ctx, q, client)
		if err == nil && resp.Status == "success" {
			for _, metric := range resp.Data.Result {
				if val, err := strconv.ParseFloat(metric.Values[1].(string), 64); err == nil {
					autoScaler.updateConnStats(ctx, key, val)
				}
			}
		}
	}
}

func MarshalCloudletMetrics(data *shepherd_common.CloudletMetrics) []*edgeproto.Metric {
	var metrics []*edgeproto.Metric
	cMetric := edgeproto.Metric{}
	nMetric := edgeproto.Metric{}
	iMetric := edgeproto.Metric{}

	// bail out if we get no metrics
	if data == nil {
		return nil
	}

	// If the timestamp for any given metric is null, don't send anything
	if data.CollectTime != nil {
		cMetric.Name = "cloudlet-utilization"
		cMetric.Timestamp = *data.CollectTime
		cloudletKey.AddTagsByFunc(cMetric.AddTag)
		zoneKey.AddTagsByFunc(cMetric.AddTag)
		cMetric.AddIntVal("vCpuUsed", data.VCpuUsed)
		cMetric.AddIntVal("vCpuMax", data.VCpuMax)
		cMetric.AddIntVal("memUsed", data.MemUsed)
		cMetric.AddIntVal("memMax", data.MemMax)
		cMetric.AddIntVal("diskUsed", data.DiskUsed)
		cMetric.AddIntVal("diskMax", data.DiskMax)
		metrics = append(metrics, &cMetric)

		nMetric.Name = "cloudlet-network"
		nMetric.Timestamp = *data.CollectTime
		cloudletKey.AddTagsByFunc(nMetric.AddTag)
		zoneKey.AddTagsByFunc(nMetric.AddTag)
		nMetric.AddIntVal("netSent", data.NetSent)
		nMetric.AddIntVal("netRecv", data.NetRecv)
		metrics = append(metrics, &nMetric)

		iMetric.Name = "cloudlet-ipusage"
		iMetric.Timestamp = *data.CollectTime
		cloudletKey.AddTagsByFunc(iMetric.AddTag)
		zoneKey.AddTagsByFunc(iMetric.AddTag)
		iMetric.AddIntVal("ipv4Max", data.Ipv4Max)
		iMetric.AddIntVal("ipv4Used", data.Ipv4Used)
		iMetric.AddIntVal("floatingIpsMax", data.FloatingIpsMax)
		iMetric.AddIntVal("floatingIpsUsed", data.FloatingIpsUsed)
		metrics = append(metrics, &iMetric)
	}
	return metrics
}
