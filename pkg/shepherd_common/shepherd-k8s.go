// Copyright 2025 EdgeXR, Inc
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

package shepherd_common

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/promutils"
)

// K8s Cluster
type K8sStats struct {
	Key         edgeproto.ClusterKey
	CloudletKey edgeproto.CloudletKey
	ClusterMetrics
	AppInstLabels
}

func (c *K8sStats) GetClusterStats(ctx context.Context, client promutils.PromClient, ops ...StatsOp) *ClusterMetrics {
	if client == nil {
		return nil
	}
	opts := GetStatsOptions(ops)

	if err := c.collectClusterPrometheusMetrics(ctx, client); err != nil {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Could not collect cluster metrics", "K8s Cluster", c)
		return nil
	}
	if opts.GetAutoScaleStats {
		if err := c.collectClusterAutoScaleMetrics(ctx, client); err != nil {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Could not collect cluster auto-scale metrics", "K8s Cluster", c)
			return nil
		}
	}
	return &c.ClusterMetrics
}

// Currently we are collecting stats for all apps in the cluster in one shot
// Implementing  EDGECLOUD-1183 would allow us to query by label and we can have each app be an individual metric
func (c *K8sStats) GetAppStats(ctx context.Context, client promutils.PromClient) map[MetricAppInstKey]*AppMetrics {
	metrics := c.collectAppPrometheusMetrics(ctx, client)
	if metrics == nil {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Could not collect app metrics", "K8s Cluster", c)
	}
	return metrics
}

func (c *K8sStats) GetAlerts(ctx context.Context, client promutils.PromClient) []edgeproto.Alert {
	if client == nil {
		return nil
	}
	alerts, err := GetPromAlerts(ctx, client)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Could not collect alerts", "K8s Cluster", c, "err", err)
		return nil
	}
	return alerts
}
