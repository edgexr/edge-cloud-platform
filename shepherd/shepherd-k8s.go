package main

import (
	"context"

	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

// K8s Cluster
type K8sClusterStats struct {
	key      edgeproto.ClusterInstKey
	promAddr string
	client   ssh.Client
	shepherd_common.ClusterMetrics
}

func (c *K8sClusterStats) GetClusterStats(ctx context.Context, ops ...shepherd_common.StatsOp) *shepherd_common.ClusterMetrics {
	if c.promAddr == "" {
		return nil
	}
	opts := shepherd_common.GetStatsOptions(ops)

	if err := collectClusterPrometheusMetrics(ctx, c); err != nil {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Could not collect cluster metrics", "K8s Cluster", c)
		return nil
	}
	if opts.GetAutoScaleStats {
		if err := collectClusterAutoScaleMetrics(ctx, c); err != nil {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Could not collect cluster auto-scale metrics", "K8s Cluster", c)
			return nil
		}
	}
	return &c.ClusterMetrics
}

// Currently we are collecting stats for all apps in the cluster in one shot
// Implementing  EDGECLOUD-1183 would allow us to query by label and we can have each app be an individual metric
func (c *K8sClusterStats) GetAppStats(ctx context.Context) map[shepherd_common.MetricAppInstKey]*shepherd_common.AppMetrics {
	if c.promAddr == "" {
		return nil
	}
	metrics := collectAppPrometheusMetrics(ctx, c)
	if metrics == nil {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Could not collect app metrics", "K8s Cluster", c)
	}
	return metrics
}

func (c *K8sClusterStats) GetAlerts(ctx context.Context) []edgeproto.Alert {
	if c.promAddr == "" {
		return nil
	}
	alerts, err := getPromAlerts(ctx, c.promAddr, c.client)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Could not collect alerts", "K8s Cluster", c, "err", err)
		return nil
	}
	return alerts
}
