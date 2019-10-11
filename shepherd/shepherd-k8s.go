package main

import (
	"context"

	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

// K8s Cluster
type K8sClusterStats struct {
	key      edgeproto.ClusterInstKey
	promAddr string
	client   pc.PlatformClient
	shepherd_common.ClusterMetrics
}

func (c *K8sClusterStats) GetClusterStats(ctx context.Context) *shepherd_common.ClusterMetrics {
	if c.promAddr == "" {
		return nil
	}
	if err := collectClusterPrometheusMetrics(ctx, c); err != nil {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Could not collect cluster metrics", "K8s Cluster", c)
		return nil
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
