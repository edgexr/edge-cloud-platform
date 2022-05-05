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

	"github.com/edgexr/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

// K8s Cluster
type K8sClusterStats struct {
	key      edgeproto.ClusterInstKey
	promAddr string // ip:port
	promPort int32  // only needed if we don't know the IP to generate promAddr
	client   ssh.Client
	shepherd_common.ClusterMetrics
	kubeNames *k8smgmt.KubeNames
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
	// update the prometheus address if needed
	if c.promAddr == "" {
		err := c.UpdatePrometheusAddr(ctx)
		if err != nil {
			log.ForceLogSpan(log.SpanFromContext(ctx))
			log.SpanLog(ctx, log.DebugLevelMetrics, "error updating UpdatePrometheusAddr", "err", err)
			return make(map[shepherd_common.MetricAppInstKey]*shepherd_common.AppMetrics)
		}
		// Update platform if it depends on the cluster-level metrics
		log.DebugLog(log.DebugLevelInfo, "Setting prometheus addr", "addr", c.promAddr)
		myPlatform.SetUsageAccessArgs(ctx, c.promAddr, c.client)
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

func (c *K8sClusterStats) UpdatePrometheusAddr(ctx context.Context) error {
	log.SpanLog(ctx, log.DebugLevelMetrics, "UpdatePrometheusAddr")
	if c.promPort == 0 {
		// this should not happen as the port should be here even if the IP is not
		return fmt.Errorf("No prometheus port specified")
	}
	// see if we can find the prometheus port as a load balancer IP
	portMap := make(map[string]string)
	err := k8smgmt.UpdateLoadBalancerPortMap(ctx, c.client, c.kubeNames, portMap)
	if err != nil {
		log.ForceLogSpan(log.SpanFromContext(ctx))
		return fmt.Errorf("error updating load balancer port map - %v", err)
	}
	pstr := edgeproto.ProtoPortToString("tcp", c.promPort)
	lbip, ok := portMap[pstr]
	if ok {
		c.promAddr = fmt.Sprintf("%s:%d", lbip, c.promPort)
		log.SpanLog(ctx, log.DebugLevelMetrics, "replaced prometheus address", "promAddr", c.promAddr)
	} else {
		// this is possible if it takes a while for prometheus to get configured and get an IP
		return fmt.Errorf("Prometheus LB IP not found")
	}
	return nil
}
