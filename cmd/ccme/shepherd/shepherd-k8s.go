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

package main

import (
	"context"
	"fmt"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/promutils"
	"github.com/edgexr/edge-cloud-platform/pkg/shepherd_common"
	ssh "github.com/edgexr/golang-ssh"
)

// K8s Cluster
type K8sClusterStats struct {
	shepherd_common.K8sStats
	promAddr  string // ip:port
	promPort  int32  // only needed if we don't know the IP to generate promAddr
	client    ssh.Client
	kubeNames *k8smgmt.KubeNames
}

func (c *K8sClusterStats) GetPromClient(ctx context.Context) (promutils.PromClient, error) {
	if c.promAddr == "" {
		err := c.UpdatePrometheusAddr(ctx)
		if err != nil {
			log.ForceLogSpan(log.SpanFromContext(ctx))
			log.SpanLog(ctx, log.DebugLevelMetrics, "error updating UpdatePrometheusAddr", "err", err)
			return nil, err
		}
		// Update platform if it depends on the cluster-level metrics
		log.DebugLog(log.DebugLevelInfo, "Setting prometheus addr", "addr", c.promAddr)
		myPlatform.SetUsageAccessArgs(ctx, c.promAddr, c.client)
	}
	return promutils.NewCurlClient(c.promAddr, c.client), nil
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
