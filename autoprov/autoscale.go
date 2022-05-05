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
	"io"
	"strconv"
	"time"

	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/cloudcommon/node"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/util/tasks"
	"google.golang.org/grpc"
)

var clusterAutoScaleWorkers tasks.KeyWorkers

func init() {
	clusterAutoScaleWorkers.Init("cluster-autoscale", runAutoScale)
}

func runAutoScale(ctx context.Context, k interface{}) {
	key, ok := k.(edgeproto.AlertKey)
	if !ok {
		log.SpanLog(ctx, log.DebugLevelApi, "Unexpected failure, autoscale key not an AlertKey", "key", k)
		return
	}
	// get alert
	alert := edgeproto.Alert{}
	if !cacheData.alertCache.Get(&key, &alert) {
		// no more alert, no work needed
		return
	}
	log.SpanLog(ctx, log.DebugLevelApi, "processing cluster autoscale alert", "alert", alert)
	if alert.State != "firing" {
		return
	}
	name := alert.Labels["alertname"]

	cinst, err := getClusterInstToScale(ctx, name, &alert)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "Failed to set up ClusterInst for scaling from Alert", "err", err)
		return
	}

	log.SpanLog(ctx, log.DebugLevelApi, "auto scaling clusterinst", "alert", alert, "ClusterInst", cinst)
	err = scaleClusterInst(ctx, name, &alert, cinst)
	if err != nil && err.Error() != cinst.Key.NotFoundError().Error() {
		// retry
		delay := settings.ClusterAutoScaleRetryDelay.TimeDuration()
		log.SpanLog(ctx, log.DebugLevelApi, "Scaling ClusterInst failed, will retry", "ClusterInst", cinst.Key, "retrydelay", delay.String(), "err", err)
		time.Sleep(delay)
		clusterAutoScaleWorkers.NeedsWork(ctx, key)
	}
}

func getClusterInstToScale(ctx context.Context, name string, alert *edgeproto.Alert) (*edgeproto.ClusterInst, error) {
	inst := edgeproto.ClusterInst{}
	inst.Key.Organization = alert.Labels[edgeproto.ClusterInstKeyTagOrganization]
	inst.Key.ClusterKey.Name = alert.Labels[edgeproto.ClusterKeyTagName]
	inst.Key.CloudletKey.Name = alert.Labels[edgeproto.CloudletKeyTagName]
	inst.Key.CloudletKey.Organization = alert.Labels[edgeproto.CloudletKeyTagOrganization]
	if name == cloudcommon.AlertClusterAutoScale {
		// new v1 scaling alert
		inst.NumNodes = uint32(alert.Value)
	} else {
		// old v0 alerts
		nodecountStr := alert.Annotations[cloudcommon.AlertKeyNodeCount]
		nodecount, err := strconv.Atoi(nodecountStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse nodecount %s, %v", nodecountStr, err)
		}

		if name == cloudcommon.AlertAutoScaleUp {
			inst.NumNodes = uint32(nodecount + 1)
		} else {
			lowStr := alert.Annotations[cloudcommon.AlertKeyLowCpuNodeCount]
			lowcount, err := strconv.Atoi(lowStr)
			if err != nil {
				return nil, fmt.Errorf("failed to parse lowcpu count %s, %v", lowStr, err)
			}
			minNodesStr := alert.Annotations[cloudcommon.AlertKeyMinNodes]
			minNodes, err := strconv.Atoi(minNodesStr)
			if err != nil {
				return nil, fmt.Errorf("failed to parse min nodes %s, %v", minNodesStr, err)
			}
			newCount := nodecount - lowcount
			if newCount < minNodes {
				newCount = minNodes
			}
			inst.NumNodes = uint32(newCount)
		}
	}
	inst.Fields = []string{edgeproto.ClusterInstFieldNumNodes}
	return &inst, nil
}

func scaleClusterInst(ctx context.Context, name string, alert *edgeproto.Alert, inst *edgeproto.ClusterInst) error {
	conn, err := grpc.Dial(*ctrlAddr, dialOpts, grpc.WithBlock(),
		grpc.WithUnaryInterceptor(log.UnaryClientTraceGrpc),
		grpc.WithStreamInterceptor(log.StreamClientTraceGrpc))
	if err != nil {
		return fmt.Errorf("Connect to controller %s failed, %v", *ctrlAddr, err)
	}
	defer conn.Close()

	eventStart := time.Now()
	client := edgeproto.NewClusterInstApiClient(conn)
	stream, err := client.UpdateClusterInst(ctx, inst)
	if err != nil {
		return err
	}
	for {
		_, err = stream.Recv()
		if err == io.EOF {
			err = nil
			break
		}
		if err != nil {
			break
		}
	}
	if err == nil {
		// only log event if scaling succeeded
		nodeMgr.TimedEvent(ctx, name+" ClusterInst", inst.Key.Organization, node.EventType, inst.Key.GetTags(), err, eventStart, time.Now(), "new nodecount", strconv.Itoa(int(inst.NumNodes)), "reason", alert.Annotations["reason"])
	}
	return err
}
