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

package autoprov

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/util/tasks"
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
	inst.Key.Organization = alert.Labels[edgeproto.ClusterKeyTagOrganization]
	inst.Key.Name = alert.Labels[edgeproto.ClusterKeyTagName]
	inst.CloudletKey.Name = alert.Labels[edgeproto.CloudletKeyTagName]
	inst.CloudletKey.Organization = alert.Labels[edgeproto.CloudletKeyTagOrganization]
	if name == cloudcommon.AlertClusterAutoScale {
		// new v1 scaling alert
		// Use ClusterInst.NumNodes so we don't have to figure
		// out the pool name
		inst.NumNodes = uint32(alert.Value)
	}
	inst.Fields = []string{edgeproto.ClusterInstFieldNumNodes}
	return &inst, nil
}

func scaleClusterInst(ctx context.Context, name string, alert *edgeproto.Alert, inst *edgeproto.ClusterInst) error {
	conn, err := grpc.Dial(*ctrlAddr, dialOpts, grpc.WithBlock(),
		grpc.WithUnaryInterceptor(log.UnaryClientTraceGrpc),
		grpc.WithStreamInterceptor(log.StreamClientTraceGrpc),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(&cloudcommon.ProtoCodec{})),
	)
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
		nodeMgr.TimedEvent(ctx, name+" ClusterInst", inst.Key.Organization, node.EventType, inst.Key.GetTags(), err, eventStart, time.Now(), "new nodecount", strconv.Itoa(int(inst.GetNumNodes())), "reason", alert.Annotations["reason"])
	}
	return err
}
