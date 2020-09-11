package main

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/cloudcommon/node"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"google.golang.org/grpc"
)

func autoScale(ctx context.Context, name string, alert *edgeproto.Alert) error {
	if alert.State != "firing" {
		return nil
	}
	inst := edgeproto.ClusterInst{}
	inst.Key.Organization = alert.Labels[edgeproto.ClusterInstKeyTagOrganization]
	inst.Key.ClusterKey.Name = alert.Labels[edgeproto.ClusterKeyTagName]
	inst.Key.CloudletKey.Name = alert.Labels[edgeproto.CloudletKeyTagName]
	inst.Key.CloudletKey.Organization = alert.Labels[edgeproto.CloudletKeyTagOrganization]

	nodecountStr := alert.Annotations[cloudcommon.AlertKeyNodeCount]
	nodecount, err := strconv.Atoi(nodecountStr)
	if err != nil {
		return fmt.Errorf("failed to parse nodecount %s, %v", nodecountStr, err)
	}

	if name == cloudcommon.AlertAutoScaleUp {
		inst.NumNodes = uint32(nodecount + 1)
	} else {
		lowStr := alert.Annotations[cloudcommon.AlertKeyLowCpuNodeCount]
		lowcount, err := strconv.Atoi(lowStr)
		if err != nil {
			return fmt.Errorf("failed to parse lowcpu count %s, %v", lowStr, err)
		}
		minNodesStr := alert.Annotations[cloudcommon.AlertKeyMinNodes]
		minNodes, err := strconv.Atoi(minNodesStr)
		if err != nil {
			return fmt.Errorf("failed to parse min nodes %s, %v", minNodesStr, err)
		}
		newCount := nodecount - lowcount
		if newCount < minNodes {
			newCount = minNodes
		}
		inst.NumNodes = uint32(newCount)
	}
	inst.Fields = []string{edgeproto.ClusterInstFieldNumNodes}

	conn, err := grpc.Dial(*ctrlAddr, dialOpts, grpc.WithBlock(),
		grpc.WithWaitForHandshake(),
		grpc.WithUnaryInterceptor(log.UnaryClientTraceGrpc),
		grpc.WithStreamInterceptor(log.StreamClientTraceGrpc))
	if err != nil {
		return fmt.Errorf("Connect to controller %s failed, %v", *ctrlAddr, err)
	}
	defer conn.Close()

	eventStart := time.Now()
	log.SpanLog(ctx, log.DebugLevelApi, "auto scaling clusterinst", "alert", alert, "ClusterInst", inst)
	client := edgeproto.NewClusterInstApiClient(conn)
	stream, err := client.UpdateClusterInst(ctx, &inst)
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
		nodeMgr.TimedEvent(ctx, name+" ClusterInst", inst.Key.Organization, node.EventType, inst.Key.GetTags(), err, eventStart, time.Now(), "previous nodecount", nodecountStr, "new nodecount", strconv.Itoa(int(inst.NumNodes)))
	}
	return err
}
