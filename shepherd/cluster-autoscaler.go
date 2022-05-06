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
	"math"
	"sync"

	"github.com/edgexr/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/util/tasks"
)

var clusterAutoScalerWorkers tasks.KeyWorkers

func init() {
	clusterAutoScalerWorkers.Init("cluster-autoscale", checkClusterAutoScale)
}

type ClusterAutoScaler struct {
	mux                       sync.Mutex
	policyName                string
	lastStabilizedTotalCpu    float32
	lastStabilizedTotalMem    float32
	lastStabilizedActiveConns float64
	scaleInProgress           bool // makes sure Alert gets deleted when done
}

func (s *ClusterAutoScaler) updateClusterStats(ctx context.Context, key edgeproto.ClusterInstKey, stats *shepherd_common.ClusterMetrics) {
	if stats == nil {
		return
	}
	needsWork := false
	s.mux.Lock()
	if s.lastStabilizedTotalCpu != float32(stats.AutoScaleCpu) {
		s.lastStabilizedTotalCpu = float32(stats.AutoScaleCpu)
		needsWork = true
	}
	if s.lastStabilizedTotalMem != float32(stats.AutoScaleMem) {
		s.lastStabilizedTotalMem = float32(stats.AutoScaleMem)
		needsWork = true
	}
	s.mux.Unlock()
	// Note scaleInProgress is needed to ensure alert is removed
	// after scaling is done, in case stats remain constant.
	if needsWork || s.scaleInProgress {
		clusterAutoScalerWorkers.NeedsWork(ctx, key)
	}
}

func (s *ClusterAutoScaler) updateConnStats(ctx context.Context, key edgeproto.ClusterInstKey, activeConns float64) {
	needsWork := false
	s.mux.Lock()
	if s.lastStabilizedActiveConns != activeConns {
		s.lastStabilizedActiveConns = activeConns
		needsWork = true
	}
	s.mux.Unlock()
	if needsWork || s.scaleInProgress {
		clusterAutoScalerWorkers.NeedsWork(ctx, key)
	}
}

func checkClusterAutoScale(ctx context.Context, k interface{}) {
	key, ok := k.(edgeproto.ClusterInstKey)
	if !ok {
		log.SpanLog(ctx, log.DebugLevelApi, "Unexpected failure, checkClusterAutoScale key not a ClusterInstKey", "key", k)
		return
	}
	log.SetContextTags(ctx, key.GetTags())

	// Get the auto scaler
	autoScaler := getClusterWorkerAutoScaler(&key)
	if autoScaler == nil {
		log.SpanLog(ctx, log.DebugLevelApi, "checkClusterAutoScale cluster worker not found", "key", key)
		return
	}

	// Lookup the policy
	policy := edgeproto.AutoScalePolicy{}
	policy.Key.Name = autoScaler.policyName
	policy.Key.Organization = key.Organization
	found := AutoScalePoliciesCache.Get(&policy.Key, &policy)
	if !found {
		log.SpanLog(ctx, log.DebugLevelApi, "checkClusterAutoScale policy not found", "policyKey", policy.Key)
		return
	}
	// Lookup ClusterInst to get current number of nodes
	cinst := edgeproto.ClusterInst{}
	found = ClusterInstCache.Get(&key, &cinst)
	if !found {
		log.SpanLog(ctx, log.DebugLevelApi, "checkClusterAutoScale cluster not found", "key", key)
		return
	}

	// Get the max desired nodes.
	// We calculate desiredNodes = ceil(total-load/target-per-node-load)
	// We do the ceil after determining the max total/per-node for each
	// metric specified.
	autoScaler.mux.Lock()
	var desiredNodesRaw float64
	reason := ""
	if policy.TargetCpu > 0 {
		numNodes := float64(autoScaler.lastStabilizedTotalCpu / (float32(policy.TargetCpu) / 100.0))
		if numNodes > desiredNodesRaw {
			desiredNodesRaw = numNodes
			reason = fmt.Sprintf("stabilized total cpu %f, target %f per node", autoScaler.lastStabilizedTotalCpu, float32(policy.TargetCpu)/100.0)
		}
	}
	if policy.TargetMem > 0 {
		numNodes := float64(autoScaler.lastStabilizedTotalMem / (float32(policy.TargetMem) / 100.0))
		if numNodes > desiredNodesRaw {
			desiredNodesRaw = numNodes
			reason = fmt.Sprintf("stabilized total mem %f, target %f per node", autoScaler.lastStabilizedTotalMem, float32(policy.TargetMem)/100.0)
		}
	}
	if policy.TargetActiveConnections > 0 {
		numNodes := autoScaler.lastStabilizedActiveConns / float64(policy.TargetActiveConnections)
		if numNodes > desiredNodesRaw {
			desiredNodesRaw = numNodes
			reason = fmt.Sprintf("stabilized total active connections %f, target %d per node", autoScaler.lastStabilizedActiveConns, policy.TargetActiveConnections)
		}
	}
	log.SpanLog(ctx, log.DebugLevelApi, "checkClusterAutoScale calculations", "key", key, "autoScaler", fmt.Sprintf("%+v", autoScaler), "policy", policy, "desiredNodesRaw", desiredNodesRaw, "curNumNodes", cinst.NumNodes, "reason", reason)
	autoScaler.mux.Unlock()
	if desiredNodesRaw == 0 {
		log.SpanLog(ctx, log.DebugLevelApi, "checkClusterAutoScale no metrics to scale on")
		return
	}

	// Create alert if desired does not equal current, or delete if it does
	desiredCeil := math.Ceil(desiredNodesRaw)
	if desiredCeil < float64(policy.MinNodes) {
		desiredCeil = float64(policy.MinNodes)
	}
	if desiredCeil > float64(policy.MaxNodes) {
		desiredCeil = float64(policy.MaxNodes)
	}
	alert := getAutoScaleAlert(&key, desiredCeil)
	// Add 10% hysteresis at the step point. This means if the desiredNodesRaw
	// is between 2.0 and 2.2 for example, if the current num nodes is 2,
	// no change will happen (because of 10% check), or, if the current num
	// nodes is 3, also no change will happen (because of the ceil check).
	if (desiredNodesRaw < float64(cinst.NumNodes)*1.1 && desiredNodesRaw >= float64(cinst.NumNodes)) || uint32(desiredCeil) == cinst.NumNodes {
		log.SpanLog(ctx, log.DebugLevelApi, "checkClusterAutoScale no scaling needed", "desiredRaw", desiredNodesRaw, "desiredCeil", uint32(desiredCeil), "actual", cinst.NumNodes)
		AlertCache.Delete(ctx, alert, 0)
		autoScaler.scaleInProgress = false
		return
	}

	// update alert if not already there with same number of desired nodes
	alert.Annotations = make(map[string]string)
	alert.Annotations["reason"] = reason
	AlertCache.UpdateModFunc(ctx, alert.GetKey(), 0, func(old *edgeproto.Alert) (*edgeproto.Alert, bool) {
		if old != nil && old.Value == alert.Value {
			return nil, false
		}
		log.SpanLog(ctx, log.DebugLevelApi, "checkClusterAutoScale updating alert")
		return alert, true
	})
	autoScaler.scaleInProgress = true
}

func getAutoScaleAlert(key *edgeproto.ClusterInstKey, desiredNodes float64) *edgeproto.Alert {
	alert := &edgeproto.Alert{}
	alert.Labels = key.GetTags()
	alert.Labels["alertname"] = cloudcommon.AlertClusterAutoScale
	alert.Labels["region"] = *region
	alert.State = "firing"
	alert.Value = desiredNodes
	return alert
}
