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
	"testing"

	"github.com/edgexr/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/testutil"
	"github.com/stretchr/testify/require"
)

func TestClusterAutoScaler(t *testing.T) {
	ctx := setupLog()
	defer log.FinishTracer()
	log.SetDebugLevel(log.DebugLevelMetrics | log.DebugLevelApi)

	cluster := testutil.ClusterInstData[2]
	policy := edgeproto.AutoScalePolicy{}
	policy.Key.Name = "test-policy"
	policy.Key.Organization = cluster.Key.Organization
	policy.MinNodes = 1
	policy.MaxNodes = 4
	policy.StabilizationWindowSec = 20
	policy.TargetCpu = 70
	policy.TargetMem = 70
	policy.TargetActiveConnections = 50

	cluster.AutoScalePolicy = policy.Key.Name
	cluster.Deployment = cloudcommon.DeploymentTypeKubernetes
	cluster.NumNodes = 2

	// inject data into caches
	edgeproto.InitAutoScalePolicyCache(&AutoScalePoliciesCache)
	edgeproto.InitClusterInstCache(&ClusterInstCache)
	edgeproto.InitAlertCache(&AlertCache)
	AutoScalePoliciesCache.Update(ctx, &policy, 0)
	ClusterInstCache.Update(ctx, &cluster, 0)
	defer func() {
		ClusterInstCache.Delete(ctx, &cluster, 0)
		AutoScalePoliciesCache.Delete(ctx, &policy, 0)
	}()
	// fake cluster worker
	worker := &ClusterWorker{}
	worker.autoScaler.policyName = cluster.AutoScalePolicy
	worker.clusterInstKey = cluster.Key
	workerMapMutex.Lock()
	workerMap = make(map[string]*ClusterWorker)
	workerMap[getClusterWorkerMapKey(&cluster.Key)] = worker
	workerMapMutex.Unlock()
	defer func() {
		workerMapMutex.Lock()
		delete(workerMap, getClusterWorkerMapKey(&cluster.Key))
		workerMapMutex.Unlock()
	}()

	updateStats := func(cpu, mem float64) {
		stats := shepherd_common.ClusterMetrics{}
		stats.AutoScaleCpu = cpu
		stats.AutoScaleMem = mem
		worker.autoScaler.updateClusterStats(ctx, worker.clusterInstKey, &stats)
		clusterAutoScalerWorkers.WaitIdle()
	}
	updateProxyStats := func(conns float64) {
		worker.autoScaler.updateConnStats(ctx, worker.clusterInstKey, conns)
		clusterAutoScalerWorkers.WaitIdle()
	}

	alert := getAutoScaleAlert(&cluster.Key, 0)
	checkAlert := func(exists bool, desiredNodes float64) {
		buf := edgeproto.Alert{}
		found := AlertCache.Get(alert.GetKey(), &buf)
		require.Equal(t, exists, found)
		if exists {
			require.Equal(t, desiredNodes, buf.Value)
		}
	}

	// Test that alerts are generated as expected based on
	// mocked collected stats.

	updateStats(0, 0)
	checkAlert(false, 0)

	updateProxyStats(0)
	checkAlert(false, 0)

	// num nodes is 2, and target is 0.7
	updateStats(1.4, 0)
	checkAlert(false, 0)
	updateStats(2.0, 0)
	checkAlert(true, 3)
	updateStats(2.8, 0)
	checkAlert(true, 4)
	updateStats(3.5, 0) // test max nodes limit
	checkAlert(true, 4)
	updateStats(1.4, 0)
	checkAlert(false, 0)
	updateStats(0.69, 0)
	checkAlert(true, 1)

	// do same for mem
	updateStats(0, 1.4)
	checkAlert(false, 0)
	updateStats(0, 2.0)
	checkAlert(true, 3)
	updateStats(0, 2.8)
	checkAlert(true, 4)
	updateStats(0, 1.4)
	checkAlert(false, 0)
	updateStats(0, 0.69)
	checkAlert(true, 1)

	// do same for active conns
	updateProxyStats(100)
	checkAlert(false, 0)
	updateProxyStats(140)
	checkAlert(true, 3)
	updateProxyStats(200)
	checkAlert(true, 4)
	updateProxyStats(100)
	checkAlert(false, 0)
	updateProxyStats(49)
	checkAlert(true, 1)

	// check combos, should go for largest
	updateStats(1, 2.2)
	updateProxyStats(60)
	checkAlert(true, 4)
	updateStats(1, 1)
	updateProxyStats(120)
	checkAlert(true, 3)
	updateStats(1, 0)
	updateProxyStats(0)
	checkAlert(false, 0)

	// check upper bound hysteresis (10% window)
	updateStats(1.4*1.09, 0)
	checkAlert(false, 0)
	updateStats(1.4*1.10, 0)
	checkAlert(true, 3)
	// no hysteresis if not near current value
	updateStats(2.1*1.09, 0)
	checkAlert(true, 4)
	// check lower bound hysteresis (ceil)
	updateStats(0.7*1.01, 0)
	checkAlert(false, 0)
	updateStats(0.7*.99, 0)
	checkAlert(true, 1)
}
