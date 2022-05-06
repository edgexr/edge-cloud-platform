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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/edgexr/edge-cloud-infra/shepherd/shepherd_platform/shepherd_unittest"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/stretchr/testify/assert"
)

const testInstCount = 50

var testWaitGroup sync.WaitGroup

type TestJsonTargets []struct {
	Targets []string `json:"targets"`
	Labels  struct {
		MetricsPath string `json:"__metrics_path__"`
		App         string `json:"app"`
		Apporg      string `json:"apporg"`
		Appver      string `json:"appver"`
		Cloudlet    string `json:"cloudlet"`
		Cloudletorg string `json:"cloudletorg"`
		Cluster     string `json:"cluster"`
		Clusterorg  string `json:"clusterorg"`
	} `json:"labels"`
}

func testUpdateAndWrite(ctx context.Context, inst *edgeproto.AppInst, t *testing.T) {
	if str := CollectProxyStats(ctx, inst); str != "" {
		targetFileWorkers.NeedsWork(ctx, targetsFileWorkerKey)
	}
}
func TestCloudletPrometheusFuncs(t *testing.T) {
	ctx := setupLog()
	defer log.FinishTracer()
	targetFileWorkers.Init("targets", writePrometheusTargetsFile)
	// test targets file
	*promTargetsFile = "/tmp/testTargets.json"
	myPlatform = &shepherd_unittest.Platform{}
	InitProxyScraper(time.Second, time.Second, nil)
	edgeproto.InitAppInstCache(&AppInstCache)
	edgeproto.InitAppCache(&AppCache)
	edgeproto.InitClusterInstCache(&ClusterInstCache)
	genApps(ctx, testInstCount)
	assert.Equal(t, testInstCount, len(AppCache.Objs))
	genClusters(ctx, testInstCount)
	assert.Equal(t, testInstCount, len(ClusterInstCache.Objs))
	testTargetAppInstances, targetKeys := genAppInstances(ctx, testInstCount)
	assert.Equal(t, testInstCount, len(testTargetAppInstances))
	assert.Equal(t, testInstCount, len(targetKeys))
	assert.Equal(t, testInstCount, len(AppInstCache.Objs))
	for ii := range testTargetAppInstances {
		testUpdateAndWrite(ctx, &testTargetAppInstances[ii], t)
	}
	// Wait for all to complete
	targetFileWorkers.WaitIdle()
	// verify they all are here
	content, err := ioutil.ReadFile(*promTargetsFile)
	assert.Nil(t, err)
	targets := TestJsonTargets{}
	err = json.Unmarshal(content, &targets)
	assert.Nil(t, err)
	assert.Len(t, targets, testInstCount)
	for _, target := range targets {
		key := target.Labels.App
		if _, found := targetKeys[key]; !found {
			assert.Fail(t, "Unable to find target", target)
		} else {
			// Delete to verify we don't have multiples
			delete(targetKeys, key)
		}
	}
	// we should have found all the keys
	assert.Len(t, targetKeys, 0)
	// clean up file
	err = os.Remove(*promTargetsFile)
	assert.Nil(t, err)
}

// generate Apps to populate cache
func genApps(ctx context.Context, cnt int) {
	for ii := 1; ii < cnt+1; ii++ {
		app := edgeproto.App{
			Key: edgeproto.AppKey{
				Name:         fmt.Sprintf("App-%d", ii),
				Organization: fmt.Sprintf("AppOrg-%d", ii),
			},
			AccessPorts: fmt.Sprintf("tcp:%d", ii),
			AccessType:  edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER,
		}
		AppCache.Update(ctx, &app, 0)
	}
}

// generate ClusterInsts to populate cache
func genClusters(ctx context.Context, cnt int) {
	for ii := 1; ii < cnt+1; ii++ {
		cluster := edgeproto.ClusterInst{
			Key: edgeproto.ClusterInstKey{
				ClusterKey: edgeproto.ClusterKey{
					Name: fmt.Sprintf("Cluster-%d", ii),
				},
				CloudletKey: edgeproto.CloudletKey{
					Organization: fmt.Sprintf("Cloudletorg-%d", ii),
					Name:         fmt.Sprintf("Cloudlet-%d", ii),
				},
				Organization: fmt.Sprintf("Clusterorg-%d", ii),
			},
		}
		ClusterInstCache.Update(ctx, &cluster, 0)
	}
}

// generate appInstances and keys for later verification
func genAppInstances(ctx context.Context, cnt int) ([]edgeproto.AppInst, map[string]struct{}) {
	list := []edgeproto.AppInst{}
	keys := map[string]struct{}{}
	for ii := 1; ii < cnt+1; ii++ {
		// Start with port 1000, since some of the lower ports are not allowed(example - 22)
		ports, _ := edgeproto.ParseAppPorts(fmt.Sprintf("tcp:%d", 1000+ii))
		inst := edgeproto.AppInst{
			Key: edgeproto.AppInstKey{
				AppKey: edgeproto.AppKey{
					Name:         fmt.Sprintf("App-%d", ii),
					Organization: fmt.Sprintf("AppOrg-%d", ii),
				},
				ClusterInstKey: edgeproto.VirtualClusterInstKey{
					ClusterKey: edgeproto.ClusterKey{
						Name: fmt.Sprintf("Cluster-%d", ii),
					},
					CloudletKey: edgeproto.CloudletKey{
						Organization: fmt.Sprintf("Cloudletorg-%d", ii),
						Name:         fmt.Sprintf("Cloudlet-%d", ii),
					},
					Organization: fmt.Sprintf("Clusterorg-%d", ii),
				},
			},
			MappedPorts: ports,
			State:       edgeproto.TrackedState_READY,
		}
		list = append(list, inst)
		keys[inst.Key.AppKey.Name] = struct{}{}
		AppInstCache.Update(ctx, &inst, 0)
	}
	return list, keys
}
