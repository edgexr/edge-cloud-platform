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
	"testing"

	"github.com/edgexr/edge-cloud/cloud-resource-manager/redundancy"
	"github.com/edgexr/edge-cloud/cloudcommon/node"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/integration/process"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/notify"
	"github.com/stretchr/testify/require"
)

// Test data
var testFlavors = []edgeproto.Flavor{
	{
		Key: edgeproto.FlavorKey{
			Name: "flavor1",
		},
		Ram:   uint64(1024),
		Vcpus: uint64(2),
		Disk:  uint64(4),
	},
}

var testCloudlets = []edgeproto.Cloudlet{
	{
		Key: edgeproto.CloudletKey{
			Name:         "cloudlet1",
			Organization: "dmuus",
		},
		State: edgeproto.TrackedState_READY,
	},
	{
		Key: edgeproto.CloudletKey{
			Name:                  "cloudlet2",
			Organization:          "dmuus",
			FederatedOrganization: "singtel",
		},
		State: edgeproto.TrackedState_READY,
	},
	{
		Key: edgeproto.CloudletKey{
			Name:                  "cloudlet3",
			Organization:          "dmuus",
			FederatedOrganization: "sonoral",
		},
		State: edgeproto.TrackedState_READY,
	},
}
var testApps = []edgeproto.App{
	{
		Key: edgeproto.AppKey{
			Organization: "dev1",
			Name:         "app1",
			Version:      "1.0",
		},
	},
}
var testClusterInsts = []edgeproto.ClusterInst{
	{
		Key: edgeproto.ClusterInstKey{
			ClusterKey: edgeproto.ClusterKey{
				Name: "cluster1",
			},
			CloudletKey:  testCloudlets[0].Key,
			Organization: "dev1",
		},
	},
	{
		Key: edgeproto.ClusterInstKey{
			ClusterKey: edgeproto.ClusterKey{
				Name: "cluster2",
			},
			CloudletKey:  testCloudlets[1].Key,
			Organization: "dev1",
		},
	},
	{
		Key: edgeproto.ClusterInstKey{
			ClusterKey: edgeproto.ClusterKey{
				Name: "cluster3",
			},
			CloudletKey:  testCloudlets[2].Key,
			Organization: "dev1",
		},
	},
}
var testAppInstances = []edgeproto.AppInst{
	{
		Key: edgeproto.AppInstKey{
			AppKey:         testApps[0].Key,
			ClusterInstKey: *testClusterInsts[0].Key.Virtual(""),
		},
	},
	{
		Key: edgeproto.AppInstKey{
			AppKey:         testApps[0].Key,
			ClusterInstKey: *testClusterInsts[1].Key.Virtual(""),
		},
	},
	{
		Key: edgeproto.AppInstKey{
			AppKey:         testApps[0].Key,
			ClusterInstKey: *testClusterInsts[2].Key.Virtual(""),
		},
	},
}

func TestFRMNotify(t *testing.T) {
	var err error
	log.SetDebugLevel(log.DebugLevelApi | log.DebugLevelNotify | log.DebugLevelInfra)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	// Test data
	data := edgeproto.AllData{
		Flavors:      testFlavors,
		Cloudlets:    testCloudlets,
		Apps:         testApps,
		ClusterInsts: testClusterInsts,
		AppInstances: testAppInstances,
	}

	// FRM is driven by controller
	ctrlHandler := notify.NewDummyHandler()
	ctrlMgr := notify.ServerMgr{}
	ctrlHandler.RegisterServer(&ctrlMgr)
	notifyAddr := "127.0.0.1:61245"
	ctrlMgr.Start("ctrl", notifyAddr, nil)

	var nodeMgr node.NodeMgr
	var haMgr redundancy.HighAvailabilityManager

	nodeOps := []node.NodeOp{
		node.WithName(*hostname),
		node.WithNoUpdateMyNode(),
		node.WithRegion(*region),
		node.WithHARole(process.HARolePrimary),
	}
	ctx, span, err := nodeMgr.Init(node.NodeTypeFRM, node.CertIssuerRegional, nodeOps...)
	require.Nil(t, err)
	defer span.Finish()

	haMgr.HARole = string(process.HARolePrimary)
	notifyClient, controllerData, err := InitFRM(ctx, &nodeMgr, &haMgr, "frm-hostname", "local", "dummy.net", notifyAddr)
	require.Nil(t, err)
	defer func() {
		nodeMgr.Finish()
		notifyClient.Stop()
		ctrlMgr.Stop()
	}()

	notifyClient.WaitForConnect(1)
	stats := notify.Stats{}
	notifyClient.GetStats(&stats)
	require.Equal(t, uint64(1), stats.Connects)

	// Add data to controller
	for ii := range data.Flavors {
		ctrlHandler.FlavorCache.Update(ctx, &data.Flavors[ii], 0)
	}
	for ii := range data.Cloudlets {
		ctrlHandler.CloudletCache.Update(ctx, &data.Cloudlets[ii], 0)
	}
	for ii := range data.Apps {
		ctrlHandler.AppCache.Update(ctx, &data.Apps[ii], 0)
	}
	for ii := range data.ClusterInsts {
		ctrlHandler.ClusterInstCache.Update(ctx, &data.ClusterInsts[ii], 0)
	}
	for ii := range data.AppInstances {
		ctrlHandler.AppInstCache.Update(ctx, &data.AppInstances[ii], 0)
	}

	// Wait for FRM to receive data
	// FRM will only receive data corresponding to federated cloudlets
	require.Nil(t, notify.WaitFor(controllerData.CloudletCache, 2))
	require.Nil(t, notify.WaitFor(&controllerData.ClusterInstCache, 2))
	require.Nil(t, notify.WaitFor(&controllerData.AppInstCache, 2))

	for key, _ := range controllerData.CloudletCache.Objs {
		require.NotEmpty(t, key.FederatedOrganization, "recvd federated cloudlet")
	}

	for key, _ := range controllerData.ClusterInstCache.Objs {
		require.NotEmpty(t, key.CloudletKey.FederatedOrganization, "recvd federated cloudlet cluster instance")
	}

	for key, _ := range controllerData.AppInstCache.Objs {
		require.NotEmpty(t, key.ClusterInstKey.CloudletKey.FederatedOrganization, "recvd federated cloudlet app instance")
	}

	require.Equal(t, 1, len(controllerData.FlavorCache.Objs))
	require.Equal(t, 1, len(controllerData.AppCache.Objs))

	// delete
	for ii := range data.AppInstances {
		ctrlHandler.AppInstCache.Delete(ctx, &data.AppInstances[ii], 0)
	}
	for ii := range data.ClusterInsts {
		ctrlHandler.ClusterInstCache.Delete(ctx, &data.ClusterInsts[ii], 0)
	}
	for ii := range data.Cloudlets {
		ctrlHandler.CloudletCache.Delete(ctx, &data.Cloudlets[ii], 0)
	}
	for ii := range data.Apps {
		ctrlHandler.AppCache.Delete(ctx, &data.Apps[ii], 0)
	}
	for ii := range data.Flavors {
		ctrlHandler.FlavorCache.Delete(ctx, &data.Flavors[ii], 0)
	}

	require.Nil(t, notify.WaitFor(&controllerData.FlavorCache, 0))
	require.Nil(t, notify.WaitFor(&controllerData.AppCache, 0))
	require.Nil(t, notify.WaitFor(&controllerData.ClusterInstCache, 0))
	require.Nil(t, notify.WaitFor(&controllerData.AppInstCache, 0))
	require.Nil(t, notify.WaitFor(controllerData.CloudletCache, 0))
}
