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

package notify

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestNotifyBasic(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelNotify)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	// override retry time
	NotifyRetryTime = 10 * time.Millisecond

	// This tests the server sending notices to
	// a client.
	addr := "127.0.0.1:61234"
	serverAddrs := []string{addr}

	// Set up server
	serverHandler := NewDummyHandler()
	serverMgr := ServerMgr{}
	serverHandler.RegisterServer(&serverMgr)
	serverMgr.Start("ctrl", addr, nil)

	// Set up client DME
	dmeHandler := NewDummyHandler()
	clientDME := NewClient("dme", serverAddrs, grpc.WithInsecure())
	dmeHandler.RegisterDMEClient(clientDME)
	clientDME.Start()

	// Set up client CRM
	crmHandler := NewDummyHandler()
	clientCRM := NewClient("crm", serverAddrs, grpc.WithInsecure())
	crmHandler.RegisterCRMClient(clientCRM)
	clientCRM.Start()

	// It takes a little while for the Run thread to start up
	// Wait until it's connected
	require.Nil(t, clientDME.WaitForConnect(1))
	require.Nil(t, clientCRM.WaitForConnect(1))
	require.Equal(t, 0, len(dmeHandler.AppCache.Objs), "num Apps")
	require.Equal(t, 0, len(dmeHandler.AppInstCache.Objs), "num appInsts")
	require.Equal(t, uint64(0), clientDME.sendrecv.stats.Recv, "num updates")
	require.Equal(t, NotifyVersion, clientDME.version, "version")
	require.Nil(t, serverMgr.WaitServerCount(2))

	// Create some app insts which will trigger updates
	serverHandler.AppCache.Update(ctx, &testutil.AppData()[0], 1)
	serverHandler.AppCache.Update(ctx, &testutil.AppData()[1], 2)
	serverHandler.AppCache.Update(ctx, &testutil.AppData()[2], 3)
	serverHandler.AppCache.Update(ctx, &testutil.AppData()[3], 4)
	serverHandler.AppCache.Update(ctx, &testutil.AppData()[4], 5)
	dmeHandler.WaitForAppInsts(5)
	require.Equal(t, 5, len(dmeHandler.AppCache.Objs), "num Apps")
	stats := serverMgr.GetStats(clientDME.GetLocalAddr())
	require.Equal(t, uint64(5), stats.ObjSend["App"])

	// Create some app insts which will trigger updates
	serverHandler.AppInstCache.Update(ctx, &testutil.CreatedAppInstData()[0], 0)
	serverHandler.AppInstCache.Update(ctx, &testutil.CreatedAppInstData()[1], 0)
	serverHandler.AppInstCache.Update(ctx, &testutil.CreatedAppInstData()[2], 0)
	dmeHandler.WaitForAppInsts(3)
	require.Equal(t, 3, len(dmeHandler.AppInstCache.Objs), "num appInsts")
	clientDME.GetStats(stats)
	require.Equal(t, uint64(3), stats.ObjRecv["AppInst"], "app inst updates")
	require.Equal(t, uint64(8), stats.Recv, "num updates")
	stats = serverMgr.GetStats(clientDME.GetLocalAddr())
	require.Equal(t, uint64(3), stats.ObjSend["AppInst"])

	// Kill connection out from under the code, forcing reconnect
	fmt.Println("DME cancel")
	clientDME.cancel()
	// wait for it to reconnect
	require.Nil(t, clientDME.WaitForConnect(2))
	require.Nil(t, serverMgr.WaitServerCount(2))

	// All cloudlets and all app insts will be sent again
	// Note on server side, this is a new connection so stats are reset
	serverHandler.AppInstCache.Update(ctx, &testutil.CreatedAppInstData()[3], 0)
	dmeHandler.WaitForAppInsts(4)
	require.Equal(t, 4, len(dmeHandler.AppInstCache.Objs), "num appInsts")
	require.Equal(t, uint64(17), clientDME.sendrecv.stats.Recv, "num updates")
	stats = serverMgr.GetStats(clientDME.GetLocalAddr())
	require.Equal(t, uint64(4), stats.ObjSend["AppInst"])
	require.Equal(t, uint64(5), stats.ObjSend["App"])

	// Delete an inst
	serverHandler.AppInstCache.Delete(ctx, &testutil.CreatedAppInstData()[0], 0)
	dmeHandler.WaitForAppInsts(3)
	require.Equal(t, 3, len(dmeHandler.AppInstCache.Objs), "num appInsts")
	require.Equal(t, uint64(18), clientDME.sendrecv.stats.Recv, "num updates")
	clientDME.GetStats(stats)
	require.Equal(t, uint64(8), stats.ObjRecv["AppInst"], "app inst updates")
	stats = serverMgr.GetStats(clientDME.GetLocalAddr())
	require.Equal(t, uint64(5), stats.ObjSend["AppInst"])
	require.Equal(t, uint64(5), stats.ObjSend["App"])

	// Stop DME, check that server closes connection as well
	fmt.Println("DME stop")
	clientDME.Stop()
	require.Nil(t, serverMgr.WaitServerCount(1))
	// reset data in handler, check that is it restored on reconnect
	edgeproto.InitAppInstCache(&dmeHandler.AppInstCache)
	clientDME.Start()
	require.Nil(t, clientDME.WaitForConnect(3))
	dmeHandler.WaitForAppInsts(3)
	require.Equal(t, 3, len(dmeHandler.AppInstCache.Objs), "num appInsts")

	// This time stop server, delete an inst, then start the
	// receiver again. The dmeHandler remains the same so none of
	// the data/stats changes. This tests that a delete during
	// disconnect is properly accounted for during the handling
	// of the sendall done command by removing the stale entry.
	fmt.Println("ServerMgr done")
	serverMgr.Stop()
	serverHandler.AppInstCache.Delete(ctx, &testutil.CreatedAppInstData()[1], 0)
	serverMgr.Start("ctrl", addr, nil)
	require.Nil(t, clientDME.WaitForConnect(4))
	dmeHandler.WaitForAppInsts(2)
	require.Equal(t, 2, len(dmeHandler.AppInstCache.Objs), "num appInsts")
	clientDME.GetStats(stats)
	require.Equal(t, uint64(13), stats.ObjRecv["AppInst"], "app inst updates")
	stats = serverMgr.GetStats(clientDME.GetLocalAddr())
	require.Equal(t, uint64(2), stats.ObjSend["AppInst"])

	// Now test CRM
	require.Nil(t, clientCRM.WaitForConnect(2))
	require.Equal(t, 0, len(crmHandler.CloudletCache.Objs), "num cloudlets")
	require.Equal(t, 0, len(crmHandler.FlavorCache.Objs), "num flavors")
	require.Equal(t, 0, len(crmHandler.ClusterInstCache.Objs), "num clusterInsts")
	// We should be getting all the App updates
	require.Equal(t, 5, len(crmHandler.AppCache.Objs), "num apps")
	require.Equal(t, 0, len(crmHandler.AppInstCache.Objs), "num appInsts")
	// crm must send cloudletinfo to receive clusterInsts and appInsts
	serverHandler.VMPoolCache.Update(ctx, &testutil.VMPoolData()[0], 0)
	serverHandler.VMPoolCache.Update(ctx, &testutil.VMPoolData()[1], 0)
	serverHandler.GPUDriverCache.Update(ctx, &testutil.GPUDriverData()[0], 0)
	serverHandler.GPUDriverCache.Update(ctx, &testutil.GPUDriverData()[1], 0)
	serverHandler.GPUDriverCache.Update(ctx, &testutil.GPUDriverData()[2], 0)
	// add vmpool for cloudlet
	cloudletData := testutil.CloudletData()
	vmpoolCloudlet := cloudletData[0]
	vmpoolCloudlet.VmPool = testutil.VMPoolData()[0].Key.Name
	vmpoolCloudlet.GpuConfig = edgeproto.GPUConfig{
		Driver: testutil.GPUDriverData()[0].Key,
	}
	// gpu config cloudlet with no restag table
	gpuConfigNoResTagCloudlet := cloudletData[2]
	gpuConfigNoResTagCloudlet.GpuConfig = edgeproto.GPUConfig{
		Driver: testutil.GPUDriverData()[2].Key,
	}
	serverHandler.CloudletCache.Update(ctx, &vmpoolCloudlet, 6)
	serverHandler.CloudletCache.Update(ctx, &gpuConfigNoResTagCloudlet, 7)
	serverHandler.FlavorCache.Update(ctx, &testutil.FlavorData()[0], 8)
	serverHandler.FlavorCache.Update(ctx, &testutil.FlavorData()[1], 9)
	serverHandler.FlavorCache.Update(ctx, &testutil.FlavorData()[2], 10)
	serverHandler.ClusterInstCache.Update(ctx, &testutil.CreatedClusterInstData()[0], 11)
	serverHandler.ClusterInstCache.Update(ctx, &testutil.CreatedClusterInstData()[1], 12)
	serverHandler.ClusterInstCache.Update(ctx, &testutil.CreatedClusterInstData()[2], 13)
	serverHandler.ClusterInstCache.Update(ctx, &testutil.CreatedClusterInstData()[3], 14)
	serverHandler.AppInstCache.Update(ctx, &testutil.CreatedAppInstData()[0], 15)
	serverHandler.AppInstCache.Update(ctx, &testutil.CreatedAppInstData()[1], 16)
	serverHandler.AppInstCache.Update(ctx, &testutil.CreatedAppInstData()[2], 17)
	serverHandler.AppInstCache.Update(ctx, &testutil.CreatedAppInstData()[3], 18)
	serverHandler.NetworkCache.Update(ctx, &testutil.NetworkData()[0], 19)
	// trigger updates with CloudletInfo update after updating other
	// data, otherwise the updates here plus the updates triggered by
	// updating CloudletInfo can cause updates to get sent twice,
	// messing up the stats counter checks. There's no functional
	// issue, just makes it difficult to predict the stats values.
	crmHandler.CloudletInfoCache.Update(ctx, &testutil.CloudletInfoData()[0], 0)
	// Note: only ClusterInsts and AppInsts with cloudlet keys that
	// match the CRM's cloudletinfo will be sent.
	require.Nil(t, crmHandler.WaitForCloudlets(1), "num cloudlets")
	require.Nil(t, crmHandler.WaitForFlavors(3), "num flavors")
	require.Nil(t, crmHandler.WaitForClusterInsts(2), "num clusterInsts")
	require.Nil(t, crmHandler.WaitForApps(5), "num apps")
	require.Nil(t, crmHandler.WaitForAppInsts(2), "num appInsts")
	require.Nil(t, crmHandler.WaitForVMPools(1), "num vmPools")
	require.Nil(t, crmHandler.WaitForGPUDrivers(1), "num gpuDrivers")
	require.Nil(t, crmHandler.WaitForNetworks(1), "num networks")

	// trigger updates with another CloudletInfo update, this also tests that
	// GPU driver update is received by cloudlet with no restag table configured
	crmHandler.CloudletInfoCache.Update(ctx, &testutil.CloudletInfoData()[2], 0)
	require.Nil(t, crmHandler.WaitForCloudlets(2), "num cloudlets")
	require.Nil(t, crmHandler.WaitForFlavors(3), "num flavors")
	require.Nil(t, crmHandler.WaitForClusterInsts(3), "num clusterInsts")
	require.Nil(t, crmHandler.WaitForApps(5), "num apps")
	require.Nil(t, crmHandler.WaitForAppInsts(2), "num appInsts")
	require.Nil(t, crmHandler.WaitForVMPools(1), "num vmPools")
	require.Nil(t, crmHandler.WaitForGPUDrivers(2), "num gpuDrivers")
	require.Nil(t, crmHandler.WaitForNetworks(1), "num networks")

	// verify modRef values
	appBuf := edgeproto.App{}
	flavorBuf := edgeproto.Flavor{}
	clusterInstBuf := edgeproto.ClusterInst{}
	appInstBuf := edgeproto.AppInst{}
	var modRev int64
	require.True(t, crmHandler.AppCache.GetWithRev(&testutil.AppData()[0].Key, &appBuf, &modRev))
	require.Equal(t, int64(1), modRev)
	require.True(t, crmHandler.FlavorCache.GetWithRev(&testutil.FlavorData()[0].Key, &flavorBuf, &modRev))
	require.Equal(t, int64(8), modRev)
	require.True(t, crmHandler.FlavorCache.GetWithRev(&testutil.FlavorData()[1].Key, &flavorBuf, &modRev))
	require.Equal(t, int64(9), modRev)
	require.True(t, crmHandler.FlavorCache.GetWithRev(&testutil.FlavorData()[2].Key, &flavorBuf, &modRev))
	require.Equal(t, int64(10), modRev)
	require.True(t, crmHandler.ClusterInstCache.GetWithRev(&testutil.CreatedClusterInstData()[0].Key, &clusterInstBuf, &modRev))
	require.Equal(t, int64(11), modRev)
	require.True(t, crmHandler.ClusterInstCache.GetWithRev(&testutil.CreatedClusterInstData()[3].Key, &clusterInstBuf, &modRev))
	require.Equal(t, int64(14), modRev)
	require.True(t, crmHandler.AppInstCache.GetWithRev(&testutil.CreatedAppInstData()[0].Key, &appInstBuf, &modRev))
	require.Equal(t, int64(15), modRev)
	require.True(t, crmHandler.AppInstCache.GetWithRev(&testutil.CreatedAppInstData()[1].Key, &appInstBuf, &modRev))
	require.Equal(t, int64(16), modRev)

	serverHandler.FlavorCache.Delete(ctx, &testutil.FlavorData()[1], 0)
	serverHandler.ClusterInstCache.Delete(ctx, &testutil.CreatedClusterInstData()[0], 0)
	serverHandler.AppInstCache.Delete(ctx, &testutil.CreatedAppInstData()[0], 0)
	crmHandler.WaitForFlavors(2)
	crmHandler.WaitForClusterInsts(2)
	crmHandler.WaitForAppInsts(1)
	require.Equal(t, 2, len(crmHandler.FlavorCache.Objs), "num flavors")
	require.Equal(t, 2, len(crmHandler.ClusterInstCache.Objs), "num clusterInsts")
	require.Equal(t, 1, len(crmHandler.AppInstCache.Objs), "num appInsts")
	clientCRM.GetStats(stats)
	require.Equal(t, uint64(2), stats.ObjRecv["Cloudlet"], "cloudlet updates")
	require.Equal(t, uint64(4), stats.ObjRecv["Flavor"], "flavor updates")
	require.Equal(t, uint64(4), stats.ObjRecv["ClusterInst"], "clusterInst updates")
	require.Equal(t, uint64(3), stats.ObjRecv["AppInst"], "appInst updates")
	stats = serverMgr.GetStats(clientCRM.GetLocalAddr())
	require.Equal(t, uint64(2), stats.ObjSend["Cloudlet"], "sent cloudlets")
	require.Equal(t, uint64(4), stats.ObjSend["Flavor"], "sent flavors")
	require.Equal(t, uint64(4), stats.ObjSend["ClusterInst"], "sent clusterInsts")
	require.Equal(t, uint64(3), stats.ObjSend["AppInst"], "sent appInsts")
	require.Nil(t, serverMgr.WaitServerCount(2))

	// Send data from CRM to server
	fmt.Println("Create AppInstInfo")
	for _, ai := range testutil.CreatedAppInstData() {
		info := edgeproto.AppInstInfo{}
		info.Key = ai.Key
		crmHandler.AppInstInfoCache.Update(ctx, &info, 0)
	}
	serverHandler.WaitForAppInstInfo(len(testutil.CreatedAppInstData()))
	require.Equal(t, len(testutil.CreatedAppInstData()),
		len(serverHandler.AppInstInfoCache.Objs),
		"sent appInstInfo")

	for _, ci := range testutil.CreatedClusterInstData() {
		info := edgeproto.ClusterInstInfo{}
		info.Key = ci.Key
		crmHandler.ClusterInstInfoCache.Update(ctx, &info, 0)
	}
	serverHandler.WaitForClusterInstInfo(len(testutil.CreatedClusterInstData()))
	require.Equal(t, len(testutil.CreatedClusterInstData()),
		len(serverHandler.ClusterInstInfoCache.Objs),
		"sent clusterInstInfo")

	for _, cl := range cloudletData {
		info := edgeproto.CloudletInfo{}
		info.Key = cl.Key
		crmHandler.CloudletInfoCache.Update(ctx, &info, 0)
	}
	serverHandler.WaitForCloudletInfo(len(cloudletData))
	require.Equal(t, len(cloudletData),
		len(serverHandler.CloudletInfoCache.Objs),
		"sent cloudletInfo")

	clientDME.Stop()
	clientCRM.Stop()
}
