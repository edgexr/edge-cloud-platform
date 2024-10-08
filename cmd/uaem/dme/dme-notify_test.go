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
	"testing"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/notify"
	uaemcommon "github.com/edgexr/edge-cloud-platform/pkg/uaem-common"
	uaemtest "github.com/edgexr/edge-cloud-platform/pkg/uaem-testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

var (
	appInstUsable    bool = true
	appInstNotUsable bool = false
)

func TestNotify(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelNotify | log.DebugLevelDmereq | log.DebugLevelDmedb | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	eehandler, err := initEdgeEventsPlugin(ctx, "standalone")
	require.Nil(t, err, "init edge events plugin")
	uaemcommon.SetupMatchEngine(eehandler)
	initRateLimitMgr()
	uaemcommon.InitAppInstClients(time.Minute)
	defer uaemcommon.StopAppInstClients()
	apps := uaemtest.GenerateApps()
	appInsts := uaemtest.GenerateAppInsts()

	// test dummy server sending notices to dme
	addr := "127.0.0.1:60002"

	// dummy server side
	serverHandler := notify.NewDummyHandler()
	serverMgr := notify.ServerMgr{}
	serverHandler.RegisterServer(&serverMgr)
	serverMgr.Start("ctrl", addr, nil)

	// client (dme) side
	client := initNotifyClient(ctx, addr, grpc.WithInsecure())
	client.Start()

	// create data on server side
	for _, cloudlet := range uaemtest.GenerateCloudlets() {
		uaemcommon.SetInstStateFromCloudlet(ctx, &edgeproto.Cloudlet{Key: cloudlet.Key})
		uaemcommon.SetInstStateFromCloudletInfo(ctx, cloudlet)
	}
	for _, app := range apps {
		serverHandler.AppCache.Update(ctx, app, 0)
	}
	for _, appInst := range appInsts {
		serverHandler.AppInstCache.Update(ctx, appInst, 0)
	}
	// wait for the last appInst data to show up locally
	last := len(appInsts) - 1
	waitForAppInst(appInsts[last])
	// check that all data is present
	checkAllData(t, appInsts)

	// remove one appinst
	remaining := appInsts[:last]
	serverHandler.AppInstCache.Delete(ctx, appInsts[last], 0)
	// wait for it to be gone locally
	waitForNoAppInst(appInsts[last])
	// check new data
	checkAllData(t, remaining)
	// add it back
	serverHandler.AppInstCache.Update(ctx, appInsts[last], 0)
	// wait for it to be present again
	waitForAppInst(appInsts[last])
	checkAllData(t, appInsts)

	// update cloudletInfo for a single cloudlet and make sure it gets propagated to appInsts
	cloudletInfo := edgeproto.CloudletInfo{
		Key: edgeproto.CloudletKey{
			Organization: uaemtest.Cloudlets[2].CarrierName,
			Name:         uaemtest.Cloudlets[2].Name,
		},
		State: dme.CloudletState_CLOUDLET_STATE_OFFLINE,
	}
	cloudlet := edgeproto.Cloudlet{
		Key: cloudletInfo.Key,
	}
	serverHandler.CloudletCache.Update(ctx, &cloudlet, 0)
	serverHandler.CloudletInfoCache.Update(ctx, &cloudletInfo, 0)
	// check that the appInsts on that cloudlet are not available
	waitAndCheckCloudletforApps(t, &cloudletInfo.Key, appInstNotUsable)

	// update cloudletInfo for a single cloudlet and make sure it gets propagated to appInsts
	cloudletInfo.State = dme.CloudletState_CLOUDLET_STATE_READY
	serverHandler.CloudletInfoCache.Update(ctx, &cloudletInfo, 0)
	// check that the appInsts on that cloudlet are available
	waitAndCheckCloudletforApps(t, &cloudletInfo.Key, appInstUsable)

	// mark cloudlet under maintenance state just for cloudlet object
	cloudlet.MaintenanceState = dme.MaintenanceState_UNDER_MAINTENANCE
	serverHandler.CloudletCache.Update(ctx, &cloudlet, 0)
	waitAndCheckCloudletforApps(t, &cloudletInfo.Key, appInstNotUsable)

	// mark cloudlet operational just for cloudlet object
	cloudlet.MaintenanceState = dme.MaintenanceState_NORMAL_OPERATION
	serverHandler.CloudletCache.Update(ctx, &cloudlet, 0)
	waitAndCheckCloudletforApps(t, &cloudletInfo.Key, appInstUsable)

	// set cloudletInfo maintenance state in maintenance mode,
	// should not affect appInst
	cloudletInfo.MaintenanceState = dme.MaintenanceState_CRM_UNDER_MAINTENANCE
	serverHandler.CloudletInfoCache.Update(ctx, &cloudletInfo, 0)
	waitAndCheckCloudletforApps(t, &cloudletInfo.Key, appInstUsable)

	// delete cloudlet object appInst should not be usable, even though
	serverHandler.CloudletCache.Delete(ctx, &cloudlet, 0)
	waitAndCheckCloudletforApps(t, &cloudletInfo.Key, appInstNotUsable)

	// stop client, delete appInst on server, then start client.
	// This checks that client deletes locally data
	// that was deleted while the connection was down.
	client.Stop()
	serverHandler.AppInstCache.Delete(ctx, appInsts[last], 0)
	client.Start()
	waitForNoAppInst(appInsts[last])
	checkAllData(t, remaining)

	// add a new device - see that it makes it to the server
	for _, reg := range uaemtest.DeviceData {
		uaemcommon.RecordDevice(ctx, &reg)
	}
	// verify the devices were added to the server
	count := len(uaemtest.DeviceData) - 1 // Since one is a duplicate
	// verify that devices are in local cache
	assert.Equal(t, count, len(uaemcommon.PlatformClientsCache.Objs))
	require.Nil(t, serverHandler.WaitForDevices(count))
	// Delete all elements from local cache directly
	for _, data := range uaemcommon.PlatformClientsCache.Objs {
		obj := data.Obj
		delete(uaemcommon.PlatformClientsCache.Objs, obj.GetKeyVal())
		delete(uaemcommon.PlatformClientsCache.List, obj.GetKeyVal())
	}
	assert.Equal(t, 0, len(uaemcommon.PlatformClientsCache.Objs))
	assert.Equal(t, count, len(serverHandler.DeviceCache.Objs))
	// Add a single device - make sure count in local cache is updated
	uaemcommon.RecordDevice(ctx, &uaemtest.DeviceData[0])
	assert.Equal(t, 1, len(uaemcommon.PlatformClientsCache.Objs))
	// Make sure that count in the server cache is the same
	assert.Equal(t, count, len(serverHandler.DeviceCache.Objs))
	// Add the same device, check that nothing is updated
	uaemcommon.RecordDevice(ctx, &uaemtest.DeviceData[0])
	assert.Equal(t, 1, len(uaemcommon.PlatformClientsCache.Objs))
	assert.Equal(t, count, len(serverHandler.DeviceCache.Objs))

	serverMgr.Stop()
	client.Stop()
}

func waitAndCheckCloudletforApps(t *testing.T, key *edgeproto.CloudletKey, isAppInstUsable bool) {
	var still_enabled bool

	tbl := uaemcommon.DmeAppTbl
	carrier := key.Organization
	for i := 0; i < 10; i++ {
		still_enabled = false
		for _, app := range tbl.Apps {
			if c, found := app.Carriers[carrier]; found {
				for _, appInst := range c.Insts {
					if appInst.GetCloudletKey().GetKeyString() == key.GetKeyString() {
						fmt.Printf("Appinst is %+v\n", appInst)
					}
					if appInst.GetCloudletKey().GetKeyString() == key.GetKeyString() &&
						uaemcommon.IsAppInstUsable(appInst) {
						still_enabled = true
					}
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if isAppInstUsable {
		require.True(t, still_enabled, "Notify message should have propagated")
	} else {
		require.False(t, still_enabled, "Notify message did not propagate")
	}
}

func waitForAppInst(appInst *edgeproto.AppInst) {
	tbl := uaemcommon.DmeAppTbl

	appkey := appInst.AppKey
	for i := 0; i < 20; i++ {
		if app, found := tbl.Apps[appkey]; found {
			for _, c := range app.Carriers {
				if _, found := c.Insts[appInst.Key]; found {
					break
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func waitForNoAppInst(appInst *edgeproto.AppInst) {
	tbl := uaemcommon.DmeAppTbl

	appkey := appInst.AppKey
	for i := 0; i < 10; i++ {
		app, found := tbl.Apps[appkey]
		if !found {
			break
		}
		for _, c := range app.Carriers {
			if _, found := c.Insts[appInst.Key]; !found {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
}
