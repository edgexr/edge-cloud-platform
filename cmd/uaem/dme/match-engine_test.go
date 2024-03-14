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
	"fmt"
	"testing"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	uaemcommon "github.com/edgexr/edge-cloud-platform/pkg/uaem-common"
	uaemtest "github.com/edgexr/edge-cloud-platform/pkg/uaem-testutil"
	"github.com/opentracing/opentracing-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
)

func TestAddRemove(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelDmereq | log.DebugLevelDmedb)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())
	span := log.SpanFromContext(ctx)

	eehandler, err := initEdgeEventsPlugin(ctx, "standalone")
	require.Nil(t, err, "init edge events plugin")
	uaemcommon.SetupMatchEngine(eehandler)
	uaemcommon.InitAppInstClients(time.Minute)
	defer uaemcommon.StopAppInstClients()

	setupJwks()
	apps := uaemtest.GenerateApps()
	appInsts := uaemtest.GenerateAppInsts()
	cloudlets := uaemtest.GenerateCloudlets()

	tbl := uaemcommon.DmeAppTbl

	// Add cloudlets first as we check the state via cloudlets
	for _, cloudlet := range cloudlets {
		uaemcommon.SetInstStateFromCloudletInfo(ctx, cloudlet)
	}
	require.Equal(t, len(tbl.Cloudlets), 0, "without cloudlet object, cloudletInfo is not considered")
	for _, cloudlet := range cloudlets {
		uaemcommon.SetInstStateFromCloudlet(ctx, &edgeproto.Cloudlet{Key: cloudlet.Key})
		uaemcommon.SetInstStateFromCloudletInfo(ctx, cloudlet)
	}
	require.Equal(t, len(tbl.Cloudlets), len(cloudlets), "cloudlet object exists")

	// add alliance orgs
	cloudletShared := edgeproto.Cloudlet{
		Key:          cloudlets[1].Key,
		AllianceOrgs: []string{"DMUUS"},
	}
	uaemcommon.SetInstStateFromCloudlet(ctx, &cloudletShared)

	// add all data, check that number of instances matches
	for _, inst := range apps {
		uaemcommon.AddApp(ctx, inst)
	}
	for _, inst := range appInsts {
		uaemcommon.AddAppInst(ctx, inst)
	}
	checkAllData(t, appInsts)
	// only one cloudlet with one alliance org, and since all apps are
	// deployed to each cloudlet, that means one set of appinsts are
	// added to the alliance count for cloudlets[1].
	checkAllianceInsts(t, len(apps))

	// re-add data, counts should remain unchanged
	for _, inst := range appInsts {
		uaemcommon.AddAppInst(ctx, inst)
	}
	checkAllData(t, appInsts)
	checkAllianceInsts(t, len(apps))

	// delete one data, check new counts
	uaemcommon.RemoveAppInst(ctx, appInsts[0])
	remaining := appInsts[1:]
	checkAllData(t, remaining)
	checkAllianceInsts(t, len(apps))
	serv := server{}

	// test findCloudlet
	runFindCloudlet(t, uaemtest.FindCloudletData, span, &serv)
	runFindCloudlet(t, uaemtest.FindCloudletAllianceOrg, span, &serv)
	runGetAppInstList(t, uaemtest.GetAppInstListAllianceOrg, span, &serv)

	// update cloudlet alliance orgs to remove them
	cloudletNotShared := cloudletShared
	cloudletNotShared.AllianceOrgs = []string{}
	uaemcommon.SetInstStateFromCloudlet(ctx, &cloudletNotShared)
	// run checks
	checkAllianceInsts(t, 0)
	runFindCloudlet(t, uaemtest.FindCloudletData, span, &serv)
	runFindCloudlet(t, uaemtest.FindCloudletNoAllianceOrg, span, &serv)
	runGetAppInstList(t, uaemtest.GetAppInstListNoAllianceOrg, span, &serv)

	// add back alliance orgs
	uaemcommon.SetInstStateFromCloudlet(ctx, &cloudletShared)
	// run checks
	checkAllianceInsts(t, len(apps))
	runFindCloudlet(t, uaemtest.FindCloudletData, span, &serv)
	runFindCloudlet(t, uaemtest.FindCloudletAllianceOrg, span, &serv)
	runGetAppInstList(t, uaemtest.GetAppInstListAllianceOrg, span, &serv)

	// test findCloudlet HA. Repeat the FindCloudlet 100 times and
	// make sure we get results for both cloudlets
	for ii, rr := range uaemtest.FindCloudletHAData {
		ctx := uaemcommon.PeerContext(context.Background(), "127.0.0.1", 123, span)
		numFindsCloudlet1 := 0
		numFindsCloudlet2 := 0
		maxAttempts := 100
		minExpectedEachCloudlet := 35
		regReply, err := serv.RegisterClient(ctx, &rr.Reg)
		assert.Nil(t, err, "register client")
		ckey, err := uaemcommon.VerifyCookie(ctx, regReply.SessionCookie)
		assert.Nil(t, err, "verify cookie")
		ctx = uaemcommon.NewCookieContext(ctx, ckey)
		// Make sure we get the statsKey value filled in
		call := uaemcommon.ApiStatCall{}
		ctx = context.WithValue(ctx, uaemcommon.StatKeyContextKey, &call.Key)

		for attempt := 0; attempt < maxAttempts; attempt++ {

			reply, err := serv.FindCloudlet(ctx, &rr.Req)
			assert.Nil(t, err, "find cloudlet")
			assert.Equal(t, rr.Reply.Status, reply.Status, "findCloudletHAData[%d]", ii)
			if reply.Status == dme.FindCloudletReply_FIND_FOUND {
				if reply.Fqdn == rr.Reply.Fqdn {
					numFindsCloudlet1++
				} else if reply.Fqdn == rr.ReplyAlternate.Fqdn {
					numFindsCloudlet2++
				}
				// carrier is the same either way
				assert.Equal(t, rr.ReplyCarrier,
					call.Key.CloudletFound.Organization, "findCloudletHAData[%d]", ii)
			}
		}
		// we expect at least 35% of all replies to be for each cloudlet, with confidence of 99.8%
		assert.GreaterOrEqual(t, numFindsCloudlet1, minExpectedEachCloudlet)
		assert.GreaterOrEqual(t, numFindsCloudlet2, minExpectedEachCloudlet)
		// total for both should match attempts
		assert.Equal(t, maxAttempts, numFindsCloudlet1+numFindsCloudlet2)
	}

	// Check Platform Devices register UUID
	reg := uaemtest.DeviceData[0]
	// Both or none should be set
	reg.UniqueId = "123"
	reg.UniqueIdType = ""
	ctx = uaemcommon.PeerContext(context.Background(), "127.0.0.1", 123, span)
	regReply, err := serv.RegisterClient(ctx, &reg)
	assert.NotNil(t, err, "register client")
	assert.Contains(t, err.Error(), "Both, or none of UniqueId and UniqueIdType should be set")
	reg.UniqueId = ""
	reg.UniqueIdType = "typeOnly"
	regReply, err = serv.RegisterClient(ctx, &reg)
	assert.NotNil(t, err, "register client")
	assert.Contains(t, err.Error(), "Both, or none of UniqueId and UniqueIdType should be set")
	// Reset UUID to empty strings
	reg.UniqueId = ""
	reg.UniqueIdType = ""
	regReply, err = serv.RegisterClient(ctx, &reg)
	assert.Nil(t, err, "register client")
	ckey, err := uaemcommon.VerifyCookie(ctx, regReply.SessionCookie)
	assert.Nil(t, err, "verify cookie")
	// verify that UUID type is the platform one
	assert.Equal(t, reg.OrgName+":"+reg.AppName, regReply.UniqueIdType)
	// should match what's in the cookie
	assert.Equal(t, regReply.UniqueId, ckey.UniqueId)
	assert.Equal(t, regReply.UniqueIdType, ckey.UniqueIdType)

	// disable one cloudlet and check the newly found cloudlet
	cloudletInfo := cloudlets[2]
	cloudletInfo.State = dme.CloudletState_CLOUDLET_STATE_UNKNOWN
	uaemcommon.SetInstStateFromCloudletInfo(ctx, cloudletInfo)
	ctx = uaemcommon.PeerContext(context.Background(), "127.0.0.1", 123, span)

	regReply, err = serv.RegisterClient(ctx, &uaemtest.DisabledCloudletRR.Reg)
	assert.Nil(t, err, "register client")
	ckey, err = uaemcommon.VerifyCookie(ctx, regReply.SessionCookie)
	assert.Nil(t, err, "verify cookie")
	ctx = uaemcommon.NewCookieContext(ctx, ckey)

	reply, err := serv.FindCloudlet(ctx, &uaemtest.DisabledCloudletRR.Req)
	assert.Nil(t, err, "find cloudlet")
	assert.Equal(t, uaemtest.DisabledCloudletRR.Reply.Status, reply.Status)
	assert.Equal(t, uaemtest.DisabledCloudletRR.Reply.Fqdn, reply.Fqdn)
	// re-enable and check that the results is now what original findCloudlet[3] is
	cloudletInfo.State = dme.CloudletState_CLOUDLET_STATE_READY
	uaemcommon.SetInstStateFromCloudletInfo(ctx, cloudletInfo)
	reply, err = serv.FindCloudlet(ctx, &uaemtest.DisabledCloudletRR.Req)
	assert.Nil(t, err, "find cloudlet")
	assert.Equal(t, uaemtest.FindCloudletData[3].Reply.Status, reply.Status)
	assert.Equal(t, uaemtest.FindCloudletData[3].Reply.Fqdn, reply.Fqdn)

	// Change the health check status of the appInst and get check the results
	appInst := uaemtest.MakeAppInst(&uaemtest.Apps[0], &uaemtest.Cloudlets[2])
	appInst.HealthCheck = dme.HealthCheck_HEALTH_CHECK_ROOTLB_OFFLINE
	uaemcommon.AddAppInst(ctx, appInst)
	reply, err = serv.FindCloudlet(ctx, &uaemtest.DisabledCloudletRR.Req)
	assert.Nil(t, err, "find cloudlet")
	assert.Equal(t, uaemtest.DisabledCloudletRR.Reply.Status, reply.Status)
	assert.Equal(t, uaemtest.DisabledCloudletRR.Reply.Fqdn, reply.Fqdn)
	// reset and check the one that we get is returned
	appInst.HealthCheck = dme.HealthCheck_HEALTH_CHECK_OK
	uaemcommon.AddAppInst(ctx, appInst)
	reply, err = serv.FindCloudlet(ctx, &uaemtest.DisabledCloudletRR.Req)
	assert.Nil(t, err, "find cloudlet")
	assert.Equal(t, appInst.Uri, reply.Fqdn)

	// Check GetAppInstList API - check sorted by distance
	runGetAppInstList(t, uaemtest.GetAppInstListData, span, &serv)

	// delete all data
	for _, app := range apps {
		uaemcommon.RemoveApp(ctx, app)
	}
	assert.Equal(t, 0, len(tbl.Apps))
}

type dummyDmeApp struct {
	insts map[edgeproto.CloudletKey]struct{}
}

func checkAllData(t *testing.T, appInsts []*edgeproto.AppInst) {
	tbl := uaemcommon.DmeAppTbl

	appsCheck := make(map[edgeproto.AppKey]*dummyDmeApp)
	for _, inst := range appInsts {
		app, found := appsCheck[inst.AppKey]
		if !found {
			app = &dummyDmeApp{}
			app.insts = make(map[edgeproto.CloudletKey]struct{})
			appsCheck[inst.AppKey] = app
		}
		app.insts[inst.Key.CloudletKey] = struct{}{}
	}
	assert.Equal(t, len(appsCheck), len(tbl.Apps), "Number of apps")
	totalInstances := 0
	for k, app := range tbl.Apps {
		_, found := appsCheck[k]
		assert.True(t, found, "found app %s", k)
		if !found {
			continue
		}
		for cname := range app.Carriers {
			totalInstances += len(app.Carriers[cname].Insts)
		}
	}
	require.Equal(t, len(appInsts), totalInstances, "Number of appInstances")
}

func checkAllianceInsts(t *testing.T, expectedCount int) {
	tbl := uaemcommon.DmeAppTbl
	total := 0
	for _, app := range tbl.Apps {
		for cname := range app.Carriers {
			total += len(app.Carriers[cname].AllianceInsts)
		}
	}
	require.Equal(t, expectedCount, total, "Number of alliance appInstances")
}

func runFindCloudlet(t *testing.T, rrs []uaemtest.FindCloudletRR, span opentracing.Span, serv *server) {
	for ii, rr := range rrs {
		ctx := uaemcommon.PeerContext(context.Background(), "127.0.0.1", 123, span)

		regReply, err := serv.RegisterClient(ctx, &rr.Reg)
		assert.Nil(t, err, "register client")

		// Since we're directly calling functions, we end up
		// bypassing the interceptor which sets up the cookie key.
		// So set it on the context manually.
		ckey, err := uaemcommon.VerifyCookie(ctx, regReply.SessionCookie)
		assert.Nil(t, err, "verify cookie")
		// verify that UUID in the response is a new value if it was empty in the request
		if rr.Reg.UniqueId == "" {
			assert.NotEqual(t, regReply.UniqueId, "")
			assert.NotEqual(t, regReply.UniqueIdType, "")
			// should match what's in the cookie
			assert.Equal(t, regReply.UniqueId, ckey.UniqueId)
			assert.Equal(t, regReply.UniqueIdType, ckey.UniqueIdType)
		} else {
			// If it was not empty cookie should have the uuid from the register
			assert.Equal(t, rr.Reg.UniqueId, ckey.UniqueId)
			assert.Equal(t, rr.Reg.UniqueIdType, ckey.UniqueIdType)
		}
		ctx = uaemcommon.NewCookieContext(ctx, ckey)
		// Make sure we get the statsKey value filled in
		call := uaemcommon.ApiStatCall{}
		ctx = context.WithValue(ctx, uaemcommon.StatKeyContextKey, &call.Key)

		reply, err := serv.FindCloudlet(ctx, &rr.Req)
		assert.Nil(t, err, "find cloudlet")
		assert.Equal(t, rr.Reply.Status, reply.Status, "findCloudletData[%d]", ii)
		if reply.Status == dme.FindCloudletReply_FIND_FOUND {
			require.Equal(t, rr.Reply.Fqdn, reply.Fqdn,
				"findCloudletData[%d]", ii)
			// Check the filled in cloudlet details
			require.Equal(t, rr.ReplyCarrier,
				call.Key.CloudletFound.Organization, "findCloudletData[%d]", ii)
			require.Equal(t, rr.ReplyCloudlet,
				call.Key.CloudletFound.Name, "findCloudletData[%d]", ii)
		}
	}
}

func runGetAppInstList(t *testing.T, rrs []uaemtest.GetAppInstListRR, span opentracing.Span, serv *server) {
	for ii, rr := range rrs {
		ctx := uaemcommon.PeerContext(context.Background(), "127.0.0.1", 123, span)
		info := fmt.Sprintf("[%d]", ii)

		regReply, err := serv.RegisterClient(ctx, &rr.Reg)
		require.Nil(t, err, info)
		ckey, err := uaemcommon.VerifyCookie(ctx, regReply.SessionCookie)
		require.Nil(t, err, info)
		// set session cookie key directly on context since we're bypassing
		// interceptors
		ctx = uaemcommon.NewCookieContext(ctx, ckey)

		reply, err := serv.GetAppInstList(ctx, &rr.Req)
		require.Nil(t, err, info)
		require.Equal(t, rr.Reply.Status, reply.Status, info)
		require.Equal(t, len(rr.Reply.Cloudlets), len(reply.Cloudlets), info)
		var lastDistance float64
		for jj, clExp := range rr.Reply.Cloudlets {
			clAct := reply.Cloudlets[jj]
			info2 := fmt.Sprintf("[%d][%d]", ii, jj)

			require.NotNil(t, clAct, info2)
			require.Equal(t, clExp.CarrierName, clAct.CarrierName, info2)
			require.Equal(t, clExp.CloudletName, clAct.CloudletName, info2)
			require.NotNil(t, clAct.GpsLocation, info2)
			require.Equal(t, clExp.GpsLocation.Latitude, clAct.GpsLocation.Latitude, info2)
			require.Equal(t, clExp.GpsLocation.Longitude, clAct.GpsLocation.Longitude, info2)
			require.GreaterOrEqual(t, clAct.Distance, lastDistance, info2)
			lastDistance = clAct.Distance
		}
	}
}
