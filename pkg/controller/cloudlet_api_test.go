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

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/ccrmdummy"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/svcnode"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/notify"
	"github.com/edgexr/edge-cloud-platform/pkg/objstore"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/fake"
	"github.com/edgexr/edge-cloud-platform/pkg/process"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/require"
	"go.etcd.io/etcd/client/v3/concurrency"
	"google.golang.org/grpc"
)

type stateTransition struct {
	triggerState   dme.CloudletState
	triggerVersion string
	expectedState  edgeproto.TrackedState
	ignoreState    bool
}

const (
	crm_v1 = "2001-01-31"
	crm_v2 = "2002-01-31"
)

var eMock *EventMock

type EventMock struct {
	names map[string][]svcnode.EventTag
	addr  string
	mux   sync.Mutex
}

func NewEventMock(addr string) *EventMock {
	event := EventMock{}
	event.addr = addr
	event.names = make(map[string][]svcnode.EventTag)
	return &event
}

func (e *EventMock) registerResponders(t *testing.T, mockTransport *httpmock.MockTransport) {
	// register mock responders
	api := fmt.Sprintf("%s/_template/events-log", e.addr)
	mockTransport.RegisterResponder("PUT", api,
		func(req *http.Request) (*http.Response, error) {
			return httpmock.NewStringResponse(200, "Success"), nil
		},
	)
	recordEvent := func(data []byte) {
		eData := svcnode.EventData{}
		err := json.Unmarshal(data, &eData)
		require.Nil(t, err, "json unmarshal event data")
		require.NotEmpty(t, eData.Name, "event name exists")
		e.mux.Lock()
		e.names[strings.ToLower(eData.Name)] = eData.Tags
		e.mux.Unlock()
	}

	api = fmt.Sprintf("=~%s/events-log-.*/_doc", e.addr)
	mockTransport.RegisterResponder("POST", api,
		func(req *http.Request) (*http.Response, error) {
			data, _ := ioutil.ReadAll(req.Body)
			recordEvent(data)
			return httpmock.NewStringResponse(200, "Success"), nil
		},
	)
	api = fmt.Sprintf("=~%s/.*/_bulk", e.addr)
	mockTransport.RegisterResponder("POST", api,
		func(req *http.Request) (*http.Response, error) {
			data, _ := ioutil.ReadAll(req.Body)
			lines := strings.Split(string(data), "\n")
			// each record is 2 lines, first line is metadata,
			// second line is data. Final line is blank.
			for ii := 0; ii < len(lines)-1; ii += 2 {
				recordEvent([]byte(lines[ii+1]))
			}
			return httpmock.NewStringResponse(200, "Success"), nil
		},
	)
}

func (e *EventMock) verifyEvent(t *testing.T, name string, tags []svcnode.EventTag) {
	// Events are written in a separate thread so we need to poll
	// to check when they're registered.
	var eTags []svcnode.EventTag
	var ok bool
	for ii := 0; ii < 20; ii++ {
		e.mux.Lock()
		eTags, ok = e.names[strings.ToLower(name)]
		e.mux.Unlock()
		if ok {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	require.True(t, ok, "event exists")
	require.NotEqual(t, len(eTags), 0, "there should be more than 0 tags")
	require.NotEqual(t, len(tags), 0, "there should be more than 0 tags")
	eTagsMap := make(map[string]string)
	for _, eTag := range eTags {
		eTagsMap[eTag.Key] = eTag.Value
	}
	for _, tag := range tags {
		val, ok := eTagsMap[tag.Key]
		require.True(t, ok, "tag key exists")
		require.Equal(t, val, tag.Value, "tag value matches")
	}
}

func TestCloudletApi(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi | log.DebugLevelNotify | log.DebugLevelEvents)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	testSvcs := testinit(ctx, t)
	defer testfinish(testSvcs)

	dummy := regiondata.InMemoryStore{}
	dummy.Start()
	defer dummy.Stop()

	sync := regiondata.InitSync(&dummy)
	apis := NewAllApis(sync)
	sync.Start()
	defer sync.Done()
	responder := DefaultDummyInfoResponder(apis)
	responder.InitDummyInfoResponder()

	reduceInfoTimeouts(t, ctx, apis)

	// mock http to redirect requests
	mockTransport := httpmock.NewMockTransport()
	// any requests that don't have a registered URL will be fetched normally
	mockTransport.RegisterNoResponder(httpmock.InitialTransport.RoundTrip)

	esURL := "http://dummy-es"
	eMock = NewEventMock(esURL)
	eMock.registerResponders(t, mockTransport)

	// setup nodeMgr for events
	nodeMgr = svcnode.SvcNodeMgr{
		VaultAddr: vault.UnitTestIgnoreVaultAddr,
	}
	ctx, _, err := nodeMgr.Init(svcnode.SvcNodeTypeController, "", svcnode.WithRegion("unit-test"),
		svcnode.WithESUrls(esURL), svcnode.WithTestTransport(mockTransport))
	require.Nil(t, err)
	require.NotNil(t, nodeMgr.OSClient)
	defer nodeMgr.Finish()

	ccrm := ccrmdummy.StartDummyCCRM(ctx, nodeMgr.VaultConfig, &dummy)
	registerDummyCCRMConn(t, ccrm)
	defer ccrm.Stop()

	// create flavors
	addTestPlatformFeatures(t, ctx, apis, testutil.PlatformFeaturesData())
	cloudletData := testutil.CloudletData()
	testutil.InternalFlavorCreate(t, apis.flavorApi, testutil.FlavorData())
	testutil.InternalGPUDriverTest(t, "cud", apis.gpuDriverApi, testutil.GPUDriverData())
	testutil.InternalResTagTableCreate(t, apis.resTagTableApi, testutil.ResTagTableData())
	testutil.InternalZoneCreate(t, apis.zoneApi, testutil.ZoneData())
	testutil.InternalCloudletTest(t, "cud", apis.cloudletApi, cloudletData)

	// test invalid location values
	clbad := cloudletData[0]
	clbad.Key.Name = "bad loc"
	testBadLat(t, ctx, &clbad, []float64{90.1, -90.1, -1323213, 1232334}, "create", apis)
	testBadLong(t, ctx, &clbad, []float64{180.1, -180.1, -1323213, 1232334}, "create", apis)

	clbad = cloudletData[0]
	clbad.Key.Name = "test num dyn ips"
	err = apis.cloudletApi.CreateCloudlet(&clbad, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err)
	clbad.NumDynamicIps = 0
	clbad.Fields = []string{edgeproto.CloudletFieldNumDynamicIps}
	err = apis.cloudletApi.UpdateCloudlet(&clbad, testutil.NewCudStreamoutCloudlet(ctx))
	require.NotNil(t, err)

	cl := cloudletData[1]
	cl.Key.Name = "test invalid lat-long"
	err = apis.cloudletApi.CreateCloudlet(&cl, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err)
	testBadLat(t, ctx, &cl, []float64{90.1, -90.1, -1323213, 1232334}, "update", apis)
	testBadLong(t, ctx, &cl, []float64{180.1, -180.1, -1323213, 1232334}, "update", apis)

	testCloudletZoneRef(t, ctx, apis)
	testCloudletDnsLabel(t, ctx, apis)
	testChangeCloudletDNS(t, ctx, apis)

	// Resource Mapping tests
	testResMapKeysApi(t, ctx, &cl, apis)

	// Cloudlet state tests
	testCloudletStates(t, ctx, apis)
	testManualBringup(t, ctx, apis)

	testShowFlavorsForZone(t, ctx, apis)
	testShowPlatformFeaturesForZone(t, ctx, apis)
	testAllianceOrgs(t, ctx, apis)
	testCloudletEdgeboxOnly(t, ctx, cloudletData[2], apis)
	testCloudletUpdateInfo(t, ctx, apis)
	testCloudletManagedClusters(t, ctx, apis)
}

func testBadLat(t *testing.T, ctx context.Context, clbad *edgeproto.Cloudlet, lats []float64, action string, apis *AllApis) {
	for _, lat := range lats {
		clbad.Location.Latitude = lat
		clbad.Fields = []string{edgeproto.CloudletFieldLocationLatitude}
		switch action {
		case "create":
			err := apis.cloudletApi.CreateCloudlet(clbad, testutil.NewCudStreamoutCloudlet(ctx))
			require.NotNil(t, err, "create cloudlet bad latitude")
		case "update":
			err := apis.cloudletApi.UpdateCloudlet(clbad, testutil.NewCudStreamoutCloudlet(ctx))
			require.NotNil(t, err, "update cloudlet bad latitude")
		}
	}
}

func testBadLong(t *testing.T, ctx context.Context, clbad *edgeproto.Cloudlet, longs []float64, action string, apis *AllApis) {
	for _, long := range longs {
		clbad.Location.Longitude = long
		clbad.Fields = []string{edgeproto.CloudletFieldLocationLongitude}
		switch action {
		case "create":
			err := apis.cloudletApi.CreateCloudlet(clbad, testutil.NewCudStreamoutCloudlet(ctx))
			require.NotNil(t, err, "create cloudlet bad longitude")
		case "update":
			err := apis.cloudletApi.CreateCloudlet(clbad, testutil.NewCudStreamoutCloudlet(ctx))
			require.NotNil(t, err, "update cloudlet bad longitude")
		}
	}
}

func waitForState(key *edgeproto.CloudletKey, state edgeproto.TrackedState, apis *AllApis) error {
	lastState := edgeproto.TrackedState_TRACKED_STATE_UNKNOWN
	for i := 0; i < 10; i++ {
		cloudlet := edgeproto.Cloudlet{}
		if apis.cloudletApi.cache.Get(key, &cloudlet) {
			if cloudlet.State == state {
				return nil
			}
			lastState = cloudlet.State
		}
		time.Sleep(10 * time.Millisecond)
	}

	return fmt.Errorf("Unable to get desired cloudlet state, actual state %s, desired state %s", lastState, state)
}

func forceCloudletInfoState(ctx context.Context, key *edgeproto.CloudletKey, state dme.CloudletState, taskName, version string, apis *AllApis) {
	info := edgeproto.CloudletInfo{}
	info.Key = *key
	info.State = state
	info.ContainerVersion = version
	info.Status.SetTask(taskName)
	apis.cloudletInfoApi.Update(ctx, &info, 0)
}

// Not used?
func forceCloudletInfoMaintenanceState(ctx context.Context, key *edgeproto.CloudletKey, state dme.MaintenanceState, apis *AllApis) {
	info := edgeproto.CloudletInfo{}
	if !apis.cloudletInfoApi.cache.Get(key, &info) {
		info.Key = *key
	}
	info.MaintenanceState = state
	apis.cloudletInfoApi.Update(ctx, &info, 0)
}

func deleteCloudletInfo(ctx context.Context, key *edgeproto.CloudletKey, apis *AllApis) {
	info := edgeproto.CloudletInfo{}
	info.Key = *key
	apis.cloudletInfoApi.Delete(ctx, &info, 0)
}

func testNotifyId(t *testing.T, ctrlHandler *notify.DummyHandler, key *edgeproto.CloudletKey, nodeCount, notifyId int, crmVersion string) {
	require.Equal(t, nodeCount, len(ctrlHandler.SvcNodeCache.Objs), "node count matches")
	nodeVersion, nodeNotifyId, err := ctrlHandler.GetCloudletDetails(key)
	require.Nil(t, err, "get cloudlet version & notifyId from node cache")
	require.Equal(t, crmVersion, nodeVersion, "node version matches")
	require.Equal(t, int64(notifyId), nodeNotifyId, "node notifyId matches")
}

func testCloudletStates(t *testing.T, ctx context.Context, apis *AllApis) {
	ctrlHandler := notify.NewDummyHandler()
	ctrlMgr := notify.ServerMgr{}
	ctrlHandler.RegisterServer(&ctrlMgr)
	ctrlNotifyAddr := "127.0.0.1:50001"
	ctrlMgr.Start("ctrl", ctrlNotifyAddr, nil)
	defer ctrlMgr.Stop()

	getPublicCertApi := &cloudcommon.TestPublicCertApi{}
	publicCertManager, err := svcnode.NewPublicCertManager("localhost", "", getPublicCertApi, "", "")
	require.Nil(t, err)
	tlsConfig, err := publicCertManager.GetServerTlsConfig(ctx)
	require.Nil(t, err)
	err = services.accessKeyGrpcServer.Start(*accessApiAddr, apis.cloudletApi.accessKeyServer, tlsConfig, func(accessServer *grpc.Server) {
		edgeproto.RegisterCloudletAccessApiServer(accessServer, apis.cloudletApi)
		edgeproto.RegisterCloudletAccessKeyApiServer(accessServer, apis.cloudletApi)
	})
	require.Nil(t, err, "start access server")
	defer services.accessKeyGrpcServer.Stop()

	crm_notifyaddr := "127.0.0.1:0"
	cloudlet := testutil.CloudletData()[2]
	cloudlet.ContainerVersion = crm_v1
	cloudlet.Key.Name = "testcloudletstates"
	cloudlet.NotifySrvAddr = crm_notifyaddr
	cloudlet.CrmOverride = edgeproto.CRMOverride_NO_OVERRIDE
	cloudlet.CrmOnEdge = true

	pfConfig := &edgeproto.PlatformConfig{
		EnvVar:          make(map[string]string),
		AccessApiAddr:   *accessApiAddr,
		NotifyCtrlAddrs: ctrlNotifyAddr,
	}
	require.Nil(t, err, "get platform config")
	pfConfig.EnvVar["E2ETEST_TLS"] = "true"

	err = apis.cloudletApi.CreateCloudlet(&cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err, "create cloudlet")
	cloudletFound := apis.cloudletApi.cache.Get(&cloudlet.Key, &cloudlet)
	require.True(t, cloudletFound)

	defer apis.cloudletApi.DeleteCloudlet(&cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
	res, err := apis.cloudletApi.GenerateAccessKey(ctx, &cloudlet.Key)
	require.Nil(t, err, "generate access key")
	pfConfig.CrmAccessPrivateKey = res.Message
	pfConfig.AccessApiAddr = services.accessKeyGrpcServer.ApiAddr()

	streamCloudlet := NewStreamoutMsg(ctx)
	go func() {
		// copy objects required for WatchKey on cloudletInfo
		apis.cloudletInfoApi.cache.Objs = ctrlHandler.CloudletInfoCache.Objs
		apis.cloudletInfoApi.cache.KeyWatchers = ctrlHandler.CloudletInfoCache.KeyWatchers
		// setup cloudlet stream
		err = apis.streamObjApi.StreamCloudlet(&cloudlet.Key, streamCloudlet)
		require.Nil(t, err, "stream cloudlet, %s", err)
	}()

	err = process.StartCRMService(ctx, &cloudlet, pfConfig, process.HARolePrimary, nil)
	require.Nil(t, err, "start cloudlet")
	defer func() {
		// Delete CRM
		err = process.StopCRMService(ctx, &cloudlet, process.HARolePrimary)
		require.Nil(t, err, "stop cloudlet")
	}()

	err = ctrlHandler.WaitForCloudletState(&cloudlet.Key, dme.CloudletState_CLOUDLET_STATE_INIT)
	require.Nil(t, err, "cloudlet state transition")

	cloudlet.State = edgeproto.TrackedState_CRM_INITOK
	ctrlHandler.CloudletCache.Update(ctx, &cloudlet, 0)

	err = ctrlHandler.WaitForCloudletState(&cloudlet.Key, dme.CloudletState_CLOUDLET_STATE_READY)
	require.Nil(t, err, "cloudlet state transition")

	cloudlet.State = edgeproto.TrackedState_READY
	ctrlHandler.CloudletCache.Update(ctx, &cloudlet, 0)

	cloudletMsgs := []string{"Setting up cloudlet", "Initializing controller connection", "Initializing platform", "Done initializing fake platform", "Gathering Cloudlet Info", "Cloudlet setup successfully"}
	require.Equal(t, len(cloudletMsgs), len(streamCloudlet.Msgs), "progress messages")
	for ii, msg := range cloudletMsgs {
		require.Equal(t, streamCloudlet.Msgs[ii].Message, msg, "message matches")
	}

	cloudlet.State = edgeproto.TrackedState_UPDATE_REQUESTED
	ctrlHandler.CloudletCache.Update(ctx, &cloudlet, 0)

	// Note: CRM sends back two state changes as it's doing work.
	// It sets cloudletInfo.State first to dme.CLOUDLET_STATE_UPGRADE,
	// which the controller converts to TrackedState_UPDATING.
	// It then sets cloudletInfo.State to READY once its done.
	// There is no wait between those two state changes, so from the
	// controller side it's possible it never sees the UPGRADE
	// transition (due to notify condensing updates). So we can
	// only really wait for READY here.
	err = ctrlHandler.WaitForCloudletState(&cloudlet.Key, dme.CloudletState_CLOUDLET_STATE_READY)
	require.Nil(t, err, "cloudlet state transition")

	cloudletInfo := edgeproto.CloudletInfo{}
	found := ctrlHandler.CloudletInfoCache.Get(&cloudlet.Key, &cloudletInfo)
	require.True(t, found, "cloudlet info exists")
	require.Equal(t, len(cloudletInfo.ResourcesSnapshot.Info), 6, "cloudlet resources info exists")
	sort.Slice(cloudletInfo.ResourcesSnapshot.Info, func(i, j int) bool {
		return cloudletInfo.ResourcesSnapshot.Info[i].ResKey() < cloudletInfo.ResourcesSnapshot.Info[j].ResKey()
	})
	expRes := []edgeproto.InfraResource{{
		Name:          cloudcommon.ResourceDiskGb,
		Value:         80,
		InfraMaxValue: fake.FakeDiskMax,
		Units:         cloudcommon.ResourceDiskUnits,
	}, {
		Name:          cloudcommon.ResourceExternalIPs,
		Value:         1,
		InfraMaxValue: fake.FakeExternalIpsMax,
	}, {
		Name:  cloudcommon.ResourceInstances,
		Value: 2,
	}, {
		Name:          cloudcommon.ResourceRamMb,
		Value:         8192,
		InfraMaxValue: fake.FakeRamMax,
		Units:         cloudcommon.ResourceRamUnits,
	}, {
		Name:          "nvidia-t4",
		Value:         0,
		InfraMaxValue: 4,
		Type:          "gpu",
	}, {
		Name:          cloudcommon.ResourceVcpus,
		Value:         4,
		InfraMaxValue: fake.FakeVcpusMax,
	}}
	require.Equal(t, expRes, cloudletInfo.ResourcesSnapshot.Info)
}

func testManualBringup(t *testing.T, ctx context.Context, apis *AllApis) {
	var err error
	cloudlet := testutil.CloudletData()[2]
	cloudlet.Key.Name = "crmmanualbringup"
	cloudlet.ContainerVersion = crm_v1
	err = apis.cloudletApi.CreateCloudlet(&cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err)

	err = waitForState(&cloudlet.Key, edgeproto.TrackedState_READY, apis)
	require.Nil(t, err, "cloudlet obj created")

	forceCloudletInfoState(ctx, &cloudlet.Key, dme.CloudletState_CLOUDLET_STATE_INIT, "sending init", crm_v2, apis)
	err = waitForState(&cloudlet.Key, edgeproto.TrackedState_CRM_INITOK, apis)
	require.Nil(t, err, fmt.Sprintf("cloudlet state transtions"))
	eMock.verifyEvent(t, "upgrading cloudlet", []svcnode.EventTag{
		svcnode.EventTag{
			Key:   "from-version",
			Value: crm_v1,
		},
		svcnode.EventTag{
			Key:   "to-version",
			Value: crm_v2,
		},
	})

	forceCloudletInfoState(ctx, &cloudlet.Key, dme.CloudletState_CLOUDLET_STATE_READY, "sending ready", crm_v2, apis)
	err = waitForState(&cloudlet.Key, edgeproto.TrackedState_READY, apis)
	require.Nil(t, err, fmt.Sprintf("cloudlet state transtions"))
	eMock.verifyEvent(t, "cloudlet online", []svcnode.EventTag{
		svcnode.EventTag{
			Key:   "state",
			Value: "CLOUDLET_STATE_READY",
		},
		svcnode.EventTag{
			Key:   "version",
			Value: crm_v2,
		},
	})

	stateTransitions := map[dme.MaintenanceState]dme.MaintenanceState{
		dme.MaintenanceState_FAILOVER_REQUESTED:    dme.MaintenanceState_FAILOVER_DONE,
		dme.MaintenanceState_CRM_REQUESTED:         dme.MaintenanceState_CRM_UNDER_MAINTENANCE,
		dme.MaintenanceState_NORMAL_OPERATION_INIT: dme.MaintenanceState_NORMAL_OPERATION,
	}

	cancel := apis.cloudletApi.cache.WatchKey(&cloudlet.Key, func(ctx context.Context) {
		cl := edgeproto.Cloudlet{}
		if !apis.cloudletApi.cache.Get(&cloudlet.Key, &cl) {
			return
		}
		switch cl.MaintenanceState {
		case dme.MaintenanceState_FAILOVER_REQUESTED:
			info := edgeproto.AutoProvInfo{}
			if !apis.autoProvInfoApi.cache.Get(&cloudlet.Key, &info) {
				info.Key = cloudlet.Key
			}
			info.MaintenanceState = stateTransitions[cl.MaintenanceState]
			apis.autoProvInfoApi.cache.Update(ctx, &info, 0)
		case dme.MaintenanceState_CRM_REQUESTED:
			fallthrough
		case dme.MaintenanceState_NORMAL_OPERATION_INIT:
			info := edgeproto.CloudletInfo{}
			if !apis.cloudletInfoApi.cache.Get(&cloudlet.Key, &info) {
				info.Key = cloudlet.Key
			}
			info.MaintenanceState = stateTransitions[cl.MaintenanceState]
			apis.cloudletInfoApi.cache.Update(ctx, &info, 0)
		}
	})

	defer cancel()

	cloudlet.MaintenanceState = dme.MaintenanceState_MAINTENANCE_START
	cloudlet.Fields = append(cloudlet.Fields, edgeproto.CloudletFieldMaintenanceState)
	err = apis.cloudletApi.UpdateCloudlet(&cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err, fmt.Sprintf("update cloudlet maintenance state"))

	eMock.verifyEvent(t, "cloudlet maintenance start", []svcnode.EventTag{
		svcnode.EventTag{
			Key:   "maintenance-state",
			Value: "UNDER_MAINTENANCE",
		},
	})

	cloudlet.MaintenanceState = dme.MaintenanceState_NORMAL_OPERATION
	err = apis.cloudletApi.UpdateCloudlet(&cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err, fmt.Sprintf("update cloudlet maintenance state"))
	eMock.verifyEvent(t, "cloudlet maintenance done", []svcnode.EventTag{
		svcnode.EventTag{
			Key:   "maintenance-state",
			Value: "NORMAL_OPERATION",
		},
	})

	deleteCloudletInfo(ctx, &cloudlet.Key, apis)
	eMock.verifyEvent(t, "cloudlet offline", []svcnode.EventTag{
		svcnode.EventTag{
			Key:   "reason",
			Value: "notify disconnect",
		},
	})

	// Cloudlet state is INITOK but from old CRM (crm_v1)
	forceCloudletInfoState(ctx, &cloudlet.Key, dme.CloudletState_CLOUDLET_STATE_INIT, "sending init", crm_v1, apis)
	err = waitForState(&cloudlet.Key, edgeproto.TrackedState_CRM_INITOK, apis)
	require.Nil(t, err, fmt.Sprintf("cloudlet state transtions"))

	// Cloudlet should still be ready, ignoring the above stale entry
	forceCloudletInfoState(ctx, &cloudlet.Key, dme.CloudletState_CLOUDLET_STATE_READY, "sending ready", crm_v2, apis)
	err = waitForState(&cloudlet.Key, edgeproto.TrackedState_READY, apis)
	require.Nil(t, err, fmt.Sprintf("cloudlet state transtions"))

	found := apis.autoProvInfoApi.cache.Get(&cloudlet.Key, &edgeproto.AutoProvInfo{})
	require.True(t, found, "autoprovinfo for cloudlet exists")

	err = apis.cloudletApi.DeleteCloudlet(&cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err)

	found = apis.autoProvInfoApi.cache.Get(&cloudlet.Key, &edgeproto.AutoProvInfo{})
	require.False(t, found, "autoprovinfo for cloudlet should be cleaned up")
}

func testResMapKeysApi(t *testing.T, ctx context.Context, cl *edgeproto.Cloudlet, apis *AllApis) {
	// We can add/remove edgeproto.ResTagTableKey values to the cl.ResTagMap map
	// which then can be used in the GetVMSpec call when matching our meta-resource specificer
	// to a deployments actual resources/flavrs.
	resmap := edgeproto.CloudletResMap{}
	resmap.Key = cl.Key
	// test_data contains sample resource tag maps, add them to the cloudlet
	// verify, and remove them. ClI should follow suit.
	if cl.ResTagMap == nil {
		cl.ResTagMap = make(map[string]*edgeproto.ResTagTableKey)
	}
	if resmap.Mapping == nil {
		resmap.Mapping = make(map[string]string)
	}

	// use the OptResNames as clould.ResTagMap[key] = tblkey in test
	// gpu, nas and nic are the current set of Resource Names.
	// setup the test map using the test_data objects
	// The AddCloudResMapKey is setup to accept multiple res tbl keys at once
	// but we're doing it one by one.
	restblkeys := testutil.Restblkeys()
	resmap.Mapping[strings.ToLower(edgeproto.OptResNames_name[0])] = restblkeys[0].Name
	_, err := apis.cloudletApi.AddCloudletResMapping(ctx, &resmap)
	require.Nil(t, err, "AddCloudletResMapKey")

	resmap.Mapping[strings.ToLower(edgeproto.OptResNames_name[1])] = restblkeys[1].Name
	_, err = apis.cloudletApi.AddCloudletResMapping(ctx, &resmap)
	require.Nil(t, err, "AddCloudletResMapKey")

	resmap.Mapping[strings.ToLower(edgeproto.OptResNames_name[2])] = restblkeys[2].Name
	_, err = apis.cloudletApi.AddCloudletResMapping(ctx, &resmap)
	require.Nil(t, err, "AddCloudletResMapKey")

	testcl := &edgeproto.Cloudlet{}
	// now it's all stored, fetch a copy of the cloudlet and verify
	err = apis.cloudletApi.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		if !apis.cloudletApi.store.STMGet(stm, &cl.Key, testcl) {
			return cl.Key.NotFoundError()
		}
		return err
	})

	// what's in our testcl? Check the resource map
	tkey := testcl.ResTagMap[strings.ToLower(edgeproto.OptResNames_name[0])]
	require.Equal(t, testutil.Restblkeys()[0].Name, tkey.Name, "AddCloudletResMapKey")
	tkey = testcl.ResTagMap[strings.ToLower(edgeproto.OptResNames_name[1])]
	require.Equal(t, testutil.Restblkeys()[1].Name, tkey.Name, "AddCloudletResMapKey")
	tkey = testcl.ResTagMap[strings.ToLower(edgeproto.OptResNames_name[2])]
	require.Equal(t, testutil.Restblkeys()[2].Name, tkey.Name, "AddCloudletResMapKey")

	// and the actual keys should match as well
	require.Equal(t, testutil.Restblkeys()[0], *testcl.ResTagMap[testutil.Restblkeys()[0].Name], "AddCloudletResMapKey")
	require.Equal(t, testutil.Restblkeys()[1], *testcl.ResTagMap[testutil.Restblkeys()[1].Name], "AddCloudletResMapKey")
	require.Equal(t, testutil.Restblkeys()[2], *testcl.ResTagMap[testutil.Restblkeys()[2].Name], "AddCloudletResMapKey")

	resmap1 := edgeproto.CloudletResMap{}
	resmap1.Mapping = make(map[string]string)
	resmap1.Mapping[strings.ToLower(edgeproto.OptResNames_name[2])] = testutil.Restblkeys()[2].Name
	resmap1.Mapping[strings.ToLower(edgeproto.OptResNames_name[1])] = testutil.Restblkeys()[1].Name
	resmap1.Key = cl.Key

	_, err = apis.cloudletApi.RemoveCloudletResMapping(ctx, &resmap1)
	require.Nil(t, err, "RemoveCloudletResMapKey")

	rmcl := &edgeproto.Cloudlet{}
	if rmcl.ResTagMap == nil {
		rmcl.ResTagMap = make(map[string]*edgeproto.ResTagTableKey)
	}
	rmcl.Key = resmap1.Key

	err = apis.cloudletApi.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		if !apis.cloudletApi.store.STMGet(stm, &cl.Key, rmcl) {
			return cl.Key.NotFoundError()
		}
		return err
	})

	require.Nil(t, err, "STMGet failure")
	// and check the maps len = 1
	require.Equal(t, 1, len(rmcl.ResTagMap), "RemoveCloudletResMapKey")
	// and might as well check the key "gpu" exists
	_, ok := rmcl.ResTagMap[testutil.Restblkeys()[0].Name]
	require.Equal(t, true, ok, "RemoveCloudletResMapKey")
}

func testShowFlavorsForZone(t *testing.T, ctx context.Context, apis *AllApis) {
	insertCloudletInfo(ctx, apis, testutil.CloudletInfoData())
	// Use a clouldet with no ResourceTagMap
	cCldApi := testutil.NewInternalCloudletApi(apis.cloudletApi)
	zone := testutil.ZoneData()[1]
	zkey := &zone.Key

	show := testutil.ShowFlavorsForZone{}
	show.Init()

	err := cCldApi.ShowFlavorsForZone(ctx, zkey, &show)
	require.Nil(t, err)
	require.Equal(t, 2, len(show.Data))

	// Show flavors for a chosen operator.
	show.Init()
	zone.Key.Name = ""

	err = cCldApi.ShowFlavorsForZone(ctx, zkey, &show)
	require.Nil(t, err)
	require.Equal(t, 6, len(show.Data))

	// Show flavors for a chosen cloudlet name.
	show.Init()
	zone = testutil.ZoneData()[1]
	zone.Key.Organization = ""

	err = cCldApi.ShowFlavorsForZone(ctx, zkey, &show)
	require.Nil(t, err)
	require.Equal(t, 2, len(show.Data))
}

func testShowPlatformFeaturesForZone(t *testing.T, ctx context.Context, apis *AllApis) {
	// Show features for specific zone (single cloudlet in zone)
	show := testutil.NewShowServerStream[*edgeproto.PlatformFeatures](ctx)

	zones := testutil.ZoneData()
	err := apis.platformFeaturesApi.ShowPlatformFeaturesForZone(&zones[0].Key, show)
	require.Nil(t, err)
	require.Equal(t, 1, len(show.Data))
	require.Equal(t, "fake", show.Data[0].PlatformType)

	// Show features for operator
	show = testutil.NewShowServerStream[*edgeproto.PlatformFeatures](ctx)
	filter := edgeproto.ZoneKey{
		Organization: testutil.OperatorData()[2],
	}
	// operatorData[2] yields CloudletData[3] (fake) and CloudletData[4] (fakesinglecluster)
	err = apis.platformFeaturesApi.ShowPlatformFeaturesForZone(&filter, show)
	require.Nil(t, err)
	require.Equal(t, 2, len(show.Data))
	require.Equal(t, "fake", show.Data[0].PlatformType)
	require.Equal(t, "fakesinglecluster", show.Data[1].PlatformType)
}

func testAllianceOrgs(t *testing.T, ctx context.Context, apis *AllApis) {
	data := testutil.CloudletData()
	cloudlet := data[0]

	// negative tests
	selfOrgErr := `Cannot add cloudlet's own org "UFGT Inc." as alliance org`
	dupOrgErr := `Duplicate alliance org "foo" specified`

	// update cloudlet checks
	cloudlet.AllianceOrgs = []string{cloudlet.Key.Organization}
	err := apis.cloudletApi.UpdateCloudlet(&cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
	require.NotNil(t, err)
	require.Equal(t, selfOrgErr, err.Error())
	cloudlet.AllianceOrgs = []string{"foo", "bar", "foo"}
	err = apis.cloudletApi.UpdateCloudlet(&cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
	require.NotNil(t, err)
	require.Equal(t, dupOrgErr, err.Error())

	// create cloudlet checks
	cloudlet.Key.Name += "allianceorgtest"
	cloudlet.AllianceOrgs = []string{cloudlet.Key.Organization}
	err = apis.cloudletApi.CreateCloudlet(&cloudlet, testutil.NewCudStreamoutCloudlet(ctx))

	require.NotNil(t, err)
	require.Equal(t, selfOrgErr, err.Error())
	cloudlet.AllianceOrgs = []string{"foo", "bar", "foo"}
	err = apis.cloudletApi.CreateCloudlet(&cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
	require.NotNil(t, err)
	require.Equal(t, dupOrgErr, err.Error())

	// add alliance org checks
	cao := edgeproto.CloudletAllianceOrg{
		Key:          data[0].Key,
		Organization: data[0].Key.Organization,
	}
	_, err = apis.cloudletApi.AddCloudletAllianceOrg(ctx, &cao)
	require.NotNil(t, err)
	require.Equal(t, selfOrgErr, err.Error())
	cao.Organization = "foo"
	_, err = apis.cloudletApi.AddCloudletAllianceOrg(ctx, &cao)
	require.Nil(t, err)
	_, err = apis.cloudletApi.AddCloudletAllianceOrg(ctx, &cao)
	require.NotNil(t, err)
	require.Equal(t, dupOrgErr, err.Error())
	_, err = apis.cloudletApi.RemoveCloudletAllianceOrg(ctx, &cao)
	require.Nil(t, err)
	_, err = apis.cloudletApi.RemoveCloudletAllianceOrg(ctx, &cao)
	require.Nil(t, err)
	// verify removed
	check := edgeproto.Cloudlet{}
	found := apis.cloudletApi.cache.Get(&data[0].Key, &check)
	require.True(t, found)
	require.Equal(t, 0, len(check.AllianceOrgs))
}

func TestShowCloudletsAppDeploy(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	testSvcs := testinit(ctx, t)
	defer testfinish(testSvcs)

	dummy := regiondata.InMemoryStore{}
	dummy.Start()

	sync := regiondata.InitSync(&dummy)
	apis := NewAllApis(sync)
	sync.Start()
	defer sync.Done()

	responder := DefaultDummyInfoResponder(apis)
	responder.InitDummyInfoResponder()
	ccrm := ccrmdummy.StartDummyCCRM(ctx, testSvcs.DummyVault.Config, &dummy)
	registerDummyCCRMConn(t, ccrm)
	defer ccrm.Stop()
	reduceInfoTimeouts(t, ctx, apis)

	cAppApi := testutil.NewInternalAppApi(apis.appApi)

	show := testutil.ShowZonesForAppDeployment{}
	show.Init()

	app := testutil.AppData()[2]
	request := edgeproto.DeploymentZoneRequest{
		App:          &app,
		DryRunDeploy: false,
	}
	app.DefaultFlavor = testutil.FlavorData()[0].Key // x1.tiny
	app.Deployment = cloudcommon.DeploymentTypeVM
	filter := request

	// test data
	addTestPlatformFeatures(t, ctx, apis, testutil.PlatformFeaturesData())
	testutil.InternalFlavorCreate(t, apis.flavorApi, testutil.FlavorData())
	testutil.InternalGPUDriverCreate(t, apis.gpuDriverApi, testutil.GPUDriverData())
	testutil.InternalResTagTableCreate(t, apis.resTagTableApi, testutil.ResTagTableData())
	testutil.InternalZoneCreate(t, apis.zoneApi, testutil.ZoneData())
	testutil.InternalCloudletCreate(t, apis.cloudletApi, testutil.CloudletData())
	insertCloudletInfo(ctx, apis, testutil.CloudletInfoData())

	// either create the policy expected by one of all cloudlets, or remove that bit of config, or
	// just don't create that specific cloudlet. #1 create the policy.
	testutil.InternalAutoProvPolicyCreate(t, apis.autoProvPolicyApi, testutil.AutoProvPolicyData())
	testutil.InternalAutoScalePolicyCreate(t, apis.autoScalePolicyApi, testutil.AutoScalePolicyData())

	for _, obj := range testutil.ClusterInstData() {
		err := apis.clusterInstApi.CreateClusterInst(&obj, testutil.NewCudStreamoutClusterInst(ctx))
		require.Nil(t, err, "Create ClusterInst")
	}

	err := cAppApi.ShowZonesForAppDeployment(ctx, &filter, &show)
	require.Nil(t, err, "ShowZonesForAppDeployment")
	require.Equal(t, 5, len(show.Data), "ShowZonesForAppDeployment")

	for k, v := range show.Data {
		fmt.Printf("\t next k: %s v: %+v flavor %s \n", k, v, filter.App.DefaultFlavor)
	}
	show.Init()
	// increase the flavor size, and expect fewer cloudlet matches
	// TODO: create sets of OS flavors to attach to our CloudletInfo objs  as substitues for whats there in test_data.go
	// for more complex matching.
	app.DefaultFlavor = testutil.FlavorData()[2].Key // 3 = x1.large 4 = x1.tiny.gpu 2 = x1.medium
	err = cAppApi.ShowZonesForAppDeployment(ctx, &filter, &show)
	require.Nil(t, err, "ShowZonesForAppDeployment")
	require.Equal(t, 4, len(show.Data), "ShowZonesForAppDeployment")

	show.Init()
	app.DefaultFlavor = testutil.FlavorData()[3].Key // 3 = x1.large 4 = x1.tiny.gpu 2 = x1.medium
	err = cAppApi.ShowZonesForAppDeployment(ctx, &filter, &show)
	require.Nil(t, err, "ShowZonesForAppDeployment")
	require.Equal(t, 2, len(show.Data), "ShowZonesForAppDeployment")
	show.Init()

	filter.DryRunDeploy = true

	err = cAppApi.ShowZonesForAppDeployment(ctx, &filter, &show)
	require.Nil(t, err, "ShowZonesForAppDeployment")
	require.Equal(t, 2, len(show.Data), "ShowZonesForAppDeployment DryRun=True")
	// TODO: Increase cloudlets refs such that San Jose can no longer support the App deployment
	dummy.Stop()
}

func testCloudletDnsLabel(t *testing.T, ctx context.Context, apis *AllApis) {
	var err error

	data := testutil.CloudletData()
	// Check that dns segment ids are unique for cloudlets.
	cl0 := data[0]
	cl0.Key.Name = "abc"
	cl0.Key.Organization = "def"
	cl0.ResTagMap = nil
	cl0.GpuConfig = edgeproto.GPUConfig{}
	cl0.Zone = ""

	cl1 := data[1]
	cl1.Key.Name = "ab,c"
	cl1.Key.Organization = "d,ef"
	cl1.ResTagMap = nil
	cl1.GpuConfig = edgeproto.GPUConfig{}
	cl1.Zone = ""

	dnsLabel0 := "abc-def"
	dnsLabel1 := "abc-def1"

	err = apis.cloudletApi.CreateCloudlet(&cl0, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err)
	err = apis.cloudletApi.CreateCloudlet(&cl1, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err)

	check0 := edgeproto.Cloudlet{}
	require.True(t, apis.cloudletApi.cache.Get(&cl0.Key, &check0))
	require.Equal(t, dnsLabel0, check0.DnsLabel)

	check1 := edgeproto.Cloudlet{}
	require.True(t, apis.cloudletApi.cache.Get(&cl1.Key, &check1))
	require.Equal(t, dnsLabel1, check1.DnsLabel)

	require.NotEqual(t, dnsLabel0, dnsLabel1)
	// check that ids are present in database
	require.True(t, testHasCloudletDnsLabel(apis.cloudletApi.sync.GetKVStore(), dnsLabel0))
	require.True(t, testHasCloudletDnsLabel(apis.cloudletApi.sync.GetKVStore(), dnsLabel1))

	// clean up
	err = apis.cloudletApi.DeleteCloudlet(&cl0, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err)
	err = apis.cloudletApi.DeleteCloudlet(&cl1, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err)
	// check that ids are removed from database
	require.False(t, testHasCloudletDnsLabel(apis.cloudletApi.sync.GetKVStore(), dnsLabel0))
	require.False(t, testHasCloudletDnsLabel(apis.cloudletApi.sync.GetKVStore(), dnsLabel1))
}

func testHasCloudletDnsLabel(kvstore objstore.KVStore, id string) bool {
	return testKVStoreHasKey(kvstore, edgeproto.CloudletDnsLabelDbKey(id))
}

func testCloudletEdgeboxOnly(t *testing.T, ctx context.Context, cloudlet edgeproto.Cloudlet, apis *AllApis) {
	// When edgebox only is set (by MC), cannot create non-edgebox platform.
	cloudlet.Key.Name = "test-edgebox-only"
	cloudlet.PlatformType = platform.PlatformTypeFake
	cloudlet.EdgeboxOnly = true
	err := apis.cloudletApi.CreateCloudlet(&cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Cloudlet is restricted to edgebox or mock only platforms")
	// Test can create edgebox platform.
	cloudlet.PlatformType = platform.PlatformTypeFakeEdgebox
	err = apis.cloudletApi.CreateCloudlet(&cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err)
	// clean up
	err = apis.cloudletApi.DeleteCloudlet(&cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
}

func testCloudletZoneRef(t *testing.T, ctx context.Context, apis *AllApis) {
	cloudlet := testutil.CloudletData()[0]

	// create fails if refers to missing zone
	cloudlet.Key.Name = "test-zone-ref"
	cloudlet.Zone = "invalid-zone"
	err := apis.cloudletApi.CreateCloudlet(&cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Zone")
	require.Contains(t, err.Error(), "not found")

	// update fails if refers to missing zone
	zone := edgeproto.Zone{}
	zone.Key.Name = "valid-zone"
	zone.Key.Organization = cloudlet.Key.Organization
	zone2 := edgeproto.Zone{}
	zone2.Key.Name = "valid-zone2"
	zone2.Key.Organization = cloudlet.Key.Organization
	// create valid zones
	_, err = apis.zoneApi.CreateZone(ctx, &zone)
	require.Nil(t, err)
	_, err = apis.zoneApi.CreateZone(ctx, &zone2)
	require.Nil(t, err)
	// create cloudlet with valid zone
	cloudlet.Zone = zone.Key.Name
	err = apis.cloudletApi.CreateCloudlet(&cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err)
	// update to invalid zone must fail
	cloudlet.Zone = "invalid-zone"
	cloudlet.Fields = []string{edgeproto.CloudletFieldZone}
	err = apis.cloudletApi.UpdateCloudlet(&cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Zone")
	require.Contains(t, err.Error(), "not found")
	// update to a different valid zone should succeed
	cloudlet.Zone = zone2.Key.Name
	cloudlet.Fields = []string{edgeproto.CloudletFieldZone}
	err = apis.cloudletApi.UpdateCloudlet(&cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err)
	// cleanup
	err = apis.cloudletApi.DeleteCloudlet(&cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err)
	_, err = apis.zoneApi.DeleteZone(ctx, &zone)
	require.Nil(t, err)
	_, err = apis.zoneApi.DeleteZone(ctx, &zone2)
	require.Nil(t, err)
}

func testChangeCloudletDNS(t *testing.T, ctx context.Context, apis *AllApis) {
	// For now CRM off edge is unsupported
	err := apis.cloudletApi.ChangeCloudletDNS(&testutil.CloudletData()[0].Key, testutil.NewCudStreamoutCloudlet(ctx))
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "unsupported")

	// Create a cloudlet to test with
	cloudlet := testutil.CloudletData()[2]
	cloudlet.Key.Name = "cloudletDNSUpdate"
	err = apis.cloudletApi.CreateCloudlet(&cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err)
	info := testutil.CloudletInfoData()[2]
	info.Key = cloudlet.Key
	info.State = dme.CloudletState_CLOUDLET_STATE_READY
	apis.cloudletInfoApi.Update(ctx, &info, 0)
	err = waitForState(&cloudlet.Key, edgeproto.TrackedState_READY, apis)
	require.Nil(t, err, "cloudlet obj created")
	// check that static fqdn and running match
	cloudletObj := edgeproto.Cloudlet{}
	ok := apis.cloudletApi.store.Get(ctx, &cloudlet.Key, &cloudletObj)
	require.True(t, ok)
	require.Equal(t, cloudletObj.RootLbFqdn, cloudletObj.StaticRootLbFqdn)
	// add dedicated clusterInst
	clusterInst := testutil.ClusterInstData()[5]
	clusterInst.CloudletKey = cloudlet.Key
	err = apis.clusterInstApi.CreateClusterInst(&clusterInst, testutil.NewCudStreamoutClusterInst(ctx))
	require.Nil(t, err, "Create Dedicated ClusterInst")
	clusterObj := edgeproto.ClusterInst{}
	ok = apis.clusterInstApi.store.Get(ctx, &clusterInst.Key, &clusterObj)
	require.True(t, ok)
	originalFqdn := clusterObj.Fqdn
	// add shared clusterInst
	clusterInstShared := testutil.ClusterInstData()[6]
	clusterInstShared.CloudletKey = cloudlet.Key
	err = apis.clusterInstApi.CreateClusterInst(&clusterInstShared, testutil.NewCudStreamoutClusterInst(ctx))
	require.Nil(t, err, "Create Shared ClusterInst")
	ok = apis.clusterInstApi.store.Get(ctx, &clusterInstShared.Key, &clusterObj)
	require.True(t, ok)

	// add regual app/appinst
	app := testutil.AppData()[1]
	_, err = apis.appApi.CreateApp(ctx, &app)
	require.Nil(t, err, "Create App")
	regAppInstName := "changednsregularapp"
	appInst := edgeproto.AppInst{
		Key: edgeproto.AppInstKey{
			Name:         regAppInstName,
			Organization: clusterInst.Key.Organization,
		},
		AppKey:      app.Key,
		CloudletKey: cloudlet.Key,
		ClusterKey:  clusterInst.Key,
		CloudletLoc: cloudlet.Location,
		PowerState:  edgeproto.PowerState_POWER_ON,
	}
	err = apis.appInstApi.CreateAppInst(&appInst, testutil.NewCudStreamoutAppInst(ctx))
	require.Nil(t, err, "Create AppInst")
	ok = apis.appInstApi.store.Get(ctx, &appInst.Key, &appInst)
	require.True(t, ok)
	origURI := appInst.Uri

	// add internal app/appinst
	app = testutil.AppData()[7]
	_, err = apis.appApi.CreateApp(ctx, &app)
	require.Nil(t, err, "Create Internal App")
	internalAppInstName := "changednsinternallapp"
	appInst = edgeproto.AppInst{
		Key: edgeproto.AppInstKey{
			Name:         internalAppInstName,
			Organization: clusterInst.Key.Organization,
		},
		AppKey:      app.Key,
		CloudletKey: cloudlet.Key,
		ClusterKey:  clusterInst.Key,
		CloudletLoc: cloudlet.Location,
		PowerState:  edgeproto.PowerState_POWER_ON,
	}
	err = apis.appInstApi.CreateAppInst(&appInst, testutil.NewCudStreamoutAppInst(ctx))
	require.Nil(t, err, "Create Internal AppInst")
	ok = apis.appInstApi.store.Get(ctx, &appInst.Key, &appInst)
	require.True(t, ok)
	require.Empty(t, appInst.Uri)

	app = testutil.AppData()[1]
	regAppInstSharedAccName := "changednsregularsharedapp"
	appInst = edgeproto.AppInst{
		Key: edgeproto.AppInstKey{
			Name:         regAppInstSharedAccName,
			Organization: clusterInstShared.Key.Organization,
		},
		AppKey:      app.Key,
		CloudletKey: cloudlet.Key,
		ClusterKey:  clusterInstShared.Key,
		CloudletLoc: cloudlet.Location,
		PowerState:  edgeproto.PowerState_POWER_ON,
	}
	err = apis.appInstApi.CreateAppInst(&appInst, testutil.NewCudStreamoutAppInst(ctx))
	require.Nil(t, err, "Create AppInst with shared access")
	ok = apis.appInstApi.store.Get(ctx, &appInst.Key, &appInst)
	require.True(t, ok)

	// Set up a different appDNSRoot
	*appDNSRoot = "new.and.improved.dns.com"
	// Cloudlet has to be in maintenance mode
	err = apis.cloudletApi.ChangeCloudletDNS(&cloudlet.Key, testutil.NewCudStreamoutCloudlet(ctx))
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "maintenance mode")
	err = apis.cloudletApi.setMaintenanceState(ctx, &cloudlet.Key, dme.MaintenanceState_UNDER_MAINTENANCE, ctx, "none")
	require.Nil(t, err, "update cloudlet maintenance state")

	eMock.verifyEvent(t, "cloudlet maintenance start", []svcnode.EventTag{
		svcnode.EventTag{
			Key:   "maintenance-state",
			Value: "UNDER_MAINTENANCE",
		},
	})
	err = apis.cloudletApi.ChangeCloudletDNS(&cloudlet.Key, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err)

	updatedRootLbFqdn := ""
	checkDNS := func() {
		// check new fqdn
		cloudletObj = edgeproto.Cloudlet{}
		ok = apis.cloudletApi.store.Get(ctx, &cloudlet.Key, &cloudletObj)
		require.True(t, ok)
		require.Contains(t, cloudletObj.RootLbFqdn, *appDNSRoot)
		// at this point static and current fqdns should be different
		require.NotEqual(t, cloudletObj.RootLbFqdn, cloudletObj.StaticRootLbFqdn)
		if updatedRootLbFqdn == "" {
			updatedRootLbFqdn = cloudletObj.RootLbFqdn
		} else {
			// This is test of the second run - check that nothing changed
			require.Equal(t, cloudletObj.RootLbFqdn, updatedRootLbFqdn)
		}
		annotationDNS, ok := cloudletObj.Annotations[cloudcommon.AnnotationPreviousDNSName]
		require.True(t, ok)
		require.Equal(t, cloudletObj.StaticRootLbFqdn, annotationDNS)
		ok = apis.clusterInstApi.store.Get(ctx, &clusterInst.Key, &clusterObj)
		require.True(t, ok)
		require.NotEqual(t, clusterObj.Fqdn, originalFqdn)
		require.Contains(t, clusterObj.Fqdn, *appDNSRoot)
		annotationDNS, ok = clusterObj.Annotations[cloudcommon.AnnotationPreviousDNSName]
		require.True(t, ok)
		require.Equal(t, originalFqdn, annotationDNS)
		// Check regular app
		appInst.Key.Name = regAppInstName
		ok = apis.appInstApi.store.Get(ctx, &appInst.Key, &appInst)
		require.True(t, ok)
		require.NotEqual(t, appInst.Uri, origURI)
		require.Contains(t, appInst.Uri, *appDNSRoot)
		// check that it has uri that matches the cluster fqdn
		require.Equal(t, clusterObj.Fqdn, appInst.Uri)
		annotationDNS, ok = appInst.Annotations[cloudcommon.AnnotationPreviousDNSName]
		require.True(t, ok)
		require.Equal(t, origURI, annotationDNS)
		// Check internal app - no changes
		appInst.Key.Name = internalAppInstName
		ok = apis.appInstApi.store.Get(ctx, &appInst.Key, &appInst)
		require.True(t, ok)
		require.Empty(t, appInst.Uri)
		_, ok = appInst.Annotations[cloudcommon.AnnotationPreviousDNSName]
		require.False(t, ok)
		// check shared access appInst
		appInst.Key.Name = regAppInstSharedAccName
		ok = apis.appInstApi.store.Get(ctx, &appInst.Key, &appInst)
		require.True(t, ok)
		require.Contains(t, appInst.Uri, *appDNSRoot)
		// check that it has uri that matches the sharedRootLb fqdn
		require.Equal(t, cloudletObj.RootLbFqdn, appInst.Uri)
		_, ok = appInst.Annotations[cloudcommon.AnnotationPreviousDNSName]
		require.True(t, ok)
	}
	checkDNS()

	// Repeat update should result in the same fqdn
	err = apis.cloudletApi.ChangeCloudletDNS(&cloudlet.Key, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err)
	checkDNS()
}

func testCloudletUpdateInfo(t *testing.T, ctx context.Context, apis *AllApis) {
	// Test for triggering updated CloudletInfo.
	// Currently for CCRM-based cloudlets, GatherCloudletInfo, which
	// grabs the Flavors from the cloudlet-specific infra, is only
	// run at create time. If for some reason flavors change, we need a
	// mechanism to be able to update those flavors.
	// That mechanism is currently hidden inside UpdateCloudlet.
	// Any update to the cloudlet will trigger updating the flavors.
	// For CRM-based cloudlets, GatherCloudletInfo is called every
	// time the CRM restarts (this is sub-optimal, as CRM restart
	// causes a control-plane outage).
	// In the future we may want to consider a combination of a periodic
	// thread that checks for flavor changes in addition to an API that
	// can trigger an immediate check.
	// This test uses a CCRM-based cloudlet because:
	// 1) the CCRM dummy uses a real CCRMHandler, so we test the actual
	// code that sends back CloudletInfos
	// 2) the CCRM needs to be tested to make sure it re-inits the platform
	// instance held in cache to update the env vars.
	cloudlet := &testutil.CloudletData()[0]
	cloudlet.Key.Name = "update-envvars-test"
	cloudlet.CrmOnEdge = false // test that CCRM re-inits platform in cache
	if cloudlet.EnvVar == nil {
		cloudlet.EnvVar = map[string]string{}
	}
	cloudlet.Zone = ""
	flavors := []*edgeproto.FlavorInfo{{
		Name:  "s1-2",
		Vcpus: 2,
		Ram:   8192,
		Disk:  16,
	}, {
		Name:  "s1-4",
		Vcpus: 4,
		Ram:   16384,
		Disk:  32,
	}}
	flavorsJSON, err := json.Marshal(flavors)
	require.Nil(t, err)
	cloudlet.EnvVar["FLAVORS"] = string(flavorsJSON)

	// create cloudlet
	err = apis.cloudletApi.CreateCloudlet(cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err)
	defer func() {
		err = apis.cloudletApi.DeleteCloudlet(cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
		require.Nil(t, err)
	}()

	// check cloudletInfo
	cloudletInfo := &edgeproto.CloudletInfo{}
	found := apis.cloudletInfoApi.cache.Get(&cloudlet.Key, cloudletInfo)
	require.True(t, found)
	require.Equal(t, flavors, cloudletInfo.Flavors)

	// update flavors env var
	updatedFlavors := append(flavors, &edgeproto.FlavorInfo{
		Name:  "s1-8",
		Vcpus: 8,
		Ram:   32768,
		Disk:  64,
	})
	flavorsJSON, err = json.Marshal(updatedFlavors)
	require.Nil(t, err)
	cloudlet.EnvVar["FLAVORS"] = string(flavorsJSON)
	cloudlet.Fields = []string{
		edgeproto.CloudletFieldEnvVar,
	}
	err = apis.cloudletApi.UpdateCloudlet(cloudlet, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err)
	// check cloudletInfo
	cloudletInfo = &edgeproto.CloudletInfo{}
	found = apis.cloudletInfoApi.cache.Get(&cloudlet.Key, cloudletInfo)
	require.True(t, found)
	require.Equal(t, updatedFlavors, cloudletInfo.Flavors)
}

type cmcOutStream struct {
	data []*edgeproto.CloudletManagedCluster
	grpc.ServerStream
	ctx context.Context
}

func (s *cmcOutStream) Send(obj *edgeproto.CloudletManagedCluster) error {
	s.data = append(s.data, obj)
	return nil
}

func (s *cmcOutStream) Context() context.Context {
	return s.ctx
}

func testCloudletManagedClusters(t *testing.T, ctx context.Context, apis *AllApis) {
	testCloudlet := edgeproto.Cloudlet{
		Key: edgeproto.CloudletKey{
			Name:         "managed-cluster-test",
			Organization: "managed-operator",
		},
		PlatformType:  platform.PlatformTypeFake,
		NumDynamicIps: 100,
		Location: dme.Loc{
			Latitude:  1,
			Longitude: 1,
		},
		AccessVars: map[string]string{
			"APIKey": "xyz",
		},
		EnvVar: map[string]string{
			"LOAD_MANAGED_CLUSTERS": "true",
		},
	}
	cloudletManagedClusters := []*edgeproto.CloudletManagedCluster{}
	for ii := range 3 {
		cmc := &edgeproto.CloudletManagedCluster{}
		cmc.Key.Name = fmt.Sprintf("managed-cluster-name-%d", ii)
		cmc.Key.Id = fmt.Sprintf("managed-cluster-id-%d", ii)
		cloudletManagedClusters = append(cloudletManagedClusters, cmc)
	}
	fake.CloudletManagedClusters = cloudletManagedClusters
	defer func() {
		fake.CloudletManagedClusters = nil
	}()

	// create cloudlet
	log.SpanLog(ctx, log.DebugLevelApi, "creating cloudlet", "key", testCloudlet.Key)
	err := apis.cloudletApi.CreateCloudlet(&testCloudlet, testutil.NewCudStreamoutCloudlet(ctx))
	require.Nil(t, err)
	defer func() {
		err = apis.cloudletApi.DeleteCloudlet(&testCloudlet, testutil.NewCudStreamoutCloudlet(ctx))
		require.Nil(t, err)
	}()

	// verify show cloudlet managed clusters
	cmcOutData := cmcOutStream{
		ctx: ctx,
	}
	filter := &edgeproto.CloudletManagedCluster{
		CloudletKey: testCloudlet.Key,
	}
	log.SpanLog(ctx, log.DebugLevelApi, "show cloudlet managed clusters", "key", testCloudlet.Key, "filter", filter)
	err = apis.cloudletApi.ShowCloudletManagedCluster(filter, &cmcOutData)
	require.Nil(t, err)
	require.Equal(t, len(cloudletManagedClusters), len(cmcOutData.data))
	for ii := range len(cloudletManagedClusters) {
		require.Equal(t, cloudletManagedClusters[ii].Key, cmcOutData.data[ii].Key)
	}

	// registering a non-existing cloudlet managed cluster must fail
	cmcBad := &edgeproto.CloudletManagedCluster{
		CloudletKey: testCloudlet.Key,
		ClusterKey: edgeproto.ClusterKey{
			Name:         "test-cluster",
			Organization: "test-organization",
		},
		Key: edgeproto.CloudletManagedClusterKey{
			Name: "non-existing",
		},
	}
	err = apis.cloudletApi.RegisterCloudletManagedCluster(cmcBad, testutil.NewCudStreamoutClusterInst(ctx))
	require.NotNil(t, err)
	require.Contains(t, err.Error(), `Cloudlet managed cluster name "non-existing" or id "" not found`)

	// run twice to verify we can re-register after deregistering
	for _ = range 2 {
		// register an existing cluster
		cmc := *cloudletManagedClusters[0]
		cmc.CloudletKey = testCloudlet.Key
		cmc.ClusterKey.Name = "managed-cluster-reservable"
		cmc.ClusterKey.Organization = edgeproto.OrganizationEdgeCloud
		cmc.Reservable = true
		err = apis.cloudletApi.RegisterCloudletManagedCluster(&cmc, testutil.NewCudStreamoutClusterInst(ctx))
		require.Nil(t, err)
		// check that clusterinst was created
		ci := edgeproto.ClusterInst{}
		found := apis.clusterInstApi.cache.Get(&cmc.ClusterKey, &ci)
		require.True(t, found)
		require.Equal(t, cmc.ClusterKey, ci.Key)
		require.Equal(t, cmc.CloudletKey, ci.CloudletKey)
		require.Equal(t, cmc.Key.Name, ci.CloudletManagedClusterName)
		require.Equal(t, cmc.Key.Id, ci.CloudletManagedClusterId)
		require.Equal(t, cmc.Reservable, ci.Reservable)

		// registering the same cloudlet managed cluster twice must fail
		err = apis.cloudletApi.RegisterCloudletManagedCluster(&cmc, testutil.NewCudStreamoutClusterInst(ctx))
		require.NotNil(t, err)
		require.Contains(t, err.Error(), fmt.Sprintf("cluster with infra id %q already registered", cmc.Key.Id))

		// deregister the cloudlet managed cluster
		err = apis.cloudletApi.DeregisterCloudletManagedCluster(&cmc, testutil.NewCudStreamoutClusterInst(ctx))
		require.Nil(t, err)
		// check that clusterinst was deleted
		found = apis.clusterInstApi.cache.Get(&cmc.ClusterKey, &ci)
		require.False(t, found)
	}
}
