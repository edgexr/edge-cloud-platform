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

package orm

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	edgeproto "github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/billing"
	"github.com/edgexr/edge-cloud-platform/pkg/cli"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/nodetest"
	"github.com/edgexr/edge-cloud-platform/pkg/fedewapi"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/federation"
	ormtestutil "github.com/edgexr/edge-cloud-platform/pkg/mc/orm/testutil"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormclient"
	"github.com/edgexr/edge-cloud-platform/pkg/mcctl/mctestclient"
	"github.com/edgexr/edge-cloud-platform/pkg/process"
	intprocess "github.com/edgexr/edge-cloud-platform/pkg/process"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
	"github.com/jarcoal/httpmock"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

var MockESUrl = "http://mock.es"
var PartnerApiKey = "dummyKey"
var ResourceValue = uint64(1030)

type CtrlObj struct {
	addr        string
	notifyAddr  string
	dc          *grpc.Server
	ds          *testutil.DummyServer
	dcnt        int
	operatorIds []string
	region      string
}

type OPAttr struct {
	uri          string
	fedAddr      string
	tokenAddr    string
	server       *Server
	ctrls        []CtrlObj
	vaultCleanup func()
}

type FederatorAttr struct {
	tokenAd     string
	tokenOper   string
	operatorId  string
	tokenDev    string
	developerId string
	fedCtxId    string
	countryCode string
	fedId       string
	fedName     string
	fedAddr     string
	region      string
	apiKey      string
}

func (o *OPAttr) CleanupOperatorPlatform(ctx context.Context) {
	for _, ctrl := range o.ctrls {
		ctrl.Cleanup(ctx)
	}
	o.server.Stop()
	if o.vaultCleanup != nil {
		o.vaultCleanup()
	}
}

func SetupControllerService(t *testing.T, ctx context.Context, operatorIds []string, region string, vroles *process.VaultRoles, vaultAddr string) *CtrlObj {
	ctrlAddr, err := cloudcommon.GetAvailablePort("127.0.0.1:0")
	require.Nil(t, err, "get available port")
	// run dummy controller - this always returns success
	// to all APIs directed to it, and does not actually
	// create or delete objects. We are mocking it out
	// so we can test rbac permissions.
	dc := grpc.NewServer(
		grpc.UnaryInterceptor(testutil.UnaryInterceptor),
		grpc.StreamInterceptor(testutil.StreamInterceptor),
		grpc.ForceServerCodec(&cloudcommon.ProtoCodec{}),
	)
	lis, err := net.Listen("tcp", ctrlAddr)
	require.Nil(t, err)
	ds := testutil.RegisterDummyServer(dc)
	go func() {
		dc.Serve(lis)
	}()
	// number of fake objects internally sent back by dummy server
	ds.ShowDummyCount = 0

	// number of dummy objects we add of each type and org
	dcnt := 3
	ds.SetDummyObjs(ctx, testutil.Create, "common", dcnt)
	for _, operatorId := range operatorIds {
		ds.SetDummyOrgObjs(ctx, testutil.Create, operatorId, dcnt)
	}

	// Setup resource-quota/infra-max limit for all the cloudlets
	allCloudletKeys := make(map[edgeproto.CloudletKey]int)
	clcnt := 0
	ds.CloudletCache.GetAllKeys(ctx, func(k *edgeproto.CloudletKey, modRev int64) {
		allCloudletKeys[*k] = clcnt
		clcnt++
	})
	for key, clcnt := range allCloudletKeys {
		// For some cloudlets set resource-quota and for some infra-max
		// so that zones can consider infra-max if resource-quota is missing
		// for calculating upper limit quota
		if clcnt%2 == 0 {
			clObj := edgeproto.Cloudlet{}
			require.True(t, ds.CloudletCache.Get(&key, &clObj))
			clObj.ResourceQuotas = []edgeproto.ResourceQuota{
				{
					Name:  cloudcommon.ResourceRamMb,
					Value: ResourceValue,
				},
				{
					Name:  cloudcommon.ResourceVcpus,
					Value: ResourceValue,
				},
				{
					Name:  cloudcommon.ResourceDiskGb,
					Value: ResourceValue,
				},
			}
			ds.CloudletCache.Update(ctx, &clObj, 0)
		} else {
			clObj := edgeproto.CloudletInfo{}
			require.True(t, ds.CloudletInfoCache.Get(&key, &clObj))
			clObj.ResourcesSnapshot.Info = []edgeproto.InfraResource{
				{
					Name:          cloudcommon.ResourceRamMb,
					InfraMaxValue: ResourceValue,
				},
				{
					Name:          cloudcommon.ResourceVcpus,
					InfraMaxValue: ResourceValue,
				},
				{
					Name:          cloudcommon.ResourceDiskGb,
					InfraMaxValue: ResourceValue,
				},
			}
			ds.CloudletInfoCache.Update(ctx, &clObj, 0)
		}
	}

	return &CtrlObj{
		addr:        ctrlAddr,
		ds:          ds,
		dcnt:        dcnt,
		dc:          dc,
		operatorIds: operatorIds,
		region:      region,
	}
}

func (c *CtrlObj) Cleanup(ctx context.Context) {
	c.ds.SetDummyObjs(ctx, testutil.Delete, "common", c.dcnt)
	for _, operatorId := range c.operatorIds {
		c.ds.SetDummyOrgObjs(ctx, testutil.Delete, operatorId, c.dcnt)
	}
	c.dc.Stop()
}

func SetupOperatorPlatform(t *testing.T, ctx context.Context, mockTransport *httpmock.MockTransport) (*OPAttr, []FederatorAttr) {
	mockESUrl := "http://mock.es"
	testAlertMgrAddr, err := InitAlertmgrMock(mockTransport)
	require.Nil(t, err)
	de := &nodetest.DummyEventsES{}
	de.InitHttpMock(mockESUrl, mockTransport)

	// run a dummy http server to mimic influxdb
	// this will reply with empty json to everything
	influxServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"data":[{"Messages": null,"Series": null}]}`)
	}))
	defer influxServer.Close()
	// =======================

	addr, err := cloudcommon.GetAvailablePort("127.0.0.1:0")
	require.Nil(t, err, "get available port")

	sqlAddr, err := cloudcommon.GetAvailablePort("127.0.0.1:0")
	require.Nil(t, err, "get available port")

	fedAddr, err := cloudcommon.GetAvailablePort("127.0.0.1:0")
	require.Nil(t, err, "get available port")

	regions := []string{"USEast", "USWest"}

	vp := process.Vault{
		Common: process.Common{
			Name: "vault",
		},
		ListenAddr: "https://127.0.0.1:8203",
		PKIDomain:  "edgecloud.net",
		Regions:    strings.Join(regions, ","),
	}
	_, vroles, vaultCleanup := testutil.NewVaultTestCluster(t, &vp)
	os.Setenv("VAULT_ROLE_ID", vroles.MCRoleID)
	os.Setenv("VAULT_SECRET_ID", vroles.MCSecretID)
	vcleanup := func() {
		os.Unsetenv("VAULT_ROLE_ID")
		os.Unsetenv("VAULT_SECRET_ID")
		vaultCleanup()
	}

	defaultConfig.DisableRateLimit = true
	defer func() {
		defaultConfig.DisableRateLimit = false
	}()

	uri := "http://" + addr + "/api/v1"
	config := ServerConfig{
		ServAddr:                 addr,
		SqlAddr:                  sqlAddr,
		FederationAddr:           fedAddr,
		FederationExternalAddr:   "http://" + fedAddr,
		ConsoleAddr:              "http://" + addr,
		RunLocal:                 true,
		InitLocal:                true,
		IgnoreEnv:                true,
		VaultAddr:                vp.ListenAddr,
		AlertMgrAddr:             testAlertMgrAddr,
		AlertmgrResolveTimout:    3 * time.Minute,
		UsageCheckpointInterval:  "MONTH",
		BillingPlatform:          billing.BillingTypeFake,
		DeploymentTag:            "local",
		AlertCache:               &edgeproto.AlertCache{},
		PublicAddr:               "http://mc.edgecloud.net",
		PasswordResetConsolePath: "#/passwordreset",
		VerifyEmailConsolePath:   "#/verify",
		testTransport:            mockTransport,
	}
	unitTestNodeMgrOps = []node.NodeOp{
		node.WithESUrls(MockESUrl),
	}
	defer func() {
		unitTestNodeMgrOps = []node.NodeOp{}
	}()

	server, err := RunServer(&config)
	require.Nil(t, err, "run server")

	Jwks.Init(config.vaultConfig, "region", "mcorm")
	Jwks.Meta.CurrentVersion = 1
	Jwks.Keys[1] = &vault.JWK{
		Secret:  "12345",
		Refresh: "1s",
	}

	countryCode := "US"
	operatorIds := []string{"operP", "operC"}
	developerIds := []string{"devP", "devC"}

	ctrl1 := SetupControllerService(t, ctx, operatorIds, regions[0], vroles, vp.ListenAddr)
	ctrl2 := SetupControllerService(t, ctx, operatorIds, regions[1], vroles, vp.ListenAddr)
	ctrlObjs := []CtrlObj{*ctrl1, *ctrl2}

	opAttr := OPAttr{
		uri:          uri,
		fedAddr:      fedAddr,
		tokenAddr:    addr,
		server:       server,
		ctrls:        ctrlObjs,
		vaultCleanup: vcleanup,
	}

	// wait till mc is ready
	err = server.WaitUntilReady()
	require.Nil(t, err, "server online")

	enforcer.LogEnforce(true)

	partnerApi.AllowPlainHttp()

	mcClient := mctestclient.NewClient(&ormclient.Client{})

	// Setup Controller, Orgs, Users
	// =============================
	// login as super user
	tokenAd, _, err := mcClient.DoLogin(uri, DefaultSuperuser, DefaultSuperpass, NoOTP, NoApiKeyId, NoApiKey)
	require.Nil(t, err, "login as superuser")

	// create controllers
	for _, ctrlObj := range ctrlObjs {
		ctrl := ormapi.Controller{
			Region:   ctrlObj.region,
			Address:  ctrlObj.addr,
			InfluxDB: influxServer.URL,
		}
		status, err := mcClient.CreateController(uri, tokenAd, &ctrl)
		require.Nil(t, err, "create controller")
		require.Equal(t, http.StatusOK, status)
	}

	ctrls, status, err := mcClient.ShowController(uri, tokenAd, ClientNoShowFilter)
	require.Nil(t, err, "show controllers")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 2, len(ctrls))

	selfFederators := []FederatorAttr{}
	for ii, operatorId := range operatorIds {
		// create an operator
		_, _, tokenOper := testCreateUserOrg(t, mcClient, uri, operatorId+"-user", OrgTypeOperator, operatorId)
		// admin allow non-edgebox cloudlets on operator org
		setOperatorOrgNoEdgeboxOnly(t, mcClient, uri, tokenAd, operatorId)
		// create a developer
		devId := developerIds[ii]
		_, _, tokenDev := testCreateUserOrg(t, mcClient, uri, devId+"-user", OrgTypeDeveloper, devId)
		fed := FederatorAttr{}
		fed.fedName = "fed-" + operatorId
		fed.tokenOper = tokenOper
		fed.operatorId = operatorId
		fed.tokenDev = tokenDev
		fed.developerId = devId
		fed.countryCode = countryCode
		fed.tokenAd = tokenAd
		fed.region = regions[ii]
		fed.fedAddr = "http://" + fedAddr
		selfFederators = append(selfFederators, fed)
	}

	return &opAttr, selfFederators
}

func TestFederation(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	unitTest = true

	mockTransport := httpmock.NewMockTransport()
	// any requests that don't have a registered URL will be fetched normally
	mockTransport.RegisterNoResponder(http.DefaultTransport.RoundTrip)

	// Setup Operator Platform with both Host OP and Consumer OP
	op, selfFederators := SetupOperatorPlatform(t, ctx, mockTransport)
	defer op.CleanupOperatorPlatform(ctx)

	for _, clientRun := range getUnitTestClientRuns(mockTransport) {
		testFederationInterconnect(t, ctx, clientRun, op, selfFederators)
		testFederationIgnorePartner(t, ctx, clientRun, op, selfFederators)
	}
}

func createAndShareProviderZones(t *testing.T, ctx context.Context, mcClient *mctestclient.Client, op *OPAttr, provAttr FederatorAttr, cloudlets []edgeproto.Cloudlet) []string {
	names := []string{}
	for _, cloudlet := range cloudlets {
		fedZone := &ormapi.ProviderZoneBase{
			ZoneId:      cloudlet.Key.Name,
			OperatorId:  provAttr.operatorId,
			CountryCode: provAttr.countryCode,
			Region:      provAttr.region,
			Cloudlets:   []string{cloudlet.Key.Name},
		}
		_, status, err := mcClient.CreateHostZoneBase(op.uri, provAttr.tokenOper, fedZone)
		require.Nil(t, err, "create provider zone basis")
		require.Equal(t, http.StatusOK, status)
		names = append(names, cloudlet.Key.Name)
	}
	zoneShReq := &ormapi.FederatedZoneShareRequest{
		FedHost: provAttr.fedName,
		Zones:   names,
	}
	_, status, err := mcClient.ShareHostZone(op.uri, provAttr.tokenOper, zoneShReq)
	require.Nil(t, err, "share zones")
	require.Equal(t, http.StatusOK, status)

	// Show shared zones
	showFedSelfZone := &cli.MapData{
		Namespace: cli.StructNamespace,
		Data: map[string]interface{}{
			"OperatorId":   provAttr.operatorId,
			"ProviderName": provAttr.fedName,
		},
	}
	sharedZones, status, err := mcClient.ShowHostZone(op.uri, provAttr.tokenOper, showFedSelfZone)
	require.Nil(t, err, "show shared self federator zones")
	require.Equal(t, http.StatusOK, status)
	idmap := map[string]struct{}{}
	for _, zoneId := range names {
		idmap[zoneId] = struct{}{}
	}
	// these zones are not yet registered
	for _, zone := range sharedZones {
		if _, found := idmap[zone.ZoneId]; !found {
			continue
		}
		require.Equal(t, federation.StatusUnregistered, zone.Status)
		delete(idmap, zone.ZoneId)
	}
	require.Equal(t, 0, len(idmap), "missing host zones: %v", idmap)
	return names
}

func checkConsumerZones(t *testing.T, ctx context.Context, mcClient *mctestclient.Client, op *OPAttr, consAttr FederatorAttr, expectedZones []string, expectedStatus string) {
	showConsZone := &cli.MapData{
		Namespace: cli.StructNamespace,
		Data: map[string]interface{}{
			"OperatorId":   consAttr.operatorId,
			"ConsumerName": consAttr.fedName,
		},
	}
	consZones, status, err := mcClient.ShowGuestZone(op.uri, consAttr.tokenOper, showConsZone)
	require.Nil(t, err, "show consumer zones")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, len(expectedZones), len(consZones))
	for _, zone := range consZones {
		require.Equal(t, expectedStatus, zone.Status, "status for zone %s is %s", zone.ZoneId, zone.Status)
	}
}

func testFederationInterconnect(t *testing.T, ctx context.Context, clientRun mctestclient.ClientRun, op *OPAttr, selfFederators []FederatorAttr) {
	mcClient := mctestclient.NewClient(clientRun)

	// federation host operator
	provAttr := selfFederators[0]
	// federation consumer operator
	consAttr := selfFederators[1]
	log.SpanLog(ctx, log.DebugLevelApi, "Host", "provAttr", provAttr)
	log.SpanLog(ctx, log.DebugLevelApi, "Consumer", "consAttr", provAttr)

	// Create federation host
	// ==========================
	provReq := &ormapi.FederationProvider{
		Name:       provAttr.fedName,
		OperatorId: provAttr.operatorId,
		Regions:    []string{provAttr.region},
		MyInfo: ormapi.Federator{
			CountryCode: provAttr.countryCode,
			MCC:         "340",
			MNC:         []string{"120", "121", "122"},
		},
	}
	provResp, status, err := mcClient.CreateFederationHost(op.uri, provAttr.tokenOper, provReq)
	require.Nil(t, err, "create federation provider")
	require.Equal(t, http.StatusOK, status)
	require.NotEmpty(t, provResp.ClientId)
	require.NotEmpty(t, provResp.ClientKey)
	require.NotEmpty(t, provResp.TargetAddr)

	// Show provider
	showProvFed := &cli.MapData{
		Namespace: cli.StructNamespace,
		Data: map[string]interface{}{
			"Name":       provAttr.fedName,
			"OperatorId": provAttr.operatorId,
		},
	}
	provShowResp, status, err := mcClient.ShowFederationHost(op.uri, provAttr.tokenOper, showProvFed)
	require.Nil(t, err, "show federation provider")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(provShowResp))
	provShow := provShowResp[0]
	require.Equal(t, provAttr.fedName, provShow.Name)
	require.Equal(t, provAttr.operatorId, provShow.OperatorId)
	require.Equal(t, provAttr.countryCode, provShow.MyInfo.CountryCode)
	require.Equal(t, pq.StringArray{"120", "121", "122"}, provShow.MyInfo.MNC)

	// Test org is inuse check
	err = orgInUseByFederatorCheck(ctx, provAttr.operatorId)
	require.NotNil(t, err, "org in use by FederationProvider")
	require.Contains(t, err.Error(), "in use by FederationProvider")

	// Get cloudlets that will be provided to consumer
	// ===============================================
	clList := []edgeproto.Cloudlet{}
	filter := &edgeproto.Cloudlet{
		Key: edgeproto.CloudletKey{
			Organization: provAttr.operatorId,
		},
	}
	clList, status, err = ormtestutil.TestShowCloudlet(mcClient, op.uri, provAttr.tokenOper, provAttr.region, filter)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 3, len(clList))

	// Create and share one provider zone. This tests that
	// consumer zones gets created during federation connect.
	// ===============================================
	sharedZones := []string{}
	pz := createAndShareProviderZones(t, ctx, mcClient, op, provAttr, clList[:1])
	sharedZones = append(sharedZones, pz...)

	// No consumer zones exist yet, because consumer
	// has not been created.
	// =======================================================
	checkConsumerZones(t, ctx, mcClient, op, consAttr, []string{}, federation.StatusUnregistered)

	// Create federation consumer.
	// This will cause MC to connect back to itself to
	// link consumer to provider.
	// ======================================
	consReq := &ormapi.FederationConsumer{
		Name:            consAttr.fedName,
		OperatorId:      consAttr.operatorId,
		Public:          true,
		PartnerAddr:     "http://" + op.fedAddr,
		PartnerTokenUrl: "http://" + op.tokenAddr + "/" + federation.TokenUrl,
		MyInfo: ormapi.Federator{
			CountryCode: consAttr.countryCode,
			MCC:         "123",
			MNC:         []string{"123", "345"},
		},
	}
	// This will fail, because auth creds are not present
	_, status, err = mcClient.CreateFederationGuest(op.uri, consAttr.tokenOper, consReq)
	require.NotNil(t, err, "create federation consumer no auth")
	require.Contains(t, err.Error(), "Missing OAuth Client Id")

	// add in auth creds and create
	consReq.ProviderClientId = provResp.ClientId
	consReq.ProviderClientKey = provResp.ClientKey
	_, status, err = mcClient.CreateFederationGuest(op.uri, consAttr.tokenOper, consReq)
	require.Nil(t, err, "create federation consumer")
	require.Equal(t, http.StatusOK, status)

	// Show consumer
	showConsFed := &cli.MapData{
		Namespace: cli.StructNamespace,
		Data: map[string]interface{}{
			"Name":       consAttr.fedName,
			"OperatorId": consAttr.operatorId,
		},
	}
	consShowResp, status, err := mcClient.ShowFederationGuest(op.uri, consAttr.tokenOper, showConsFed)
	require.Nil(t, err, "show federation consumer")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(consShowResp))
	consShow := consShowResp[0]
	require.Equal(t, consAttr.fedName, consShow.Name)
	require.Equal(t, consAttr.operatorId, consShow.OperatorId)
	require.Equal(t, pq.StringArray{"120", "121", "122"}, provShow.MyInfo.MNC)

	// Test org is inuse check
	err = orgInUseByFederatorCheck(ctx, consAttr.operatorId)
	require.NotNil(t, err, "org in use by FederationConsumer")
	require.Contains(t, err.Error(), "in use by FederationConsumer")

	// Federation creation with same federation provider should fail
	badConsReq := *consReq
	badConsReq.Name = "testErr"
	_, _, err = mcClient.CreateFederationGuest(op.uri, consAttr.tokenOper, &badConsReq)
	require.NotNil(t, err, "create federation consumer")
	require.Contains(t, err.Error(), "already in use by another consumer")

	// Show provider to get updated info
	provShowResp, status, err = mcClient.ShowFederationHost(op.uri, provAttr.tokenOper, showProvFed)
	require.Nil(t, err, "show federation provider")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(provShowResp))
	provShow = provShowResp[0]
	require.NotEmpty(t, provShow.PartnerNotifyDest)
	require.NotEmpty(t, provShow.PartnerNotifyTokenUrl)
	require.NotEmpty(t, provShow.PartnerNotifyClientId)
	require.Equal(t, provShow.Status, federation.StatusRegistered)

	// Validate partner federator info
	require.Equal(t, provShow.FederationContextId, consShow.FederationContextId)
	require.Equal(t, provShow.MyInfo.FederationId, consShow.PartnerInfo.FederationId)
	require.Equal(t, consShow.MyInfo.FederationId, provShow.PartnerInfo.FederationId)

	// Perms test: consOrg and provOrg should not be able to see
	// each other's federations
	// =====================================================
	checkProvFeds, status, err := mcClient.ShowFederationHost(op.uri, consAttr.tokenOper, showProvFed)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(checkProvFeds))
	// guest fed is public, so can be seen, but not all info
	checkConsFeds, status, err := mcClient.ShowFederationGuest(op.uri, provAttr.tokenOper, showConsFed)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(checkConsFeds))
	require.Zero(t, checkConsFeds[0].FederationContextId)

	// Update provider federation MCC value
	// ===============================
	updateFed := &cli.MapData{
		Namespace: cli.StructNamespace,
		Data:      make(map[string]interface{}),
	}
	updateFed.Data["OperatorId"] = provAttr.operatorId
	updateFed.Data["Name"] = provAttr.fedName
	updateFed.Data["MyInfo"] = map[string]interface{}{
		"MCC": "344",
		"MNC": []string{"123"},
	}
	_, status, err = mcClient.UpdateFederationHost(op.uri, provAttr.tokenOper, updateFed)
	require.Nil(t, err, "update federation provider")
	require.Equal(t, http.StatusOK, status)

	// Show federator info
	fedInfo, status, err := mcClient.ShowFederationHost(op.uri, provAttr.tokenOper, showProvFed)
	require.Nil(t, err, "show federation provider")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(fedInfo), "one entry")
	require.Equal(t, "344", fedInfo[0].MyInfo.MCC, "matches updated field")
	require.Equal(t, pq.StringArray{"123"}, fedInfo[0].MyInfo.MNC, "matches updated field")

	// TODO: test the consumer got notified of the new provider MCC value
	// ==================================================================

	// One consumer zone should have been created as part of
	// consumer create
	// =====================================================
	checkConsumerZones(t, ctx, mcClient, op, consAttr, sharedZones, federation.StatusUnregistered)

	// Negative tests for provider zone create
	// =======================================
	testZone := &ormapi.ProviderZoneBase{
		ZoneId:      "testzone",
		OperatorId:  provAttr.operatorId,
		CountryCode: provAttr.countryCode,
		Region:      provAttr.region,
		Cloudlets:   []string{clList[0].Key.Name},
		GeoLocation: "1.1,1.1",
	}

	// invalid region
	invalidZone := *testZone
	invalidZone.Region = "ABCD"
	_, status, err = mcClient.CreateHostZoneBase(op.uri, provAttr.tokenOper, &invalidZone)
	require.NotNil(t, err, "create federation zone fails")
	require.Contains(t, err.Error(), "Region \"ABCD\" not found")

	// invalid country code
	invalidZone = *testZone
	invalidZone.CountryCode = "ABCD"
	_, status, err = mcClient.CreateHostZoneBase(op.uri, provAttr.tokenOper, &invalidZone)
	require.NotNil(t, err, "create federation zone fails")
	require.Contains(t, err.Error(), "Invalid country code")

	// Create the rest of the federation provider zones
	// ================================================
	pz = createAndShareProviderZones(t, ctx, mcClient, op, provAttr, clList[1:])
	sharedZones = append(sharedZones, pz...)

	// Verify that all provider zones are created
	// =================================
	showZoneBase := &cli.MapData{
		Namespace: cli.StructNamespace,
		Data: map[string]interface{}{
			"OperatorId": provAttr.operatorId,
			"Region":     provAttr.region,
		},
	}
	selfFedZones, status, err := mcClient.ShowHostZoneBase(op.uri, provAttr.tokenOper, showZoneBase)
	require.Nil(t, err, "show provider zone bases")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, len(sharedZones), len(selfFedZones), "provider zone bases match")

	// Check consumer zones were created via notify and are
	// still unregistered
	// ====================================================
	checkConsumerZones(t, ctx, mcClient, op, consAttr, sharedZones, federation.StatusUnregistered)

	// Register consumer zone should fail if zoneid is invalid
	// ==================================================================
	zoneRegReq := &ormapi.FederatedZoneRegRequest{
		FedGuest: consAttr.fedName,
		Region:   consAttr.region,
		Zones:    []string{"badzone"},
	}
	_, _, err = mcClient.RegisterGuestZone(op.uri, consAttr.tokenAd, zoneRegReq)
	require.NotNil(t, err, "Zone not found")
	require.Contains(t, err.Error(), "Zone not found")

	// Register all the partner zones to be used
	// =========================================
	zoneRegReq.Zones = sharedZones
	_, status, err = mcClient.RegisterGuestZone(op.uri, consAttr.tokenOper, zoneRegReq)
	require.Nil(t, err, "register partner federator zone")
	require.Equal(t, http.StatusOK, status)

	// Verify that consumer zones are registered
	checkConsumerZones(t, ctx, mcClient, op, consAttr, sharedZones, federation.StatusRegistered)

	// Check that cloudlets have been created
	for _, zoneId := range sharedZones {
		// Verify that registered zone is added as cloudlet
		clLookup := ormapi.RegionCloudlet{
			Region: consAttr.region,
			Cloudlet: edgeproto.Cloudlet{
				Key: edgeproto.CloudletKey{
					Name:                  zoneId,
					Organization:          consAttr.fedName,
					FederatedOrganization: consAttr.operatorId,
				},
			},
		}
		selfFed1Cls, status, err := mcClient.ShowCloudlet(op.uri, consAttr.tokenOper, &clLookup)
		require.Nil(t, err, "show registered consumer zone as cloudlet")
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, 1, len(selfFed1Cls))

		// Verify that cloudlet infos were added as well
		clInfoLookup := ormapi.RegionCloudletInfo{
			Region: consAttr.region,
			CloudletInfo: edgeproto.CloudletInfo{
				Key: edgeproto.CloudletKey{
					Name:                  zoneId,
					Organization:          consAttr.fedName,
					FederatedOrganization: consAttr.operatorId,
				},
			},
		}
		clInfos, status, err := mcClient.ShowCloudletInfo(op.uri, consAttr.tokenOper, &clInfoLookup)
		require.Nil(t, err, "show registered consumer zone as cloudlet")
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, 1, len(clInfos))
	}

	// Verify that provider zones are marked as registered
	provZones, status, err := mcClient.ShowHostZone(op.uri, provAttr.tokenOper, nil)
	require.Nil(t, err, "show shared self federator zones")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, len(sharedZones), len(provZones))
	for _, zone := range provZones {
		require.Equal(t, federation.StatusRegistered, zone.Status)
	}

	// Consumer developer create Apps
	// ==============================

	// developer should be able to see federations to be able
	// to onboard images and Apps.
	feds, status, err := mcClient.ShowFederation(op.uri, consAttr.tokenDev, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(feds))
	require.Equal(t, consAttr.fedName, feds[0].Name)

	// create apps to be onboarded
	for _, app := range getConsApps(consAttr.developerId) {
		regionApp := ormapi.RegionApp{
			Region: consAttr.region,
			App:    app,
		}
		_, status, err = mcClient.CreateApp(op.uri, consAttr.tokenDev, &regionApp)
		require.Nil(t, err)
		require.Equal(t, http.StatusOK, status)
	}

	// Test File APIs
	// ==============

	// developer create image on federation
	consImages := getConsImages(consAttr.developerId, consAttr.fedName)
	for _, consImage := range consImages {
		_, status, err = mcClient.CreateGuestImage(op.uri, consAttr.tokenDev, consImage)
		require.Nil(t, err)
		require.Equal(t, http.StatusOK, status)
	}
	// check duplicates
	for _, consImage := range consImages {
		dup := *consImage
		// exact dup no error
		_, status, err = mcClient.CreateGuestImage(op.uri, consAttr.tokenDev, &dup)
		require.Nil(t, err)
		require.Equal(t, http.StatusOK, status)
		// mismatch duplicate yields error
		dup = *consImage
		dup.Checksum = "3209f029"
		_, status, err = mcClient.CreateGuestImage(op.uri, consAttr.tokenDev, &dup)
		require.NotNil(t, err)
		require.Equal(t, http.StatusBadRequest, status)
		require.Contains(t, err.Error(), "please choose a different Name")
	}

	// Test App APIs
	// ==============
	// also creates images and artefacts
	consAppsExp := []ormapi.ConsumerApp{}
	for _, app := range getConsApps(consAttr.developerId) {
		req := ormapi.ConsumerApp{}
		req.Region = consAttr.region
		req.AppName = app.Key.Name
		req.AppOrg = app.Key.Organization
		req.AppVers = app.Key.Version
		req.FederationName = consAttr.fedName
		_, status, err = mcClient.OnboardGuestApp(op.uri, consAttr.tokenDev, &req)
		fmt.Printf("***** Onboard consumer app %d, %s\n", status, err)
		require.Nil(t, err)
		require.Equal(t, http.StatusOK, status)
		consAppsExp = append(consAppsExp, req)
	}
	consAppImages := getConsAppImages(t, consAttr.developerId, consAttr.fedName)
	consImagesExp := append(consImages, consAppImages...)

	// developer can see created images
	consImagesShow, status, err := mcClient.ShowGuestImage(op.uri, consAttr.tokenDev, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, len(consImagesExp), len(consImagesShow))
	for ii := range consImagesExp {
		exp := consImagesExp[ii]
		act := consImagesShow[ii]
		require.NotZero(t, act.ID)
		require.Equal(t, exp.Organization, act.Organization)
		require.Equal(t, exp.FederationName, act.FederationName)
		require.Equal(t, federation.ImageStatusReady, act.Status)
	}
	// developer can see created apps
	consAppsShow, status, err := mcClient.ShowGuestApp(op.uri, consAttr.tokenDev, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, len(consAppsExp), len(consAppsShow))
	for ii := range consAppsExp {
		exp := consAppsExp[ii]
		act := consAppsShow[ii]
		require.NotZero(t, act.ID)
		require.Equal(t, exp.AppName, act.AppName)
		require.Equal(t, exp.AppOrg, act.AppOrg)
		require.Equal(t, exp.AppVers, act.AppVers)
		require.Equal(t, exp.FederationName, act.FederationName)
	}

	// provider can see created images
	provImagesShow, status, err := mcClient.ShowHostImage(op.uri, provAttr.tokenOper, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, len(consImagesExp), len(provImagesShow))
	for ii := range provImagesShow {
		exp := consImagesShow[ii]
		act := provImagesShow[ii]
		require.Equal(t, provAttr.fedName, act.FederationName)
		require.Equal(t, exp.ID, act.FileID)
		require.Equal(t, util.DNSSanitize(exp.Organization), act.AppProviderId)
		require.Equal(t, exp.Type, act.Type)
		require.Equal(t, federation.ImageStatusReady, act.Status)
	}
	// provider can see created providerArtefacts
	provArtsShow, status, err := mcClient.ShowHostArtefact(op.uri, provAttr.tokenOper, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, len(consAppsExp), len(provArtsShow))
	for ii := range provArtsShow {
		exp := consAppsShow[ii]
		act := provArtsShow[ii]
		require.Equal(t, provAttr.fedName, act.FederationName)
		require.Equal(t, exp.ID, act.AppName)
		require.Equal(t, exp.AppVers, act.AppVers)
		require.Equal(t, util.DNSSanitize(exp.AppOrg), act.AppProviderId)
	}
	// provider can see created providerApps
	provAppsShow, status, err := mcClient.ShowHostApp(op.uri, provAttr.tokenOper, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, len(consAppsExp), len(provAppsShow))
	for ii := range provAppsShow {
		act := provAppsShow[ii]
		require.Equal(t, provAttr.fedName, act.FederationName)
	}
	// provider can see created regional apps
	provAppFilter := ormapi.RegionApp{
		Region: provAttr.region,
	}
	appsShow, status, err := mcClient.ShowApp(op.uri, provAttr.tokenOper, &provAppFilter)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, len(consAppsExp), len(appsShow))
	// app cannot be deleted via DeleteApp, must be via EWBI
	for _, app := range appsShow {
		rapp := ormapi.RegionApp{
			Region: provAttr.region,
			App:    app,
		}
		_, status, err = mcClient.DeleteApp(op.uri, provAttr.tokenAd, &rapp)
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "Cannot delete App created via federation")
	}

	// check direct get file funcs
	for _, image := range provImagesShow {
		findImage := ormapi.ConsumerImage{
			FederationName: consAttr.fedName,
			ID:             image.FileID,
		}
		file, status, err := mcClient.GetFederationFile(op.uri, consAttr.tokenOper, &findImage)
		require.Nil(t, err)
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, image.FileID, file.FileId)
		require.Equal(t, image.AppProviderId, file.AppProviderId)
		if image.Description == "" {
			require.Nil(t, file.FileDescription)
		} else {
			require.NotNil(t, file.FileDescription)
			require.Equal(t, image.Description, *file.FileDescription)
		}
		require.Equal(t, image.Name, file.FileName)
		require.Equal(t, image.Version, file.FileVersionInfo)
		require.Equal(t, image.Type, string(file.FileType))
		if image.Checksum == "" {
			require.Nil(t, file.Checksum)
		} else {
			require.NotNil(t, file.Checksum)
			require.Equal(t, image.Checksum, *file.Checksum)
		}
		require.Equal(t, fedewapi.CPUARCHTYPE_X86_64, file.ImgInsSetArch)
	}

	// --------+
	// Cleanup |
	// --------+

	// Delete Apps
	for _, app := range getConsApps(consAttr.developerId) {
		req := ormapi.ConsumerApp{}
		req.AppName = app.Key.Name
		req.AppOrg = app.Key.Organization
		req.AppVers = app.Key.Version
		req.FederationName = consAttr.fedName
		_, status, err = mcClient.DeboardGuestApp(op.uri, consAttr.tokenDev, &req)
		require.Nil(t, err)
		require.Equal(t, http.StatusOK, status)
	}

	// consumer apps should be empty
	consAppsShow, status, err = mcClient.ShowGuestApp(op.uri, consAttr.tokenDev, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(consAppsShow))
	// provider artefacts should be empty
	provArtsShow, status, err = mcClient.ShowHostArtefact(op.uri, provAttr.tokenOper, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(provArtsShow))
	// provider app should be empty
	provAppsShow, status, err = mcClient.ShowHostApp(op.uri, provAttr.tokenOper, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(provAppsShow))
	// provider regional apps should be empty
	appsShow, status, err = mcClient.ShowApp(op.uri, provAttr.tokenOper, &provAppFilter)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(appsShow))

	// Delete images
	// =============
	for _, image := range consImagesShow {
		_, status, err = mcClient.DeleteGuestImage(op.uri, consAttr.tokenDev, &image)
		require.Nil(t, err)
		require.Equal(t, http.StatusOK, status)
	}
	consImagesShow, status, err = mcClient.ShowGuestImage(op.uri, consAttr.tokenDev, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(consImagesShow))
	provImagesShow, status, err = mcClient.ShowHostImage(op.uri, provAttr.tokenOper, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(provImagesShow))

	// delete regional app definitions
	for _, app := range getConsApps(consAttr.developerId) {
		regionApp := ormapi.RegionApp{
			Region: consAttr.region,
			App:    app,
		}
		_, status, err = mcClient.DeleteApp(op.uri, consAttr.tokenDev, &regionApp)
		require.Nil(t, err)
		require.Equal(t, http.StatusOK, status)
	}

	// Delete of either Provider should fail if there
	// are registered zones. Consumer will automatically deregister zones.
	// =================================================================
	provDelReq := &ormapi.FederationProvider{
		OperatorId: provAttr.operatorId,
		Name:       provAttr.fedName,
	}
	_, _, err = mcClient.DeleteFederationHost(op.uri, provAttr.tokenOper, provDelReq)
	require.NotNil(t, err, "delete federation provider")
	require.Contains(t, err.Error(), "Cannot delete Host when the following zones are still registered")

	// Unshare provider zone should fail if it's still in use
	// ======================================================
	zoneShReq := &ormapi.FederatedZoneShareRequest{
		FedHost: provAttr.fedName,
		Zones:   sharedZones,
	}
	_, status, err = mcClient.UnshareHostZone(op.uri, provAttr.tokenOper, zoneShReq)
	require.NotNil(t, err, "unshare zones")
	require.Contains(t, err.Error(), "Cannot unshare registered zone")

	// Deregister all the partner zones
	// ================================
	zoneRegReq = &ormapi.FederatedZoneRegRequest{
		FedGuest: consAttr.fedName,
		Region:   consAttr.region,
		Zones:    sharedZones,
	}
	_, status, err = mcClient.DeregisterGuestZone(op.uri, consAttr.tokenOper, zoneRegReq)
	require.Nil(t, err, "deregister consumer zones")
	require.Equal(t, http.StatusOK, status)

	// check that federated cloudlets have been deleted
	for _, zoneId := range sharedZones {
		clLookup := ormapi.RegionCloudlet{
			Region: consAttr.region,
			Cloudlet: edgeproto.Cloudlet{
				Key: edgeproto.CloudletKey{
					Name:                  zoneId,
					Organization:          consAttr.fedName,
					FederatedOrganization: consAttr.operatorId,
				},
			},
		}
		selfFed1Cls, status, err := mcClient.ShowCloudlet(op.uri, consAttr.tokenOper, &clLookup)
		require.Nil(t, err, "partner zone is removed as cloudlet")
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, 0, len(selfFed1Cls))
		clInfoLookup := ormapi.RegionCloudletInfo{
			Region: consAttr.region,
			CloudletInfo: edgeproto.CloudletInfo{
				Key: clLookup.Cloudlet.Key,
			},
		}
		// Evict cloudletinfo manually, as normally
		// controller DeleteCloudlet would do it.
		_, status, err = mcClient.EvictCloudletInfo(op.uri, consAttr.tokenOper, &clInfoLookup)
		require.Nil(t, err, "remove cloudletinfo")
		require.Equal(t, http.StatusOK, status)
	}

	// Check that provider zones are now unregistered
	provZones, status, err = mcClient.ShowHostZone(op.uri, provAttr.tokenOper, nil)
	require.Nil(t, err, "show shared provider zones")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, len(sharedZones), len(provZones))
	for _, zone := range provZones {
		require.Equal(t, federation.StatusUnregistered, zone.Status)
	}

	// check that consumer zones are now unregistered
	checkConsumerZones(t, ctx, mcClient, op, consAttr, sharedZones, federation.StatusUnregistered)

	// Delete a single provider zone to trigger delete of the
	// matching consumer zone (tests notify zone remove)
	// ======================================================
	zoneShReq.Zones = sharedZones[:1]
	_, status, err = mcClient.UnshareHostZone(op.uri, provAttr.tokenOper, zoneShReq)
	require.Nil(t, err, "unshare zones")
	require.Equal(t, http.StatusOK, status)

	// provider zone should be removed
	provZones, status, err = mcClient.ShowHostZone(op.uri, provAttr.tokenOper, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, len(sharedZones[1:]), len(provZones))

	// consumer zone should be removed
	consZones, status, err := mcClient.ShowGuestZone(op.uri, consAttr.tokenOper, nil)
	require.Nil(t, err, "show consumer zones")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, len(sharedZones[1:]), len(consZones))

	// Delete federation between provider and consumer
	// TODO: test delete of provider first, should have same outcome
	// as long as all zones are unregistered.
	// ========================================================
	consDelReq := &ormapi.FederationConsumer{
		OperatorId: consAttr.operatorId,
		Name:       consAttr.fedName,
	}
	_, status, err = mcClient.DeleteFederationGuest(op.uri, consAttr.tokenOper, consDelReq)
	require.Nil(t, err, "delete federation guest")
	require.Equal(t, http.StatusOK, status)

	// check consumer is gone
	checkConsFeds, status, err = mcClient.ShowFederationGuest(op.uri, provAttr.tokenOper, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(checkConsFeds))

	// check provider is unregistered
	provShowResp, status, err = mcClient.ShowFederationHost(op.uri, provAttr.tokenOper, nil)
	require.Nil(t, err, "show federation provider")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(provShowResp))
	require.Equal(t, provShowResp[0].Status, federation.StatusUnregistered)

	// check that all consumer zones have been removed
	consZones, status, err = mcClient.ShowGuestZone(op.uri, consAttr.tokenOper, nil)
	require.Nil(t, err, "show consumer zones")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(consZones))

	// Delete FederationProvider
	// =========================
	_, status, err = mcClient.DeleteFederationHost(op.uri, provAttr.tokenOper, provReq)
	require.Nil(t, err, "delete federation provider")
	require.Equal(t, http.StatusOK, status)

	// check that federation provider is gone
	provShowResp, status, err = mcClient.ShowFederationHost(op.uri, provAttr.tokenOper, nil)
	require.Nil(t, err, "show federation provider")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(provShowResp))

	// check that all provider zones have been removed
	provZones, status, err = mcClient.ShowHostZone(op.uri, provAttr.tokenOper, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(provZones))

	// Clean up ProviderZoneBase as they are still present
	// because they are not associated with any FederationProvider.
	// ============================================================
	selfFedZones, status, err = mcClient.ShowHostZoneBase(op.uri, provAttr.tokenOper, nil)
	require.Nil(t, err, "show provider zone bases")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, len(sharedZones), len(selfFedZones), "provider zone bases match")

	// delete provider zones bases
	for _, cloudlet := range clList {
		fedZone := &ormapi.ProviderZoneBase{
			ZoneId:      cloudlet.Key.Name,
			OperatorId:  provAttr.operatorId,
			CountryCode: provAttr.countryCode,
			Region:      provAttr.region,
			Cloudlets:   []string{cloudlet.Key.Name},
		}
		_, status, err := mcClient.DeleteHostZoneBase(op.uri, provAttr.tokenOper, fedZone)
		require.Nil(t, err, "delete provider zone basis")
		require.Equal(t, http.StatusOK, status)
	}

	// check that they are gone
	selfFedZones, status, err = mcClient.ShowHostZoneBase(op.uri, provAttr.tokenOper, nil)
	require.Nil(t, err, "show provider zone bases")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(selfFedZones), "provider zone bases match")
}

func testFederationIgnorePartner(t *testing.T, ctx context.Context, clientRun mctestclient.ClientRun, op *OPAttr, selfFederators []FederatorAttr) {
	mcClient := mctestclient.NewClient(clientRun)

	// federation provider operator
	provAttr := selfFederators[0]
	// federation consumer operator
	consAttr := selfFederators[1]

	// Create federation provider
	// ==========================
	provReq := &ormapi.FederationProvider{
		Name:       provAttr.fedName,
		OperatorId: provAttr.operatorId,
		Regions:    []string{provAttr.region},
		MyInfo: ormapi.Federator{
			CountryCode: provAttr.countryCode,
			MCC:         "340",
			MNC:         []string{"120", "121", "122"},
		},
	}
	provResp, status, err := mcClient.CreateFederationHost(op.uri, provAttr.tokenOper, provReq)
	require.Nil(t, err, "create federation provider")
	require.Equal(t, http.StatusOK, status)

	// Get cloudlets that will be provided to consumer
	// ===============================================
	clList := []edgeproto.Cloudlet{}
	filter := &edgeproto.Cloudlet{
		Key: edgeproto.CloudletKey{
			Organization: provAttr.operatorId,
		},
	}
	clList, status, err = ormtestutil.TestShowCloudlet(mcClient, op.uri, provAttr.tokenOper, provAttr.region, filter)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 3, len(clList))

	// Create and share one provider zone. This tests that
	// consumer zones gets created during federation connect.
	// ===============================================
	sharedZones := []string{}
	pz := createAndShareProviderZones(t, ctx, mcClient, op, provAttr, clList)
	sharedZones = append(sharedZones, pz...)

	// Create federation consumer.
	// This will cause MC to connect back to itself to
	// link consumer to provider.
	// ======================================
	consReq := &ormapi.FederationConsumer{
		Name:            consAttr.fedName,
		OperatorId:      consAttr.operatorId,
		Public:          true,
		PartnerAddr:     "http://" + op.fedAddr,
		PartnerTokenUrl: "http://" + op.tokenAddr + "/" + federation.TokenUrl,
		MyInfo: ormapi.Federator{
			CountryCode: consAttr.countryCode,
			MCC:         "123",
			MNC:         []string{"123", "345"},
		},
		ProviderClientId:  provResp.ClientId,
		ProviderClientKey: provResp.ClientKey,
	}
	_, status, err = mcClient.CreateFederationGuest(op.uri, consAttr.tokenOper, consReq)
	require.Nil(t, err, "create federation consumer")
	require.Equal(t, http.StatusOK, status)

	// Register all the partner zones to be used
	// =========================================
	zoneRegReq := &ormapi.FederatedZoneRegRequest{
		FedGuest: consAttr.fedName,
		Region:   consAttr.region,
		Zones:    sharedZones,
	}
	_, status, err = mcClient.RegisterGuestZone(op.uri, consAttr.tokenOper, zoneRegReq)
	require.Nil(t, err, "register partner federator zone")
	require.Equal(t, http.StatusOK, status)

	// Verify that consumer zones are registered
	checkConsumerZones(t, ctx, mcClient, op, consAttr, sharedZones, federation.StatusRegistered)

	// Consumer developer create Apps
	// ==============================
	consApps := getConsApps(consAttr.developerId)
	for _, app := range consApps {
		regionApp := ormapi.RegionApp{
			Region: consAttr.region,
			App:    app,
		}
		_, status, err = mcClient.CreateApp(op.uri, consAttr.tokenDev, &regionApp)
		require.Nil(t, err)
		require.Equal(t, http.StatusOK, status)
	}
	// onboard apps
	for _, app := range getConsApps(consAttr.developerId) {
		req := ormapi.ConsumerApp{}
		req.Region = consAttr.region
		req.AppName = app.Key.Name
		req.AppOrg = app.Key.Organization
		req.AppVers = app.Key.Version
		req.FederationName = consAttr.fedName
		_, status, err = mcClient.OnboardGuestApp(op.uri, consAttr.tokenDev, &req)
		fmt.Printf("***** Onboard consumer app %d, %s\n", status, err)
		require.Nil(t, err)
		require.Equal(t, http.StatusOK, status)
	}

	// Provider unsafe delete all data
	// ===============================
	// apps
	provAppsShow, status, err := mcClient.ShowHostApp(op.uri, provAttr.tokenOper, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, len(consApps), len(provAppsShow))
	for _, app := range provAppsShow {
		_, status, err = mcClient.UnsafeDeleteHostApp(op.uri, provAttr.tokenOper, &app)
		require.Nil(t, err)
		require.Equal(t, http.StatusOK, status)
	}
	provAppsShow, status, err = mcClient.ShowHostApp(op.uri, provAttr.tokenOper, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(provAppsShow))
	// artefacts
	provArtsShow, status, err := mcClient.ShowHostArtefact(op.uri, provAttr.tokenOper, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, len(consApps), len(provArtsShow))
	for _, art := range provArtsShow {
		_, status, err = mcClient.UnsafeDeleteHostArtefact(op.uri, provAttr.tokenOper, &art)
		require.Nil(t, err)
		require.Equal(t, http.StatusOK, status)
	}
	provArtsShow, status, err = mcClient.ShowHostArtefact(op.uri, provAttr.tokenOper, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(provArtsShow))
	// images
	consAppImages := getConsAppImages(t, consAttr.developerId, consAttr.fedName)
	provImagesShow, status, err := mcClient.ShowHostImage(op.uri, provAttr.tokenOper, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, len(consAppImages), len(provImagesShow))
	for _, image := range provImagesShow {
		_, status, err = mcClient.UnsafeDeleteHostImage(op.uri, provAttr.tokenOper, &image)
		require.Nil(t, err)
		require.Equal(t, http.StatusOK, status)
	}
	provImagesShow, status, err = mcClient.ShowHostImage(op.uri, provAttr.tokenOper, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(provImagesShow))
	// zones
	zoneShReq := &ormapi.FederatedZoneShareRequest{
		FedHost: provAttr.fedName,
		Zones:   sharedZones,
	}
	queryParams := map[string]string{
		"ignorepartner": "true",
	}
	_, status, err = mcClient.UnshareHostZone(op.uri, provAttr.tokenOper, zoneShReq, mctestclient.WithQueryParams(queryParams))
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	provZones, status, err := mcClient.ShowHostZone(op.uri, provAttr.tokenOper, nil)
	require.Nil(t, err, "show shared self federator zones")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(provZones))
	// zone bases
	for _, cloudlet := range clList {
		fedZone := &ormapi.ProviderZoneBase{
			ZoneId:      cloudlet.Key.Name,
			OperatorId:  provAttr.operatorId,
			CountryCode: provAttr.countryCode,
			Region:      provAttr.region,
			Cloudlets:   []string{cloudlet.Key.Name},
		}
		_, status, err := mcClient.DeleteHostZoneBase(op.uri, provAttr.tokenOper, fedZone)
		require.Nil(t, err, "delete provider zone basis")
		require.Equal(t, http.StatusOK, status)
	}
	// provider
	_, status, err = mcClient.DeleteFederationHost(op.uri, provAttr.tokenOper, provReq, mctestclient.WithQueryParams(queryParams))
	require.Nil(t, err, "delete federation provider")
	require.Equal(t, http.StatusOK, status)
	// check that federation provider is gone
	provShowResp, status, err := mcClient.ShowFederationHost(op.uri, provAttr.tokenOper, nil)
	require.Nil(t, err, "show federation provider")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(provShowResp))

	// Consumer delete all data, ignoring partner
	// ==========================================
	// apps
	for _, app := range getConsApps(consAttr.developerId) {
		req := ormapi.ConsumerApp{}
		req.AppName = app.Key.Name
		req.AppOrg = app.Key.Organization
		req.AppVers = app.Key.Version
		req.FederationName = consAttr.fedName
		_, status, err = mcClient.DeboardGuestApp(op.uri, consAttr.tokenDev, &req, mctestclient.WithQueryParams(queryParams))
		require.Nil(t, err)
		require.Equal(t, http.StatusOK, status)
	}
	// consumer apps should be empty
	consAppsShow, status, err := mcClient.ShowGuestApp(op.uri, consAttr.tokenDev, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(consAppsShow))
	// images
	consImagesShow, status, err := mcClient.ShowGuestImage(op.uri, consAttr.tokenDev, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, len(consAppImages), len(consImagesShow))
	for _, image := range consImagesShow {
		_, status, err = mcClient.DeleteGuestImage(op.uri, consAttr.tokenDev, &image, mctestclient.WithQueryParams(queryParams))
		require.Nil(t, err)
		require.Equal(t, http.StatusOK, status)
	}
	consImagesShow, status, err = mcClient.ShowGuestImage(op.uri, consAttr.tokenDev, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(consImagesShow))
	// delete regional app definitions
	for _, app := range getConsApps(consAttr.developerId) {
		regionApp := ormapi.RegionApp{
			Region: consAttr.region,
			App:    app,
		}
		_, status, err = mcClient.DeleteApp(op.uri, consAttr.tokenDev, &regionApp)
		require.Nil(t, err)
		require.Equal(t, http.StatusOK, status)
	}
	// zones
	zoneRegReq = &ormapi.FederatedZoneRegRequest{
		FedGuest: consAttr.fedName,
		Region:   consAttr.region,
		Zones:    sharedZones,
	}
	_, status, err = mcClient.DeregisterGuestZone(op.uri, consAttr.tokenOper, zoneRegReq, mctestclient.WithQueryParams(queryParams))
	require.Nil(t, err, "deregister consumer zones")
	require.Equal(t, http.StatusOK, status)
	// consumer
	consDelReq := &ormapi.FederationConsumer{
		OperatorId: consAttr.operatorId,
		Name:       consAttr.fedName,
	}
	_, status, err = mcClient.DeleteFederationGuest(op.uri, consAttr.tokenOper, consDelReq, mctestclient.WithQueryParams(queryParams))
	require.Nil(t, err, "delete federation consumer")
	require.Equal(t, http.StatusOK, status)
	// check consumer is gone
	checkConsFeds, status, err := mcClient.ShowFederationGuest(op.uri, provAttr.tokenOper, nil)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(checkConsFeds))
}

type DBExec struct {
	obj  interface{}
	pass bool
}

func StartDB() (*intprocess.Sql, *gorm.DB, error) {
	sqlAddrHost := "127.0.0.1"
	sqlAddrPort := "51001"
	dbUser := "testuser"
	dbName := "mctestdb"
	sql := intprocess.Sql{
		Common: process.Common{
			Name: "sql1",
		},
		DataDir:  "./.postgres",
		HttpAddr: sqlAddrHost + ":" + sqlAddrPort,
		Username: dbUser,
		Dbname:   dbName,
	}
	_, err := os.Stat(sql.DataDir)
	if os.IsNotExist(err) {
		sql.InitDataDir()
	}
	err = sql.StartLocal("")
	if err != nil {
		return nil, nil, fmt.Errorf("local sql start failed: %v", err)
	}

	db, err := gorm.Open("postgres", fmt.Sprintf("host=%s port=%s user=%s dbname=%s sslmode=disable", sqlAddrHost, sqlAddrPort, dbUser, dbName))
	if err != nil {
		sql.StopLocal()
		return nil, nil, fmt.Errorf("failed to open gorm object: %v", err)
	}
	return &sql, db, nil
}

type FederationProvider struct {
	ID                     uint             `gorm:"primary_key"`
	Name                   string           `gorm:"unique_index:fedprovindex;type:text;not null"`
	OperatorId             string           `gorm:"unique_index:fedprovindex;type:citext REFERENCES organizations(name);not null"`
	Regions                pq.StringArray   `gorm:"type:text[]"`
	FederationContextId    string           `gorm:"unique;not null"`
	MyInfo                 ormapi.Federator `gorm:"embedded;embedded_prefix:my_"`
	PartnerInfo            ormapi.Federator `gorm:"embedded;embedded_prefix:partner_"`
	PartnerNotifyDest      string
	PartnerNotifyTokenUrl  string
	PartnerNotifyClientId  string
	PartnerNotifyClientKey string
	Status                 string
	ProviderClientId       string
	CreatedAt              time.Time `json:",omitempty"`
	UpdatedAt              time.Time `json:",omitempty"`
}

type FederationConsumer struct {
	ID                  uint   `gorm:"primary_key"`
	Name                string `gorm:"unique_index:fedconsindex;type:text;not null"`
	OperatorId          string `gorm:"unique_index:fedconsindex;type:citext REFERENCES organizations(name);not null"`
	PartnerAddr         string `gorm:"not null"`
	PartnerTokenUrl     string
	Region              string `gorm:"not null"`
	FederationContextId string
	MyInfo              ormapi.Federator `gorm:"embedded;embedded_prefix:my_"`
	PartnerInfo         ormapi.Federator `gorm:"embedded;embedded_prefix:partner_"`
	AutoRegisterZones   bool
	Status              string
	ProviderClientId    string
	ProviderClientKey   string
	NotifyClientId      string
	CreatedAt           time.Time `json:",omitempty"`
	UpdatedAt           time.Time `json:",omitempty"`
}

type ProviderZone struct {
	ZoneId               string `gorm:"primary_key"`
	ProviderName         string `gorm:"primary_key"`
	OperatorId           string `gorm:"primary_key;type:citext"`
	Status               string
	PartnerNotifyZoneURI string
}

type ConsumerZone struct {
	ZoneId           string `gorm:"primary_key"`
	ConsumerName     string `gorm:"primary_key"`
	OperatorId       string `gorm:"primary_key;type:citext"`
	GeoLocation      string
	GeographyDetails string
	Status           string
}

type testFedObjOpts struct {
	runUpgrade      bool
	idempotentCheck bool
}

func TestGormFederationObjs(t *testing.T) {
	opts := testFedObjOpts{}
	testGormFederationObjs(t, opts)
}

func TestGormFederationObjsUpgrade(t *testing.T) {
	opts := testFedObjOpts{
		runUpgrade: true,
	}
	testGormFederationObjs(t, opts)
}

func TestGormFederationObjsRestart(t *testing.T) {
	opts := testFedObjOpts{
		runUpgrade:      true,
		idempotentCheck: true,
	}
	testGormFederationObjs(t, opts)
}

// Test both upgrade changes to federation objects and constraints
func testGormFederationObjs(t *testing.T, opts testFedObjOpts) {
	log.SetDebugLevel(log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	sql, db, err := StartDB()
	require.Nil(t, err, "start sql db")
	defer sql.StopLocal()
	defer db.Close()

	dbObjsOld := []interface{}{
		&ormapi.Organization{},
		&FederationProvider{},
		&FederationConsumer{},
		&ormapi.ProviderZoneBase{},
		&ProviderZone{},
		&ConsumerZone{},
	}
	dbObjs := []interface{}{
		&ormapi.Organization{},
		&ormapi.FederationProvider{},
		&ormapi.FederationConsumer{},
		&ormapi.ProviderZoneBase{},
		&ormapi.ProviderZone{},
		&ormapi.ConsumerZone{},
		&ormapi.ProviderImage{},
		&ormapi.ConsumerImage{},
		&ormapi.ConsumerApp{},
		&ormapi.ProviderArtefact{},
		&ormapi.ProviderApp{},
	}

	// drop based on the order of dependency
	for ii := len(dbObjs) - 1; ii >= 0; ii-- {
		db.DropTableIfExists(dbObjs[ii])
	}
	db.LogMode(true)

	if opts.runUpgrade {
		// create old objects
		db.AutoMigrate(dbObjsOld...)

		// set old constraints
		err = db.Exec(`ALTER TABLE provider_zones ADD CONSTRAINT fk_provider_nameoperator_id_constraint FOREIGN KEY ("provider_name","operator_id") REFERENCES federation_providers("name","operator_id")`).Error
		require.Nil(t, err)
		err = db.Exec(`ALTER TABLE provider_zones ADD CONSTRAINT fk_zone_idoperator_id_constraint FOREIGN KEY ("zone_id","operator_id") REFERENCES provider_zone_bases("zone_id","operator_id")`).Error
		require.Nil(t, err)
		err = db.Exec(`ALTER TABLE consumer_zones ADD CONSTRAINT fk_consumer_nameoperator_id_constraint FOREIGN KEY ("consumer_name","operator_id") REFERENCES federation_consumers("name","operator_id")`).Error
		require.Nil(t, err)
	}

	init := func() {
		// table upgrade
		err = fixFederationTables(ctx, db)
		require.Nil(t, err)

		db.AutoMigrate(dbObjs...)

		err = InitFederationAPIConstraints(db)
		require.Nil(t, err, "set constraints")
	}
	init()

	if opts.idempotentCheck {
		init()
	}

	tests := []DBExec{{
		obj:  &ormapi.Organization{Name: "GDDT"},
		pass: true,
	}, {
		obj:  &ormapi.Organization{Name: "P1"},
		pass: true,
	}, {
		obj:  &ormapi.Organization{Name: "P2"},
		pass: true,
	}, {
		obj:  &ormapi.Organization{Name: "P3"},
		pass: true,
	}, {
		obj:  &ormapi.Organization{Name: "BT"},
		pass: true,
	}, {
		obj:  &ormapi.Organization{Name: "C1"},
		pass: true,
	}, {
		obj:  &ormapi.Organization{Name: "C2"},
		pass: true,
	}, {
		obj: &ormapi.FederationProvider{
			OperatorId:          "GDDT",
			Name:                "P1",
			FederationContextId: "1",
		},
		pass: true,
	}, {
		// pass: same operator can create another federation
		obj: &ormapi.FederationProvider{
			OperatorId:          "GDDT",
			Name:                "P2",
			FederationContextId: "2",
		},
		pass: true,
	}, {
		// fail: provider name does not reference existing org
		obj: &ormapi.FederationProvider{
			OperatorId: "GDDT",
			Name:       "pbad",
		},
		pass: false,
	}, {
		// fail: unique name already exists
		obj: &ormapi.FederationProvider{
			OperatorId:          "BT",
			Name:                "P2",
			FederationContextId: "3",
		},
		pass: false,
	}, {
		// fail: BTS does not exist
		obj: &ormapi.FederationProvider{
			OperatorId:          "BTS",
			Name:                "P3",
			FederationContextId: "4",
		},
	}, {
		obj: &ormapi.FederationConsumer{
			OperatorId: "BT",
			Name:       "C1",
		},
		pass: true,
	}, {
		// pass: same operator can create another consumer
		obj: &ormapi.FederationConsumer{
			OperatorId: "BT",
			Name:       "C2",
		},
		pass: true,
	}, {
		// fail: consumer name does not reference existing org
		obj: &ormapi.FederationConsumer{
			OperatorId: "BT",
			Name:       "cbad",
		},
		pass: false,
	}, {
		// fail: unique name already exists
		obj: &ormapi.FederationConsumer{
			OperatorId: "GDDT",
			Name:       "C2",
		},
		pass: false,
	}, {
		// fail: BTS does not exist
		obj: &ormapi.FederationConsumer{
			OperatorId: "BTS",
			Name:       "C2",
		},
		pass: false,
	}, {
		obj: &ormapi.ProviderZoneBase{
			ZoneId:     "zone1",
			OperatorId: "GDDT",
		},
		pass: true,
	}, {
		// Pass: composite primary key with operatorid already used
		obj: &ormapi.ProviderZoneBase{
			ZoneId:     "zone2",
			OperatorId: "GDDT",
		},
		pass: true,
	}, {
		// Pass: composite primary key with zone already used
		obj: &ormapi.ProviderZoneBase{
			ZoneId:     "zone1",
			OperatorId: "BT",
		},
		pass: true,
	}, {
		// Fail: missing operator
		obj: &ormapi.ProviderZoneBase{
			ZoneId:     "zone2",
			OperatorId: "bad",
		},
		pass: false,
	}, {
		// Fail: duplicate composite primary key
		obj: &ormapi.ProviderZoneBase{
			ZoneId:     "zone1",
			OperatorId: "GDDT",
		},
		pass: false,
	}, {
		obj: &ormapi.ProviderZone{
			ZoneId:       "zone1",
			OperatorId:   "GDDT",
			ProviderName: "P1",
		},
		pass: true,
	}, {
		// pass: composite primary key zone+provider
		obj: &ormapi.ProviderZone{
			ZoneId:       "zone2",
			OperatorId:   "GDDT",
			ProviderName: "P1",
		},
		pass: true,
	}, {
		// fail: duplicate primary key zone+provider
		obj: &ormapi.ProviderZone{
			ZoneId:       "zone2",
			OperatorId:   "BT",
			ProviderName: "P1",
		},
		pass: false,
	}, {
		// fail: missing zone
		obj: &ormapi.ProviderZone{
			ZoneId:       "zoneBad",
			OperatorId:   "GDDT",
			ProviderName: "P1",
		},
		pass: false,
	}, {
		// fail: missing operator
		obj: &ormapi.ProviderZone{
			ZoneId:       "zone1",
			OperatorId:   "bad",
			ProviderName: "P1",
		},
		pass: false,
	}, {
		// fail: missing provider
		obj: &ormapi.ProviderZone{
			ZoneId:       "zone1",
			OperatorId:   "GDDT",
			ProviderName: "bad",
		},
		pass: false,
	}, {
		obj: &ormapi.ConsumerZone{
			ZoneId:       "zone1",
			ConsumerName: "C1",
			OperatorId:   "BT",
		},
		pass: true,
	}, {
		// pass: composite primary key zone+consumer
		obj: &ormapi.ConsumerZone{
			ZoneId:       "zone2",
			ConsumerName: "C1",
			OperatorId:   "BT",
		},
		pass: true,
	}, {
		// fail: duplicate composite primary key zone+consumer
		obj: &ormapi.ConsumerZone{
			ZoneId:       "zone2",
			ConsumerName: "C1",
			OperatorId:   "GDDT",
		},
		pass: false,
	}, {
		// fail: missing consumer
		obj: &ormapi.ConsumerZone{
			ZoneId:       "zone1",
			ConsumerName: "bad",
			OperatorId:   "BT",
		},
		pass: false,
	}, {
		// fail: missing operator
		obj: &ormapi.ConsumerZone{
			ZoneId:       "zone1",
			ConsumerName: "C1",
			OperatorId:   "bad",
		},
		pass: false,
	}}

	for _, test := range tests {
		err = db.Create(test.obj).Error
		if test.pass {
			require.Nil(t, err, test.obj)
			defer db.Delete(test.obj)
		} else {
			require.NotNil(t, err, test.obj)
		}
	}
}
