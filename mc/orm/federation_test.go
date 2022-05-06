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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jarcoal/httpmock"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/labstack/echo"
	"github.com/lib/pq"
	"github.com/edgexr/edge-cloud-infra/billing"
	intprocess "github.com/edgexr/edge-cloud-infra/e2e-tests/int-process"
	"github.com/edgexr/edge-cloud-infra/mc/federation"
	"github.com/edgexr/edge-cloud-infra/mc/mcctl/mctestclient"
	ormtestutil "github.com/edgexr/edge-cloud-infra/mc/orm/testutil"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud-infra/mc/ormclient"
	"github.com/edgexr/edge-cloud/cli"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/cloudcommon/node"
	"github.com/edgexr/edge-cloud/cloudcommon/nodetest"
	edgeproto "github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/integration/process"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/testutil"
	"github.com/edgexr/edge-cloud/vault"
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
	uri    string
	server *Server
	ctrls  []CtrlObj
}

type FederatorAttr struct {
	tokenAd     string
	tokenOper   string
	operatorId  string
	countryCode string
	fedId       string
	fedName     string
	fedAddr     string
	region      string
	zones       []federation.ZoneInfo
	apiKey      string
}

func (o *OPAttr) CleanupOperatorPlatform(ctx context.Context) {
	for _, ctrl := range o.ctrls {
		ctrl.Cleanup(ctx)
	}
	o.server.Stop()
}

func SetupControllerService(t *testing.T, ctx context.Context, operatorIds []string, region string) *CtrlObj {
	ctrlAddr, err := cloudcommon.GetAvailablePort("127.0.0.1:0")
	require.Nil(t, err, "get available port")
	// run dummy controller - this always returns success
	// to all APIs directed to it, and does not actually
	// create or delete objects. We are mocking it out
	// so we can test rbac permissions.
	dc := grpc.NewServer(
		grpc.UnaryInterceptor(testutil.UnaryInterceptor),
		grpc.StreamInterceptor(testutil.StreamInterceptor),
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

func SetupOperatorPlatform(t *testing.T, ctx context.Context) (*OPAttr, []FederatorAttr) {
	// any requests that don't have a registered URL will be fetched normally
	mockESUrl := "http://mock.es"
	httpmock.RegisterNoResponder(httpmock.InitialTransport.RoundTrip)
	testAlertMgrAddr, err := InitAlertmgrMock()
	require.Nil(t, err)
	de := &nodetest.DummyEventsES{}
	de.InitHttpMock(mockESUrl)

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

	uri := "http://" + addr + "/api/v1"
	config := ServerConfig{
		ServAddr:                 addr,
		SqlAddr:                  sqlAddr,
		FederationAddr:           fedAddr,
		RunLocal:                 true,
		InitLocal:                true,
		LocalVault:               true,
		IgnoreEnv:                true,
		AlertMgrAddr:             testAlertMgrAddr,
		AlertmgrResolveTimout:    3 * time.Minute,
		UsageCheckpointInterval:  "MONTH",
		BillingPlatform:          billing.BillingTypeFake,
		DeploymentTag:            "local",
		AlertCache:               &edgeproto.AlertCache{},
		PublicAddr:               "http://mc.mobiledgex.net",
		PasswordResetConsolePath: "#/passwordreset",
		VerifyEmailConsolePath:   "#/verify",
	}
	unitTestNodeMgrOps = []node.NodeOp{
		node.WithESUrls(MockESUrl),
	}
	defer func() {
		unitTestNodeMgrOps = []node.NodeOp{}
	}()

	server, err := RunServer(&config)
	require.Nil(t, err, "run server")

	// set unit test flag
	fedClient.UnitTest = true

	Jwks.Init(config.vaultConfig, "region", "mcorm")
	Jwks.Meta.CurrentVersion = 1
	Jwks.Keys[1] = &vault.JWK{
		Secret:  "12345",
		Refresh: "1s",
	}

	countryCode := "US"
	operatorIds := []string{"oper1", "oper2"}
	regions := []string{"US-East", "US-West"}

	ctrl1 := SetupControllerService(t, ctx, operatorIds, regions[0])
	ctrl2 := SetupControllerService(t, ctx, operatorIds, regions[1])
	ctrlObjs := []CtrlObj{*ctrl1, *ctrl2}

	opAttr := OPAttr{
		uri:    uri,
		server: server,
		ctrls:  ctrlObjs,
	}

	// wait till mc is ready
	err = server.WaitUntilReady()
	require.Nil(t, err, "server online")

	defaultConfig.DisableRateLimit = true
	enforcer.LogEnforce(true)

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
	for _, operatorId := range operatorIds {
		// create an operator
		_, _, tokenOper := testCreateUserOrg(t, mcClient, uri, operatorId+"-user", OrgTypeOperator, operatorId)
		// admin allow non-edgebox cloudlets on operator org
		setOperatorOrgNoEdgeboxOnly(t, mcClient, uri, tokenAd, operatorId)
		for _, region := range regions {
			fed := FederatorAttr{}
			fed.tokenOper = tokenOper
			fed.operatorId = operatorId
			fed.countryCode = countryCode
			fed.tokenAd = tokenAd
			fed.region = region
			fed.fedAddr = "http://" + fedAddr
			selfFederators = append(selfFederators, fed)
		}
	}

	return &opAttr, selfFederators
}

func getFederationAPI(fedAddr, fedApi string) string {
	return fedAddr + fedApi
}

func registerFederationAPIs(t *testing.T, partnerFed *FederatorAttr) {
	valApiKey := func(req *http.Request) error {
		auth := req.Header.Get(echo.HeaderAuthorization)
		scheme := "Bearer"
		l := len(scheme)
		apiKey := ""
		if len(auth) > len(scheme) && strings.HasPrefix(auth, scheme) {
			apiKey = auth[l+1:]
		}
		if apiKey == "" {
			return fmt.Errorf("no api key found")
		}
		if apiKey != PartnerApiKey {
			return fmt.Errorf("invalid api key")
		}
		return nil
	}
	httpmock.RegisterResponder("POST", getFederationAPI(partnerFed.fedAddr, federation.OperatorPartnerAPI),
		func(req *http.Request) (*http.Response, error) {
			err := valApiKey(req)
			if err != nil {
				fmt.Printf("failed to validate api key from request %s: %v\n", req.URL.String(), err)
				return httpmock.NewStringResponse(400, "api key error"), nil
			}
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				fmt.Printf("failed to read body from request %s: %v\n", req.URL.String(), err)
				return httpmock.NewStringResponse(400, "failed to read body"), nil
			}
			fedReq := federation.OperatorRegistrationRequest{}
			err = json.Unmarshal(body, &fedReq)
			if err != nil {
				fmt.Printf("failed to unmarshal req data %s: %v\n", body, err)
				return httpmock.NewStringResponse(400, "failed to read body"), nil
			}

			out := federation.OperatorRegistrationResponse{
				OrigOperatorId:    partnerFed.operatorId,
				OrigFederationId:  partnerFed.fedId,
				PartnerOperatorId: fedReq.OperatorId,
				DestFederationId:  fedReq.OrigFederationId,
				MCC:               "340",
				MNC:               []string{"120", "121", "122"},
				PartnerZone:       partnerFed.zones,
			}
			return httpmock.NewJsonResponse(200, out)
		},
	)

	httpmock.RegisterResponder("PUT", getFederationAPI(partnerFed.fedAddr, federation.OperatorPartnerAPI),
		func(req *http.Request) (*http.Response, error) {
			err := valApiKey(req)
			if err != nil {
				fmt.Printf("failed to validate api key from request %s: %v\n", req.URL.String(), err)
				return httpmock.NewStringResponse(400, "api key error"), nil
			}
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				fmt.Printf("failed to read body from request %s: %v\n", req.URL.String(), err)
				return httpmock.NewStringResponse(400, "failed to read body"), nil
			}
			inReq := federation.UpdateMECNetConf{}
			err = json.Unmarshal(body, &inReq)
			if err != nil {
				fmt.Printf("failed to unmarshal req data %s: %v\n", body, err)
				return httpmock.NewStringResponse(400, "failed to read body"), nil
			}

			return httpmock.NewStringResponse(200, "updated successfully"), nil
		},
	)

	httpmock.RegisterResponder("DELETE", getFederationAPI(partnerFed.fedAddr, federation.OperatorPartnerAPI),
		func(req *http.Request) (*http.Response, error) {
			err := valApiKey(req)
			if err != nil {
				fmt.Printf("failed to validate api key from request %s: %v\n", req.URL.String(), err)
				return httpmock.NewStringResponse(400, "api key error"), nil
			}
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				fmt.Printf("failed to read body from request %s: %v\n", req.URL.String(), err)
				return httpmock.NewStringResponse(400, "failed to read body"), nil
			}
			inReq := federation.FederationRequest{}
			err = json.Unmarshal(body, &inReq)
			if err != nil {
				fmt.Printf("failed to unmarshal req data %s: %v\n", body, err)
				return httpmock.NewStringResponse(400, "failed to read body"), nil
			}

			return httpmock.NewStringResponse(200, "delete partner OP successfully"), nil
		},
	)

	httpmock.RegisterResponder("POST", getFederationAPI(partnerFed.fedAddr, federation.OperatorZoneAPI),
		func(req *http.Request) (*http.Response, error) {
			err := valApiKey(req)
			if err != nil {
				fmt.Printf("failed to validate api key from request %s: %v\n", req.URL.String(), err)
				return httpmock.NewStringResponse(400, "api key error"), nil
			}
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				fmt.Printf("failed to read body from request %s: %v\n", req.URL.String(), err)
				return httpmock.NewStringResponse(400, "failed to read body"), nil
			}
			zoneRegReq := federation.OperatorZoneRegister{}
			err = json.Unmarshal(body, &zoneRegReq)
			if err != nil {
				fmt.Printf("failed to unmarshal req data %s: %v\n", body, err)
				return httpmock.NewStringResponse(400, "failed to read body"), nil
			}

			zoneRegDetailsOut := []federation.ZoneRegisterDetails{}
			for _, zoneName := range zoneRegReq.Zones {
				zoneRegDetailsOut = append(zoneRegDetailsOut, federation.ZoneRegisterDetails{
					ZoneId:            zoneName,
					RegistrationToken: zoneRegReq.OrigFederationId,
				})
			}

			out := federation.OperatorZoneRegisterResponse{
				LeadOperatorId: partnerFed.operatorId,
				FederationId:   partnerFed.fedId,
				Zone:           zoneRegDetailsOut,
			}
			return httpmock.NewJsonResponse(200, out)
		},
	)
	httpmock.RegisterResponder("DELETE", getFederationAPI(partnerFed.fedAddr, federation.OperatorZoneAPI),
		func(req *http.Request) (*http.Response, error) {
			err := valApiKey(req)
			if err != nil {
				fmt.Printf("failed to validate api key from request %s: %v\n", req.URL.String(), err)
				return httpmock.NewStringResponse(400, "api key error"), nil
			}
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				fmt.Printf("failed to read body from request %s: %v\n", req.URL.String(), err)
				return httpmock.NewStringResponse(400, "failed to read body"), nil
			}
			zoneDeRegReq := federation.ZoneMultiRequest{}
			err = json.Unmarshal(body, &zoneDeRegReq)
			if err != nil {
				fmt.Printf("failed to unmarshal req data %s: %v\n", body, err)
				return httpmock.NewStringResponse(400, "failed to read body"), nil
			}

			return httpmock.NewStringResponse(200, "successfully deregistered"), nil
		},
	)

	httpmock.RegisterResponder("POST", getFederationAPI(partnerFed.fedAddr, federation.OperatorNotifyZoneAPI),
		func(req *http.Request) (*http.Response, error) {
			err := valApiKey(req)
			if err != nil {
				fmt.Printf("failed to validate api key from request %s: %v\n", req.URL.String(), err)
				return httpmock.NewStringResponse(400, "api key error"), nil
			}
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				fmt.Printf("failed to read body from request %s: %v\n", req.URL.String(), err)
				return httpmock.NewStringResponse(400, "failed to read body"), nil
			}
			inReq := federation.NotifyPartnerOperatorZone{}
			err = json.Unmarshal(body, &inReq)
			if err != nil {
				fmt.Printf("failed to unmarshal req data %s: %v\n", body, err)
				return httpmock.NewStringResponse(400, "failed to read body"), nil
			}

			if inReq.PartnerZone.ZoneId == "" {
				return httpmock.NewStringResponse(400, "must specify zone ID"), nil
			}

			return httpmock.NewStringResponse(200, "Added zone successfully"), nil
		},
	)
	httpmock.RegisterResponder("DELETE", getFederationAPI(partnerFed.fedAddr, federation.OperatorNotifyZoneAPI),
		func(req *http.Request) (*http.Response, error) {
			err := valApiKey(req)
			if err != nil {
				fmt.Printf("failed to validate api key from request %s: %v\n", req.URL.String(), err)
				return httpmock.NewStringResponse(400, "api key error"), nil
			}
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				fmt.Printf("failed to read body from request %s: %v\n", req.URL.String(), err)
				return httpmock.NewStringResponse(400, "failed to read body"), nil
			}
			inReq := federation.ZoneSingleRequest{}
			err = json.Unmarshal(body, &inReq)
			if err != nil {
				fmt.Printf("failed to unmarshal req data %s: %v\n", body, err)
				return httpmock.NewStringResponse(400, "failed to read body"), nil
			}

			if inReq.Zone == "" {
				return httpmock.NewStringResponse(400, "must specify zone ID"), nil
			}

			return httpmock.NewStringResponse(200, "Deleted zone successfully"), nil
		},
	)
}

func TestFederation(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	unitTest = true

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// Setup Operator Platform (MC - Self federator)
	op, selfFederators := SetupOperatorPlatform(t, ctx)
	defer op.CleanupOperatorPlatform(ctx)

	// Setup partner federator
	partnerFedId := uuid.New().String()
	partnerFed := &FederatorAttr{
		operatorId:  "partnerOper",
		countryCode: "ES",
		fedId:       partnerFedId,
		fedName:     "partnerFed",
		fedAddr:     "http://111.111.111.111",
		apiKey:      PartnerApiKey,
	}
	partnerZones := []federation.ZoneInfo{
		federation.ZoneInfo{
			ZoneId:      fmt.Sprintf("%s-testzone0", partnerFed.operatorId),
			GeoLocation: "1.1,2.2",
			City:        "New York",
			State:       "New York",
			EdgeCount:   2,
		},
		federation.ZoneInfo{
			ZoneId:      fmt.Sprintf("%s-testzone1", partnerFed.operatorId),
			GeoLocation: "2.2,3.3",
			City:        "Nevada",
			State:       "Nevada",
			EdgeCount:   1,
		},
	}
	partnerFed.zones = partnerZones

	// Register mock federation APIs
	registerFederationAPIs(t, partnerFed)

	for _, clientRun := range getUnitTestClientRuns() {
		testFederationInterconnect(t, ctx, clientRun, op, selfFederators, partnerFed)
	}
}

func testPartnerFederationAPIs(t *testing.T, ctx context.Context, mcClient *mctestclient.Client, op *OPAttr, selfFederators []FederatorAttr, partnerFed *FederatorAttr) {
	selfFed1 := selfFederators[0]

	// Verify that selfFed1 has added partnerFed as partner federator (federation planning)
	// ====================================================================================
	showFedn := &cli.MapData{
		Namespace: cli.StructNamespace,
		Data: map[string]interface{}{
			"SelfOperatorId":   selfFed1.operatorId,
			"SelfFederationId": selfFed1.fedId,
		},
	}
	fedInfo, status, err := mcClient.ShowFederation(op.uri, selfFed1.tokenOper, showFedn)
	require.Nil(t, err, "show federator")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(fedInfo))

	// Partner federator sends federation creation request
	// ==================================================
	opRegReq := federation.OperatorRegistrationRequest{
		RequestId:        "r1",
		OrigFederationId: partnerFed.fedId,
		DestFederationId: selfFed1.fedId,
		OperatorId:       partnerFed.operatorId,
		CountryCode:      partnerFed.countryCode,
	}
	opRegRes := federation.OperatorRegistrationResponse{}
	err = fedClient.SendRequest(ctx, "POST", selfFed1.fedAddr, partnerFed.fedName, selfFed1.apiKey, federation.OperatorPartnerAPI, &opRegReq, &opRegRes)
	require.Nil(t, err, "partnerFed adds selfFed1 as partner OP")
	// verify federation response
	require.Equal(t, opRegRes.OrigOperatorId, selfFed1.operatorId)
	require.Equal(t, opRegRes.PartnerOperatorId, partnerFed.operatorId)
	require.Equal(t, opRegRes.OrigFederationId, selfFed1.fedId)
	require.Equal(t, opRegRes.DestFederationId, partnerFed.fedId)
	require.Equal(t, len(opRegRes.PartnerZone), len(selfFed1.zones), "selfFed1 zones are shared")
	require.Equal(t, opRegReq.RequestId, opRegRes.RequestId)

	// Verify federation is setup in DB
	federations, status, err := mcClient.ShowFederation(op.uri, selfFed1.tokenOper, showFedn)
	require.Nil(t, err, "show federations")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(federations), "federation exists")
	require.True(t, federations[0].PartnerRoleShareZonesWithSelf, "federation direction exists")
	require.True(t, federations[0].PartnerRoleAccessToSelfZones, "federation direction exists")
	require.Equal(t, opRegReq.RequestId, federations[0].Revision)

	// partnerFed updates its MCC value and notifies selfFed1 about it
	// ===============================================================
	updateReq := federation.UpdateMECNetConf{
		RequestId:        "r2",
		OrigFederationId: partnerFed.fedId,
		DestFederationId: selfFed1.fedId,
		Operator:         partnerFed.operatorId,
		Country:          partnerFed.countryCode,
		MCC:              "999",
	}
	err = fedClient.SendRequest(ctx, "PUT", selfFed1.fedAddr, partnerFed.fedName, selfFed1.apiKey, federation.OperatorPartnerAPI, &updateReq, nil)
	require.Nil(t, err, "partnerFed updates its attributes and notifies selfFed1 about it")

	// verify that selfFed1 has successfully updated partnerFed's new MCC value
	showFedn = &cli.MapData{
		Namespace: cli.StructNamespace,
		Data: map[string]interface{}{
			"SelfOperatorId":   selfFed1.operatorId,
			"SelfFederationId": selfFed1.fedId,
		},
	}
	fedInfo, status, err = mcClient.ShowFederation(op.uri, selfFed1.tokenOper, showFedn)
	require.Nil(t, err, "show federator")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(fedInfo), "federator exists")
	require.Equal(t, fedInfo[0].MCC, updateReq.MCC, "MCC values match")
	require.Equal(t, updateReq.RequestId, fedInfo[0].Revision)

	// partnerFed sends registration request for selfFed1 zone
	// =======================================================
	regZones := []string{}
	for _, sZone := range selfFed1.zones {
		regZones = append(regZones, sZone.ZoneId)
	}
	zoneRegReq := federation.OperatorZoneRegister{
		RequestId:        "r3",
		OrigFederationId: partnerFed.fedId,
		DestFederationId: selfFed1.fedId,
		Operator:         partnerFed.operatorId,
		Country:          partnerFed.countryCode,
		Zones:            regZones,
	}
	opZoneRes := federation.OperatorZoneRegisterResponse{}
	err = fedClient.SendRequest(ctx, "POST", selfFed1.fedAddr, partnerFed.fedName, selfFed1.apiKey, federation.OperatorZoneAPI, &zoneRegReq, &opZoneRes)
	require.Nil(t, err, "partnerFed sends registration request for selfFed1 zones")
	require.Equal(t, zoneRegReq.RequestId, opZoneRes.RequestId)
	require.Equal(t, len(opZoneRes.Zone), len(regZones))
	for _, resZone := range opZoneRes.Zone {
		require.Equal(t, resZone.UpperLimitQuota.CPU, int64(ResourceValue))
		require.Equal(t, resZone.UpperLimitQuota.RAM, int64(ResourceValue)/1024)
		require.Equal(t, resZone.UpperLimitQuota.Disk, int64(ResourceValue))
		require.Equal(t, resZone.GuaranteedResources.CPU, int64(ResourceValue))
		require.Equal(t, resZone.GuaranteedResources.RAM, int64(ResourceValue)/1024)
		require.Equal(t, resZone.GuaranteedResources.Disk, int64(ResourceValue))
	}

	for _, regZone := range regZones {
		// Verify that registered zones are shown
		showFedSelfZone := &cli.MapData{
			Namespace: cli.StructNamespace,
			Data: map[string]interface{}{
				"SelfOperatorId": selfFed1.operatorId,
				"FederationName": partnerFed.fedName,
				"ZoneId":         regZone,
			},
		}
		selfFed1Zones, status, err := mcClient.ShowFederatedSelfZone(op.uri, selfFed1.tokenOper, showFedSelfZone)
		require.Nil(t, err, "show self federator zones")
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, 1, len(selfFed1Zones))
		require.True(t, selfFed1Zones[0].Registered)
		require.Equal(t, zoneRegReq.RequestId, selfFed1Zones[0].Revision)
	}

	// partnerFed notifies selfFed1 about a new zone
	// =============================================
	newZone := federation.ZoneInfo{
		ZoneId:      fmt.Sprintf("%s-testzoneX", partnerFed.operatorId),
		GeoLocation: "9.9",
		City:        "Newark",
		State:       "Newark",
		EdgeCount:   2,
	}
	zoneNotifyReq := federation.NotifyPartnerOperatorZone{
		RequestId:        "r4",
		OrigFederationId: partnerFed.fedId,
		DestFederationId: selfFed1.fedId,
		Operator:         partnerFed.operatorId,
		Country:          partnerFed.countryCode,
		PartnerZone:      newZone,
	}
	err = fedClient.SendRequest(ctx, "POST", selfFed1.fedAddr, partnerFed.fedName, selfFed1.apiKey, federation.OperatorNotifyZoneAPI, &zoneNotifyReq, nil)
	require.Nil(t, err, "partnerFed notifies selfFed1 about a new zone")

	// verify that selfFed1 added this new zone in its db
	showFedPartnerZone := &cli.MapData{
		Namespace: cli.StructNamespace,
		Data: map[string]interface{}{
			"SelfOperatorId": selfFed1.operatorId,
			"FederationName": partnerFed.fedName,
			"FederatorZone": map[string]interface{}{
				"ZoneId": newZone.ZoneId,
			},
		},
	}
	pZones, status, err := mcClient.ShowFederatedPartnerZone(op.uri, selfFed1.tokenOper, showFedPartnerZone)
	require.Nil(t, err, "show federator zones")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(pZones))
	require.Equal(t, partnerFed.operatorId, pZones[0].OperatorId)
	require.Equal(t, partnerFed.countryCode, pZones[0].CountryCode)
	require.Equal(t, newZone.ZoneId, pZones[0].ZoneId)
	require.False(t, pZones[0].Registered, "not registered")
	require.Equal(t, zoneNotifyReq.RequestId, pZones[0].Revision)

	// partnerFed notifies selfFed1 about a deleted zone
	// =================================================
	zoneUnshareReq := federation.ZoneSingleRequest{
		RequestId:        "r5",
		OrigFederationId: partnerFed.fedId,
		DestFederationId: selfFed1.fedId,
		Operator:         partnerFed.operatorId,
		Country:          partnerFed.countryCode,
		Zone:             newZone.ZoneId,
	}
	err = fedClient.SendRequest(ctx, "DELETE", selfFed1.fedAddr, partnerFed.fedName, selfFed1.apiKey, federation.OperatorNotifyZoneAPI, &zoneUnshareReq, nil)
	require.Nil(t, err, "partnerFed notifies selfFed1 about a deleted zone")

	// verify that selfFed1 deleted this zone from its db
	pZones, status, err = mcClient.ShowFederatedPartnerZone(op.uri, selfFed1.tokenOper, showFedPartnerZone)
	require.Nil(t, err, "show federator zones")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(pZones))

	// partnerFed sends deregistration request for selfFed1 zone
	// =========================================================
	deregZones := []string{}
	for _, sZone := range selfFed1.zones {
		deregZones = append(deregZones, sZone.ZoneId)
	}
	zoneDeRegReq := federation.ZoneMultiRequest{
		RequestId:        "r6",
		OrigFederationId: partnerFed.fedId,
		DestFederationId: selfFed1.fedId,
		Operator:         partnerFed.operatorId,
		Country:          partnerFed.countryCode,
		Zones:            deregZones,
	}
	err = fedClient.SendRequest(ctx, "DELETE", selfFed1.fedAddr, partnerFed.fedName, selfFed1.apiKey, federation.OperatorZoneAPI, &zoneDeRegReq, nil)
	require.Nil(t, err, "partnerFed sends deregistration request for selfFed1 zone")

	for _, deregZone := range deregZones {
		// Verify that zones are deregistered
		showFedSelfZone := &cli.MapData{
			Namespace: cli.StructNamespace,
			Data: map[string]interface{}{
				"SelfOperatorId": selfFed1.operatorId,
				"FederationName": partnerFed.fedName,
				"ZoneId":         deregZone,
			},
		}
		selfFed1Zones, status, err := mcClient.ShowFederatedSelfZone(op.uri, selfFed1.tokenOper, showFedSelfZone)
		require.Nil(t, err, "show self federator zones")
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, 1, len(selfFed1Zones))
		require.False(t, selfFed1Zones[0].Registered)
		require.Equal(t, zoneDeRegReq.RequestId, selfFed1Zones[0].Revision)
	}

	// partnerFed removes selfFed1 as federation partner
	// =================================================
	opFedReq := federation.FederationRequest{
		RequestId:        "r7",
		OrigFederationId: partnerFed.fedId,
		DestFederationId: selfFed1.fedId,
		Operator:         partnerFed.operatorId,
		Country:          partnerFed.countryCode,
	}
	err = fedClient.SendRequest(ctx, "DELETE", selfFed1.fedAddr, partnerFed.fedName, selfFed1.apiKey, federation.OperatorPartnerAPI, &opFedReq, nil)
	require.Nil(t, err, "partnerFed removes selfFed1 as partner OP")

	// verify that partnerFed has successfully removed federation with selfFed1
	showFedn = &cli.MapData{
		Namespace: cli.StructNamespace,
		Data: map[string]interface{}{
			"SelfOperatorId":   selfFed1.operatorId,
			"SelfFederationId": selfFed1.fedId,
		},
	}
	federations, status, err = mcClient.ShowFederation(op.uri, selfFed1.tokenOper, showFedn)
	require.Nil(t, err, "show federations")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(federations), "federation exists")
	require.False(t, federations[0].PartnerRoleAccessToSelfZones, "federation from partner to self is deleted")
	require.True(t, federations[0].PartnerRoleShareZonesWithSelf, "federation from self to partner exists")
	require.Equal(t, opFedReq.RequestId, federations[0].Revision)
}

func testFederationInterconnect(t *testing.T, ctx context.Context, clientRun mctestclient.ClientRun, op *OPAttr, selfFederators []FederatorAttr, partnerFed *FederatorAttr) {
	mcClient := mctestclient.NewClient(clientRun)

	// Create self federator objs
	// ==========================
	for ii, selfFed := range selfFederators {
		fedReq := &ormapi.Federator{
			OperatorId:  selfFed.operatorId,
			CountryCode: selfFed.countryCode,
			Region:      selfFed.region,
			MCC:         "340",
			MNC:         []string{"120", "121", "122"},
		}
		resp, status, err := mcClient.CreateSelfFederator(op.uri, selfFed.tokenOper, fedReq)
		require.Nil(t, err, "create self federator")
		require.Equal(t, http.StatusOK, status)
		require.NotEmpty(t, resp.FederationId)
		require.NotEmpty(t, resp.ApiKey)
		selfFederators[ii].fedId = resp.FederationId
		selfFederators[ii].apiKey = resp.ApiKey

		showFed := &cli.MapData{
			Namespace: cli.StructNamespace,
			Data: map[string]interface{}{
				"Region":       selfFed.region,
				"OperatorId":   selfFed.operatorId,
				"CountryCode":  selfFed.countryCode,
				"FederationId": resp.FederationId,
			},
		}
		fedInfo, status, err := mcClient.ShowSelfFederator(op.uri, selfFed.tokenOper, showFed)
		require.Nil(t, err, "show self federator")
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, 1, len(fedInfo))
		require.Equal(t, selfFed.operatorId, fedInfo[0].OperatorId)
		require.Equal(t, selfFed.countryCode, fedInfo[0].CountryCode)
		require.Equal(t, pq.StringArray{"120", "121", "122"}, fedInfo[0].MNC)
		require.NotEmpty(t, fedInfo[0].Revision)
	}

	selfFed1 := selfFederators[0]
	selfFed2 := selfFederators[2]

	// Test org is inuse check
	err := orgInUseByFederatorCheck(ctx, selfFed1.operatorId)
	require.NotNil(t, err, "org in use by federator")
	require.Contains(t, err.Error(), "in use by federator")

	// selfFed1 creates partner federator obj
	// ======================================
	partnerFedReq := &ormapi.Federation{
		Name:             partnerFed.fedName,
		SelfOperatorId:   selfFed1.operatorId,
		SelfFederationId: selfFed1.fedId,
		Federator: ormapi.Federator{
			OperatorId:     partnerFed.operatorId,
			CountryCode:    partnerFed.countryCode,
			FederationId:   partnerFed.fedId,
			FederationAddr: partnerFed.fedAddr,
			MNC:            []string{"123", "345"},
			ApiKey:         partnerFed.apiKey,
		},
	}
	_, status, err := mcClient.CreateFederation(op.uri, selfFed1.tokenOper, partnerFedReq)
	require.Nil(t, err, "create federation")
	require.Equal(t, http.StatusOK, status)

	// Federation creation with same federation ID pair should fail
	newPartnerFedReq := *partnerFedReq
	newPartnerFedReq.Name = "testErr"
	_, _, err = mcClient.CreateFederation(op.uri, selfFed1.tokenOper, &newPartnerFedReq)
	require.NotNil(t, err, "create federation")
	require.Contains(t, err.Error(), "same federation id pair")

	// Federation creation with same self federation ID should fail
	newPartnerFedReq = *partnerFedReq
	newPartnerFedReq.Name = "testErr"
	newPartnerFedReq.FederationId = "12345678"
	_, _, err = mcClient.CreateFederation(op.uri, selfFed1.tokenOper, &newPartnerFedReq)
	require.NotNil(t, err, "create federation")
	require.Contains(t, err.Error(), "same self federation id")

	// Federation creation with same partner federation ID should fail
	newPartnerFedReq = *partnerFedReq
	newPartnerFedReq.Name = "testErr"
	newPartnerFedReq.SelfOperatorId = selfFed2.operatorId
	newPartnerFedReq.SelfFederationId = selfFed2.fedId
	_, _, err = mcClient.CreateFederation(op.uri, selfFed2.tokenOper, &newPartnerFedReq)
	require.NotNil(t, err, "create federation")
	require.Contains(t, err.Error(), "same federation id")

	// Federation with invalid partner country code should fail
	newPartnerFedReq = *partnerFedReq
	newPartnerFedReq.Name = "testErr"
	newPartnerFedReq.SelfFederationId = selfFed2.fedId
	newPartnerFedReq.FederationId = "87654321"
	newPartnerFedReq.CountryCode = "USA"
	_, _, err = mcClient.CreateFederation(op.uri, selfFed1.tokenOper, &newPartnerFedReq)
	require.NotNil(t, err, "create federation")
	require.Contains(t, err.Error(), "Invalid country code")

	// Validate partner federator info
	showFedn := &cli.MapData{
		Namespace: cli.StructNamespace,
		Data: map[string]interface{}{
			"Name":             partnerFed.fedName,
			"SelfOperatorId":   selfFed1.operatorId,
			"SelfFederationId": selfFed1.fedId,
		},
	}
	federations, status, err := mcClient.ShowFederation(op.uri, selfFed1.tokenOper, showFedn)
	require.Nil(t, err, "show partner federation")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(federations))
	require.Equal(t, selfFed1.operatorId, federations[0].SelfOperatorId)
	require.Equal(t, selfFed1.fedId, federations[0].SelfFederationId)
	require.Equal(t, partnerFed.operatorId, federations[0].OperatorId)
	require.Equal(t, partnerFed.countryCode, federations[0].CountryCode)
	require.Equal(t, pq.StringArray{"123", "345"}, federations[0].MNC)
	require.False(t, federations[0].PartnerRoleShareZonesWithSelf, "no federation exists yet")
	require.False(t, federations[0].PartnerRoleAccessToSelfZones, "no federation exists yet")
	require.NotEmpty(t, federations[0].Revision)

	// selfFed2 should not be able to see selfFed1's partner
	// =====================================================
	federations, status, err = mcClient.ShowFederation(op.uri, selfFed2.tokenOper, showFedn)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(federations))
	showFedn = &cli.MapData{
		Namespace: cli.StructNamespace,
		Data: map[string]interface{}{
			"SelfOperatorId":   selfFed2.operatorId,
			"SelfFederationId": selfFed2.fedId,
		},
	}
	federations, status, err = mcClient.ShowFederation(op.uri, selfFed2.tokenOper, showFedn)
	require.Nil(t, err, "show partner federator")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(federations))

	// Update self federator MCC value
	// ===============================
	updateFed := &cli.MapData{
		Namespace: cli.ArgsNamespace,
		Data:      make(map[string]interface{}),
	}
	updateFed.Data["OperatorId"] = selfFed1.operatorId
	updateFed.Data["FederationId"] = selfFed1.fedId
	updateFed.Data["MCC"] = "344"
	_, status, err = mcClient.UpdateSelfFederator(op.uri, selfFed1.tokenOper, updateFed)
	require.Nil(t, err, "update self federation")
	require.Equal(t, http.StatusOK, status)

	// Show federator info
	showFed := &cli.MapData{
		Namespace: cli.StructNamespace,
		Data: map[string]interface{}{
			"OperatorId":  selfFed1.operatorId,
			"CountryCode": selfFed1.countryCode,
			"Region":      selfFed1.region,
		},
	}
	fedInfo, status, err := mcClient.ShowSelfFederator(op.uri, selfFed1.tokenOper, showFed)
	require.Nil(t, err, "show self federation")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(fedInfo), "one entry")
	require.Equal(t, "344", fedInfo[0].MCC, "matches updated field")
	require.NotEmpty(t, fedInfo[0].Revision)

	// Create self federator zones
	// ===========================
	clList := []edgeproto.Cloudlet{}
	for fid, selfFed := range selfFederators {
		zones := []federation.ZoneInfo{}
		filter := &edgeproto.Cloudlet{
			Key: edgeproto.CloudletKey{
				Organization: selfFed.operatorId,
			},
		}
		clList, status, err = ormtestutil.TestShowCloudlet(mcClient, op.uri, selfFed.tokenOper, selfFed.region, filter)
		require.Nil(t, err)
		require.Equal(t, http.StatusOK, status)
		for jj, cl := range clList {
			fedZone := &ormapi.FederatorZone{
				ZoneId:      fmt.Sprintf("op-testzone-%s-%s-%s", selfFed.operatorId, selfFed.region, cl.Key.Name),
				OperatorId:  selfFed.operatorId,
				CountryCode: selfFed.countryCode,
				GeoLocation: fmt.Sprintf("%d,%d", jj, jj),
				Region:      selfFed.region,
				City:        "New York",
				State:       "New York",
				Cloudlets:   []string{cl.Key.Name},
			}
			_, status, err = mcClient.CreateSelfFederatorZone(op.uri, selfFed.tokenOper, fedZone)
			require.Nil(t, err, "create federation zone")
			require.Equal(t, http.StatusOK, status)
			fedZoneInfo := federation.ZoneInfo{
				ZoneId:      fedZone.ZoneId,
				GeoLocation: fedZone.GeoLocation,
				City:        fedZone.City,
				State:       fedZone.State,
				EdgeCount:   len(fedZone.Cloudlets),
			}
			zones = append(zones, fedZoneInfo)
		}
		selfFederators[fid].zones = zones
	}

	// Negative tests
	// ==============
	testZone := &ormapi.FederatorZone{
		ZoneId:      "testZone",
		OperatorId:  selfFed1.operatorId,
		CountryCode: selfFed1.countryCode,
		Region:      selfFed1.region,
		Cloudlets:   []string{clList[0].Key.Name},
		GeoLocation: "1.1,1.1",
	}

	// invalid region
	invalidZone := *testZone
	invalidZone.Region = "ABCD"
	_, status, err = mcClient.CreateSelfFederatorZone(op.uri, selfFederators[0].tokenOper, &invalidZone)
	require.NotNil(t, err, "create federation zone fails")
	require.Contains(t, err.Error(), "Region \"ABCD\" not found")

	// invalid country code
	invalidZone = *testZone
	invalidZone.CountryCode = "ABCD"
	_, status, err = mcClient.CreateSelfFederatorZone(op.uri, selfFederators[0].tokenOper, &invalidZone)
	require.NotNil(t, err, "create federation zone fails")
	require.Contains(t, err.Error(), "Invalid country code")

	// Verify that all zones are created
	// =================================
	for _, selfFed := range selfFederators {
		showSelfZone := &cli.MapData{
			Namespace: cli.StructNamespace,
			Data: map[string]interface{}{
				"OperatorId":  selfFed.operatorId,
				"CountryCode": selfFed.countryCode,
				"Region":      selfFed.region,
			},
		}
		selfFedZones, status, err := mcClient.ShowSelfFederatorZone(op.uri, selfFed.tokenOper, showSelfZone)
		require.Nil(t, err, "show self federator zones")
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, len(selfFed.zones), len(selfFedZones), "self federator zones match")
	}

	selfFed1Zones := selfFederators[0].zones

	// As part of federation planning, mark zones to be shared with partner federator
	// ==============================================================================
	for _, zone := range selfFed1Zones {
		zoneShReq := &ormapi.FederatedSelfZone{
			SelfOperatorId: selfFed1.operatorId,
			FederationName: partnerFed.fedName,
			ZoneId:         zone.ZoneId,
		}
		_, status, err := mcClient.ShareSelfFederatorZone(op.uri, selfFed1.tokenOper, zoneShReq)
		require.Nil(t, err, "mark zones to be shared with partner federator")
		require.Equal(t, http.StatusOK, status)

		// All zones are marked to be shared with partner federator
		showFedSelfZone := &cli.MapData{
			Namespace: cli.StructNamespace,
			Data: map[string]interface{}{
				"SelfOperatorId": selfFed1.operatorId,
				"FederationName": partnerFed.fedName,
				"ZoneId":         zone.ZoneId,
			},
		}
		selfFedZones, status, err := mcClient.ShowFederatedSelfZone(op.uri, selfFed1.tokenOper, showFedSelfZone)
		require.Nil(t, err, "show shared self federator zones")
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, 1, len(selfFedZones))
		// these zones are not yet registered
		require.False(t, selfFedZones[0].Registered)
		require.NotEmpty(t, selfFedZones[0].Revision)
	}

	// No partner zones exist as federation is not yet created
	// =======================================================
	showFedPartnerZone := &cli.MapData{
		Namespace: cli.StructNamespace,
		Data: map[string]interface{}{
			"SelfOperatorId": selfFed1.operatorId,
			"FederationName": partnerFed.fedName,
		},
	}
	partnerZones, status, err := mcClient.ShowFederatedPartnerZone(op.uri, selfFed1.tokenOper, showFedPartnerZone)
	require.Nil(t, err, "show partner federator zones")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(partnerZones))

	// Register partner zone should fail if selfoperatorid is invalid
	// ==================================================================
	zoneRegReq := &ormapi.FederatedZoneRegRequest{
		SelfOperatorId: "invalidOrgName",
		FederationName: partnerFed.fedName,
		Zones:          []string{partnerFed.zones[0].ZoneId},
	}
	_, _, err = mcClient.RegisterPartnerFederatorZone(op.uri, selfFed1.tokenAd, zoneRegReq)
	require.NotNil(t, err, "cannot register partner zone as selfoperatorid not found")
	require.Contains(t, err.Error(), "not found")

	// Register partner zone should fail as federation is not yet created
	// ==================================================================
	zoneRegReq = &ormapi.FederatedZoneRegRequest{
		SelfOperatorId: selfFed1.operatorId,
		FederationName: partnerFed.fedName,
		Zones:          []string{partnerFed.zones[0].ZoneId},
	}
	_, _, err = mcClient.RegisterPartnerFederatorZone(op.uri, selfFed1.tokenOper, zoneRegReq)
	require.NotNil(t, err, "cannot register partner zone as federation does not exist")
	require.Contains(t, err.Error(), "not allowed to access zones")

	// Create federation between selfFed1 and partner federator
	// ========================================================
	fedReq := &ormapi.Federation{
		SelfOperatorId: selfFed1.operatorId,
		Name:           partnerFed.fedName,
	}
	_, status, err = mcClient.RegisterFederation(op.uri, selfFed1.tokenOper, fedReq)
	require.Nil(t, err, "register federation")
	require.Equal(t, http.StatusOK, status)

	// Verify federation is created
	showFedn = &cli.MapData{
		Namespace: cli.StructNamespace,
		Data: map[string]interface{}{
			"SelfOperatorId": selfFed1.operatorId,
			"Name":           partnerFed.fedName,
		},
	}
	federations, status, err = mcClient.ShowFederation(op.uri, selfFed1.tokenOper, showFedn)
	require.Nil(t, err, "show federations")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(federations), "federation exists")
	require.True(t, federations[0].PartnerRoleShareZonesWithSelf, "role matches")
	require.NotEmpty(t, federations[0].Revision)

	// Verify federation does not exist with selfFed2
	fedReq = &ormapi.Federation{
		SelfOperatorId:   selfFed2.operatorId,
		SelfFederationId: selfFed2.fedId,
		Federator: ormapi.Federator{
			FederationId: partnerFed.fedId,
		},
	}
	showFedn = &cli.MapData{
		Namespace: cli.StructNamespace,
		Data: map[string]interface{}{
			"SelfOperatorId":   selfFed1.operatorId,
			"SelfFederationId": selfFed2.fedId,
			"Federator": map[string]interface{}{
				"FederationId": partnerFed.fedId,
			},
		},
	}
	federations, status, err = mcClient.ShowFederation(op.uri, selfFed2.tokenOper, showFedn)
	require.Nil(t, err, "show federations")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(federations), "federation does not exist")

	// Partner zones are shared as part of federation create
	// =====================================================
	showFedPartnerZone = &cli.MapData{
		Namespace: cli.StructNamespace,
		Data: map[string]interface{}{
			"SelfOperatorId": selfFed1.operatorId,
			"FederationName": partnerFed.fedName,
		},
	}
	partnerZones, status, err = mcClient.ShowFederatedPartnerZone(op.uri, selfFed1.tokenOper, showFedPartnerZone)
	require.Nil(t, err, "show partner federator zones")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, len(partnerFed.zones), len(partnerZones))
	// none of them are registered yet
	zoneList := []string{}
	for _, pZone := range partnerZones {
		require.Equal(t, partnerFed.operatorId, pZone.OperatorId)
		require.Equal(t, partnerFed.countryCode, pZone.CountryCode)
		require.False(t, pZone.Registered)
		require.NotEmpty(t, pZone.Revision)
		zoneList = append(zoneList, pZone.ZoneId)
	}

	// Register all the partner zones to be used
	// =========================================
	pZoneReq := ormapi.FederatedZoneRegRequest{
		SelfOperatorId: selfFed1.operatorId,
		FederationName: partnerFed.fedName,
		Zones:          zoneList,
	}
	_, status, err = mcClient.RegisterPartnerFederatorZone(op.uri, selfFed1.tokenOper, &pZoneReq)
	require.Nil(t, err, "register partner federator zone")
	require.Equal(t, http.StatusOK, status)

	// Verify that registered zones are shown
	for _, pZone := range partnerZones {
		showFedPartnerZone = &cli.MapData{
			Namespace: cli.StructNamespace,
			Data: map[string]interface{}{
				"SelfOperatorId": selfFed1.operatorId,
				"FederationName": partnerFed.fedName,
				"FederatorZone": map[string]interface{}{
					"ZoneId": pZone.ZoneId,
				},
			},
		}
		out, status, err := mcClient.ShowFederatedPartnerZone(op.uri, selfFed1.tokenOper, showFedPartnerZone)
		require.Nil(t, err, "show partner federator zones")
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, 1, len(out))
		require.True(t, out[0].Registered)
		require.NotEmpty(t, out[0].Revision)

		// Verify that registered zone is added as cloudlet
		clLookup := ormapi.RegionCloudlet{
			Region: selfFed1.region,
			Cloudlet: edgeproto.Cloudlet{
				Key: edgeproto.CloudletKey{
					Name:                  pZone.ZoneId,
					Organization:          selfFed1.operatorId,
					FederatedOrganization: pZone.OperatorId,
				},
			},
		}
		selfFed1Cls, status, err := mcClient.ShowCloudlet(op.uri, selfFed1.tokenOper, &clLookup)
		require.Nil(t, err, "show added federator zone as cloudlet")
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, 1, len(selfFed1Cls))
	}
	clLookup := ormapi.RegionCloudlet{
		Region: selfFed1.region,
		Cloudlet: edgeproto.Cloudlet{
			Key: edgeproto.CloudletKey{
				FederatedOrganization: partnerFed.operatorId,
			},
			PlatformType: edgeproto.PlatformType_PLATFORM_TYPE_FEDERATION,
		},
	}
	selfFed1Cls, status, err := mcClient.ShowCloudlet(op.uri, selfFed1.tokenOper, &clLookup)
	require.Nil(t, err, "match federation zone list with cloudlets")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, len(partnerZones), len(selfFed1Cls))

	// Test federation APIs
	// ====================
	testPartnerFederationAPIs(t, ctx, mcClient, op, selfFederators, partnerFed)

	// --------+
	// Cleanup |
	// --------+

	// Federation deletion between selfFed1 and partner federator should
	// fail if there are partner zones registered
	// =================================================================
	fedReq = &ormapi.Federation{
		SelfOperatorId: selfFed1.operatorId,
		Name:           partnerFed.fedName,
	}
	_, _, err = mcClient.DeregisterFederation(op.uri, selfFed1.tokenOper, fedReq)
	require.NotNil(t, err, "deregister federation")
	require.Contains(t, err.Error(), "Please deregister it before deregistering")

	// Deregister all the partner zones
	// ================================
	zoneList = []string{}
	for _, pZone := range partnerFed.zones {
		zoneList = append(zoneList, pZone.ZoneId)
	}
	zoneRegReq = &ormapi.FederatedZoneRegRequest{
		SelfOperatorId: selfFed1.operatorId,
		FederationName: partnerFed.fedName,
		Zones:          zoneList,
	}
	_, status, err = mcClient.DeRegisterPartnerFederatorZone(op.uri, selfFed1.tokenOper, zoneRegReq)
	require.Nil(t, err, "deregister partner federator zone")
	require.Equal(t, http.StatusOK, status)

	for _, pZone := range partnerFed.zones {
		// Verify that zones are deregistered
		showFedPartnerZone = &cli.MapData{
			Namespace: cli.StructNamespace,
			Data: map[string]interface{}{
				"SelfOperatorId": selfFed1.operatorId,
				"FederationName": partnerFed.fedName,
				"FederatorZone": map[string]interface{}{
					"ZoneId": pZone.ZoneId,
				},
			},
		}
		partnerZones, status, err = mcClient.ShowFederatedPartnerZone(op.uri, selfFed1.tokenOper, showFedPartnerZone)
		require.Nil(t, err, "show partner federator zones")
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, 1, len(partnerZones))
		require.False(t, partnerZones[0].Registered)
		require.NotEmpty(t, partnerZones[0].Revision)

		// Verify that deregistered zone is removed as cloudlet
		clLookup := ormapi.RegionCloudlet{
			Region: selfFed1.region,
			Cloudlet: edgeproto.Cloudlet{
				Key: edgeproto.CloudletKey{
					Name:                  pZone.ZoneId,
					Organization:          selfFed1.operatorId,
					FederatedOrganization: partnerFed.operatorId,
				},
			},
		}
		selfFed1Cls, status, err := mcClient.ShowCloudlet(op.uri, selfFed1.tokenOper, &clLookup)
		require.Nil(t, err, "partner zone is removed as cloudlet")
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, 0, len(selfFed1Cls))
	}
	clLookup = ormapi.RegionCloudlet{
		Region: selfFed1.region,
		Cloudlet: edgeproto.Cloudlet{
			Key: edgeproto.CloudletKey{
				FederatedOrganization: partnerFed.operatorId,
			},
			PlatformType: edgeproto.PlatformType_PLATFORM_TYPE_FEDERATION,
		},
	}
	selfFed1Cls, status, err = mcClient.ShowCloudlet(op.uri, selfFed1.tokenOper, &clLookup)
	require.Nil(t, err, "no partner zones as cloudlets")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(selfFed1Cls))

	// Delete federation between selfFed1 and partner federator
	// ========================================================
	fedReq = &ormapi.Federation{
		SelfOperatorId: selfFed1.operatorId,
		Name:           partnerFed.fedName,
	}
	_, status, err = mcClient.DeregisterFederation(op.uri, selfFed1.tokenOper, fedReq)
	require.Nil(t, err, "deregister federation")
	require.Equal(t, http.StatusOK, status)

	// Verify federation is deleted
	showFedn = &cli.MapData{
		Namespace: cli.StructNamespace,
		Data: map[string]interface{}{
			"SelfOperatorId": selfFed1.operatorId,
			"Name":           partnerFed.fedName,
		},
	}
	federations, status, err = mcClient.ShowFederation(op.uri, selfFed1.tokenOper, showFedn)
	require.Nil(t, err, "show federations")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(federations), "federator exists")
	require.False(t, federations[0].PartnerRoleShareZonesWithSelf, "no federation exists")
	require.NotEmpty(t, federations[0].Revision)

	// No partner zones exist as federation is deleted
	// =======================================================
	showFedPartnerZone = &cli.MapData{
		Namespace: cli.StructNamespace,
		Data: map[string]interface{}{
			"SelfOperatorId": selfFed1.operatorId,
			"FederationName": partnerFed.fedName,
		},
	}
	partnerZones, status, err = mcClient.ShowFederatedPartnerZone(op.uri, selfFed1.tokenOper, showFedPartnerZone)
	require.Nil(t, err, "show partner federator zones")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(partnerZones))

	// Deletion of self federator zone should fail if it is shared with a partner federator
	// ====================================================================================
	zoneReq := &ormapi.FederatorZone{
		OperatorId:  selfFed1.operatorId,
		CountryCode: selfFed1.countryCode,
		ZoneId:      selfFed1Zones[0].ZoneId,
	}
	_, _, err = mcClient.DeleteSelfFederatorZone(op.uri, selfFed1.tokenOper, zoneReq)
	require.NotNil(t, err, "delete self federator zone should fail as it is shared")

	// Unshare all shared zones
	// ========================
	for _, zone := range selfFed1Zones {
		zoneShReq := &ormapi.FederatedSelfZone{
			SelfOperatorId: selfFed1.operatorId,
			FederationName: partnerFed.fedName,
			ZoneId:         zone.ZoneId,
		}
		_, status, err := mcClient.UnshareSelfFederatorZone(op.uri, selfFed1.tokenOper, zoneShReq)
		require.Nil(t, err, "mark zones to be unshared with partner federator")
		require.Equal(t, http.StatusOK, status)
	}

	// No zones are shared
	showFedSelfZone := &cli.MapData{
		Namespace: cli.StructNamespace,
		Data: map[string]interface{}{
			"SelfOperatorId": selfFed1.operatorId,
			"FederationName": partnerFed.fedName,
		},
	}
	fedSelfZones, status, err := mcClient.ShowFederatedSelfZone(op.uri, selfFed1.tokenOper, showFedSelfZone)
	require.Nil(t, err, "show self federated zone")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(fedSelfZones), status)

	// Delete self federator zones
	// ===========================
	for _, selfFed := range selfFederators {
		for _, zone := range selfFed.zones {
			zoneReq := &ormapi.FederatorZone{
				OperatorId:  selfFed.operatorId,
				CountryCode: selfFed.countryCode,
				ZoneId:      zone.ZoneId,
			}
			_, status, err = mcClient.DeleteSelfFederatorZone(op.uri, selfFed.tokenOper, zoneReq)
			require.Nil(t, err, "delete self federator zone")
			require.Equal(t, http.StatusOK, status)
		}
	}

	for _, selfFed := range selfFederators {
		// No zones should exist
		showSelfZone := &cli.MapData{
			Namespace: cli.StructNamespace,
			Data: map[string]interface{}{
				"OperatorId":  selfFed.operatorId,
				"CountryCode": selfFed.countryCode,
			},
		}
		fedZones, status, err := mcClient.ShowSelfFederatorZone(op.uri, selfFed.tokenOper, showSelfZone)
		require.Nil(t, err, "show self federator zones")
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, 0, len(fedZones))
	}

	// Deletion of self federator should fail if its associated partner
	// federators still exist
	// ================================================================
	fedDelReq := &ormapi.Federator{
		OperatorId:  selfFed1.operatorId,
		CountryCode: selfFed1.countryCode,
	}
	_, status, err = mcClient.DeleteSelfFederator(op.uri, selfFed1.tokenOper, fedDelReq)
	require.NotNil(t, err, "cannot delete self federator")

	// Delete partner federator obj
	// ============================
	partnerFedReq = &ormapi.Federation{
		SelfOperatorId: selfFed1.operatorId,
		Name:           partnerFed.fedName,
	}
	_, status, err = mcClient.DeleteFederation(op.uri, selfFed1.tokenOper, partnerFedReq)
	require.Nil(t, err, "delete federation")
	require.Equal(t, http.StatusOK, status)

	// Delete self federators
	// =======================
	for _, selfFed := range selfFederators {
		fedReq := &ormapi.Federator{
			FederationId: selfFed.fedId,
			OperatorId:   selfFed.operatorId,
		}
		_, status, err := mcClient.DeleteSelfFederator(op.uri, selfFed.tokenOper, fedReq)
		require.Nil(t, err, "delete self federator")
		require.Equal(t, http.StatusOK, status)
	}
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

func TestGormFederationObjs(t *testing.T) {
	sql, db, err := StartDB()
	require.Nil(t, err, "start sql db")
	defer sql.StopLocal()
	defer db.Close()

	dbObjs := []interface{}{
		&ormapi.Organization{},
		&ormapi.Federator{},
		&ormapi.Federation{},
		&ormapi.FederatorZone{},
		&ormapi.FederatedPartnerZone{},
		&ormapi.FederatedSelfZone{},
	}

	// drop based on the order of dependency
	for ii := len(dbObjs) - 1; ii >= 0; ii-- {
		db.DropTableIfExists(dbObjs[ii])
	}
	db.LogMode(true)
	db.AutoMigrate(dbObjs...)

	err = InitFederationAPIConstraints(db)
	require.Nil(t, err, "set constraints")

	tests := []DBExec{
		{
			obj:  &ormapi.Organization{Name: "GDDT"},
			pass: true,
		},
		{
			obj:  &ormapi.Organization{Name: "BT"},
			pass: true,
		},
		{
			obj:  &ormapi.Federator{OperatorId: "GDDT", CountryCode: "EU", FederationId: "key1"},
			pass: true,
		},
		{
			obj:  &ormapi.Federator{OperatorId: "BT", CountryCode: "US", FederationId: "key2"},
			pass: true,
		},
		{
			// NOTE: This should fail, as org "BTS" does not exist
			obj:  &ormapi.Federator{OperatorId: "BTS", CountryCode: "US", FederationId: "key3"},
			pass: false,
		},
		{
			obj: &ormapi.Federation{
				Name:             "fed1",
				SelfFederationId: "key1",
				Federator: ormapi.Federator{
					OperatorId: "VOD", CountryCode: "KR", FederationId: "keyA",
				},
				PartnerRoleShareZonesWithSelf: true,
			},
			pass: true,
		},
		{
			obj: &ormapi.Federation{
				Name:             "fed2",
				SelfFederationId: "key2",
				Federator: ormapi.Federator{
					OperatorId: "VOD", CountryCode: "KR", FederationId: "keyB",
				},
			},
			pass: true,
		},
		{
			// same self federation ID cannot be used with another partner federator
			obj: &ormapi.Federation{
				Name:             "fed3",
				SelfFederationId: "key2",
				Federator: ormapi.Federator{
					OperatorId: "VODA", CountryCode: "KR", FederationId: "keyC",
				},
			},
			pass: false,
		},
		{
			// NOTE: This should fail
			obj: &ormapi.Federation{
				Name:             "fedX",
				SelfFederationId: "keyX",
				Federator: ormapi.Federator{
					OperatorId: "VODA", CountryCode: "KR", FederationId: "keyD",
				},
			},
			pass: false,
		},
		{
			// NOTE: This should fail, as org "BTS" does not exist
			obj: &ormapi.FederatorZone{
				OperatorId: "BTS", CountryCode: "EU",
				ZoneId:      "Z2",
				GeoLocation: "123,321",
			},
			pass: false,
		},
		{
			obj: &ormapi.FederatorZone{
				OperatorId: "BT", CountryCode: "US",
				ZoneId:      "Z1",
				GeoLocation: "123,321",
			},
			pass: true,
		},
		{
			obj: &ormapi.FederatorZone{
				OperatorId: "GDDT", CountryCode: "EU",
				ZoneId:      "Z2",
				GeoLocation: "123,321",
			},
			pass: true,
		},
		{
			// NOTE: should fail, as such federation doesn't exist
			obj: &ormapi.FederatedPartnerZone{
				FederationName: "fedX",
				FederatorZone: ormapi.FederatorZone{
					OperatorId: "VODA", CountryCode: "KR",
					ZoneId:      "Z4",
					GeoLocation: "123,321",
				},
				Registered: true,
			},
			pass: false,
		},
		{
			obj: &ormapi.FederatedPartnerZone{
				FederationName: "fed1",
				FederatorZone: ormapi.FederatorZone{
					OperatorId: "VOD", CountryCode: "KR",
					ZoneId:      "Z4",
					GeoLocation: "123,321",
				},
				Registered: true,
			},
			pass: true,
		},
	}

	for _, test := range tests {
		err = db.Create(test.obj).Error
		if test.pass {
			require.Nil(t, err, test.obj)
		} else {
			require.NotNil(t, err, test.obj)
		}
		defer db.Delete(test.obj)
	}
}
