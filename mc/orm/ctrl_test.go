package orm

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
	"github.com/mitchellh/mapstructure"
	"github.com/mobiledgex/edge-cloud-infra/billing"
	ormtestutil "github.com/mobiledgex/edge-cloud-infra/mc/orm/testutil"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormclient"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/testutil"
	"github.com/mobiledgex/edge-cloud/vault"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

var Success = true
var Fail = false

func TestController(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())
	addr := "127.0.0.1:9999"
	uri := "http://" + addr + "/api/v1"

	vaultServer, vaultConfig := vault.DummyServer()
	defer vaultServer.Close()

	// mock http to redirect requests
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	// any requests that don't have a registered URL will be fetched normally
	httpmock.RegisterNoResponder(httpmock.InitialTransport.RoundTrip)
	testAlertMgrAddr, err := InitAlertmgrMock()
	require.Nil(t, err)

	config := ServerConfig{
		ServAddr:                addr,
		SqlAddr:                 "127.0.0.1:5445",
		RunLocal:                true,
		InitLocal:               true,
		IgnoreEnv:               true,
		SkipVerifyEmail:         true,
		vaultConfig:             vaultConfig,
		AlertMgrAddr:            testAlertMgrAddr,
		AlertmgrResolveTimout:   3 * time.Minute,
		UsageCheckpointInterval: "MONTH",
		BillingPlatform:         billing.BillingTypeFake,
	}
	server, err := RunServer(&config)
	require.Nil(t, err, "run server")
	defer server.Stop()
	enforcer.LogEnforce(true)

	Jwks.Init(vaultConfig, "region", "mcorm")
	Jwks.Meta.CurrentVersion = 1
	Jwks.Keys[1] = &vault.JWK{
		Secret:  "12345",
		Refresh: "1s",
	}

	// run a dummy http server to mimic influxdb
	// this will reply with empty json to everything
	influxServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"data":[{"Messages": null,"Series": null}]}`)
	}))
	defer influxServer.Close()

	// run dummy controller - this always returns success
	// to all APIs directed to it, and does not actually
	// create or delete objects. We are mocking it out
	// so we can test rbac permissions.
	dc := grpc.NewServer(
		grpc.UnaryInterceptor(testutil.UnaryInterceptor),
		grpc.StreamInterceptor(testutil.StreamInterceptor),
	)
	ctrlAddr := "127.0.0.1:9998"
	lis, err := net.Listen("tcp", ctrlAddr)
	require.Nil(t, err)
	ds := testutil.RegisterDummyServer(dc)
	go func() {
		dc.Serve(lis)
	}()
	defer dc.Stop()

	// wait till mc is ready
	err = server.WaitUntilReady()
	require.Nil(t, err, "server online")

	mcClient := &ormclient.Client{}

	// login as super user
	token, err := mcClient.DoLogin(uri, DefaultSuperuser, DefaultSuperpass, NoOTP, NoApiKeyId, NoApiKey)
	require.Nil(t, err, "login as superuser")

	// test controller api
	ctrls, status, err := mcClient.ShowController(uri, token)
	require.Nil(t, err, "show controllers")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(ctrls))
	ctrl := ormapi.Controller{
		Region:   "USA",
		Address:  ctrlAddr,
		InfluxDB: influxServer.URL,
	}
	// create controller
	status, err = mcClient.CreateController(uri, token, &ctrl)
	require.Nil(t, err, "create controller")
	require.Equal(t, http.StatusOK, status)
	ctrls, status, err = mcClient.ShowController(uri, token)
	require.Nil(t, err, "show controllers")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(ctrls))
	require.Equal(t, ctrl.Region, ctrls[0].Region)
	require.Equal(t, ctrl.Address, ctrls[0].Address)

	// delete non-existing controller
	status, err = mcClient.DeleteController(uri, token, &ormapi.Controller{})
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Controller Region not specified")

	// create admin
	admin, tokenAd, _ := testCreateUser(t, mcClient, uri, "admin1")
	testAddUserRole(t, mcClient, uri, token, "", "AdminManager", admin.Name, Success)

	// create a developers
	org1 := "org1"
	org2 := "org2"
	dev, _, tokenDev := testCreateUserOrg(t, mcClient, uri, "dev", "developer", org1)
	_, _, tokenDev2 := testCreateUserOrg(t, mcClient, uri, "dev2", "developer", org2)
	dev3, tokenDev3, _ := testCreateUser(t, mcClient, uri, "dev3")
	dev4, tokenDev4, _ := testCreateUser(t, mcClient, uri, "dev4")
	// create an operator
	org3 := "org3"
	org4 := "org4"
	_, _, tokenOper := testCreateUserOrg(t, mcClient, uri, "oper", "operator", org3)
	_, _, tokenOper2 := testCreateUserOrg(t, mcClient, uri, "oper2", "operator", org4)
	oper3, tokenOper3, _ := testCreateUser(t, mcClient, uri, "oper3")
	oper4, tokenOper4, _ := testCreateUser(t, mcClient, uri, "oper4")

	// number of fake objects internally sent back by dummy server
	ds.ShowDummyCount = 0

	// number of dummy objects we add of each type and org
	dcnt := 3
	ds.AddDummyObjs(ctx, dcnt)
	ds.AddDummyOrgObjs(ctx, org1, dcnt)
	ds.AddDummyOrgObjs(ctx, org2, dcnt)
	ds.AddDummyOrgObjs(ctx, org3, dcnt)
	ds.AddDummyOrgObjs(ctx, org4, dcnt)

	// number of org objects total of each type (sum of above)
	count := 4 * dcnt

	// additional users don't have access to orgs yet
	badPermTestApp(t, mcClient, uri, tokenDev3, ctrl.Region, org1)
	badPermTestShowApp(t, mcClient, uri, tokenDev3, ctrl.Region, org1)

	badPermTestAppInst(t, mcClient, uri, tokenDev3, ctrl.Region, org1, nil)
	badPermTestShowAppInst(t, mcClient, uri, tokenDev3, ctrl.Region, org1)

	badPermTestClusterInst(t, mcClient, uri, tokenDev3, ctrl.Region, org1, nil)
	badPermTestShowClusterInst(t, mcClient, uri, tokenDev3, ctrl.Region, org1)

	badPermTestCloudlet(t, mcClient, uri, tokenOper3, ctrl.Region, org1)
	badPermTestMetrics(t, mcClient, uri, tokenDev3, ctrl.Region, org1)
	badPermTestEvents(t, mcClient, uri, tokenDev3, ctrl.Region, org1)
	badPermTestAlertReceivers(t, mcClient, uri, tokenDev3, ctrl.Region, org1)
	// add new users to orgs
	testAddUserRole(t, mcClient, uri, tokenDev, org1, "DeveloperContributor", dev3.Name, Success)
	testAddUserRole(t, mcClient, uri, tokenDev, org1, "DeveloperViewer", dev4.Name, Success)
	testAddUserRole(t, mcClient, uri, tokenOper, org3, "OperatorContributor", oper3.Name, Success)
	testAddUserRole(t, mcClient, uri, tokenOper, org3, "OperatorViewer", oper4.Name, Success)
	// make sure dev/ops without user perms can't add new users
	user5, _, _ := testCreateUser(t, mcClient, uri, "user5")
	testAddUserRole(t, mcClient, uri, tokenDev3, org1, "DeveloperViewer", user5.Name, Fail)
	testAddUserRole(t, mcClient, uri, tokenDev4, org1, "DeveloperViewer", user5.Name, Fail)
	testAddUserRole(t, mcClient, uri, tokenOper3, org3, "OperatorViewer", user5.Name, Fail)
	testAddUserRole(t, mcClient, uri, tokenOper4, org3, "OperatorViewer", user5.Name, Fail)

	// make sure developer and operator cannot modify controllers
	// all users can see controllers (required for UI to be able to
	// fork requests to each controller as the user).
	ctrlNew := ormapi.Controller{
		Region:  "Bad",
		Address: "bad.mobiledgex.net",
	}
	status, err = mcClient.CreateController(uri, tokenDev, &ctrlNew)
	require.Equal(t, http.StatusForbidden, status)
	status, err = mcClient.CreateController(uri, tokenOper, &ctrlNew)
	require.Equal(t, http.StatusForbidden, status)
	ctrls, status, err = mcClient.ShowController(uri, tokenDev)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(ctrls))
	ctrls, status, err = mcClient.ShowController(uri, tokenOper)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(ctrls))

	// create targetCloudlet in dummy controller
	// cloudlet defaults to "public"
	org3Cloudlet := edgeproto.Cloudlet{
		Key: edgeproto.CloudletKey{
			Organization: org3,
			Name:         org3,
		},
	}
	ds.CloudletCache.Update(ctx, &org3Cloudlet, 0)
	org3CloudletInfo := edgeproto.CloudletInfo{
		Key: org3Cloudlet.Key,
	}
	ds.CloudletInfoCache.Update(ctx, &org3CloudletInfo, 0)
	tc3 := &org3Cloudlet.Key

	// +1 count for Cloudlets because of extra one above
	ccount := count + 1

	// admin can do everything
	goodPermTestFlavor(t, mcClient, uri, tokenAd, ctrl.Region, "", dcnt)
	goodPermTestCloudlet(t, mcClient, uri, tokenAd, ctrl.Region, org3, ccount)
	goodPermTestCloudlet(t, mcClient, uri, tokenAd, ctrl.Region, org4, ccount)
	goodPermTestApp(t, mcClient, uri, tokenAd, ctrl.Region, org1, dcnt)
	goodPermTestApp(t, mcClient, uri, tokenAd, ctrl.Region, org2, dcnt)
	goodPermTestAppInst(t, mcClient, uri, tokenAd, ctrl.Region, org1, tc3, dcnt)
	goodPermTestAppInst(t, mcClient, uri, tokenAd, ctrl.Region, org2, tc3, dcnt)
	goodPermTestClusterInst(t, mcClient, uri, tokenAd, ctrl.Region, org1, tc3, dcnt)
	goodPermTestClusterInst(t, mcClient, uri, tokenAd, ctrl.Region, org2, tc3, dcnt)
	goodPermTestCloudletPool(t, mcClient, uri, tokenAd, ctrl.Region, org1, dcnt)
	goodPermTestCloudletPool(t, mcClient, uri, tokenAd, ctrl.Region, org2, dcnt)
	goodPermTestAutoProvPolicy(t, mcClient, uri, tokenAd, ctrl.Region, org1, dcnt)
	goodPermTestAutoProvPolicy(t, mcClient, uri, tokenAd, ctrl.Region, org2, dcnt)

	// test non-existent org check
	// (no check by admin because it returns a different error code)
	badPermTestNonExistent(t, mcClient, uri, tokenDev, ctrl.Region, tc3)
	badPermTestNonExistent(t, mcClient, uri, tokenDev2, ctrl.Region, tc3)
	badPermTestNonExistent(t, mcClient, uri, tokenDev3, ctrl.Region, tc3)
	badPermTestNonExistent(t, mcClient, uri, tokenDev4, ctrl.Region, tc3)
	badPermTestNonExistent(t, mcClient, uri, tokenOper, ctrl.Region, tc3)
	badPermTestNonExistent(t, mcClient, uri, tokenOper2, ctrl.Region, tc3)
	badPermTestNonExistent(t, mcClient, uri, tokenOper3, ctrl.Region, tc3)
	badPermTestNonExistent(t, mcClient, uri, tokenOper4, ctrl.Region, tc3)

	// bug 1756 - better error message for nonexisting org in image path
	badApp := &edgeproto.App{}
	badApp.Key.Organization = "nonexistent"
	badApp.ImagePath = "docker-qa.mobiledgex.net/nonexistent/images/server_ping_threaded:5.0"
	_, status, err = ormtestutil.TestCreateApp(mcClient, uri, token, ctrl.Region, badApp)
	require.NotNil(t, err)
	require.Equal(t, http.StatusBadRequest, status)
	require.Contains(t, err.Error(), "Organization nonexistent from ImagePath not found")

	// flavors, clusterflavors are special - can be seen by all
	goodPermTestShowFlavor(t, mcClient, uri, tokenDev, ctrl.Region, "", dcnt)
	goodPermTestShowFlavor(t, mcClient, uri, tokenDev2, ctrl.Region, "", dcnt)
	goodPermTestShowFlavor(t, mcClient, uri, tokenDev3, ctrl.Region, "", dcnt)
	goodPermTestShowFlavor(t, mcClient, uri, tokenDev4, ctrl.Region, "", dcnt)
	goodPermTestShowFlavor(t, mcClient, uri, tokenOper, ctrl.Region, "", dcnt)
	goodPermTestShowFlavor(t, mcClient, uri, tokenOper2, ctrl.Region, "", dcnt)
	goodPermTestShowFlavor(t, mcClient, uri, tokenOper3, ctrl.Region, "", dcnt)
	goodPermTestShowFlavor(t, mcClient, uri, tokenOper4, ctrl.Region, "", dcnt)
	// cloudlets are currently all public and can be seen by all
	goodPermTestShowCloudlet(t, mcClient, uri, tokenDev, ctrl.Region, "", ccount)
	goodPermTestShowCloudlet(t, mcClient, uri, tokenDev2, ctrl.Region, "", ccount)
	goodPermTestShowCloudlet(t, mcClient, uri, tokenDev3, ctrl.Region, "", ccount)
	goodPermTestShowCloudlet(t, mcClient, uri, tokenDev4, ctrl.Region, "", ccount)
	goodPermTestShowCloudlet(t, mcClient, uri, tokenOper, ctrl.Region, "", ccount)
	goodPermTestShowCloudlet(t, mcClient, uri, tokenOper2, ctrl.Region, "", ccount)
	goodPermTestShowCloudlet(t, mcClient, uri, tokenOper3, ctrl.Region, "", ccount)
	goodPermTestShowCloudlet(t, mcClient, uri, tokenOper4, ctrl.Region, "", ccount)

	// However, flavors and clusterflavors cannot be modified by non-admins
	badPermTestFlavor(t, mcClient, uri, tokenDev, ctrl.Region, "")
	badPermTestFlavor(t, mcClient, uri, tokenDev2, ctrl.Region, "")
	badPermTestFlavor(t, mcClient, uri, tokenDev3, ctrl.Region, "")
	badPermTestFlavor(t, mcClient, uri, tokenDev4, ctrl.Region, "")
	badPermTestFlavor(t, mcClient, uri, tokenOper, ctrl.Region, "")
	badPermTestFlavor(t, mcClient, uri, tokenOper2, ctrl.Region, "")
	badPermTestFlavor(t, mcClient, uri, tokenOper3, ctrl.Region, "")
	badPermTestFlavor(t, mcClient, uri, tokenOper4, ctrl.Region, "")

	// No orgs have been restricted to cloudlet pools, and no cloudlets
	// have been assigned to pools, so everyone should be able to see
	// all cloudlets.
	testShowOrgCloudlet(t, mcClient, uri, tokenAd, ctrl.Region, org1, ccount)
	testShowOrgCloudlet(t, mcClient, uri, tokenAd, ctrl.Region, org2, ccount)
	testShowOrgCloudlet(t, mcClient, uri, tokenDev, ctrl.Region, org1, ccount)
	testShowOrgCloudlet(t, mcClient, uri, tokenDev2, ctrl.Region, org2, ccount)
	testShowOrgCloudlet(t, mcClient, uri, tokenOper, ctrl.Region, org3, ccount)
	testShowOrgCloudlet(t, mcClient, uri, tokenOper2, ctrl.Region, org4, ccount)
	// no permissions outside of own org for ShowOrgCloudlet
	// (nothing to do with cloudlet pools, just checking API access)
	badPermShowOrgCloudlet(t, mcClient, uri, tokenDev, ctrl.Region, org2)
	badPermShowOrgCloudlet(t, mcClient, uri, tokenDev, ctrl.Region, org3)
	badPermShowOrgCloudlet(t, mcClient, uri, tokenDev, ctrl.Region, org4)
	badPermShowOrgCloudlet(t, mcClient, uri, tokenDev2, ctrl.Region, org1)
	badPermShowOrgCloudlet(t, mcClient, uri, tokenDev2, ctrl.Region, org3)
	badPermShowOrgCloudlet(t, mcClient, uri, tokenDev2, ctrl.Region, org4)
	badPermShowOrgCloudlet(t, mcClient, uri, tokenOper, ctrl.Region, org1)
	badPermShowOrgCloudlet(t, mcClient, uri, tokenOper, ctrl.Region, org2)
	badPermShowOrgCloudlet(t, mcClient, uri, tokenOper, ctrl.Region, org4)
	badPermShowOrgCloudlet(t, mcClient, uri, tokenOper2, ctrl.Region, org1)
	badPermShowOrgCloudlet(t, mcClient, uri, tokenOper2, ctrl.Region, org2)
	badPermShowOrgCloudlet(t, mcClient, uri, tokenOper2, ctrl.Region, org3)

	// make sure operator cannot create apps, appinsts, clusters, etc
	badPermTestApp(t, mcClient, uri, tokenOper, ctrl.Region, org1)
	badPermTestShowApp(t, mcClient, uri, tokenOper, ctrl.Region, org1)

	badPermTestAppInst(t, mcClient, uri, tokenOper, ctrl.Region, org1, tc3)
	badPermTestShowAppInst(t, mcClient, uri, tokenOper, ctrl.Region, org1)

	badPermTestClusterInst(t, mcClient, uri, tokenOper, ctrl.Region, org1, tc3)
	badPermTestShowClusterInst(t, mcClient, uri, tokenOper, ctrl.Region, org1)

	badPermTestApp(t, mcClient, uri, tokenOper2, ctrl.Region, org1)
	badPermTestShowApp(t, mcClient, uri, tokenOper2, ctrl.Region, org1)

	badPermTestAppInst(t, mcClient, uri, tokenOper2, ctrl.Region, org1, tc3)
	badPermTestShowAppInst(t, mcClient, uri, tokenOper2, ctrl.Region, org1)

	badPermTestClusterInst(t, mcClient, uri, tokenOper2, ctrl.Region, org1, tc3)
	badPermTestShowClusterInst(t, mcClient, uri, tokenOper2, ctrl.Region, org1)

	// make sure developer cannot create cloudlet (but they can see all of them)
	badPermTestCloudlet(t, mcClient, uri, tokenDev, ctrl.Region, org3)
	badPermTestCloudlet(t, mcClient, uri, tokenDev2, ctrl.Region, org3)

	// test operators can modify their own objs but not each other's
	badPermTestCloudlet(t, mcClient, uri, tokenOper, ctrl.Region, org4)
	badPermTestCloudlet(t, mcClient, uri, tokenOper2, ctrl.Region, org3)
	permTestCloudletPool(t, mcClient, uri, tokenOper, tokenOper2, ctrl.Region, org3, org4, dcnt)
	permTestVMPool(t, mcClient, uri, tokenOper, tokenOper2, ctrl.Region, org3, org4, dcnt)
	permTestTrustPolicy(t, mcClient, uri, tokenOper, tokenOper2, ctrl.Region, org3, org4, dcnt)

	// test developers can modify their own objs but not each other's
	// tests also that developers can create AppInsts/ClusterInsts on tc3.
	permTestApp(t, mcClient, uri, tokenDev, tokenDev2, ctrl.Region,
		org1, org2, dcnt)
	permTestAppInst(t, mcClient, uri, tokenDev, tokenDev2, ctrl.Region,
		org1, org2, tc3, dcnt)
	permTestClusterInst(t, mcClient, uri, tokenDev, tokenDev2, ctrl.Region,
		org1, org2, tc3, dcnt)
	permTestAutoProvPolicy(t, mcClient, uri, tokenDev, tokenDev2, ctrl.Region,
		org1, org2, dcnt)
	permTestAutoScalePolicy(t, mcClient, uri, tokenDev, tokenDev2, ctrl.Region,
		org1, org2, dcnt)
	// test users with different roles
	goodPermTestApp(t, mcClient, uri, tokenDev3, ctrl.Region, org1, dcnt)
	goodPermTestAppInst(t, mcClient, uri, tokenDev3, ctrl.Region, org1, tc3, dcnt)
	goodPermTestClusterInst(t, mcClient, uri, tokenDev3, ctrl.Region, org1, tc3, dcnt)
	goodPermTestMetrics(t, mcClient, uri, tokenDev3, tokenOper3, ctrl.Region, org1, org3)
	goodPermTestEvents(t, mcClient, uri, tokenDev3, tokenOper3, ctrl.Region, org1, org3)

	// test users with different roles
	goodPermTestCloudlet(t, mcClient, uri, tokenOper3, ctrl.Region, org3, ccount)
	goodPermTestClusterInst(t, mcClient, uri, tokenDev, ctrl.Region, org1, tc3, dcnt)
	badPermTestClusterInst(t, mcClient, uri, tokenDev2, ctrl.Region, org1, tc3)

	// test alert receivers permissions and validations
	goodPermTestAlertReceivers(t, mcClient, uri, tokenDev3, tokenOper3, ctrl.Region, org1, org3)
	// test ability of different users to delete/show other users's receivers
	userPermTestAlertReceivers(t, mcClient, uri, dev.Name, tokenDev, dev3.Name, tokenDev3, ctrl.Region, org1, org3)

	{
		// developers can't create AppInsts on other developemar's ClusterInsts
		appinst := edgeproto.AppInst{}
		appinst.Key.AppKey.Organization = org1
		appinst.Key.ClusterInstKey.Organization = cloudcommon.OrganizationMobiledgeX
		_, status, err := ormtestutil.TestCreateAppInst(mcClient, uri, tokenDev, ctrl.Region, &appinst)
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "AppInst organization must match ClusterInst organization")
		// but admin can
		_, status, err = ormtestutil.TestCreateAppInst(mcClient, uri, tokenAd, ctrl.Region, &appinst)
		require.Nil(t, err)
		require.Equal(t, http.StatusOK, status)
		_, status, err = ormtestutil.TestDeleteAppInst(mcClient, uri, tokenAd, ctrl.Region, &appinst)
		require.Nil(t, err)
		require.Equal(t, http.StatusOK, status)
	}

	// remove users from roles, test that they can't modify anything anymore
	testRemoveUserRole(t, mcClient, uri, tokenDev, org1, "DeveloperContributor", dev3.Name, Success)
	badPermTestApp(t, mcClient, uri, tokenDev3, ctrl.Region, org1)
	badPermTestAppInst(t, mcClient, uri, tokenDev3, ctrl.Region, org1, tc3)
	badPermTestClusterInst(t, mcClient, uri, tokenDev3, ctrl.Region, org1, tc3)
	testRemoveUserRole(t, mcClient, uri, tokenOper, org3, "OperatorContributor", oper3.Name, Success)
	badPermTestCloudlet(t, mcClient, uri, tokenOper3, ctrl.Region, org3)

	// operator create cloudlet pool for org3
	pool := ormapi.RegionCloudletPool{
		Region: ctrl.Region,
		CloudletPool: edgeproto.CloudletPool{
			Key: edgeproto.CloudletPoolKey{
				Name:         "pool1",
				Organization: org3,
			},
		},
	}
	_, status, err = mcClient.CreateCloudletPool(uri, tokenOper, &pool)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)

	poollist, status, err := mcClient.ShowCloudletPool(uri, tokenOper, &pool)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(poollist))

	// admin can see pool
	poollist, status, err = mcClient.ShowCloudletPool(uri, token, &pool)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(poollist))

	// other operator or developer can't see pool
	poollist, status, err = mcClient.ShowCloudletPool(uri, tokenOper2, &pool)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(poollist))
	poollist, status, err = mcClient.ShowCloudletPool(uri, tokenDev, &pool)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(poollist))

	// associate cloudletpool with org, allows org1 to see cloudlets in pool
	op1 := ormapi.OrgCloudletPool{
		Org:             org1,
		Region:          ctrl.Region,
		CloudletPool:    pool.CloudletPool.Key.Name,
		CloudletPoolOrg: pool.CloudletPool.Key.Organization, // org3
	}
	status, err = mcClient.CreateOrgCloudletPool(uri, tokenOper, &op1)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)

	// trying to delete cloudletpool should fail because it's in use by orgcloudletpool
	_, status, err = mcClient.DeleteCloudletPool(uri, tokenOper, &pool)
	require.NotNil(t, err)
	require.Equal(t, http.StatusBadRequest, status)
	require.Contains(t, err.Error(), "because it is in use by OrgCloudletPool")

	// add tc3 to pool1, so it's accessible for org1
	member := ormapi.RegionCloudletPoolMember{
		Region:             ctrl.Region,
		CloudletPoolMember: edgeproto.CloudletPoolMember{},
	}
	member.CloudletPoolMember.Key = pool.CloudletPool.Key
	member.CloudletPoolMember.CloudletName = tc3.Name
	_, status, err = mcClient.AddCloudletPoolMember(uri, tokenOper, &member)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)

	log.SetDebugLevel(log.DebugLevelApi)

	autoProvTc3 := func(in *edgeproto.AutoProvPolicy) {
		in.Cloudlets = append(in.Cloudlets, &edgeproto.AutoProvCloudlet{
			Key: *tc3,
		})
	}
	autoProvAddTc3 := func(in *edgeproto.AutoProvPolicyCloudlet) {
		in.CloudletKey = *tc3
	}

	// tc3 should now be visible along with all other cloudlets
	testShowOrgCloudlet(t, mcClient, uri, tokenDev, ctrl.Region, org1, ccount)
	// tc3 should not be visible by other orgs
	// (note count here is without tc3, except for org3 to which it belongs)
	testShowOrgCloudlet(t, mcClient, uri, tokenDev2, ctrl.Region, org2, count)
	testShowOrgCloudlet(t, mcClient, uri, tokenOper, ctrl.Region, org3, ccount)
	testShowOrgCloudlet(t, mcClient, uri, tokenOper2, ctrl.Region, org4, count)

	// tc3 should now be usable for org1
	goodPermTestClusterInst(t, mcClient, uri, tokenDev, ctrl.Region, org1, tc3, dcnt)
	goodPermTestAppInst(t, mcClient, uri, tokenDev, ctrl.Region, org1, tc3, dcnt)
	goodPermTestAutoProvPolicy(t, mcClient, uri, tokenDev, ctrl.Region, org1, dcnt, autoProvTc3)
	goodPermAddAutoProvPolicyCloudlet(t, mcClient, uri, tokenDev, ctrl.Region, org1, autoProvAddTc3)
	// tc3 should be unusable for other org2
	badPermCreateClusterInst(t, mcClient, uri, tokenDev2, ctrl.Region, org2, tc3)
	badPermCreateAppInst(t, mcClient, uri, tokenDev2, ctrl.Region, org2, tc3)
	badPermTestAutoProvPolicy400(t, mcClient, uri, tokenDev2, ctrl.Region, org2, autoProvTc3)
	badPermAddAutoProvPolicyCloudlet400(t, mcClient, uri, tokenDev2, ctrl.Region, org2, autoProvAddTc3)

	// show cloudlet for org1 will only show those in pool1 plus public cloudlets
	goodPermTestShowCloudlet(t, mcClient, uri, tokenDev, ctrl.Region, "", ccount)
	// show cloudlet will not show tc3 since it's now part of a pool
	// (except for operator who owns tc3).
	goodPermTestShowCloudlet(t, mcClient, uri, tokenDev2, ctrl.Region, "", count)
	goodPermTestShowCloudlet(t, mcClient, uri, tokenOper, ctrl.Region, "", ccount)
	goodPermTestShowCloudlet(t, mcClient, uri, tokenOper2, ctrl.Region, "", count)
	// bug1741 - empty args to Delete CloudletPool when pools are present
	// Should allow delete to continue to controller which always returns success
	_, status, err = ormtestutil.TestDeleteCloudletPool(mcClient, uri, tokenAd, ctrl.Region, &edgeproto.CloudletPool{})
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)

	// test user api keys
	testUserApiKeys(t, ctx, ds, &ctrl, count, mcClient, uri, token)

	// delete org cloudlet pools
	status, err = mcClient.DeleteOrgCloudletPool(uri, tokenOper, &op1)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	// delete cloudlet pool
	_, status, err = mcClient.DeleteCloudletPool(uri, tokenOper, &pool)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)

	// delete controller
	status, err = mcClient.DeleteController(uri, token, &ctrl)
	require.Nil(t, err, "delete controller")
	require.Equal(t, http.StatusOK, status)
	ctrls, status, err = mcClient.ShowController(uri, token)
	require.Nil(t, err, "show controllers")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(ctrls))

	// Test Streaming APIs
	dc2 := grpc.NewServer()
	ctrlAddr2 := "127.0.0.1:9997"
	lis2, err := net.Listen("tcp", ctrlAddr2)
	require.Nil(t, err)
	sds := StreamDummyServer{}
	sds.next = make(chan int, 1)
	edgeproto.RegisterClusterInstApiServer(dc2, &sds)
	edgeproto.RegisterCloudletPoolApiServer(dc2, &sds)
	go func() {
		dc2.Serve(lis2)
	}()
	defer dc2.Stop()

	ctrl = ormapi.Controller{
		Region:  "Stream",
		Address: ctrlAddr2,
	}
	// create controller
	status, err = mcClient.CreateController(uri, token, &ctrl)
	require.Nil(t, err, "create controller")
	require.Equal(t, http.StatusOK, status)
	dat := ormapi.RegionClusterInst{
		Region: ctrl.Region,
		ClusterInst: edgeproto.ClusterInst{
			Key: edgeproto.ClusterInstKey{
				Organization: "org1",
			},
		},
	}
	out := edgeproto.Result{}
	count = 0
	// check that we get intermediate results.
	// the callback func is only called when data is read back.
	status, err = mcClient.PostJsonStreamOut(uri+"/auth/ctrl/CreateClusterInst",
		token, &dat, &out, func() {
			// got a result, trigger next result
			count++
			require.Equal(t, count, int(out.Code))
			sds.next <- 1
		})
	require.Nil(t, err, "stream test create cluster inst")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 3, count)
	// check that we hit timeout if we don't trigger the next one.
	count = 0
	sds.next = make(chan int, 1)
	status, err = mcClient.PostJsonStreamOut(uri+"/auth/ctrl/CreateClusterInst",
		token, &dat, &out, func() {
			count++
		})
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "timedout")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, count)

	count = 0
	wsOut := ormapi.WSStreamPayload{}
	// check that we get intermediate results.
	// the callback func is only called when data is read back.
	// Test Websocket connection
	uri = "ws://" + addr + "/ws/api/v1"
	status, err = mcClient.PostJsonStreamOut(uri+"/auth/ctrl/CreateClusterInst",
		token, &dat, &wsOut, func() {
			// got a result, trigger next result
			count++
			require.Equal(t, 200, int(wsOut.Code))
			result := edgeproto.Result{}
			err = mapstructure.Decode(wsOut.Data, &result)
			require.Nil(t, err, "Received data of type Result")
			require.Equal(t, count, int(result.Code))
			sds.next <- 1
		})
	require.Nil(t, err, "stream test create cluster inst")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 3, count)
	// check that we hit timeout if we don't trigger the next one.
	count = 0
	sds.next = make(chan int, 1)
	status, err = mcClient.PostJsonStreamOut(uri+"/auth/ctrl/CreateClusterInst",
		token, &dat, &wsOut, func() {
			count++
		})
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "timedout")
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, 1, count)
}

func testCreateUser(t *testing.T, mcClient *ormclient.Client, uri, name string) (*ormapi.User, string, string) {
	user := ormapi.User{
		Name:       name,
		Email:      name + "@gmail.com",
		Passhash:   name + "-password-super-long-crazy-hard-difficult",
		EnableTOTP: true,
	}
	resp, status, err := mcClient.CreateUser(uri, &user)
	require.Nil(t, err, "create user ", name)
	require.Equal(t, http.StatusOK, status)
	require.NotEmpty(t, resp.TOTPSharedKey, "user totp shared key", name)
	require.NotNil(t, resp.TOTPQRImage, "user totp qa", name)
	// login
	otp, err := totp.GenerateCode(resp.TOTPSharedKey, time.Now())
	require.Nil(t, err, "generate otp", name)
	token, err := mcClient.DoLogin(uri, user.Name, user.Passhash, otp, NoApiKeyId, NoApiKey)
	require.Nil(t, err, "login as ", name)
	return &user, token, user.Passhash
}

func testCreateOrg(t *testing.T, mcClient *ormclient.Client, uri, token, orgType, orgName string) *ormapi.Organization {
	// create org
	org := ormapi.Organization{
		Type: orgType,
		Name: orgName,
	}
	status, err := mcClient.CreateOrg(uri, token, &org)
	require.Nil(t, err, "create org ", orgName)
	require.Equal(t, http.StatusOK, status)
	return &org
}

var updateOrgData = `{"Name":"%s","PublicImages":%t}`
var updateOrgType = `{"Name":"%s","Type":"%s"}`
var updateOrgDeleteInProgress = `{"Name":"%s","DeleteInProgress":%t}`

func testUpdateOrg(t *testing.T, mcClient *ormclient.Client, uri, token, orgName string) {
	org := getOrg(t, mcClient, uri, token, orgName)
	update := *org
	update.PublicImages = !org.PublicImages

	// For updates, must specify json directly so we can
	// specify empty strings and false values. Otherwise json.Marshal()
	// will just ignore them.
	dat := fmt.Sprintf(updateOrgData, update.Name, update.PublicImages)

	status, err := mcClient.UpdateOrg(uri, token, dat)
	require.Nil(t, err, "update org ", org.Name)
	require.Equal(t, http.StatusOK, status)

	check := getOrg(t, mcClient, uri, token, org.Name)
	// ignore updated timestamps
	check.UpdatedAt = update.UpdatedAt
	require.Equal(t, update, *check, "updated org should be as expected")

	// change back
	dat = fmt.Sprintf(updateOrgData, org.Name, org.PublicImages)
	status, err = mcClient.UpdateOrg(uri, token, dat)
	require.Nil(t, err, "update org ", org.Name)
	require.Equal(t, http.StatusOK, status)

	check = getOrg(t, mcClient, uri, token, org.Name)
	// ignore updated timestamps
	check.UpdatedAt = org.UpdatedAt
	require.Equal(t, org, check, "updated org should be as expected")

	// changing type should fail
	typ := OrgTypeDeveloper
	if org.Type == OrgTypeDeveloper {
		typ = OrgTypeOperator
	}
	dat = fmt.Sprintf(updateOrgType, org.Name, typ)
	status, err = mcClient.UpdateOrg(uri, token, dat)
	require.NotNil(t, err, "update org type")
	require.Equal(t, http.StatusBadRequest, status)
	require.Contains(t, err.Error(), "Cannot change Organization type")
	dat = fmt.Sprintf(updateOrgType, org.Name, OrgTypeAdmin)
	status, err = mcClient.UpdateOrg(uri, token, dat)
	require.NotNil(t, err, "update org type")
	require.Equal(t, http.StatusBadRequest, status)
	require.Contains(t, err.Error(), "Cannot change Organization type")
}

func testUpdateOrgFail(t *testing.T, mcClient *ormclient.Client, uri, token, orgName string) {
	dat := fmt.Sprintf(updateOrgData, orgName, false)
	status, err := mcClient.UpdateOrg(uri, token, dat)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
}

func getOrg(t *testing.T, mcClient *ormclient.Client, uri, token, name string) *ormapi.Organization {
	orgs, status, err := mcClient.ShowOrg(uri, token)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	for _, org := range orgs {
		if org.Name == name {
			return &org
		}
	}
	require.True(t, false, fmt.Errorf("org %s not found", name))
	return nil
}

func testCreateUserOrg(t *testing.T, mcClient *ormclient.Client, uri, name, orgType, orgName string) (*ormapi.User, *ormapi.Organization, string) {
	user, token, _ := testCreateUser(t, mcClient, uri, name)
	org := testCreateOrg(t, mcClient, uri, token, orgType, orgName)
	return user, org, token
}

func testAddUserRole(t *testing.T, mcClient *ormclient.Client, uri, token, org, role, username string, success bool) {
	roleArg := ormapi.Role{
		Username: username,
		Org:      org,
		Role:     role,
	}
	status, err := mcClient.AddUserRole(uri, token, &roleArg)
	if success {
		require.Nil(t, err, "add user role")
		require.Equal(t, http.StatusOK, status)
	} else {
		require.Equal(t, http.StatusForbidden, status)
	}
}

func testRemoveUserRole(t *testing.T, mcClient *ormclient.Client, uri, token, org, role, username string, success bool) {
	roleArg := ormapi.Role{
		Username: username,
		Org:      org,
		Role:     role,
	}
	status, err := mcClient.RemoveUserRole(uri, token, &roleArg)
	require.Nil(t, err, "remove user role")
	require.Equal(t, http.StatusOK, status)
	if success {
	} else {
		require.Equal(t, http.StatusForbidden, status)
	}
}

func setClusterInstDev(dev string, insts []edgeproto.ClusterInst) {
	for ii, _ := range insts {
		insts[ii].Key.Organization = dev
	}
}

func testShowOrgCloudlet(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string, showcount int) {
	oc := ormapi.OrgCloudlet{}
	oc.Region = region
	oc.Org = org
	list, status, err := mcClient.ShowOrgCloudlet(uri, token, &oc)
	require.Nil(t, err, "show org cloudlet")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, showcount, len(list))
	infolist, infostatus, err := mcClient.ShowOrgCloudletInfo(uri, token, &oc)
	require.Nil(t, err, "show org cloudletinfo")
	require.Equal(t, http.StatusOK, infostatus)
	require.Equal(t, showcount, len(infolist))
}

func badPermTestOrgCloudletPool(t *testing.T, mcClient *ormclient.Client, uri, token string, op *ormapi.OrgCloudletPool) {
	status, err := mcClient.CreateOrgCloudletPool(uri, token, op)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
	status, err = mcClient.DeleteOrgCloudletPool(uri, token, op)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
	list, status, err := mcClient.ShowOrgCloudletPool(uri, token)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(list))
}

func badPermShowOrgCloudlet(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string) {
	oc := ormapi.OrgCloudlet{}
	oc.Region = region
	oc.Org = org
	_, status, err := mcClient.ShowOrgCloudlet(uri, token, &oc)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)

	_, infostatus, err := mcClient.ShowOrgCloudletInfo(uri, token, &oc)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, infostatus)
}

// Test that we get forbidden for Orgs that don't exist
func badPermTestNonExistent(t *testing.T, mcClient *ormclient.Client, uri, token, region string, tc *edgeproto.CloudletKey) {
	neOrg := "non-existent-org"
	badPermCreateApp(t, mcClient, uri, token, region, neOrg)
	badPermCreateAppInst(t, mcClient, uri, token, region, neOrg, tc)
	badPermCreateCloudlet(t, mcClient, uri, token, region, neOrg)
	badPermCreateClusterInst(t, mcClient, uri, token, region, neOrg, tc)
	badPermCreateOperatorCode(t, mcClient, uri, token, region, neOrg)
	badPermCreateAutoProvPolicy(t, mcClient, uri, token, region, neOrg)
	badPermCreateAutoScalePolicy(t, mcClient, uri, token, region, neOrg)
	badPermCreateTrustPolicy(t, mcClient, uri, token, region, neOrg)
	badPermCreateCloudletPool(t, mcClient, uri, token, region, neOrg)
	badPermCreateResTagTable(t, mcClient, uri, token, region, neOrg)
}

func badPermTestAutoProvPolicy400(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.AutoProvPolicy)) {
	// check for "No permissions" instead of Forbidden(403)
	_, status, err := ormtestutil.TestPermCreateAutoProvPolicy(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, http.StatusBadRequest, status)
	require.Contains(t, err.Error(), "No permissions for Cloudlet")
	_, status, err = ormtestutil.TestPermUpdateAutoProvPolicy(mcClient, uri, token, region, org, modFuncs...)
	require.NotNil(t, err)
	require.Equal(t, http.StatusBadRequest, status)
	require.Contains(t, err.Error(), "No permissions for Cloudlet")
}

func badPermAddAutoProvPolicyCloudlet400(t *testing.T, mcClient *ormclient.Client, uri, token, region, org string, modFuncs ...func(*edgeproto.AutoProvPolicyCloudlet)) {
	// check for "No permissions" instead of Forbidden(403)
	_, status, err := ormtestutil.TestPermAddAutoProvPolicyCloudlet(mcClient, uri, token, region, org, modFuncs...)
	require.Equal(t, http.StatusBadRequest, status)
	require.Contains(t, err.Error(), "No permissions for Cloudlet")
}

type StreamDummyServer struct {
	next chan int
	fail bool
}

func (s *StreamDummyServer) CreateClusterInst(in *edgeproto.ClusterInst, server edgeproto.ClusterInstApi_CreateClusterInstServer) error {
	server.Send(&edgeproto.Result{Code: 1})
	for ii := 2; ii < 4; ii++ {
		select {
		case <-s.next:
		case <-time.After(1 * time.Second):
			return fmt.Errorf("timedout")
		}
		server.Send(&edgeproto.Result{Code: int32(ii)})
	}
	if s.fail {
		return fmt.Errorf("fail")
	}
	return nil
}

func (s *StreamDummyServer) DeleteClusterInst(in *edgeproto.ClusterInst, server edgeproto.ClusterInstApi_DeleteClusterInstServer) error {
	return nil
}

func (s *StreamDummyServer) UpdateClusterInst(in *edgeproto.ClusterInst, server edgeproto.ClusterInstApi_UpdateClusterInstServer) error {
	return nil
}

func (s *StreamDummyServer) ShowClusterInst(in *edgeproto.ClusterInst, server edgeproto.ClusterInstApi_ShowClusterInstServer) error {
	return nil
}

func (s *StreamDummyServer) CreateCloudletPool(ctx context.Context, in *edgeproto.CloudletPool) (*edgeproto.Result, error) {
	return &edgeproto.Result{}, nil
}

func (s *StreamDummyServer) DeleteCloudletPool(ctx context.Context, in *edgeproto.CloudletPool) (*edgeproto.Result, error) {
	return &edgeproto.Result{}, nil
}

func (s *StreamDummyServer) UpdateCloudletPool(ctx context.Context, in *edgeproto.CloudletPool) (*edgeproto.Result, error) {
	return &edgeproto.Result{}, nil
}

func (s *StreamDummyServer) AddCloudletPoolMember(ctx context.Context, in *edgeproto.CloudletPoolMember) (*edgeproto.Result, error) {
	return &edgeproto.Result{}, nil
}

func (s *StreamDummyServer) RemoveCloudletPoolMember(ctx context.Context, in *edgeproto.CloudletPoolMember) (*edgeproto.Result, error) {
	return &edgeproto.Result{}, nil
}

func (s *StreamDummyServer) ShowCloudletPool(in *edgeproto.CloudletPool, cb edgeproto.CloudletPoolApi_ShowCloudletPoolServer) error {
	return nil
}

func testUserApiKeys(t *testing.T, ctx context.Context, ds *testutil.DummyServer, ctrl *ormapi.Controller, count int, mcClient *ormclient.Client, uri, token string) {
	// login as super user
	token, err := mcClient.DoLogin(uri, DefaultSuperuser, DefaultSuperpass, NoOTP, NoApiKeyId, NoApiKey)
	require.Nil(t, err, "login as superuser")

	// create developer & operator orgs
	devOrg := ormapi.Organization{
		Type: "developer",
		Name: "DevOrg",
	}
	status, err := mcClient.CreateOrg(uri, token, &devOrg)
	require.Nil(t, err, "create org")
	require.Equal(t, http.StatusOK, status, "create org status")
	operOrg := ormapi.Organization{
		Type: "operator",
		Name: "OperOrg",
	}
	status, err = mcClient.CreateOrg(uri, token, &operOrg)
	require.Nil(t, err, "create org")
	require.Equal(t, http.StatusOK, status, "create org status")

	// create user
	user1, token1, _ := testCreateUser(t, mcClient, uri, "user1")
	// add user role
	testAddUserRole(t, mcClient, uri, token, devOrg.Name, "DeveloperViewer", user1.Name, Success)

	// invalid action error
	userApiKeyObj := ormapi.CreateUserApiKey{
		UserApiKey: ormapi.UserApiKey{
			Description: "App view only key",
			Org:         devOrg.Name,
		},
		Permissions: []ormapi.RolePerm{
			ormapi.RolePerm{
				Action:   "views",
				Resource: "apps",
			},
		},
	}
	_, status, err = mcClient.CreateUserApiKey(uri, token1, &userApiKeyObj)
	require.NotNil(t, err, "invalid actions")
	require.Contains(t, err.Error(), "Invalid action", "invalid action err match")
	require.Equal(t, http.StatusBadRequest, status, "bad request")

	// invalid permission error
	userApiKeyObj.Permissions = []ormapi.RolePerm{
		ormapi.RolePerm{
			Action:   "view",
			Resource: "app",
		},
	}
	_, status, err = mcClient.CreateUserApiKey(uri, token1, &userApiKeyObj)
	require.NotNil(t, err, "invalid permission")
	require.Contains(t, err.Error(), "Invalid permission specified", "err match")
	require.Equal(t, http.StatusBadRequest, status, "bad request")

	// user of developer org should fail to create operator role based api key
	userApiKeyObj.Permissions = []ormapi.RolePerm{
		ormapi.RolePerm{
			Action:   "manage",
			Resource: "cloudlets",
		},
	}
	_, status, err = mcClient.CreateUserApiKey(uri, token1, &userApiKeyObj)
	require.NotNil(t, err, "not allowed to use operator resource")
	require.Contains(t, err.Error(), "Invalid permission specified", "err match")
	require.Equal(t, http.StatusBadRequest, status, "bad request")

	// user of developerviewer role should fail to create manage action based api key
	userApiKeyObj.Permissions = []ormapi.RolePerm{
		ormapi.RolePerm{
			Action:   "manage",
			Resource: "apps",
		},
	}
	_, status, err = mcClient.CreateUserApiKey(uri, token1, &userApiKeyObj)
	require.NotNil(t, err, "not allowed to use manage action")
	require.Contains(t, err.Error(), "Invalid permission specified", "err match")
	require.Equal(t, http.StatusBadRequest, status, "bad request")

	// user of operator org should fail to create developer role based api key
	testRemoveUserRole(t, mcClient, uri, token, devOrg.Name, "DeveloperViewer", user1.Name, Success)
	testAddUserRole(t, mcClient, uri, token, operOrg.Name, "OperatorViewer", user1.Name, Success)
	userApiKeyObj.Org = operOrg.Name
	userApiKeyObj.Permissions = []ormapi.RolePerm{
		ormapi.RolePerm{
			Action:   "view",
			Resource: "apps",
		},
	}
	_, status, err = mcClient.CreateUserApiKey(uri, token1, &userApiKeyObj)
	require.NotNil(t, err, "invalid permission")
	require.Contains(t, err.Error(), "Invalid permission specified", "err match")
	require.Equal(t, http.StatusBadRequest, status, "bad request")

	// user of operator org should fail to create admin role based api key
	userApiKeyObj.Permissions = []ormapi.RolePerm{
		ormapi.RolePerm{
			Action:   "manage",
			Resource: "users",
		},
	}
	_, status, err = mcClient.CreateUserApiKey(uri, token1, &userApiKeyObj)
	require.NotNil(t, err, "invalid permission")
	require.Contains(t, err.Error(), "Invalid permission specified", "err match")
	require.Equal(t, http.StatusBadRequest, status, "bad request")

	// user of operatorviewer role should fail to create manage action based api key
	userApiKeyObj.Permissions = []ormapi.RolePerm{
		ormapi.RolePerm{
			Action:   "manage",
			Resource: "cloudlets",
		},
	}
	_, status, err = mcClient.CreateUserApiKey(uri, token1, &userApiKeyObj)
	require.NotNil(t, err, "not allowed to use manage action")
	require.Contains(t, err.Error(), "Invalid permission specified", "err match")
	require.Equal(t, http.StatusBadRequest, status, "bad request")

	// user should be able to create api key if action, resource input are correct
	testRemoveUserRole(t, mcClient, uri, token, operOrg.Name, "OperatorViewer", user1.Name, Success)
	testAddUserRole(t, mcClient, uri, token, operOrg.Name, "OperatorManager", user1.Name, Success)
	userApiKeyObj.Permissions = []ormapi.RolePerm{
		ormapi.RolePerm{
			Action:   "view",
			Resource: "cloudlets",
		},
		ormapi.RolePerm{
			Action:   "manage",
			Resource: "cloudlets",
		},
	}
	resp, status, err := mcClient.CreateUserApiKey(uri, token1, &userApiKeyObj)
	require.Nil(t, err, "create apikey")
	require.Equal(t, http.StatusOK, status, "create apikey success")
	require.NotEmpty(t, resp.Id, "api key id exists")
	require.NotEmpty(t, resp.ApiKey, "api key exists")

	// verify role exists
	roleAssignments, status, err := mcClient.ShowRoleAssignment(uri, token)
	require.Nil(t, err, "show roles")
	require.Equal(t, http.StatusOK, status, "show role status")
	apiKeyRole := ormapi.Role{}
	for _, role := range roleAssignments {
		if isApiKeyRole(role.Role) {
			apiKeyRole = role
			break
		}
	}
	require.Equal(t, apiKeyRole.Role, getApiKeyRoleName(resp.Id))
	require.Equal(t, apiKeyRole.Username, resp.Id)
	require.Equal(t, apiKeyRole.Org, operOrg.Name)
	policies, status, err := showRolePerms(mcClient, uri, token)
	require.Nil(t, err, "show role perms err")
	require.Equal(t, http.StatusOK, status, "show role perms status")
	apiKeyRoleViewPerm := ormapi.RolePerm{}
	apiKeyRoleManagePerm := ormapi.RolePerm{}
	for _, policy := range policies {
		if isApiKeyRole(policy.Role) {
			if policy.Action == ActionView {
				apiKeyRoleViewPerm = policy
			} else if policy.Action == ActionManage {
				apiKeyRoleManagePerm = policy
			}
		}
	}
	require.Equal(t, apiKeyRoleViewPerm.Role, getApiKeyRoleName(resp.Id))
	require.Equal(t, apiKeyRoleViewPerm.Action, ActionView)
	require.Equal(t, apiKeyRoleViewPerm.Resource, ResourceCloudlets)
	require.Equal(t, apiKeyRoleManagePerm.Role, getApiKeyRoleName(resp.Id))
	require.Equal(t, apiKeyRoleManagePerm.Action, ActionManage)
	require.Equal(t, apiKeyRoleManagePerm.Resource, ResourceCloudlets)

	// show api key should show the created keys
	apiKeys, status, err := mcClient.ShowUserApiKey(uri, token, nil)
	require.Nil(t, err, "show apikey")
	require.Equal(t, http.StatusOK, status, "show apikey")
	require.Equal(t, len(apiKeys), 1, "match api key count")

	// login using api key
	apiKeyLoginToken, err := mcClient.DoLogin(uri, NoUserName, NoPassword, NoOTP, resp.Id, resp.ApiKey)
	require.Nil(t, err, "login using api key")

	// user's login token should have shorter expiration time
	claims := UserClaims{}
	_, err = Jwks.VerifyCookie(apiKeyLoginToken, &claims)
	require.Nil(t, err, "parse token")
	delta := claims.ExpiresAt - claims.IssuedAt
	require.Equal(t, delta, int64(JWTShortDuration.Seconds()), "match short expiration time")

	// user should not be able to create/delete/show apikey
	userApiKeyObj.Permissions = []ormapi.RolePerm{
		ormapi.RolePerm{
			Action:   "view",
			Resource: "cloudlets",
		},
		ormapi.RolePerm{
			Action:   "manag",
			Resource: "cloudlets",
		},
	}
	_, status, err = mcClient.CreateUserApiKey(uri, apiKeyLoginToken, &userApiKeyObj)
	require.NotNil(t, err, "create apikey should fail")
	require.Equal(t, http.StatusForbidden, status, "create apikey failure")
	require.Contains(t, err.Error(), "not allowed to create", "err matches")

	delKeyObj := ormapi.CreateUserApiKey{UserApiKey: ormapi.UserApiKey{Id: resp.Id}}
	status, err = mcClient.DeleteUserApiKey(uri, apiKeyLoginToken, &delKeyObj)
	require.NotNil(t, err, "delete apikey should fail")
	require.Equal(t, http.StatusForbidden, status, "delete apikey failure")
	require.Contains(t, err.Error(), "not allowed to delete", "err matches")

	_, status, err = mcClient.ShowUserApiKey(uri, apiKeyLoginToken, nil)
	require.NotNil(t, err, "show apikey should fail")
	require.Equal(t, http.StatusForbidden, status, "show apikey failure")
	require.Contains(t, err.Error(), "not allowed to show", "err matches")

	// user should be able to view/manage the resources it is allowed to
	dcnt := 2
	ds.AddDummyObjs(ctx, dcnt)
	ds.AddDummyOrgObjs(ctx, operOrg.Name, dcnt)
	goodPermTestCloudlet(t, mcClient, uri, apiKeyLoginToken, ctrl.Region, operOrg.Name, count+2)
	goodPermTestShowCloudlet(t, mcClient, uri, apiKeyLoginToken, ctrl.Region, operOrg.Name, count+2)
	tc := edgeproto.CloudletKey{
		Organization: operOrg.Name,
		Name:         "0",
	}

	// current apikey doesn't allow user to manage app resource
	badPermTestApp(t, mcClient, uri, apiKeyLoginToken, ctrl.Region, operOrg.Name)
	badPermTestAppInst(t, mcClient, uri, apiKeyLoginToken, ctrl.Region, operOrg.Name, &tc)
	badPermTestShowAppInst(t, mcClient, uri, apiKeyLoginToken, ctrl.Region, operOrg.Name)
	badPermTestClusterInst(t, mcClient, uri, apiKeyLoginToken, ctrl.Region, operOrg.Name, &tc)

	// user should not be able to manage the resources it is not allowed to
	status, err = mcClient.DeleteUser(uri, apiKeyLoginToken, user1)
	require.NotNil(t, err, "delete user")
	require.Equal(t, http.StatusForbidden, status, "forbidden")
	require.Contains(t, err.Error(), "Forbidden", "err matches")

	// deletion of apikey should result in deletion of respective roles
	delKeyObj = ormapi.CreateUserApiKey{UserApiKey: ormapi.UserApiKey{Id: resp.Id}}
	status, err = mcClient.DeleteUserApiKey(uri, token1, &delKeyObj)
	require.Nil(t, err, "delete user api key")

	// verify role doesn't exist
	roleAssignments, status, err = mcClient.ShowRoleAssignment(uri, token)
	require.Nil(t, err, "show roles")
	require.Equal(t, http.StatusOK, status, "show role status")
	found := false
	apiKeyRole = ormapi.Role{}
	for _, role := range roleAssignments {
		if isApiKeyRole(role.Role) {
			found = true
			break
		}
	}
	require.False(t, found, "role doesn't exist")
	policies, status, err = showRolePerms(mcClient, uri, token)
	require.Nil(t, err, "show role perms err")
	require.Equal(t, http.StatusOK, status, "show role perms status")
	found = false
	for _, policy := range policies {
		if isApiKeyRole(policy.Role) {
			found = true
			break
		}
	}
	require.False(t, found, "policy doesn't exist")

	// create max api keys allowed for user
	userApiKeyObj.Permissions = []ormapi.RolePerm{
		ormapi.RolePerm{
			Action:   "view",
			Resource: "cloudlets",
		},
	}
	for ii := 0; ii < defaultConfig.UserApiKeyCreateLimit; ii++ {
		_, _, err = mcClient.CreateUserApiKey(uri, token1, &userApiKeyObj)
		require.Nil(t, err, "create apikey")
	}

	// user should only be able to create limited number of api keys
	_, status, err = mcClient.CreateUserApiKey(uri, token1, &userApiKeyObj)
	require.NotNil(t, err, "create apikey limit reached")
	require.Equal(t, http.StatusBadRequest, status, "create should fail")
	require.Contains(t, err.Error(), "cannot create more than", "err matches")

	// show api key should show the created keys
	apiKeys, status, err = mcClient.ShowUserApiKey(uri, token1, nil)
	require.Nil(t, err, "show apikey")
	require.Equal(t, http.StatusOK, status, "show apikey")
	require.Equal(t, len(apiKeys), defaultConfig.UserApiKeyCreateLimit, "match api key count")

	// delete all the api keys
	for _, apiKeyObj := range apiKeys {
		status, err = mcClient.DeleteUserApiKey(uri, token1, &apiKeyObj)
		require.Nil(t, err, "delete user api key")
		require.Equal(t, http.StatusOK, status)
	}
}
