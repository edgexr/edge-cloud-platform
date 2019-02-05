package orm

import (
	"net"
	"net/http"
	"testing"

	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/testutil"
	"github.com/mobiledgex/edge-cloud/vault"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

var Success = true
var Fail = false

func TestController(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelApi)
	addr := "127.0.0.1:9999"
	uri := "http://" + addr + "/api/v1"

	config := ServerConfig{
		ServAddr:  addr,
		SqlAddr:   "127.0.0.1:5445",
		RunLocal:  true,
		InitLocal: true,
		IgnoreEnv: true,
	}
	server, err := RunServer(&config)
	require.Nil(t, err, "run server")
	defer server.Stop()

	Jwks.Init("addr", "mcorm", "roleID", "secretID")
	Jwks.Meta.CurrentVersion = 1
	Jwks.Keys[1] = &vault.JWK{
		Secret:  "12345",
		Refresh: "1s",
	}

	// run dummy controller - this always returns success
	// to all APIs directed to it, and does not actually
	// create or delete objects. We are mocking it out
	// so we can test rbac permissions.
	dc := grpc.NewServer()
	ctrlAddr := "127.0.0.1:9998"
	lis, err := net.Listen("tcp", ctrlAddr)
	require.Nil(t, err)
	testutil.RegisterDummyServer(dc)
	go func() {
		dc.Serve(lis)
	}()
	defer dc.Stop()

	// wait till mc is ready
	err = server.WaitUntilReady()
	require.Nil(t, err, "server online")

	// login as super user
	token, err := doLogin(uri, DefaultSuperuser, DefaultSuperpass)
	require.Nil(t, err, "login as superuser")

	// test controller api
	ctrls, status, err := showController(uri, token)
	require.Nil(t, err, "show controllers")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(ctrls))
	ctrl := Controller{
		Region:  "USA",
		Address: ctrlAddr,
	}
	// create controller
	status, err = createController(uri, token, &ctrl)
	require.Nil(t, err, "create controller")
	require.Equal(t, http.StatusOK, status)
	ctrls, status, err = showController(uri, token)
	require.Nil(t, err, "show controllers")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(ctrls))
	require.Equal(t, ctrl.Region, ctrls[0].Region)
	require.Equal(t, ctrl.Address, ctrls[0].Address)

	// create a developers
	_, orgDev, tokenDev := testCreateUserOrg(t, uri, "dev", "developer",
		testutil.DevData[0].Key.Name)
	_, _, tokenDev2 := testCreateUserOrg(t, uri, "dev2", "developer",
		testutil.DevData[3].Key.Name)
	dev3, tokenDev3 := testCreateUser(t, uri, "dev3")
	dev4, tokenDev4 := testCreateUser(t, uri, "dev4")
	// create an operator
	_, orgOper, tokenOper := testCreateUserOrg(t, uri, "oper", "operator",
		testutil.OperatorData[0].Key.Name)
	_, _, tokenOper2 := testCreateUserOrg(t, uri, "oper2", "operator",
		testutil.OperatorData[1].Key.Name)
	oper3, tokenOper3 := testCreateUser(t, uri, "oper3")
	oper4, tokenOper4 := testCreateUser(t, uri, "oper4")

	// additional users don't have access to orgs yet
	badPermTestApp(t, uri, tokenDev3, ctrl.Region, &testutil.AppData[0])
	badPermTestAppInst(t, uri, tokenDev3, ctrl.Region, &testutil.AppInstData[0])
	badPermTestCloudlet(t, uri, tokenOper3, ctrl.Region, &testutil.CloudletData[0])

	// add new users to orgs
	testAddUserRole(t, uri, tokenDev, orgDev.Name, "DeveloperContributor", dev3.ID, Success)
	testAddUserRole(t, uri, tokenDev, orgDev.Name, "DeveloperViewer", dev4.ID, Success)
	testAddUserRole(t, uri, tokenOper, orgOper.Name, "OperatorContributor", oper3.ID, Success)
	testAddUserRole(t, uri, tokenOper, orgOper.Name, "OperatorViewer", oper4.ID, Success)
	// make sure dev/ops without user perms can't add new users
	user5, _ := testCreateUser(t, uri, "user5")
	testAddUserRole(t, uri, tokenDev3, orgDev.Name, "DeveloperViewer", user5.ID, Fail)
	testAddUserRole(t, uri, tokenDev4, orgDev.Name, "DeveloperViewer", user5.ID, Fail)
	testAddUserRole(t, uri, tokenOper3, orgOper.Name, "OperatorViewer", user5.ID, Fail)
	testAddUserRole(t, uri, tokenOper4, orgOper.Name, "OperatorViewer", user5.ID, Fail)

	// make sure developer and operator cannot see or modify controllers
	ctrlNew := Controller{
		Region:  "Bad",
		Address: "bad.mobiledgex.net",
	}
	status, err = createController(uri, tokenDev, &ctrlNew)
	require.Equal(t, http.StatusForbidden, status)
	status, err = createController(uri, tokenOper, &ctrlNew)
	require.Equal(t, http.StatusForbidden, status)
	ctrls, status, err = showController(uri, tokenDev)
	require.Equal(t, http.StatusForbidden, status)
	require.Equal(t, 0, len(ctrls))
	ctrls, status, err = showController(uri, tokenOper)
	require.Equal(t, http.StatusForbidden, status)
	require.Equal(t, 0, len(ctrls))

	// make sure operator cannot create apps, appinsts, clusters, etc
	badPermTestApp(t, uri, tokenOper, ctrl.Region, &testutil.AppData[0])
	badPermTestAppInst(t, uri, tokenOper, ctrl.Region, &testutil.AppInstData[0])
	//badPermTestCluster(t, uri, tokenOper, ctrl.Region, &testutil.ClusterData[0])
	//badPermTestClusterInst(t, uri, tokenOper, ctrl.Region, &testutil.ClusterInstData[0])
	badPermTestApp(t, uri, tokenOper2, ctrl.Region, &testutil.AppData[0])
	badPermTestAppInst(t, uri, tokenOper2, ctrl.Region, &testutil.AppInstData[0])
	//badPermTestCluster(t, uri, tokenOper2, ctrl.Region, &testutil.ClusterData[0])
	//badPermTestClusterInst(t, uri, tokenOper2, ctrl.Region, &testutil.ClusterInstData[0])
	// make sure developer cannot create cloudlet
	badPermTestCloudlet(t, uri, tokenDev, ctrl.Region, &testutil.CloudletData[0])
	badPermTestCloudlet(t, uri, tokenDev2, ctrl.Region, &testutil.CloudletData[0])

	// test operators can modify their own objs but not each other's
	permTestCloudlet(t, uri, tokenOper, tokenOper2, ctrl.Region,
		&testutil.CloudletData[0], &testutil.CloudletData[2])
	// test developers can modify their own objs but not each other's
	permTestApp(t, uri, tokenDev, tokenDev2, ctrl.Region,
		&testutil.AppData[0], &testutil.AppData[5])
	permTestAppInst(t, uri, tokenDev, tokenDev2, ctrl.Region,
		&testutil.AppInstData[0], &testutil.AppInstData[5])
	// test users with different roles
	goodPermTestApp(t, uri, tokenDev3, ctrl.Region, &testutil.AppData[0])
	goodPermTestAppInst(t, uri, tokenDev3, ctrl.Region, &testutil.AppInstData[0])
	// test users with different roles
	goodPermTestCloudlet(t, uri, tokenOper3, ctrl.Region, &testutil.CloudletData[0])

	// developers should be able to create any cluster/clusterinsts,
	// since they are not tied to a developer organization
	goodPermTestCluster(t, uri, tokenDev, ctrl.Region, &testutil.ClusterData[0])
	goodPermTestCluster(t, uri, tokenDev2, ctrl.Region, &testutil.ClusterData[0])
	goodPermTestClusterInst(t, uri, tokenDev, ctrl.Region, &testutil.ClusterInstData[0])
	goodPermTestClusterInst(t, uri, tokenDev2, ctrl.Region, &testutil.ClusterInstData[0])

	// remove users from roles, test that they can't modify anything anymore
	testRemoveUserRole(t, uri, tokenDev, orgDev.Name, "DeveloperContributor", dev3.ID, Success)
	badPermTestApp(t, uri, tokenDev3, ctrl.Region, &testutil.AppData[0])
	badPermTestAppInst(t, uri, tokenDev3, ctrl.Region, &testutil.AppInstData[0])
	testRemoveUserRole(t, uri, tokenOper, orgOper.Name, "OperatorContributor", oper3.ID, Success)
	badPermTestCloudlet(t, uri, tokenOper3, ctrl.Region, &testutil.CloudletData[0])

	// delete controller
	status, err = deleteController(uri, token, &ctrl)
	require.Nil(t, err, "delete controller")
	require.Equal(t, http.StatusOK, status)
	ctrls, status, err = showController(uri, token)
	require.Nil(t, err, "show controllers")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(ctrls))
}

func createController(uri, token string, ctrl *Controller) (int, error) {
	result := ResultID{}
	status, err := postJson(uri+"/auth/controller/create", token, ctrl, &result)
	return status, err
}

func deleteController(uri, token string, ctrl *Controller) (int, error) {
	result := ResultID{}
	status, err := postJson(uri+"/auth/controller/delete", token, ctrl, &result)
	return status, err
}

func showController(uri, token string) ([]Controller, int, error) {
	ctrls := []Controller{}
	status, err := postJson(uri+"/auth/controller/show", token, nil, &ctrls)
	return ctrls, status, err
}

func testCreateUser(t *testing.T, uri, name string) (*User, string) {
	user := User{
		Name:     name,
		Email:    name + "@gmail.com",
		Passhash: name + "-password",
	}
	status, err := createUser(uri, &user)
	require.Nil(t, err, "create user ", name)
	require.Equal(t, http.StatusOK, status)
	// login
	token, err := doLogin(uri, user.Name, user.Passhash)
	require.Nil(t, err, "login as ", name)
	return &user, token
}

func testCreateOrg(t *testing.T, uri, token, orgType, orgName string) *Organization {
	// create org
	org := Organization{
		Type:    orgType,
		Name:    orgName,
		Address: orgName,
		Phone:   "123-123-1234",
	}
	status, err := createOrg(uri, token, &org)
	require.Nil(t, err, "create org ", orgName)
	require.Equal(t, http.StatusOK, status)
	return &org
}

func testCreateUserOrg(t *testing.T, uri, name, orgType, orgName string) (*User, *Organization, string) {
	user, token := testCreateUser(t, uri, name)
	org := testCreateOrg(t, uri, token, orgType, orgName)
	return user, org, token
}

func testAddUserRole(t *testing.T, uri, token, org, role string, userID int64, success bool) {
	roleArg := Role{
		UserID: userID,
		Org:    org,
		Role:   role,
	}
	status, err := addUserRole(uri, token, &roleArg)
	if success {
		require.Nil(t, err, "add user role")
		require.Equal(t, http.StatusOK, status)
	} else {
		require.Equal(t, http.StatusForbidden, status)
	}
}

func testRemoveUserRole(t *testing.T, uri, token, org, role string, userID int64, success bool) {
	roleArg := Role{
		UserID: userID,
		Org:    org,
		Role:   role,
	}
	status, err := removeUserRole(uri, token, &roleArg)
	require.Nil(t, err, "remove user role")
	require.Equal(t, http.StatusOK, status)
	if success {
	} else {
		require.Equal(t, http.StatusForbidden, status)
	}
}