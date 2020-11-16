package orm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormclient"
	"github.com/mobiledgex/edge-cloud-infra/mc/rbac"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
	"github.com/stretchr/testify/require"
)

func TestServer(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	addr := "127.0.0.1:9999"
	uri := "http://" + addr + "/api/v1"
	ctx := log.StartTestSpan(context.Background())

	vaultServer, vaultConfig := vault.DummyServer()
	defer vaultServer.Close()

	defaultConfig.PasswordMinCrackTimeSec = 30 * 86400
	defaultConfig.AdminPasswordMinCrackTimeSec = 20 * 365 * 86400
	BadAuthDelay = time.Millisecond

	config := ServerConfig{
		ServAddr:                addr,
		SqlAddr:                 "127.0.0.1:5445",
		RunLocal:                true,
		InitLocal:               true,
		IgnoreEnv:               true,
		SkipVerifyEmail:         true,
		vaultConfig:             vaultConfig,
		UsageCheckpointInterval: "MONTH",
	}
	server, err := RunServer(&config)
	require.Nil(t, err, "run server")
	defer server.Stop()

	Jwks.Init(vaultConfig, "region", "mcorm")
	Jwks.Meta.CurrentVersion = 1
	Jwks.Keys[1] = &vault.JWK{
		Secret:  "12345",
		Refresh: "1s",
	}

	err = server.WaitUntilReady()
	require.Nil(t, err, "server online")

	mcClient := &ormclient.Client{}

	// login as super user
	token, err := mcClient.DoLogin(uri, DefaultSuperuser, DefaultSuperpass)
	require.Nil(t, err, "login as superuser")

	super, status, err := showCurrentUser(mcClient, uri, token)
	require.Nil(t, err, "show super")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, DefaultSuperuser, super.Name, "super user name")
	require.Equal(t, "", super.Passhash, "empty pass hash")
	require.Equal(t, "", super.Salt, "empty salt")
	require.Equal(t, 0, super.Iter, "empty iter")

	roleAssignments, status, err := mcClient.ShowRoleAssignment(uri, token)
	require.Nil(t, err, "show roles")
	require.Equal(t, http.StatusOK, status, "show role status")
	require.Equal(t, 1, len(roleAssignments), "num role assignments")
	require.Equal(t, RoleAdminManager, roleAssignments[0].Role)
	require.Equal(t, super.Name, roleAssignments[0].Username)

	// show users - only super user at this point
	users, status, err := mcClient.ShowUser(uri, token, &ormapi.Organization{})
	require.Equal(t, http.StatusOK, status, "show user status")
	require.Equal(t, 1, len(users))
	require.Equal(t, DefaultSuperuser, users[0].Name, "super user name")
	require.Equal(t, "", users[0].Passhash, "empty pass hash")
	require.Equal(t, "", users[0].Salt, "empty salt")
	require.Equal(t, 0, users[0].Iter, "empty iter")

	policies, status, err := showRolePerms(mcClient, uri, token)
	require.Nil(t, err, "show role perms err")
	require.Equal(t, http.StatusOK, status, "show role perms status")
	require.Equal(t, 163, len(policies), "number of role perms")
	roles, status, err := showRoles(mcClient, uri, token)
	require.Nil(t, err, "show roles err")
	require.Equal(t, http.StatusOK, status, "show roles status")
	require.Equal(t, 10, len(roles), "number of roles")

	// create new user1
	user1 := ormapi.User{
		Name:     "MisterX",
		Email:    "misterx@gmail.com",
		Passhash: "misterx-password-super",
	}
	status, err = mcClient.CreateUser(uri, &user1)
	require.Nil(t, err, "create user")
	require.Equal(t, http.StatusOK, status, "create user status")
	// login as new user1
	tokenMisterX, err := mcClient.DoLogin(uri, user1.Name, user1.Passhash)
	require.Nil(t, err, "login as mister X")
	// create an Organization
	org1 := ormapi.Organization{
		Type: "developer",
		Name: "DevX",
	}
	orgX := org1
	orgX.Name = user1.Name
	_, err = mcClient.CreateOrg(uri, tokenMisterX, &orgX)
	require.NotNil(t, err, "create org with same name as user (case-insensitive)")
	status, err = mcClient.CreateOrg(uri, tokenMisterX, &org1)
	require.Nil(t, err, "create org")
	require.Equal(t, http.StatusOK, status, "create org status")

	// try to delete admin and user1
	status, err = mcClient.DeleteUser(uri, token, &ormapi.User{Name: DefaultSuperuser})
	require.NotNil(t, err, "delete only AdminManager")
	require.Equal(t, http.StatusBadRequest, status, "deleting lone manager")
	status, err = mcClient.DeleteUser(uri, tokenMisterX, &user1)
	require.NotNil(t, err, "delete only manager of an org")
	require.Equal(t, http.StatusBadRequest, status, "deleting lone manager")

	// create new user with same name as org
	userX := ormapi.User{
		Name:     "DevX",
		Email:    "misterX@gmail.com",
		Passhash: "misterX-password-long-super-tough-crazy-difficult",
	}
	status, err = mcClient.CreateUser(uri, &userX)
	require.NotNil(t, err, "cannot create user with same name as org")

	// create new user2
	user2 := ormapi.User{
		Name:     "MisterY",
		Email:    "mistery@gmail.com",
		Passhash: "mistery-password-long-super-tough-crazy-difficult",
	}
	status, err = mcClient.CreateUser(uri, &user2)
	require.Nil(t, err, "create user")
	require.Equal(t, http.StatusOK, status, "create user status")
	// login as new user2
	tokenMisterY, err := mcClient.DoLogin(uri, user2.Name, user2.Passhash)
	require.Nil(t, err, "login as mister Y")

	// create user2 (case-insensitive) - duplicate
	user2ci := ormapi.User{
		Name:     "Mistery",
		Email:    "mistery@gmail.com",
		Passhash: "mistery-password",
	}
	status, err = mcClient.CreateUser(uri, &user2ci)
	require.NotNil(t, err, "create duplicate user (case-insensitive)")
	require.Equal(t, http.StatusBadRequest, status, "create dup user")

	// update user2
	updateNewEmail := "misteryyy@gmail.com"
	updateNewPicture := "my pic"
	updateNewNickname := "mistery"
	mapData := map[string]interface{}{
		"Email":    updateNewEmail,
		"Picture":  updateNewPicture,
		"Nickname": updateNewNickname,
	}
	jsonData, err := json.Marshal(mapData)
	require.Nil(t, err)
	status, err = mcClient.UpdateUser(uri, tokenMisterY, string(jsonData))
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	checkUser, status, err := showCurrentUser(mcClient, uri, tokenMisterY)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, updateNewEmail, checkUser.Email)
	require.Equal(t, updateNewPicture, checkUser.Picture)
	require.Equal(t, updateNewNickname, checkUser.Nickname)

	// update user: disallowed fields
	mapData = map[string]interface{}{
		"Passhash": "uhoh",
	}
	jsonData, err = json.Marshal(mapData)
	require.Nil(t, err)
	status, err = mcClient.UpdateUser(uri, tokenMisterY, string(jsonData))
	require.NotNil(t, err)
	require.Equal(t, http.StatusBadRequest, status)

	// create an Organization
	org2 := ormapi.Organization{
		Type: "developer",
		Name: "DevY",
	}
	status, err = mcClient.CreateOrg(uri, tokenMisterY, &org2)
	require.Nil(t, err, "create org")
	require.Equal(t, http.StatusOK, status, "create org status")

	org2ci := ormapi.Organization{
		Type: "developer",
		Name: "Devy",
	}
	status, err = mcClient.CreateOrg(uri, tokenMisterY, &org2ci)
	require.NotNil(t, err, "create duplicate org (case-insensitive)")
	require.Equal(t, http.StatusBadRequest, status, "create dup org")

	// EC-31717: Test org exists func. Should be case sensitive, so looking
	// for "devy" should fail (does not exist), and not hit a false
	//  positive for org "DevY", which does exist.
	err = checkRequiresOrg(ctx, "devy", false)
	require.NotNil(t, err, "devy should not exist")

	// create new admin user
	admin := ormapi.User{
		Name:     "Admin",
		Email:    "Admin@gmail.com",
		Passhash: "admin-password-long-super-tough-crazy-difficult",
	}
	status, err = mcClient.CreateUser(uri, &admin)
	require.Nil(t, err, "create admin user")
	require.Equal(t, http.StatusOK, status, "create admin user status")
	// add admin user as admin role
	roleArg := ormapi.Role{
		Username: admin.Name,
		Role:     "AdminManager",
	}
	status, err = mcClient.AddUserRole(uri, token, &roleArg)
	require.Nil(t, err, "add user role")
	require.Equal(t, http.StatusOK, status)
	// login as new admin
	tokenAdmin, err := mcClient.DoLogin(uri, admin.Name, admin.Passhash)
	require.Nil(t, err, "login as admin")

	orgMex := ormapi.Organization{
		Type: "developer",
		Name: cloudcommon.OrganizationMobiledgeX,
	}
	_, err = mcClient.CreateOrg(uri, tokenMisterX, &orgMex)
	require.NotNil(t, err, "create reserved mobiledgex org")
	status, err = mcClient.CreateOrg(uri, tokenAdmin, &orgMex)
	require.Nil(t, err, "create reserved mobiledgex org")
	require.Equal(t, http.StatusOK, status)
	_, err = mcClient.DeleteOrg(uri, tokenMisterX, &orgMex)
	require.NotNil(t, err, "delete reserved mobiledgex org")

	// check org membership as mister x
	orgs, status, err := mcClient.ShowOrg(uri, tokenMisterX)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(orgs))
	require.Equal(t, org1.Name, orgs[0].Name)
	require.Equal(t, org1.Type, orgs[0].Type)
	// check org membership as mister y
	orgs, status, err = mcClient.ShowOrg(uri, tokenMisterY)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(orgs))
	require.Equal(t, org2.Name, orgs[0].Name)
	require.Equal(t, org2.Type, orgs[0].Type)
	// super user should be able to show all orgs
	orgs, status, err = mcClient.ShowOrg(uri, token)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 3, len(orgs))
	orgs, status, err = mcClient.ShowOrg(uri, tokenAdmin)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 3, len(orgs))

	// users should be able to update their own orgs
	testUpdateOrg(t, mcClient, uri, tokenMisterX, org1.Name)
	testUpdateOrg(t, mcClient, uri, tokenMisterY, org2.Name)
	testUpdateOrg(t, mcClient, uri, tokenAdmin, org1.Name)
	// users should not be able to update other's org
	testUpdateOrgFail(t, mcClient, uri, tokenMisterX, org2.Name)
	testUpdateOrgFail(t, mcClient, uri, tokenMisterY, org1.Name)

	// check role assignments as mister x
	roleAssignments, status, err = mcClient.ShowRoleAssignment(uri, tokenMisterX)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(roleAssignments))
	require.Equal(t, user1.Name, roleAssignments[0].Username)
	// check role assignments as mister y
	roleAssignments, status, err = mcClient.ShowRoleAssignment(uri, tokenMisterY)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(roleAssignments))
	require.Equal(t, user2.Name, roleAssignments[0].Username)
	// super user should be able to see all role assignments
	roleAssignments, status, err = mcClient.ShowRoleAssignment(uri, token)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 5, len(roleAssignments))
	roleAssignments, status, err = mcClient.ShowRoleAssignment(uri, tokenAdmin)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 5, len(roleAssignments))

	// show org users as mister x
	users, status, err = mcClient.ShowUser(uri, tokenMisterX, &org1)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(users))
	require.Equal(t, user1.Name, users[0].Name)
	// show org users as mister y
	users, status, err = mcClient.ShowUser(uri, tokenMisterY, &org2)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(users))
	require.Equal(t, user2.Name, users[0].Name)
	// super user can see all users with org ID = 0
	users, status, err = mcClient.ShowUser(uri, token, &ormapi.Organization{})
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 4, len(users))
	users, status, err = mcClient.ShowUser(uri, tokenAdmin, &ormapi.Organization{})
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 4, len(users))

	// check that x and y cannot see each other's org users
	users, status, err = mcClient.ShowUser(uri, tokenMisterX, &org2)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
	users, status, err = mcClient.ShowUser(uri, tokenMisterY, &org1)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
	foobar := &ormapi.Organization{
		Name: "foobar",
	}
	users, status, err = mcClient.ShowUser(uri, tokenMisterX, foobar)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)

	// check that x and y cannot delete each other's orgs
	status, err = mcClient.DeleteOrg(uri, tokenMisterX, &org2)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
	status, err = mcClient.DeleteOrg(uri, tokenMisterY, &org1)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)

	// create more users
	user3, token3, _ := testCreateUser(t, mcClient, uri, "user3")
	user4, token4, _ := testCreateUser(t, mcClient, uri, "user4")
	// add users to org with different roles, make sure they can see users
	testAddUserRole(t, mcClient, uri, tokenMisterX, org1.Name, "DeveloperContributor", user3.Name, Success)
	testAddUserRole(t, mcClient, uri, tokenMisterX, org1.Name, "DeveloperViewer", user4.Name, Success)
	// add user with same name as org
	roleArgX := ormapi.Role{
		Username: org1.Name,
		Org:      org1.Name,
		Role:     "DeveloperViewer",
	}
	_, err = mcClient.AddUserRole(uri, tokenMisterX, &roleArgX)
	require.NotNil(t, err, "user name with same name as org (case-insensitive)")
	// check that they can see all users in org
	users, status, err = mcClient.ShowUser(uri, token3, &org1)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 3, len(users))
	users, status, err = mcClient.ShowUser(uri, token4, &org1)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 3, len(users))
	// make sure they can't see users from other org
	users, status, err = mcClient.ShowUser(uri, token3, &org2)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
	users, status, err = mcClient.ShowUser(uri, token4, &org2)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)

	// normal user cannot remove admin roles from others
	status, err = mcClient.RemoveUserRole(uri, tokenMisterX, &roleArg)
	require.NotNil(t, err, "remove user role")
	require.Equal(t, http.StatusForbidden, status)
	// admin user can remove role
	status, err = mcClient.RemoveUserRole(uri, tokenAdmin, &roleArg)
	require.Nil(t, err, "remove user role")
	require.Equal(t, http.StatusOK, status)

	// test role + org combinations
	testRoleOrgCombos(t, uri, token, mcClient)

	// check that org cannot be deleted if it's already DeleteInProgress
	dat := fmt.Sprintf(updateOrgDeleteInProgress, org1.Name, true)
	status, err = mcClient.UpdateOrg(uri, tokenMisterX, dat)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	status, err = mcClient.DeleteOrg(uri, tokenMisterX, &org1)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "org already being deleted")
	require.Equal(t, http.StatusBadRequest, status)
	dat = fmt.Sprintf(updateOrgDeleteInProgress, org1.Name, false)
	status, err = mcClient.UpdateOrg(uri, tokenMisterX, dat)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)

	// delete orgs
	status, err = mcClient.DeleteOrg(uri, tokenMisterX, &org1)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	status, err = mcClient.DeleteOrg(uri, tokenMisterY, &org2)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	status, err = mcClient.DeleteOrg(uri, tokenAdmin, &orgMex)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	// delete users
	status, err = mcClient.DeleteUser(uri, tokenMisterX, &user1)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	status, err = mcClient.DeleteUser(uri, tokenMisterY, &user2)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	status, err = mcClient.DeleteUser(uri, token3, user3)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	status, err = mcClient.DeleteUser(uri, token4, user4)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	status, err = mcClient.DeleteUser(uri, tokenAdmin, &admin)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)

	// check orgs are gone
	orgs, status, err = mcClient.ShowOrg(uri, token)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(orgs))
	// check users are gone
	users, status, err = mcClient.ShowUser(uri, token, &ormapi.Organization{})
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(users))

	testImagePaths(t, ctx, mcClient, uri, token)
	testLockedUsers(t, uri, mcClient)
	testPasswordStrength(t, ctx, mcClient, uri, token)
}

func showCurrentUser(mcClient *ormclient.Client, uri, token string) (*ormapi.User, int, error) {
	user := ormapi.User{}
	status, err := mcClient.PostJson(uri+"/auth/user/current", token, nil, &user)
	return &user, status, err
}

func showRolePerms(mcClient *ormclient.Client, uri, token string) ([]ormapi.RolePerm, int, error) {
	perms := []ormapi.RolePerm{}
	status, err := mcClient.PostJson(uri+"/auth/role/perms/show", token, nil, &perms)
	return perms, status, err
}

func showRoles(mcClient *ormclient.Client, uri, token string) ([]string, int, error) {
	roles := []string{}
	status, err := mcClient.PostJson(uri+"/auth/role/show", token, nil, &roles)
	return roles, status, err
}

func waitServerOnline(addr string) error {
	return fmt.Errorf("wait server online failed")
}

// for debug
func dumpTables() {
	users := []ormapi.User{}
	orgs := []ormapi.Organization{}
	database.Find(&users)
	database.Find(&orgs)
	for _, user := range users {
		fmt.Printf("%v\n", user)
	}
	for _, org := range orgs {
		fmt.Printf("%v\n", org)
	}
}

func testLockedUsers(t *testing.T, uri string, mcClient *ormclient.Client) {
	// login as super user
	superTok, err := mcClient.DoLogin(uri, DefaultSuperuser, DefaultSuperpass)
	require.Nil(t, err, "login as superuser")

	// set config to be locked. This needs to be a map so that
	// marshalling the JSON doesn't put in null entries for other
	// fields, and preserves null entries for specified fields regardless
	// of omit empty.
	notifyEmail := "foo@gmail.com"
	configReq := make(map[string]interface{})
	configReq["locknewaccounts"] = true
	configReq["notifyemailaddress"] = notifyEmail
	status, err := mcClient.UpdateConfig(uri, superTok, configReq)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)

	// create new account
	user1 := ormapi.User{
		Name:     "user1",
		Email:    "user1@gmail.com",
		Passhash: "user1-password-super-long-crazy-hard-difficult",
	}
	status, err = mcClient.CreateUser(uri, &user1)
	require.Nil(t, err, "create user")
	require.Equal(t, http.StatusOK, status, "create user status")
	// login as new user1
	_, err = mcClient.DoLogin(uri, user1.Name, user1.Passhash)
	require.NotNil(t, err, "login")
	require.Contains(t, err.Error(), "Account is locked")

	// super user unlock account
	userReq := make(map[string]interface{})
	userReq["email"] = user1.Email
	userReq["locked"] = false
	status, err = mcClient.RestrictedUserUpdate(uri, superTok, userReq)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)

	// user should be able to log in now
	tok1, err := mcClient.DoLogin(uri, user1.Name, user1.Passhash)
	require.Nil(t, err)

	// create another new user
	user2 := ormapi.User{
		Name:     "user2",
		Email:    "user2@gmail.com",
		Passhash: "user2-password-super-long-crazy-hard-difficult",
	}
	status, err = mcClient.CreateUser(uri, &user2)
	require.Nil(t, err, "create user")
	require.Equal(t, http.StatusOK, status, "create user status")
	// login as new user2
	_, err = mcClient.DoLogin(uri, user2.Name, user2.Passhash)
	require.NotNil(t, err, "login")
	require.Contains(t, err.Error(), "Account is locked")

	// make sure users cannot unlock other users
	userReq = make(map[string]interface{})
	userReq["email"] = user2.Email
	userReq["locked"] = false
	status, err = mcClient.RestrictedUserUpdate(uri, tok1, userReq)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)

	// make sure users cannot modify config
	configReq = make(map[string]interface{})
	configReq["locknewaccounts"] = false
	status, err = mcClient.UpdateConfig(uri, tok1, configReq)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
	// super user unlock new accounts
	status, err = mcClient.UpdateConfig(uri, superTok, configReq)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)

	// user2 still should not be able to log in
	_, err = mcClient.DoLogin(uri, user2.Name, user2.Passhash)
	require.NotNil(t, err, "login")
	require.Contains(t, err.Error(), "Account is locked")

	// delete user2, recreate, should be unlocked now
	status, err = mcClient.DeleteUser(uri, superTok, &user2)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	status, err = mcClient.CreateUser(uri, &user2)
	require.Nil(t, err, "create user")
	require.Equal(t, http.StatusOK, status, "create user status")
	// login as new user2
	_, err = mcClient.DoLogin(uri, user2.Name, user2.Passhash)
	require.Nil(t, err)

	// show config, make sure changes didn't affect notify email address
	config, status, err := mcClient.ShowConfig(uri, superTok)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, notifyEmail, config.NotifyEmailAddress)

	// make sure users can't see config
	_, status, err = mcClient.ShowConfig(uri, tok1)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)

	// clean up
	status, err = mcClient.DeleteUser(uri, superTok, &user1)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	status, err = mcClient.DeleteUser(uri, superTok, &user2)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func testRoleOrgCombos(t *testing.T, uri, token string, mcClient *ormclient.Client) {
	devOrg := ormapi.Organization{
		Name: "rcDev",
		Type: "developer",
	}
	operOrg := ormapi.Organization{
		Name: "rcOper",
		Type: "operator",
	}
	user := ormapi.User{
		Name: "rcUser",
	}
	testCreateOrg(t, mcClient, uri, token, devOrg.Type, devOrg.Name)
	testCreateOrg(t, mcClient, uri, token, operOrg.Type, operOrg.Name)
	testCreateUser(t, mcClient, uri, user.Name)

	role := ormapi.Role{
		Username: user.Name,
	}
	expectFail := func(orgName, roleName string) {
		role.Org = orgName
		role.Role = roleName
		status, err := mcClient.AddUserRole(uri, token, &role)
		require.NotNil(t, err)
		require.Equal(t, http.StatusBadRequest, status)
	}
	expectOk := func(orgName, roleName string) {
		role.Org = orgName
		role.Role = roleName
		status, err := mcClient.AddUserRole(uri, token, &role)
		require.Nil(t, err)
		require.Equal(t, http.StatusOK, status)
		status, err = mcClient.RemoveUserRole(uri, token, &role)
		require.Nil(t, err)
		require.Equal(t, http.StatusOK, status)
	}

	// developer roles can only be assigned to dev org
	for _, rr := range []string{
		RoleDeveloperManager,
		RoleDeveloperContributor,
		RoleDeveloperViewer,
	} {
		expectOk(devOrg.Name, rr)
		expectFail("", rr)
		expectFail(operOrg.Name, rr)
	}
	// operator roles can only be assigned to operator org
	for _, rr := range []string{
		RoleOperatorManager,
		RoleOperatorContributor,
		RoleOperatorViewer,
	} {
		expectOk(operOrg.Name, rr)
		expectFail("", rr)
		expectFail(devOrg.Name, rr)
	}
	// admin roles can only be assigned to the empty org
	for _, rr := range []string{
		RoleAdminManager,
		RoleAdminContributor,
		RoleAdminViewer,
	} {
		expectOk("", rr)
		expectFail(devOrg.Name, rr)
		expectFail(operOrg.Name, rr)
	}

	// clean up
	status, err := mcClient.DeleteOrg(uri, token, &devOrg)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	status, err = mcClient.DeleteOrg(uri, token, &operOrg)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	status, err = mcClient.DeleteUser(uri, token, &user)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func testPasswordStrength(t *testing.T, ctx context.Context, mcClient *ormclient.Client, uri, token string) {
	// Create user in db to simulate old user with existing weak password
	db := loggedDB(ctx)
	adminOldPw := "oldpwd1"
	passhash, salt, iter := NewPasshash(adminOldPw)
	adminOld := ormapi.User{
		Name:          "oldadmin",
		Email:         "oldadmin@gmail.com",
		EmailVerified: true,
		Passhash:      passhash,
		Salt:          salt,
		Iter:          iter,
	}
	err := db.FirstOrCreate(&adminOld, &ormapi.User{Name: adminOld.Name}).Error
	require.Nil(t, err)
	// add admin
	psub := rbac.GetCasbinGroup("", adminOld.Name)
	err = enforcer.AddGroupingPolicy(ctx, psub, RoleAdminManager)
	require.Nil(t, err)
	// make sure login is disallowed for admins because of weak password
	_, err = mcClient.DoLogin(uri, adminOld.Name, adminOldPw)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Existing password for Admin too weak")

	// test password strength for new user
	userBad := ormapi.User{
		Name:     "Lazy",
		Email:    "lazy@gmail.com",
		Passhash: "admin123",
	}
	status, err := mcClient.CreateUser(uri, &userBad)
	require.NotNil(t, err, "bad user password")
	require.Contains(t, err.Error(), "Password too weak")

	// create user1 with decent password
	user1 := ormapi.User{
		Name:     "MisterX",
		Email:    "misterx@gmail.com",
		Passhash: "misterx-password-supe",
	}
	status, err = mcClient.CreateUser(uri, &user1)
	require.Nil(t, err, "create user")
	require.Equal(t, http.StatusOK, status, "create user status")
	// login as new user1
	tokenMisterX, err := mcClient.DoLogin(uri, user1.Name, user1.Passhash)
	require.Nil(t, err, "login as mister X")

	// change user password
	status, err = mcClient.NewPassword(uri, tokenMisterX, user1.Passhash+"1")
	require.Nil(t, err, "new password")
	require.Equal(t, http.StatusOK, status, "new password status")
	// fail password change if new password is too weak
	status, err = mcClient.NewPassword(uri, tokenMisterX, "weakweak")
	require.NotNil(t, err, "new password")
	require.Contains(t, err.Error(), "Password too weak")

	// assign admin rights to user1 should fail because password is too weak
	roleArgBad := ormapi.Role{
		Username: user1.Name,
		Role:     "AdminManager",
	}
	status, err = mcClient.AddUserRole(uri, token, &roleArgBad)
	require.NotNil(t, err, "add user role weak password")
	require.Contains(t, err.Error(), "Password too weak")

	// lower configured password strength requirements
	config := map[string]interface{}{
		"PasswordMinCrackTimeSec":      0.1,
		"AdminPasswordMinCrackTimeSec": 0.2,
	}
	status, err = mcClient.UpdateConfig(uri, token, config)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	// old admin should be able to log in now
	_, err = mcClient.DoLogin(uri, adminOld.Name, adminOldPw)
	require.Nil(t, err)

	// assign admin rights to user1, will not work because
	// password strength was reset
	status, err = mcClient.AddUserRole(uri, token, &roleArgBad)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Target user password strength not verified")
	// login to set verify password strength
	_, err = mcClient.DoLogin(uri, user1.Name, user1.Passhash+"1")
	require.Nil(t, err)
	// assign admin rights to user1, should work due to low password strength
	// requirements
	status, err = mcClient.AddUserRole(uri, token, &roleArgBad)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)

	// change config back
	config = map[string]interface{}{
		"PasswordMinCrackTimeSec":      defaultConfig.PasswordMinCrackTimeSec,
		"AdminPasswordMinCrackTimeSec": defaultConfig.AdminPasswordMinCrackTimeSec,
	}
	status, err = mcClient.UpdateConfig(uri, token, config)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	// old admin should not be able to log in now
	_, err = mcClient.DoLogin(uri, adminOld.Name, adminOldPw)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Existing password for Admin too weak")
	// user1 is now an admin and should also not be able to log in
	_, err = mcClient.DoLogin(uri, user1.Name, user1.Passhash+"1")
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Existing password for Admin too weak")

	// cleanup
	status, err = mcClient.DeleteUser(uri, token, &adminOld)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	status, err = mcClient.DeleteUser(uri, token, &user1)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}
