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
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/edgexr/edge-cloud-infra/billing"
	"github.com/edgexr/edge-cloud-infra/mc/mcctl/cliwrapper"
	"github.com/edgexr/edge-cloud-infra/mc/mcctl/mctestclient"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud-infra/mc/ormclient"
	"github.com/edgexr/edge-cloud-infra/mc/ormutil"
	"github.com/edgexr/edge-cloud-infra/mc/rbac"
	"github.com/edgexr/edge-cloud/cli"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/vault"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

func TestServer(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	addr := "127.0.0.1:9999"
	uri := "http://" + addr + "/api/v1"
	ctx := log.StartTestSpan(context.Background())

	vault.DefaultJwkRefreshDelay = time.Hour

	vaultServer, vaultConfig := vault.DummyServer()
	defer vaultServer.Close()

	defaultConfig.PasswordMinCrackTimeSec = 30 * 86400
	defaultConfig.AdminPasswordMinCrackTimeSec = 20 * 365 * 86400
	defaultConfig.DisableRateLimit = true
	BadAuthDelay = time.Millisecond

	config := ServerConfig{
		ServAddr:                 addr,
		SqlAddr:                  "127.0.0.1:5445",
		RunLocal:                 true,
		InitLocal:                true,
		IgnoreEnv:                true,
		vaultConfig:              vaultConfig,
		UsageCheckpointInterval:  "MONTH",
		BillingPlatform:          billing.BillingTypeFake,
		DeploymentTag:            "local",
		PublicAddr:               "http://mc.mobiledgex.net",
		PasswordResetConsolePath: "#/passwordreset",
		VerifyEmailConsolePath:   "#/verify",
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

	for _, clientRun := range getUnitTestClientRuns() {
		testServerClientRun(t, ctx, clientRun, uri)
	}
}

func getVerificationTokenFromEmail(msg string) (string, error) {
	parts := strings.Split(msg, "token=")
	if len(parts) != 2 {
		return "", fmt.Errorf("Invalid email message, missing `token=` string")
	}

	out := strings.Split(parts[1], "\n")
	if len(out) == 0 {
		return "", fmt.Errorf("Invalid email message, missing verification link")
	}
	return strings.TrimSpace(out[0]), nil
}

func mcClientCreateUserWithMockMail(mcClient *mctestclient.Client, uri string, createUser *ormapi.CreateUser) (*ormapi.UserResponse, string, int, error) {
	mockMail := MockSendMail{}
	mockMail.Start()
	defer mockMail.Stop()
	resp, status, err := mcClient.CreateUser(uri, createUser)
	return resp, mockMail.Message, status, err
}

func mcClientUpdateUserWithMockMail(mcClient *mctestclient.Client, uri string, token string, in *cli.MapData) (*ormapi.UserResponse, string, int, error) {
	mockMail := MockSendMail{}
	mockMail.Start()
	defer mockMail.Stop()
	resp, status, err := mcClient.UpdateUser(uri, token, in)
	return resp, mockMail.Message, status, err
}

func userVerifyEmail(mcClient *mctestclient.Client, t *testing.T, uri string, mailMsg string) {
	// verify that link to verify email is correct
	matchStr := "mcctl --addr http://mc.mobiledgex.net user verifyemail token="
	if serverConfig.ConsoleAddr != "" {
		matchStr = fmt.Sprintf("Click to verify: %s#/verify?token", serverConfig.ConsoleAddr)
	}
	require.Contains(t, mailMsg, matchStr)
	verifyToken, err := getVerificationTokenFromEmail(mailMsg)
	require.Nil(t, err, "get verification token from email")
	_, err = mcClient.VerifyEmail(uri, &ormapi.Token{Token: verifyToken})
	require.Nil(t, err, "user email verified")
}

func testServerClientRun(t *testing.T, ctx context.Context, clientRun mctestclient.ClientRun, uri string) {
	mcClient := mctestclient.NewClient(clientRun)

	// login as super user
	token, isSuper, err := mcClient.DoLogin(uri, DefaultSuperuser, DefaultSuperpass, NoOTP, NoApiKeyId, NoApiKey)
	require.Nil(t, err, "login as superuser")
	require.True(t, isSuper)

	super, status, err := mcClient.CurrentUser(uri, token)
	require.Nil(t, err, "show super")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, DefaultSuperuser, super.Name, "super user name")
	require.Equal(t, "", super.Passhash, "empty pass hash")
	require.Equal(t, "", super.Salt, "empty salt")
	require.Equal(t, 0, super.Iter, "empty iter")

	roleAssignments, status, err := mcClient.ShowRoleAssignment(uri, token, ClientNoShowFilter)
	require.Nil(t, err, "show roles")
	require.Equal(t, http.StatusOK, status, "show role status")
	require.Equal(t, 1, len(roleAssignments), "num role assignments")
	require.Equal(t, RoleAdminManager, roleAssignments[0].Role)
	require.Equal(t, super.Name, roleAssignments[0].Username)

	// show users - only super user at this point
	users, status, err := mcClient.ShowUser(uri, token, ClientNoShowFilter)
	require.Equal(t, http.StatusOK, status, "show user status")
	require.Equal(t, 1, len(users))
	require.Equal(t, DefaultSuperuser, users[0].Name, "super user name")
	require.Equal(t, "", users[0].Passhash, "empty pass hash")
	require.Equal(t, "", users[0].Salt, "empty salt")
	require.Equal(t, 0, users[0].Iter, "empty iter")

	policies, status, err := mcClient.ShowRolePerm(uri, token, ClientNoShowFilter)
	require.Nil(t, err, "show role perms err")
	require.Equal(t, http.StatusOK, status, "show role perms status")
	require.Equal(t, 163, len(policies), "number of role perms")
	roles, status, err := mcClient.ShowRoleNames(uri, token)
	require.Nil(t, err, "show roles err")
	require.Equal(t, http.StatusOK, status, "show roles status")
	require.Equal(t, 10, len(roles), "number of roles")
	// test show roleperm filtering
	showRolePerm := &cli.MapData{
		Namespace: cli.StructNamespace,
		Data: map[string]interface{}{
			"Role": RoleDeveloperViewer,
		},
	}
	policies, status, err = mcClient.ShowRolePerm(uri, token, showRolePerm)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	for ii, rp := range policies {
		require.Equal(t, RoleDeveloperViewer, rp.Role, "%d: %v", ii, rp)
	}
	showRolePerm.Data = map[string]interface{}{
		"Resource": ResourceUsers,
	}
	policies, status, err = mcClient.ShowRolePerm(uri, token, showRolePerm)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	for ii, rp := range policies {
		require.Equal(t, ResourceUsers, rp.Resource, "%d: %v", ii, rp)
	}
	showRolePerm.Data = map[string]interface{}{
		"Action": ActionManage,
	}
	policies, status, err = mcClient.ShowRolePerm(uri, token, showRolePerm)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	for ii, rp := range policies {
		require.Equal(t, ActionManage, rp.Action, "%d: %v", ii, rp)
	}

	// create new user1
	user1 := ormapi.User{
		Name:     "MisterX",
		Email:    "misterx@gmail.com",
		Passhash: "misterx-password-super",
	}
	resp, mailMsg, status, err := mcClientCreateUserWithMockMail(mcClient, uri, &ormapi.CreateUser{User: user1})
	require.Nil(t, err, "create user")
	require.Equal(t, http.StatusOK, status, "create user status")
	userVerifyEmail(mcClient, t, uri, mailMsg)
	// login as new user1, should work as 2fa is not enabled
	tokenMisterX, isAdmin, err := mcClient.DoLogin(uri, user1.Name, user1.Passhash, NoOTP, NoApiKeyId, NoApiKey)
	require.Nil(t, err, "login as user1 with no 2fa")
	require.False(t, isAdmin)
	// enable 2fa for user1
	mapData := &cli.MapData{
		Namespace: cli.StructNamespace,
		Data: map[string]interface{}{
			"EnableTOTP": true,
		},
	}
	resp, status, err = mcClient.UpdateUser(uri, tokenMisterX, mapData)
	require.Nil(t, err)
	tokenMisterX, _, err = mcClient.DoLogin(uri, user1.Name, user1.Passhash, NoOTP, NoApiKeyId, NoApiKey)
	require.NotNil(t, err, "login should fail, missing otp")
	otp, err := totp.GenerateCode(resp.TOTPSharedKey, time.Now())
	require.Nil(t, err, "generate otp")
	tokenMisterX, _, err = mcClient.DoLogin(uri, user1.Name, user1.Passhash, otp, NoApiKeyId, NoApiKey)
	require.Nil(t, err, "login as mister X")
	// disable 2fa for user1
	mapData.Data = map[string]interface{}{
		"User": map[string]interface{}{
			"EnableTOTP": false,
		},
	}
	_, status, err = mcClient.UpdateUser(uri, tokenMisterX, mapData)
	require.Nil(t, err)
	// login, should work as 2fa is now disabled
	tokenMisterX, _, err = mcClient.DoLogin(uri, user1.Name, user1.Passhash, NoOTP, NoApiKeyId, NoApiKey)
	require.Nil(t, err, "login as user1 with no 2fa")

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
		Name:       "DevX",
		Email:      "misterX@gmail.com",
		Passhash:   "misterX-password-long-super-tough-crazy-difficult",
		EnableTOTP: true,
	}
	_, _, status, err = mcClientCreateUserWithMockMail(mcClient, uri, &ormapi.CreateUser{User: userX})
	require.NotNil(t, err, "cannot create user with same name as org")

	// create new user2
	user2 := ormapi.User{
		Name:       "MisterY",
		Email:      "mistery@gmail.com",
		Passhash:   "mistery-password-long-super-tough-crazy-difficult",
		EnableTOTP: true,
		Metadata:   "{timezone:PST,theme:Dark}",
	}
	resp, mailMsg, status, err = mcClientCreateUserWithMockMail(mcClient, uri, &ormapi.CreateUser{User: user2})
	require.Nil(t, err, "create user")
	require.Equal(t, http.StatusOK, status, "create user status")
	userVerifyEmail(mcClient, t, uri, mailMsg)
	// login as new user2
	otp, err = totp.GenerateCode(resp.TOTPSharedKey, time.Now())
	require.Nil(t, err, "generate otp")
	tokenMisterY, isAdmin, err := mcClient.DoLogin(uri, user2.Name, user2.Passhash, otp, NoApiKeyId, NoApiKey)
	require.Nil(t, err, "login as mister Y")
	require.False(t, isAdmin)

	// create user2 (case-insensitive) - duplicate
	user2ci := ormapi.User{
		Name:       "Mistery",
		Email:      "mistery@gmail.com",
		Passhash:   "mistery-password",
		EnableTOTP: true,
	}
	_, _, status, err = mcClientCreateUserWithMockMail(mcClient, uri, &ormapi.CreateUser{User: user2ci})
	require.NotNil(t, err, "create duplicate user (case-insensitive)")
	require.Equal(t, http.StatusBadRequest, status, "create dup user")

	// update user2
	updateNewEmail := "misteryyy@gmail.com"
	updateNewPicture := "my pic"
	updateNewNickname := "mistery"
	updateNewMetadata := "{timezone:PST,theme:Light}"
	mapData.Data = map[string]interface{}{
		"User": map[string]interface{}{
			"Email":    updateNewEmail,
			"Picture":  updateNewPicture,
			"Nickname": updateNewNickname,
			"Metadata": updateNewMetadata,
		},
		"Verify": map[string]interface{}{
			"Email": updateNewEmail,
		},
	}
	_, mailMsg, status, err = mcClientUpdateUserWithMockMail(mcClient, uri, tokenMisterY, mapData)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	userVerifyEmail(mcClient, t, uri, mailMsg)
	checkUser, status, err := mcClient.CurrentUser(uri, tokenMisterY)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, updateNewEmail, checkUser.Email)
	require.Equal(t, updateNewPicture, checkUser.Picture)
	require.Equal(t, updateNewNickname, checkUser.Nickname)
	require.Equal(t, updateNewMetadata, checkUser.Metadata)
	require.True(t, checkUser.EmailVerified) // since email is verified

	// update user: disallowed fields
	mapData.Data = map[string]interface{}{
		"User": map[string]interface{}{
			"Passhash": "uhoh",
		},
	}
	_, status, err = mcClient.UpdateUser(uri, tokenMisterY, mapData)
	require.NotNil(t, err)
	require.Equal(t, http.StatusBadRequest, status)

	// update user check email already exists error message
	mapData.Data = map[string]interface{}{
		"User": map[string]interface{}{
			"Name":  "MisterY",
			"Email": "misterx@gmail.com",
		},
		"Verify": map[string]interface{}{
			"Email": "misterx@gmail.com",
		},
	}
	_, status, err = mcClient.UpdateUser(uri, tokenMisterY, mapData)
	require.NotNil(t, err)
	require.Equal(t, "Email misterx@gmail.com already in use", err.Error())

	// create an Organization
	org2 := ormapi.Organization{
		Type:         "developer",
		Name:         "DevY",
		PublicImages: true,
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
	err = checkRequiresOrg(ctx, "devy", "", false, false)
	require.NotNil(t, err, "devy should not exist")

	// create new admin user
	admin := ormapi.User{
		Name:       "Admin",
		Email:      "Admin@gmail.com",
		Passhash:   "admin-password-long-super-tough-crazy-difficult",
		EnableTOTP: true,
	}
	resp, mailMsg, status, err = mcClientCreateUserWithMockMail(mcClient, uri, &ormapi.CreateUser{User: admin})
	require.Nil(t, err, "create admin user")
	require.Equal(t, http.StatusOK, status, "create admin user status")
	userVerifyEmail(mcClient, t, uri, mailMsg)
	// add admin user as admin role
	roleArg := ormapi.Role{
		Username: admin.Name,
		Role:     "AdminManager",
	}
	status, err = mcClient.AddUserRole(uri, token, &roleArg)
	require.Nil(t, err, "add user role")
	require.Equal(t, http.StatusOK, status)
	// login as new admin
	otp, err = totp.GenerateCode(resp.TOTPSharedKey, time.Now())
	require.Nil(t, err, "generate otp")
	tokenAdmin, isAdmin, err := mcClient.DoLogin(uri, admin.Name, admin.Passhash, otp, NoApiKeyId, NoApiKey)
	require.Nil(t, err, "login as admin")
	require.True(t, isAdmin)

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
	orgs, status, err := mcClient.ShowOrg(uri, tokenMisterX, ClientNoShowFilter)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(orgs))
	require.Equal(t, org1.Name, orgs[0].Name)
	require.Equal(t, org1.Type, orgs[0].Type)
	// check org membership as mister y
	orgs, status, err = mcClient.ShowOrg(uri, tokenMisterY, ClientNoShowFilter)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(orgs))
	require.Equal(t, org2.Name, orgs[0].Name)
	require.Equal(t, org2.Type, orgs[0].Type)
	// super user should be able to show all orgs
	orgs, status, err = mcClient.ShowOrg(uri, token, ClientNoShowFilter)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 3, len(orgs))
	orgs, status, err = mcClient.ShowOrg(uri, tokenAdmin, ClientNoShowFilter)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 3, len(orgs))
	// show org by type
	orgFilter := &cli.MapData{
		Namespace: cli.StructNamespace,
		Data: map[string]interface{}{
			"Type": "developer",
		},
	}
	orgs, status, err = mcClient.ShowOrg(uri, tokenAdmin, orgFilter)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 3, len(orgs))
	orgFilter.Data = map[string]interface{}{
		"Type": "operator",
	}
	orgs, status, err = mcClient.ShowOrg(uri, tokenAdmin, orgFilter)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(orgs))
	// show org by empty value
	showOrg := &cli.MapData{
		Namespace: cli.StructNamespace,
		Data: map[string]interface{}{
			"PublicImages": false,
		},
	}
	orgs, status, err = mcClient.ShowOrg(uri, tokenAdmin, showOrg)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 2, len(orgs))

	// users should be able to update their own orgs
	testUpdateOrg(t, mcClient, uri, tokenMisterX, org1.Name)
	testUpdateOrg(t, mcClient, uri, tokenMisterY, org2.Name)
	testUpdateOrg(t, mcClient, uri, tokenAdmin, org1.Name)
	// users should not be able to update other's org
	testUpdateOrgFail(t, mcClient, uri, tokenMisterX, org2.Name)
	testUpdateOrgFail(t, mcClient, uri, tokenMisterY, org1.Name)

	// users cannot change certain fields on orgs
	orgDat := &cli.MapData{
		Namespace: cli.StructNamespace,
	}
	orgDat.Data = map[string]interface{}{
		"Name":   org1.Name,
		"Parent": "foo",
	}
	status, err = mcClient.UpdateOrg(uri, tokenMisterX, orgDat)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Cannot update parent")
	orgDat.Data = map[string]interface{}{
		"Name":        org1.Name,
		"EdgeboxOnly": true,
	}
	status, err = mcClient.UpdateOrg(uri, tokenMisterX, orgDat)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Cannot update edgeboxonly")

	// admin can update parent
	orgDat.Data = map[string]interface{}{
		"Name":   org1.Name,
		"Parent": "foo",
	}
	status, err = mcClient.RestrictedUpdateOrg(uri, tokenAdmin, orgDat)
	require.Nil(t, err)
	orgDat.Data = map[string]interface{}{
		"Name": org1.Name,
	}
	orgs, status, err = mcClient.ShowOrg(uri, tokenAdmin, orgDat)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(orgs))
	require.Equal(t, "foo", orgs[0].Parent)
	orgDat.Data = map[string]interface{}{
		"Name":   org1.Name,
		"Parent": "",
	}
	status, err = mcClient.RestrictedUpdateOrg(uri, tokenAdmin, orgDat)
	require.Nil(t, err)

	// callback url is validated as part of password reset request
	m := MockSendMail{}
	m.Start()
	defer m.Stop()
	emailReq := ormapi.EmailRequest{
		Email: user1.Email,
	}
	// without consoleaddr, this will send mcctl as part of email
	_, err = mcClient.PasswordResetRequest(uri, &emailReq)
	require.Nil(t, err)
	// verify that password reset link is correct
	require.Contains(t, m.Message, "mcctl --addr http://mc.mobiledgex.net user passwordreset token=")
	m.Reset()

	// with consoleaddr set, this will send console URL as part of email
	serverConfig.ConsoleAddr = "http://console-test.mobiledgex.net/"
	_, err = mcClient.PasswordResetRequest(uri, &emailReq)
	require.Nil(t, err)
	// verify that password reset link is correct
	require.Contains(t, m.Message, "Reset your password: http://console-test.mobiledgex.net/#/passwordreset?token")
	m.Reset()
	serverConfig.ConsoleAddr = ""

	_, err = mcClient.ResendVerify(uri, &emailReq)
	require.Nil(t, err)
	// verify that password reset link is correct
	require.Contains(t, m.Message, "mcctl --addr http://mc.mobiledgex.net user verifyemail token=")

	// check role assignments as mister x
	roleAssignments, status, err = mcClient.ShowRoleAssignment(uri, tokenMisterX, ClientNoShowFilter)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(roleAssignments))
	require.Equal(t, user1.Name, roleAssignments[0].Username)
	// check role assignments as mister y
	roleAssignments, status, err = mcClient.ShowRoleAssignment(uri, tokenMisterY, ClientNoShowFilter)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(roleAssignments))
	require.Equal(t, user2.Name, roleAssignments[0].Username)
	// super user should be able to see all role assignments
	roleAssignments, status, err = mcClient.ShowRoleAssignment(uri, token, ClientNoShowFilter)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 5, len(roleAssignments))
	roleAssignments, status, err = mcClient.ShowRoleAssignment(uri, tokenAdmin, ClientNoShowFilter)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 5, len(roleAssignments))
	// test show role filtering
	// two admins, "mexadmin" and "Admin"
	showRole := &cli.MapData{
		Namespace: cli.StructNamespace,
		Data: map[string]interface{}{
			"Org": "",
		},
	}
	roleAssignments, status, err = mcClient.ShowRoleAssignment(uri, tokenAdmin, showRole)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 2, len(roleAssignments))
	require.True(t, roleAssignments[0].Username == "Admin" || roleAssignments[0].Username == "mexadmin", "%v", roleAssignments)
	require.True(t, roleAssignments[1].Username == "Admin" || roleAssignments[1].Username == "mexadmin", "%v", roleAssignments)
	// two developer managers
	showRole.Data = map[string]interface{}{
		"Role": "DeveloperManager",
	}
	roleAssignments, status, err = mcClient.ShowRoleAssignment(uri, tokenAdmin, showRole)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 3, len(roleAssignments))
	require.Equal(t, "DeveloperManager", roleAssignments[0].Role)
	require.Equal(t, "DeveloperManager", roleAssignments[1].Role)
	require.Equal(t, "DeveloperManager", roleAssignments[2].Role)
	// multiple roles for admin
	showRole.Data = map[string]interface{}{
		"Username": "Admin",
	}
	roleAssignments, status, err = mcClient.ShowRoleAssignment(uri, tokenAdmin, showRole)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 2, len(roleAssignments))
	for ii, ra := range roleAssignments {
		require.Equal(t, "Admin", ra.Username, "%d: %v", ii, ra)
	}

	showUserOrg1 := &cli.MapData{
		Namespace: cli.StructNamespace,
		Data: map[string]interface{}{
			"Org": org1.Name,
		},
	}
	showUserOrg2 := &cli.MapData{
		Namespace: cli.StructNamespace,
		Data: map[string]interface{}{
			"Org": org2.Name,
		},
	}
	// show org users as mister x
	users, status, err = mcClient.ShowUser(uri, tokenMisterX, showUserOrg1)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(users))
	require.Equal(t, user1.Name, users[0].Name)
	// show org users as mister y
	users, status, err = mcClient.ShowUser(uri, tokenMisterY, showUserOrg2)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(users))
	require.Equal(t, user2.Name, users[0].Name)
	// super user can see all users with org = ""
	users, status, err = mcClient.ShowUser(uri, token, ClientNoShowFilter)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 4, len(users))
	users, status, err = mcClient.ShowUser(uri, tokenAdmin, ClientNoShowFilter)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 4, len(users))
	// super user can see other users by email
	showUserEmail := func(email string) *cli.MapData {
		return &cli.MapData{
			Namespace: cli.StructNamespace,
			Data: map[string]interface{}{
				"Email": email,
			},
		}
	}
	users, status, err = mcClient.ShowUser(uri, tokenAdmin, showUserEmail(user1.Email))
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(users))
	require.Equal(t, user1.Name, users[0].Name)
	// super user can see users by role
	showUser := &cli.MapData{
		Namespace: cli.StructNamespace,
		Data: map[string]interface{}{
			"Role": RoleAdminManager,
		},
	}
	users, status, err = mcClient.ShowUser(uri, tokenAdmin, showUser)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 2, len(users))
	require.Equal(t, admin.Name, users[0].Name)
	require.Equal(t, DefaultSuperuser, users[1].Name)
	showUser.Data = map[string]interface{}{
		"Role": RoleDeveloperManager,
	}
	users, status, err = mcClient.ShowUser(uri, tokenAdmin, showUser)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 3, len(users))
	require.Equal(t, admin.Name, users[0].Name)
	require.Equal(t, user1.Name, users[1].Name)
	require.Equal(t, user2.Name, users[2].Name)
	// check show with invalid field name
	showUser.Data = map[string]interface{}{
		"BadField": "val",
	}
	users, status, err = mcClient.ShowUser(uri, tokenAdmin, showUser)
	require.NotNil(t, err)
	require.True(t, strings.Contains(err.Error(), "Field BadField (StructNamespace) not found in struct ShowUser") || strings.Contains(err.Error(), "invalid argument: key \"badfield\""), "err is: %v", err)

	// show user by empty value
	showUser.Data = map[string]interface{}{
		"EnableTOTP": false,
	}
	users, status, err = mcClient.ShowUser(uri, tokenAdmin, showUser)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 2, len(users))
	require.Equal(t, false, users[0].EnableTOTP)
	require.Equal(t, false, users[1].EnableTOTP)

	// check that x and y cannot see each other's org users
	users, status, err = mcClient.ShowUser(uri, tokenMisterX, showUserOrg2)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
	users, status, err = mcClient.ShowUser(uri, tokenMisterY, showUserOrg1)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
	foobar := &cli.MapData{
		Namespace: cli.StructNamespace,
		Data: map[string]interface{}{
			"Org": "foobar",
		},
	}
	users, status, err = mcClient.ShowUser(uri, tokenMisterX, foobar)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
	// check that x and y cannot see each other's users filtered by email
	users, status, err = mcClient.ShowUser(uri, tokenMisterX, showUserEmail(updateNewEmail)) // user2's email is now updateNewEmail
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(users))
	users, status, err = mcClient.ShowUser(uri, tokenMisterY, showUserEmail(user1.Email))
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(users))

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
	users, status, err = mcClient.ShowUser(uri, token3, showUserOrg1)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 3, len(users))
	users, status, err = mcClient.ShowUser(uri, token4, showUserOrg1)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 3, len(users))
	// check that org owners can see filtered users without specifying org
	users, status, err = mcClient.ShowUser(uri, tokenMisterX, showUserEmail(user3.Email))
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(users))
	require.Equal(t, user3.Name, users[0].Name)

	// make sure they can't see users from other org
	users, status, err = mcClient.ShowUser(uri, token3, showUserOrg2)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
	users, status, err = mcClient.ShowUser(uri, token4, showUserOrg2)
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
	dat := &cli.MapData{
		Namespace: cli.StructNamespace,
		Data: map[string]interface{}{
			"Name":             org1.Name,
			"DeleteInProgress": true,
		},
	}
	status, err = mcClient.UpdateOrg(uri, tokenMisterX, dat)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	status, err = mcClient.DeleteOrg(uri, tokenMisterX, &org1)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Org already being deleted")
	require.Equal(t, http.StatusBadRequest, status)
	dat.Data["DeleteInProgress"] = false
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
	orgs, status, err = mcClient.ShowOrg(uri, token, ClientNoShowFilter)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 0, len(orgs))
	// check users are gone
	users, status, err = mcClient.ShowUser(uri, token, ClientNoShowFilter)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, len(users))

	testFailedLoginLockout(t, ctx, uri, token, mcClient)
	testImagePaths(t, ctx, mcClient, uri, token)
	testLockedUsers(t, uri, mcClient)
	testPasswordStrength(t, ctx, mcClient, uri, token)
	testEdgeboxOnlyOrgs(t, uri, mcClient)
	testConfigUpgrade(t, ctx)
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

func testLockedUsers(t *testing.T, uri string, mcClient *mctestclient.Client) {
	// login as super user
	superTok, _, err := mcClient.DoLogin(uri, DefaultSuperuser, DefaultSuperpass, NoOTP, NoApiKeyId, NoApiKey)
	require.Nil(t, err, "login as superuser")

	// set config to be locked. This needs to be a map so that
	// marshalling the JSON doesn't put in null entries for other
	// fields, and preserves null entries for specified fields regardless
	// of omit empty.
	notifyEmail := "foo@gmail.com"
	configReq := &cli.MapData{
		Namespace: cli.ArgsNamespace,
		Data:      make(map[string]interface{}),
	}
	configReq.Data["locknewaccounts"] = true
	configReq.Data["notifyemailaddress"] = notifyEmail
	status, err := mcClient.UpdateConfig(uri, superTok, configReq)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)

	// create new account
	user1 := ormapi.User{
		Name:       "user1",
		Email:      "user1@gmail.com",
		Passhash:   "user1-password-super-long-crazy-hard-difficult",
		EnableTOTP: true,
	}
	resp, mailMsg, status, err := mcClientCreateUserWithMockMail(mcClient, uri, &ormapi.CreateUser{User: user1})
	require.Nil(t, err, "create user")
	require.Equal(t, http.StatusOK, status, "create user status")
	require.Contains(t, mailMsg, "Locked account created")
	// login as new user1
	otp, err := totp.GenerateCode(resp.TOTPSharedKey, time.Now())
	require.Nil(t, err, "generate otp")
	_, _, err = mcClient.DoLogin(uri, user1.Name, user1.Passhash, otp, NoApiKeyId, NoApiKey)
	require.NotNil(t, err, "login")
	require.Contains(t, err.Error(), "Account is locked")

	// super user unlock account
	userReq := &cli.MapData{
		Namespace: cli.ArgsNamespace,
		Data:      make(map[string]interface{}),
	}
	userReq.Data["email"] = user1.Email
	userReq.Data["locked"] = false
	userReq.Data["emailverified"] = true
	status, err = mcClient.RestrictedUpdateUser(uri, superTok, userReq)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)

	// user should be able to log in now
	otp, err = totp.GenerateCode(resp.TOTPSharedKey, time.Now())
	require.Nil(t, err, "generate otp")
	tok1, _, err := mcClient.DoLogin(uri, user1.Name, user1.Passhash, otp, NoApiKeyId, NoApiKey)
	require.Nil(t, err)

	// create another new user
	user2 := ormapi.User{
		Name:       "user2",
		Email:      "user2@gmail.com",
		Passhash:   "user2-password-super-long-crazy-hard-difficult",
		EnableTOTP: true,
	}
	resp, mailMsg, status, err = mcClientCreateUserWithMockMail(mcClient, uri, &ormapi.CreateUser{User: user2})
	require.Nil(t, err, "create user")
	require.Equal(t, http.StatusOK, status, "create user status")
	require.Contains(t, mailMsg, "Locked account created")
	// login as new user2
	otp, err = totp.GenerateCode(resp.TOTPSharedKey, time.Now())
	require.Nil(t, err, "generate otp")
	_, _, err = mcClient.DoLogin(uri, user2.Name, user2.Passhash, otp, NoApiKeyId, NoApiKey)
	require.NotNil(t, err, "login")
	require.Contains(t, err.Error(), "Account is locked")

	// make sure users cannot unlock other users
	userReq.Data = make(map[string]interface{})
	userReq.Data["email"] = user2.Email
	userReq.Data["locked"] = false
	status, err = mcClient.RestrictedUpdateUser(uri, tok1, userReq)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)

	// make sure users cannot modify config
	configReq.Data = make(map[string]interface{})
	configReq.Data["locknewaccounts"] = false
	status, err = mcClient.UpdateConfig(uri, tok1, configReq)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)
	// super user unlock new accounts
	status, err = mcClient.UpdateConfig(uri, superTok, configReq)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)

	// user2 still should not be able to log in
	otp, err = totp.GenerateCode(resp.TOTPSharedKey, time.Now())
	require.Nil(t, err, "generate otp")
	_, _, err = mcClient.DoLogin(uri, user2.Name, user2.Passhash, otp, NoApiKeyId, NoApiKey)
	require.NotNil(t, err, "login")
	require.Contains(t, err.Error(), "Account is locked")

	// delete user2, recreate, should be unlocked now
	status, err = mcClient.DeleteUser(uri, superTok, &user2)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	resp, mailMsg, status, err = mcClientCreateUserWithMockMail(mcClient, uri, &ormapi.CreateUser{User: user2})
	require.Nil(t, err, "create user")
	require.Equal(t, http.StatusOK, status, "create user status")
	userVerifyEmail(mcClient, t, uri, mailMsg)
	// login as new user2
	otp, err = totp.GenerateCode(resp.TOTPSharedKey, time.Now())
	require.Nil(t, err, "generate otp")
	_, _, err = mcClient.DoLogin(uri, user2.Name, user2.Passhash, otp, NoApiKeyId, NoApiKey)
	require.Nil(t, err)

	// show config, make sure changes didn't affect notify email address
	config, status, err := mcClient.ShowConfig(uri, superTok)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, notifyEmail, config.NotifyEmailAddress)
	// show public config, make sure certain fields are hidden
	publicConfig, status, err := mcClient.ShowPublicConfig(uri)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, config.PasswordMinCrackTimeSec, publicConfig.PasswordMinCrackTimeSec)
	require.Equal(t, 0, publicConfig.ID)
	require.Equal(t, false, publicConfig.LockNewAccounts)
	require.Equal(t, "", publicConfig.NotifyEmailAddress)
	require.Equal(t, false, publicConfig.SkipVerifyEmail)
	require.Equal(t, float64(0), publicConfig.AdminPasswordMinCrackTimeSec)

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

func testRoleOrgCombos(t *testing.T, uri, token string, mcClient *mctestclient.Client) {
	devOrg := ormapi.Organization{
		Name: "rcDev",
		Type: "developer",
	}
	operOrg := ormapi.Organization{
		Name: "rcOper",
		Type: "operator",
	}
	user := ormapi.User{
		Name:       "rcUser",
		EnableTOTP: true,
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

func testPasswordStrength(t *testing.T, ctx context.Context, mcClient *mctestclient.Client, uri, token string) {
	// Create user in db to simulate old user with existing weak password
	db := loggedDB(ctx)
	adminOldPw := "oldpwd1"
	passhash, salt, iter := ormutil.NewPasshash(adminOldPw)
	adminOld := ormapi.User{
		Name:          "oldadmin",
		Email:         "oldadmin@gmail.com",
		EmailVerified: true,
		Passhash:      passhash,
		Salt:          salt,
		Iter:          iter,
	}
	totpKey, _, err := GenerateTOTPQR(adminOld.Email)
	require.Nil(t, err)
	adminOld.TOTPSharedKey = totpKey
	err = db.FirstOrCreate(&adminOld, &ormapi.User{Name: adminOld.Name}).Error
	require.Nil(t, err)
	// add admin
	psub := rbac.GetCasbinGroup("", adminOld.Name)
	err = enforcer.AddGroupingPolicy(ctx, psub, RoleAdminManager)
	require.Nil(t, err)
	// make sure login is disallowed for admins because of weak password
	otp, err := totp.GenerateCode(totpKey, time.Now())
	require.Nil(t, err, "generate otp")
	_, _, err = mcClient.DoLogin(uri, adminOld.Name, adminOldPw, otp, NoApiKeyId, NoApiKey)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Existing password for Admin too weak")

	// test password strength for new user
	userBad := ormapi.User{
		Name:       "Lazy",
		Email:      "lazy@gmail.com",
		Passhash:   "admin123",
		EnableTOTP: true,
	}
	_, _, _, err = mcClientCreateUserWithMockMail(mcClient, uri, &ormapi.CreateUser{User: userBad})
	require.NotNil(t, err, "bad user password")
	require.Contains(t, err.Error(), "Password too weak")

	// create user1 with decent password
	user1 := ormapi.User{
		Name:       "MisterX",
		Email:      "misterx@gmail.com",
		Passhash:   "misterx-password-supe",
		EnableTOTP: true,
	}
	resp, mailMsg, status, err := mcClientCreateUserWithMockMail(mcClient, uri, &ormapi.CreateUser{User: user1})
	require.Nil(t, err, "create user")
	require.Equal(t, http.StatusOK, status, "create user status")
	userVerifyEmail(mcClient, t, uri, mailMsg)
	// login as new user1
	otp, err = totp.GenerateCode(resp.TOTPSharedKey, time.Now())
	require.Nil(t, err, "generate otp")
	tokenMisterX, _, err := mcClient.DoLogin(uri, user1.Name, user1.Passhash, otp, NoApiKeyId, NoApiKey)
	require.Nil(t, err, "login as mister X")

	// change user password
	newPass := &ormapi.NewPassword{
		Password:        user1.Passhash + "1",
		CurrentPassword: "invalid_password",
	}
	status, err = mcClient.NewPassword(uri, tokenMisterX, newPass)
	require.NotNil(t, err, "new password change should fail as current password is invalid")
	require.Contains(t, err.Error(), "Invalid current password")
	newPass.CurrentPassword = user1.Passhash
	status, err = mcClient.NewPassword(uri, tokenMisterX, newPass)
	require.Nil(t, err, "new password")
	require.Equal(t, http.StatusOK, status, "new password status")
	// fail password change if new password is too weak
	newPass.CurrentPassword = newPass.Password
	newPass.Password = "weakweak"
	status, err = mcClient.NewPassword(uri, tokenMisterX, newPass)
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
	config := &cli.MapData{
		Namespace: cli.StructNamespace,
		Data: map[string]interface{}{
			"PasswordMinCrackTimeSec":      0.1,
			"AdminPasswordMinCrackTimeSec": 0.2,
		},
	}
	status, err = mcClient.UpdateConfig(uri, token, config)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	// old admin should be able to log in now
	otp, err = totp.GenerateCode(totpKey, time.Now())
	require.Nil(t, err, "generate otp")
	_, _, err = mcClient.DoLogin(uri, adminOld.Name, adminOldPw, otp, NoApiKeyId, NoApiKey)
	require.Nil(t, err)

	// assign admin rights to user1, will not work because
	// password strength was reset
	status, err = mcClient.AddUserRole(uri, token, &roleArgBad)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Target user password strength not verified")
	// login to set verify password strength
	otp, err = totp.GenerateCode(resp.TOTPSharedKey, time.Now())
	require.Nil(t, err, "generate otp")
	_, _, err = mcClient.DoLogin(uri, user1.Name, user1.Passhash+"1", otp, NoApiKeyId, NoApiKey)
	require.Nil(t, err)
	// assign admin rights to user1, should work due to low password strength
	// requirements
	status, err = mcClient.AddUserRole(uri, token, &roleArgBad)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)

	// change config back
	config.Data = map[string]interface{}{
		"PasswordMinCrackTimeSec":      defaultConfig.PasswordMinCrackTimeSec,
		"AdminPasswordMinCrackTimeSec": defaultConfig.AdminPasswordMinCrackTimeSec,
	}
	status, err = mcClient.UpdateConfig(uri, token, config)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
	// old admin should not be able to log in now
	otp, err = totp.GenerateCode(totpKey, time.Now())
	require.Nil(t, err, "generate otp")
	_, _, err = mcClient.DoLogin(uri, adminOld.Name, adminOldPw, otp, NoApiKeyId, NoApiKey)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Existing password for Admin too weak")
	// user1 is now an admin and should also not be able to log in
	otp, err = totp.GenerateCode(resp.TOTPSharedKey, time.Now())
	require.Nil(t, err, "generate otp")
	_, _, err = mcClient.DoLogin(uri, user1.Name, user1.Passhash+"1", otp, NoApiKeyId, NoApiKey)
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

func testEdgeboxOnlyOrgs(t *testing.T, uri string, mcClient *mctestclient.Client) {
	// login as super user
	superTok, _, err := mcClient.DoLogin(uri, DefaultSuperuser, DefaultSuperpass, NoOTP, NoApiKeyId, NoApiKey)
	require.Nil(t, err, "login as superuser")

	// create non-admin user
	user := ormapi.User{
		Name:     "user",
		Email:    "user@gmail.com",
		Passhash: "user-password-super-long-crazy-hard-difficult",
	}
	_, mailMsg, status, err := mcClientCreateUserWithMockMail(mcClient, uri, &ormapi.CreateUser{User: user})
	require.Nil(t, err, "create user")
	require.Equal(t, http.StatusOK, status, "create user status")
	userVerifyEmail(mcClient, t, uri, mailMsg)

	// login as non-admin user
	userTok, _, err := mcClient.DoLogin(uri, user.Name, user.Passhash, NoOTP, NoApiKeyId, NoApiKey)
	require.Nil(t, err, "login")

	// create an Organization
	org := ormapi.Organization{
		Type: "operator",
		Name: "Oper",
		// setting edgebox only will have no effect
		EdgeboxOnly: false,
	}
	_, err = mcClient.CreateOrg(uri, userTok, &org)
	require.Nil(t, err, "create org")

	// default operator org will be edgebox only
	check := getOrg(t, mcClient, uri, userTok, org.Name)
	require.NotNil(t, check, "org exists")
	require.True(t, check.EdgeboxOnly, "by default operator org is edgebox org")
	// super user toggle edgebox org
	orgReq := &cli.MapData{
		Namespace: cli.ArgsNamespace,
		Data:      make(map[string]interface{}),
	}
	orgReq.Data["name"] = org.Name
	orgReq.Data["edgeboxonly"] = false
	status, err = mcClient.RestrictedUpdateOrg(uri, superTok, orgReq)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)

	// check if edgeboxonly field got updated
	check = getOrg(t, mcClient, uri, userTok, org.Name)
	require.NotNil(t, check, "org exists")
	require.False(t, check.EdgeboxOnly, "toggled edgeboxonly field")

	// make sure non-admin user cannot toggle edgebox org
	orgReq.Data = make(map[string]interface{})
	orgReq.Data["name"] = org.Name
	orgReq.Data["edgeboxonly"] = true
	status, err = mcClient.RestrictedUpdateOrg(uri, userTok, orgReq)
	require.NotNil(t, err)
	require.Equal(t, http.StatusForbidden, status)

	// cleanup org
	testDeleteOrg(t, mcClient, uri, userTok, org.Name)
	// cleanup user
	testDeleteUser(t, mcClient, uri, userTok, user.Name)
}

func getUnitTestClientRuns() []mctestclient.ClientRun {
	restClient := &ormclient.Client{
		ForceDefaultTransport: true,
	}
	cliClient := cliwrapper.NewClient()
	cliClient.DebugLog = true
	cliClient.SilenceUsage = true
	cliClient.RunInline = true
	cliClient.InjectRequiredArgs = true
	return []mctestclient.ClientRun{restClient, cliClient}
}

func testFailedLoginLockout(t *testing.T, ctx context.Context, uri, superTok string, mcClient *mctestclient.Client) {
	origBadAuthDelay := BadAuthDelay
	BadAuthDelay = 0
	defer func() {
		BadAuthDelay = origBadAuthDelay
	}()

	testUser := ormapi.User{
		Name:     "Lockout",
		Email:    "lockout@gmail.com",
		Passhash: "lockout-password-blue-dog-cat",
	}
	_, mailMsg, status, err := mcClientCreateUserWithMockMail(mcClient, uri, &ormapi.CreateUser{User: testUser})
	require.Nil(t, err, "create user")
	require.Equal(t, http.StatusOK, status, "create user status")
	userVerifyEmail(mcClient, t, uri, mailMsg)

	// These helper funcs are for actions that are run multiple times
	expectLoginOk := func() string {
		token, isAdmin, err := mcClient.DoLogin(uri, testUser.Name, testUser.Passhash, NoOTP, NoApiKeyId, NoApiKey)
		require.Nil(t, err, "login as testUser")
		require.False(t, isAdmin)
		return token
	}
	expectLoginFailed := func() {
		_, _, err = mcClient.DoLogin(uri, testUser.Name, "badpass", NoOTP, NoApiKeyId, NoApiKey)
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "Invalid username or password")
	}
	expectLoginLockout := func(cnt int, pass string) {
		_, _, err = mcClient.DoLogin(uri, testUser.Name, pass, NoOTP, NoApiKeyId, NoApiKey)
		require.NotNil(t, err)
		errMsg := fmt.Sprintf("Login temporarily disabled due to %d failed login attempts, please try again", cnt)
		require.Contains(t, err.Error(), errMsg)
	}

	// check that user login works
	token := expectLoginOk()

	// trigger threshold1 lockout
	threshold1 := defaultConfig.FailedLoginLockoutThreshold1
	for ii := 0; ii < threshold1; ii++ {
		expectLoginFailed()
	}
	// next attempt should be locked out
	expectLoginLockout(threshold1, "badpass")
	expectLoginLockout(threshold1, "badpass")
	// even further attempts with correct password are locked out
	expectLoginLockout(threshold1, testUser.Passhash)
	expectLoginLockout(threshold1, testUser.Passhash)

	// configure the threshold1 lockout time to 0,
	// this effectively disables the threshold1 lockout,
	// so we can hit and test threshold 2.
	configReq := &cli.MapData{
		Namespace: cli.ArgsNamespace,
		Data:      make(map[string]interface{}),
	}
	configReq.Data["failedloginlockouttimesec1"] = 0
	status, err = mcClient.UpdateConfig(uri, superTok, configReq)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)

	threshold2 := defaultConfig.FailedLoginLockoutThreshold2
	for ii := 0; ii < threshold2-threshold1; ii++ {
		expectLoginFailed()
	}
	// login with the correct password is still disabled
	// next attempt should be locked out
	expectLoginLockout(threshold2, "badpass")
	expectLoginLockout(threshold2, "badpass")
	// even further attempts with correct password are locked out
	expectLoginLockout(threshold2, testUser.Passhash)
	expectLoginLockout(threshold2, testUser.Passhash)

	// change threshold2 to a short timeout so we can test it.
	configReq.Data["failedloginlockouttimesec2"] = 1
	status, err = mcClient.UpdateConfig(uri, superTok, configReq)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)

	time.Sleep(time.Second)
	// login should work now
	expectLoginOk()

	// change back threshold
	configReq.Data["failedloginlockouttimesec2"] = 300
	status, err = mcClient.UpdateConfig(uri, superTok, configReq)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)

	// user is not locked out because they successfully logged in
	expectLoginOk()

	// trigger lockout state again
	for ii := 0; ii < threshold2; ii++ {
		expectLoginFailed()
	}
	// user should be locked out
	expectLoginLockout(threshold2, testUser.Passhash)

	// user can reset the failed count (as long as they are already logged in)
	// this can also be done by admin
	mapData := &cli.MapData{
		Namespace: cli.ArgsNamespace,
		Data:      map[string]interface{}{},
	}
	mapData.Data["failedlogins"] = 0
	status, err = mcClient.RestrictedUpdateUser(uri, superTok, mapData)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)

	// user login should now work
	expectLoginOk()

	// restore modified config
	BadAuthDelay = 3 * time.Second
	configReq.Data["failedloginlockouttimesec1"] = defaultConfig.FailedLoginLockoutTimeSec1
	configReq.Data["failedloginlockouttimesec2"] = defaultConfig.FailedLoginLockoutTimeSec2
	status, err = mcClient.UpdateConfig(uri, superTok, configReq)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)

	// check bad config timesec1
	configReq.Data = map[string]interface{}{
		"failedloginlockouttimesec1": 1,
	}
	_, err = mcClient.UpdateConfig(uri, superTok, configReq)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Failed login lockout time sec 1 of 1s must be greater than or equal to default lockout time of 3s")
	configReq.Data = map[string]interface{}{
		"failedloginlockouttimesec1": int64(4294967295454),
	}
	_, err = mcClient.UpdateConfig(uri, superTok, configReq)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "cannot be negative")
	// check bad config timesec2
	configReq.Data = map[string]interface{}{
		"failedloginlockouttimesec2": 1,
	}
	_, err = mcClient.UpdateConfig(uri, superTok, configReq)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Failed login lockout time sec 2 of 1s must be greater than or equal to lockout time 1 of 1m0s")
	configReq.Data = map[string]interface{}{
		"failedloginlockouttimesec2": int64(4294967295454),
	}
	_, err = mcClient.UpdateConfig(uri, superTok, configReq)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "cannot be negative")
	// check bad config threshold1
	configReq.Data = map[string]interface{}{
		"failedloginlockoutthreshold1": 0,
	}
	_, err = mcClient.UpdateConfig(uri, superTok, configReq)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Failed login lockout threshold 1 cannot be less than or equal to 0")
	// check bad config threshold2
	configReq.Data = map[string]interface{}{
		"failedloginlockoutthreshold2": 0,
	}
	_, err = mcClient.UpdateConfig(uri, superTok, configReq)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Failed login lockout threshold 2 cannot be less than or equal to 0")
	configReq.Data = map[string]interface{}{
		"failedloginlockoutthreshold2": 1,
	}
	_, err = mcClient.UpdateConfig(uri, superTok, configReq)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Failed login lockout threshold 2 of 1 must be greater than threshold 1 of 3")

	// test login valid duration
	// change duration to 0, must be done directly to bypass check
	config, err := getConfig(ctx)
	require.Nil(t, err)
	config.UserLoginTokenValidDuration = 0
	db := loggedDB(ctx)
	err = db.Save(config).Error
	require.Nil(t, err)
	// get new token
	token = expectLoginOk()
	// token should be expired already
	time.Sleep(time.Second)
	_, status, err = mcClient.CurrentUser(uri, token)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Token is expired")
	// change it back
	configReq.Data = map[string]interface{}{
		"userlogintokenvalidduration": defaultConfig.UserLoginTokenValidDuration.TimeDuration().String(),
	}
	_, err = mcClient.UpdateConfig(uri, superTok, configReq)
	require.Nil(t, err)
	token = expectLoginOk()
	// token should be valid
	_, status, err = mcClient.CurrentUser(uri, token)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)

	// clean up
	status, err = mcClient.DeleteUser(uri, token, &testUser)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}

func testConfigUpgrade(t *testing.T, ctx context.Context) {
	db := loggedDB(ctx)
	// Remove existing config
	err := db.DropTable(ormapi.Config{}).Error
	require.Nil(t, err, "drop existing configs table")

	// Add old version of config
	oldCfgCmd := "CREATE TABLE configs(id INT PRIMARY KEY NOT NULL);"
	err = db.Exec(oldCfgCmd).Error
	require.Nil(t, err, "create old version of configs table")

	insertCmd := fmt.Sprintf("INSERT INTO configs(id) VALUES (%d);", defaultConfig.ID)
	err = db.Exec(insertCmd).Error
	require.Nil(t, err, "create old version of configs table")

	// upgrade configs table
	err = db.AutoMigrate(&ormapi.Config{}).Error
	require.Nil(t, err, "Upgrade configs table")

	// Upgrade to new config data, default values should be picked from defaultConfig
	err = InitConfig(ctx)
	require.Nil(t, err)

	// Verify new config has values from defaultConfig
	config, err := getConfig(ctx)
	require.Nil(t, err, "get latest config")
	// Ignore disableRateLimit as the default is set to true for unit-test,
	// but the upgrade will not set the default value for it
	config.DisableRateLimit = defaultConfig.DisableRateLimit
	require.Equal(t, defaultConfig, *config)
}
