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
	"net/url"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/billing"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormclient"
	"github.com/edgexr/edge-cloud-platform/pkg/mcctl/mctestclient"
	"github.com/edgexr/edge-cloud-platform/pkg/process"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/require"
)

type entry struct {
	Org     string            // Organization/Organization
	OrgType string            // Organization Type
	Users   map[string]string // User:UserType
}

var (
	testEntries []entry = []entry{
		entry{
			Org:     "bigorg1",
			OrgType: OrgTypeDeveloper,
			Users: map[string]string{
				"orgman1":   RoleDeveloperManager,
				"worker1":   RoleDeveloperContributor,
				"worKer1.1": RoleDeveloperViewer,
			},
		},
		entry{
			Org:     "bigOrg2",
			OrgType: OrgTypeDeveloper,
			Users: map[string]string{
				"orgMan2":   RoleDeveloperManager,
				"worker2":   RoleDeveloperContributor,
				"wOrKer2.1": RoleDeveloperViewer,
			},
		},
		entry{
			Org:     "operatorOrg",
			OrgType: OrgTypeOperator,
			Users: map[string]string{
				"oper1": RoleOperatorManager,
			},
		},
	}

	// Extra entries only present in Artifactory/Gitlab but not in MC
	extraEntries []entry = []entry{
		entry{
			Org:     "extraOrg1",
			OrgType: OrgTypeDeveloper,
			Users: map[string]string{
				"extraUser1":   RoleDeveloperManager,
				"extraWorker1": RoleDeveloperContributor,
			},
		},
	}

	// Missing entries only present in MC but not in Artifactory/Gitlab
	missingEntries []entry = []entry{
		entry{
			Org:     "missingOrg1",
			OrgType: OrgTypeDeveloper,
			Users: map[string]string{
				"missingUser1": RoleDeveloperManager,
				"missingUser2": RoleDeveloperViewer,
			},
		},
		entry{
			Org:     "missingOperOrg",
			OrgType: OrgTypeOperator,
			Users: map[string]string{
				"missingOperUser1": RoleOperatorManager,
				"missingOperUser2": RoleOperatorViewer,
			},
		},
	}

	// create operator entries present in both MC and Artifactory/Gitlab,
	// should be removed by sync thread.
	operatorEntries []entry = []entry{
		entry{
			Org:     "oldOperOrg",
			OrgType: OrgTypeOperator,
		},
		entry{
			Org:     "oldOperOrg2",
			OrgType: OrgTypeOperator,
		},
	}
)

const (
	ExtraObj   string = "extra"
	MCObj      string = "mc"
	OldOperObj string = "oldoper"
)

func TestAppStoreApi(t *testing.T) {
	domain := "edgecloud.net"

	artifactoryAddr := "https://dummy-artifactory." + domain
	artifactoryApiKey := "dummyKey"

	gitlabAddr := "https://dummy-gitlab." + domain
	gitlabApiKey := "dummyKey"

	harborAddr := "https://dummy-harbor." + domain
	harborAdmin := "admin"
	harborPassword := "password"

	var status int

	log.SetDebugLevel(log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()

	ctx := log.StartTestSpan(context.Background())

	os.Setenv("gitlab_token", gitlabApiKey)

	// mock http to redirect requests
	mockTransport := httpmock.NewMockTransport()
	// any requests that don't have a registered URL will be fetched normally
	mockTransport.RegisterNoResponder(httpmock.InitialTransport.RoundTrip)

	// master controller
	addr := "127.0.0.1:9999"
	uri := "http://" + addr + "/api/v1"

	defaultConfig.DisableRateLimit = true

	vp := process.Vault{
		Common: process.Common{
			Name: "vault",
		},
		ListenAddr: "https://127.0.0.1:8202",
		PKIDomain:  "edgecloud.net",
	}
	_, vroles, vaultCleanup := testutil.NewVaultTestCluster(t, &vp)
	os.Setenv("VAULT_ROLE_ID", vroles.MCRoleID)
	os.Setenv("VAULT_SECRET_ID", vroles.MCSecretID)
	defer func() {
		os.Unsetenv("VAULT_ROLE_ID")
		os.Unsetenv("VAULT_SECRET_ID")
		vaultCleanup()
	}()

	rtfuri, err := url.ParseRequestURI(artifactoryAddr)
	require.Nil(t, err, "parse artifactory url")

	path := "/secret/registry/" + rtfuri.Host
	out := vp.Run("vault", fmt.Sprintf("kv put %s apikey=%s", path, artifactoryApiKey), &err)
	require.Nil(t, err, "added artifactory secret to vault %s", out)

	hpath := "/secret" + HarborAdminAuthVaultPath
	out = vp.Run("vault", fmt.Sprintf("kv put %s username=%s password=%s", hpath, harborAdmin, harborPassword), &err)
	require.Nil(t, err, "added harbor secret to vault %s", out)

	// mock artifactory
	rtf := NewArtifactoryMock(artifactoryAddr, mockTransport)
	// mock gitlab
	gm := NewGitlabMock(gitlabAddr, mockTransport)
	// mock harbor
	hm := NewHarborMock(harborAddr, mockTransport, harborAdmin, harborPassword)
	harborClient = &http.Client{
		Transport: mockTransport,
		Timeout:   3 * time.Second,
	}

	config := ServerConfig{
		ServAddr:                 addr,
		SqlAddr:                  "127.0.0.1:5445",
		RunLocal:                 true,
		InitLocal:                true,
		IgnoreEnv:                true,
		VaultAddr:                vp.ListenAddr,
		ArtifactoryAddr:          artifactoryAddr,
		GitlabAddr:               gitlabAddr,
		HarborAddr:               harborAddr,
		UsageCheckpointInterval:  "MONTH",
		BillingPlatform:          billing.BillingTypeFake,
		DeploymentTag:            "local",
		PublicAddr:               "http://mc.edgecloud.net",
		PasswordResetConsolePath: "#/passwordreset",
		VerifyEmailConsolePath:   "#/verify",
		testTransport:            mockTransport,
		HTTPCookieDomain:         domain,
	}
	server, err := RunServer(&config)
	require.Nil(t, err, "run server")
	defer server.Stop()

	err = server.WaitUntilReady()
	require.Nil(t, err, "server online")

	mcClient := mctestclient.NewClient(&ormclient.Client{
		TestTransport: mockTransport,
	})

	// login as super user
	tokenAdmin, _, err := mcClient.DoLogin(uri, DefaultSuperuser, DefaultSuperpass, NoOTP, NoApiKeyId, NoApiKey)
	require.Nil(t, err, "login as superuser")

	// basic direct api tests
	for user, _ := range testEntries[0].Users {
		userObj := ormapi.User{
			Name:  user,
			Email: user + "@email.com",
		}
		// gitlab create user
		err := gitlabCreateLDAPUser(ctx, &userObj)
		require.Nil(t, err, user)
		// check that we can get user
		gitlabUser, err := gitlabGetLDAPUser(user)
		require.Nil(t, err, user)
		require.Equal(t, user, gitlabUser.Name)
		// create again should fail
		err = gitlabCreateLDAPUser(ctx, &userObj)
		require.NotNil(t, err, user)
		// delete user
		err = gitlabDeleteLDAPUser(ctx, user)
		require.Nil(t, err, user)
		// user should not exist
		_, err = gitlabGetLDAPUser(user)
		require.NotNil(t, err, user)
		// delete again should fail
		err = gitlabDeleteLDAPUser(ctx, user)
		require.NotNil(t, err, user)

		// artifactory create user
		err = artifactoryCreateLDAPUser(ctx, &userObj)
		require.Nil(t, err, user)
		// check that we can get user
		artUsers, err := artifactoryListUsers(ctx)
		require.Nil(t, err, user)
		_, found := artUsers[strings.ToLower(user)]
		require.True(t, found, user)
		// create again should fail
		err = artifactoryCreateLDAPUser(ctx, &userObj)
		require.NotNil(t, err, user)
		// delete user
		err = artifactoryDeleteLDAPUser(ctx, user)
		require.Nil(t, err, user)
		// user should not exist
		artUsers, err = artifactoryListUsers(ctx)
		require.Nil(t, err, user)
		_, found = artUsers[strings.ToLower(user)]
		require.False(t, found, user)
		// delete again should fail
		err = artifactoryDeleteLDAPUser(ctx, user)
		require.NotNil(t, err, user)

		// MC never creates harbor users directly, they
		// are created either via user logging into Harbor,
		// or via project member add.
	}

	// create "missing" data in MC but not in Art/Gitlab
	for _, v := range missingEntries {
		mcClientCreate(t, v, mcClient, uri)
	}
	rtf.initData()
	gm.initData()
	hm.initData()

	// for consistency in counts, make sure edgecloud org project exists
	harborCreateProject(ctx, &harborEdgeCloudOrg)

	// Create new users & orgs from MC
	for _, v := range testEntries {
		mcClientCreate(t, v, mcClient, uri)
		rtf.verify(t, v, MCObj)
		gm.verify(t, v, MCObj)
		hm.verify(t, v, MCObj)
	}
	rtf.verifyCount(t, testEntries, MCObj)
	hm.verifyCount(t, testEntries, MCObj)

	// Create users & orgs which are not present in MC
	for _, v := range extraEntries {
		org := ormapi.Organization{
			Name: v.Org,
			Type: v.OrgType,
		}
		artifactoryCreateGroupObjects(ctx, v.Org, v.OrgType)
		gitlabCreateGroup(ctx, &org)
		harborCreateProject(ctx, &org)
		for user, userType := range v.Users {
			userObj := ormapi.User{
				Name:  user,
				Email: user + "@email.com",
			}
			err := artifactoryCreateLDAPUser(ctx, &userObj)
			require.Nil(t, err)
			err = gitlabCreateLDAPUser(ctx, &userObj)
			require.Nil(t, err)

			roleArg := ormapi.Role{
				Username: user,
				Org:      v.Org,
				Role:     userType,
			}
			gitlabAddGroupMember(ctx, &roleArg, org.Type)
			artifactoryAddUserToGroup(ctx, &roleArg, org.Type)
			harborAddProjectMember(ctx, &roleArg, org.Type)
		}
		rtf.verify(t, v, ExtraObj)
		gm.verify(t, v, ExtraObj)
		hm.verify(t, v, ExtraObj)
	}
	rtf.verifyCount(t, append(testEntries, extraEntries...), MCObj)
	hm.verifyCount(t, append(testEntries, extraEntries...), MCObj)

	// Create operator entries in MC and then force populate them
	// in artifactory/gitlab to test that sync will remove them.
	for _, v := range operatorEntries {
		testCreateOrg(t, mcClient, uri, tokenAdmin, v.OrgType, v.Org)
		// leave Type empty so artifactory/gitlab funcs will push it
		org := ormapi.Organization{
			Name: v.Org,
		}
		// verify not in artifactory/gitlab
		rtf.verify(t, v, MCObj)
		gm.verify(t, v, MCObj)
		hm.verify(t, v, MCObj)

		artifactoryCreateGroupObjects(ctx, org.Name, org.Type)
		gitlabCreateGroup(ctx, &org)
		harborCreateProject(ctx, &org)

		// verify now in artifactory/gitlab
		rtf.verify(t, v, OldOperObj)
		gm.verify(t, v, OldOperObj)
		hm.verify(t, v, OldOperObj)
	}

	// Trigger resync to delete extra objects and create missing ones
	status, err = mcClient.ArtifactoryResync(uri, tokenAdmin)
	require.Nil(t, err, "artifactory resync")
	require.Equal(t, http.StatusOK, status, "artifactory resync status")
	status, err = mcClient.GitlabResync(uri, tokenAdmin)
	require.Nil(t, err, "gitlab resync")
	require.Equal(t, http.StatusOK, status, "gitlab resync status")
	status, err = mcClient.HarborResync(uri, tokenAdmin)
	require.Nil(t, err, "harbor resync")
	require.Equal(t, http.StatusOK, status, "harbor resync status")

	waitSyncCount(t, gitlabSync, 2)
	waitSyncCount(t, artifactorySync, 2)
	waitSyncCount(t, harborSync, 2)

	// Verify that only testEntries and missingEntries are present
	for _, v := range testEntries {
		rtf.verify(t, v, MCObj)
		gm.verify(t, v, MCObj)
		hm.verify(t, v, MCObj)
	}
	for _, v := range missingEntries {
		rtf.verify(t, v, MCObj)
		gm.verify(t, v, MCObj)
		hm.verify(t, v, MCObj)
	}
	rtf.verifyCount(t, append(testEntries, missingEntries...), MCObj)
	hm.verifyCount(t, append(testEntries, missingEntries...), MCObj)

	// Delete MC created Objects
	for _, v := range testEntries {
		mcClientDelete(t, v, mcClient, uri, tokenAdmin)
	}

	// verify missing entries are there
	rtf.verifyCount(t, missingEntries, MCObj)
	for _, v := range missingEntries {
		rtf.verify(t, v, MCObj)
		gm.verify(t, v, MCObj)
		hm.verify(t, v, MCObj)
		// delete them
		mcClientDelete(t, v, mcClient, uri, tokenAdmin)
	}

	// By now, appstore Sync threads should delete all extra objects as well
	rtf.verifyEmpty(t)
	gm.verifyEmpty(t)
	hm.verifyEmpty(t)
}

func mcClientCreate(t *testing.T, v entry, mcClient *mctestclient.Client, uri string) {
	token := ""
	for user, userType := range v.Users {
		if userType == RoleDeveloperManager || userType == RoleOperatorManager {
			_, token, _ = testCreateUser(t, mcClient, uri, user)
			testCreateOrg(t, mcClient, uri, token, v.OrgType, v.Org)
			break
		}
	}
	for user, userType := range v.Users {
		if userType != RoleDeveloperManager && userType != RoleOperatorManager {
			worker, _, _ := testCreateUser(t, mcClient, uri, user)
			testAddUserRole(t, mcClient, uri, token, v.Org, userType, worker.Name, Success)
		}
	}
}

func mcClientDelete(t *testing.T, v entry, mcClient *mctestclient.Client, uri, tokenAdmin string) {
	for user, userType := range v.Users {
		if userType == RoleDeveloperManager || userType == RoleOperatorManager {
			continue
		}
		roleArg := ormapi.Role{
			Username: user,
			Org:      v.Org,
			Role:     userType,
		}
		// admin user can remove role
		status, err := mcClient.RemoveUserRole(uri, tokenAdmin, &roleArg)
		require.Nil(t, err, "remove user role")
		require.Equal(t, http.StatusOK, status)
	}

	// delete org
	org := ormapi.Organization{
		Name: v.Org,
	}
	status, err := mcClient.DeleteOrg(uri, tokenAdmin, &org)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)

	// delete all users
	for user, _ := range v.Users {
		userObj := ormapi.User{
			Name: user,
		}
		status, err = mcClient.DeleteUser(uri, tokenAdmin, &userObj)
		require.Nil(t, err)
		require.Equal(t, http.StatusOK, status)
	}
}

func waitSyncCount(t *testing.T, sync *AppStoreSync, count int64) {
	for ii := 0; ii < 10; ii++ {
		if sync.count >= count {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if sync.count != count {
		// print all goroutines in case sync thread is stuck
		buf := make([]byte, 200*1024)
		len := runtime.Stack(buf, true)
		fmt.Println(string(buf[:len]))
	}
	require.True(t, sync.count == count, fmt.Sprintf("sync count %d != expected %d", sync.count, count))
}
