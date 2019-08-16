package orm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	v1 "github.com/atlassian/go-artifactory/v2/artifactory/v1"
	"github.com/jarcoal/httpmock"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormclient"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/stretchr/testify/require"
)

type entry struct {
	Org   string            // Organization/Developer
	Users map[string]string // User:UserType
}

var (
	rtfUserStore  map[string]*v1.User
	rtfGroupStore map[string]*v1.Group
	rtfRepoStore  map[string]*v1.LocalRepository
	rtfPermStore  map[string]*v1.PermissionTargets

	testEntries []entry = []entry{
		entry{
			Org: "bigorg1",
			Users: map[string]string{
				"orgman1":   RoleDeveloperManager,
				"worker1":   RoleDeveloperContributor,
				"worKer1.1": RoleDeveloperViewer,
			},
		},
		entry{
			Org: "bigOrg2",
			Users: map[string]string{
				"orgMan2":   RoleDeveloperManager,
				"worker2":   RoleDeveloperContributor,
				"wOrKer2.1": RoleDeveloperViewer,
			},
		},
	}

	// Entries only present in Artifactory but not in MC
	rtfDummyEntries []entry = []entry{
		entry{
			Org: "dummyOrg1",
			Users: map[string]string{
				"dummyUser1":   RoleDeveloperManager,
				"dummyWorker1": RoleDeveloperContributor,
			},
		},
	}
)

const (
	artifactoryAddr   string = "https://dummy-artifactory.mobiledgex.net"
	artifactoryApiKey string = "dummyKey"

	userApi  string = "/api/security/users/"
	groupApi string = "/api/security/groups/"
	repoApi  string = "/api/repositories/"
	permApi  string = "/api/security/permissions/"

	DummyObj string = "dummy"
	MCObj    string = "mc"
)

func getApiPath(api, name string) string {
	if name == "" {
		return artifactoryAddr + strings.TrimSuffix(api, "/")
	} else {
		return "=~(?i)^" + artifactoryAddr + api + name + "$"
	}
}

func registerCreateUser(userName string) {
	httpmock.RegisterResponder("PUT", getApiPath(userApi, userName),
		func(req *http.Request) (*http.Response, error) {
			rtfUser := v1.User{}
			err := json.NewDecoder(req.Body).Decode(&rtfUser)
			if err != nil {
				return httpmock.NewStringResponse(500, "Unable to decode JSON body"), nil
			}
			realm := "ldap"
			// As Artifactory stores username in lowercase format
			username := strings.ToLower(*rtfUser.Name)
			rtfUser.Realm = &realm
			rtfUser.Name = &username
			rtfUserStore[username] = &rtfUser

			return httpmock.NewStringResponse(200, "Success"), nil
		},
	)
}

func registerDeleteUser(userName string) {
	httpmock.RegisterResponder("DELETE", getApiPath(userApi, userName),
		func(req *http.Request) (*http.Response, error) {
			username := strings.ToLower(userName)
			if _, ok := rtfUserStore[username]; ok {
				delete(rtfUserStore, username)
				return httpmock.NewStringResponse(200, "Success"), nil
			}
			return httpmock.NewStringResponse(404, "Unable to find user"), nil
		},
	)
}

func registerCreateGroup(orgName string) {
	httpmock.RegisterResponder("PUT", getApiPath(groupApi, getArtifactoryName(orgName)),
		func(req *http.Request) (*http.Response, error) {
			rtfGroup := v1.Group{}
			err := json.NewDecoder(req.Body).Decode(&rtfGroup)
			if err != nil {
				return httpmock.NewStringResponse(500, "Unable to decode JSON body"), nil
			}
			rtfGroupStore[*rtfGroup.Name] = &rtfGroup

			return httpmock.NewStringResponse(200, "Success"), nil
		},
	)
}

func registerDeleteGroup(orgName string) {
	groupName := getArtifactoryName(orgName)
	httpmock.RegisterResponder("DELETE", getApiPath(groupApi, groupName),
		func(req *http.Request) (*http.Response, error) {
			if _, ok := rtfGroupStore[groupName]; ok {
				delete(rtfGroupStore, groupName)
				return httpmock.NewStringResponse(200, "Success"), nil
			}
			return httpmock.NewStringResponse(404, "Unable to find group"), nil
		},
	)
}

func registerCreateRepo(orgName string) {
	httpmock.RegisterResponder("PUT", getApiPath(repoApi, getArtifactoryRepoName(orgName)),
		func(req *http.Request) (*http.Response, error) {
			rtfRepo := v1.LocalRepository{}
			err := json.NewDecoder(req.Body).Decode(&rtfRepo)
			if err != nil {
				return httpmock.NewStringResponse(500, "Unable to decode JSON body"), nil
			}
			rtfRepoStore[*rtfRepo.Key] = &rtfRepo

			return httpmock.NewStringResponse(200, "Success"), nil
		},
	)
}

func registerDeleteRepo(orgName string) {
	repoName := getArtifactoryRepoName(orgName)
	httpmock.RegisterResponder("DELETE", getApiPath(repoApi, repoName),
		func(req *http.Request) (*http.Response, error) {
			if _, ok := rtfRepoStore[repoName]; ok {
				delete(rtfRepoStore, repoName)
				return httpmock.NewStringResponse(200, "Success"), nil
			}
			return httpmock.NewStringResponse(404, "Unable to find repo"), nil
		},
	)
}

func registerCreatePerm(orgName string) {
	httpmock.RegisterResponder("PUT", getApiPath(permApi, getArtifactoryName(orgName)),
		func(req *http.Request) (*http.Response, error) {
			rtfPerm := v1.PermissionTargets{}
			err := json.NewDecoder(req.Body).Decode(&rtfPerm)
			if err != nil {
				return httpmock.NewStringResponse(500, "Unable to decode JSON body"), nil
			}
			rtfPermStore[*rtfPerm.Name] = &rtfPerm

			return httpmock.NewStringResponse(200, "Success"), nil
		},
	)
}

func registerDeletePerm(orgName string) {
	permName := getArtifactoryName(orgName)
	httpmock.RegisterResponder("DELETE", getApiPath(permApi, permName),
		func(req *http.Request) (*http.Response, error) {
			if _, ok := rtfPermStore[permName]; ok {
				delete(rtfPermStore, permName)
				return httpmock.NewStringResponse(200, "Success"), nil
			}
			return httpmock.NewStringResponse(404, "Unable to find permission target"), nil
		},
	)
}

func registerGetUser(userName string) {
	httpmock.RegisterResponder("GET", getApiPath(userApi, userName),
		func(req *http.Request) (*http.Response, error) {
			if rtfUser, ok := rtfUserStore[strings.ToLower(userName)]; ok {
				return httpmock.NewJsonResponse(200, rtfUser)
			}
			return httpmock.NewStringResponse(404, "Unable to find user"), nil
		},
	)
}

func registerGetUsers() {
	httpmock.RegisterResponder("GET", getApiPath(userApi, ""),
		func(req *http.Request) (*http.Response, error) {
			users := []v1.UserDetails{}
			for _, v := range rtfUserStore {
				users = append(
					users,
					v1.UserDetails{
						Name:  v.Name,
						Realm: v.Realm,
					},
				)
			}
			return httpmock.NewJsonResponse(200, users)
		},
	)
}

func registerGetGroups() {
	httpmock.RegisterResponder("GET", getApiPath(groupApi, ""),
		func(req *http.Request) (*http.Response, error) {
			groups := []v1.GroupDetails{}
			for _, v := range rtfGroupStore {
				groups = append(
					groups,
					v1.GroupDetails{
						Name: v.Name,
					},
				)
			}
			return httpmock.NewJsonResponse(200, groups)
		},
	)
}

func registerGetRepos() {
	httpmock.RegisterResponder("GET", getApiPath(repoApi, ""),
		func(req *http.Request) (*http.Response, error) {
			repos := []v1.RepositoryDetails{}
			repoType := "local"
			for _, v := range rtfRepoStore {
				repos = append(
					repos,
					v1.RepositoryDetails{
						Key:  v.Key,
						Type: &repoType,
					},
				)
			}
			return httpmock.NewJsonResponse(200, repos)
		},
	)
}

func registerGetPerms() {
	httpmock.RegisterResponder("GET", getApiPath(permApi, ""),
		func(req *http.Request) (*http.Response, error) {
			perms := []v1.PermissionTargetsDetails{}
			for _, v := range rtfPermStore {
				perms = append(
					perms,
					v1.PermissionTargetsDetails{
						Name: v.Name,
					},
				)
			}
			return httpmock.NewJsonResponse(200, perms)
		},
	)
}

func registerUpdateUser(userName, orgName string) {
	httpmock.RegisterResponder("POST", getApiPath(userApi, userName),
		func(req *http.Request) (*http.Response, error) {
			updateUser := v1.User{}
			err := json.NewDecoder(req.Body).Decode(&updateUser)
			if err != nil {
				return httpmock.NewStringResponse(500, "Unable to decode JSON body"), nil
			}
			if rtfUser, ok := rtfUserStore[strings.ToLower(userName)]; ok {
				rtfUser.Groups = updateUser.Groups
				return httpmock.NewStringResponse(200, ""), nil
			}
			return httpmock.NewStringResponse(404, "Unable to find user"), nil
		},
	)
}

func registerMockResponders(e entry) {
	// any requests that don't have a registered URL will be fetched normally
	httpmock.RegisterNoResponder(httpmock.InitialTransport.RoundTrip)

	// Create User
	for user, _ := range e.Users {
		registerCreateUser(user)
		registerDeleteUser(user)
	}

	// Create Group/Repo/Permission-Target
	registerCreateGroup(e.Org)
	registerCreateRepo(e.Org)
	registerCreatePerm(e.Org)

	// Delete Group/Repo/Permission-Target
	registerDeleteGroup(e.Org)
	registerDeleteRepo(e.Org)
	registerDeletePerm(e.Org)

	// Get User
	for user, _ := range e.Users {
		registerGetUser(user)
	}

	// List all users
	registerGetUsers()

	// List all groups
	registerGetGroups()

	// List all repos
	registerGetRepos()

	// List all perms
	registerGetPerms()

	// Add user to group
	for user, _ := range e.Users {
		registerUpdateUser(user, e.Org)
	}
}

func contains(objects []string, e string) bool {
	for _, obj := range objects {
		if obj == e {
			return true
		}
	}
	return false
}

func verifyRtfStore(t *testing.T, v entry, objType string) {
	// Verify group exists and group name starts with required prefix
	groupName := getArtifactoryName(v.Org)
	rtfGroup, ok := rtfGroupStore[groupName]
	require.True(t, ok, "Group exists")
	require.Equal(t, *rtfGroup.Name, groupName, "Group name matches")

	// Verify repo exists and repo name starts with required prefix
	repoName := getArtifactoryRepoName(v.Org)
	rtfRepo, ok := rtfRepoStore[repoName]
	require.True(t, ok, "repo exists")
	require.Equal(t, *rtfRepo.Key, repoName, "Repo key matches")
	require.Equal(t, *rtfRepo.RClass, "local", "Repo must be local")

	// Verify perm exists and  perm name starts with required prefix
	permName := getArtifactoryName(v.Org)
	rtfPerm, ok := rtfPermStore[permName]
	require.True(t, ok, "Permission target exists")
	require.Equal(t, *rtfPerm.Name, permName, "Permission target name matches")
	require.Equal(t, (*rtfPerm.Repositories)[0], repoName, "Repository is part of permission target")
	require.NotNil(t, rtfPerm.Principals.Users, "User permissions exists")
	require.NotNil(t, rtfPerm.Principals.Groups, "Group permissions exists")
	for grp, grpPerm := range *rtfPerm.Principals.Groups {
		require.Equal(t, grp, groupName, "Group is part of permission target")
		require.False(t, contains(grpPerm, "w"), "Group should not have write permission")
		require.False(t, contains(grpPerm, "d"), "Group should not have delete permission")
		require.True(t, contains(grpPerm, "r"), "Group should have read permission")
	}

	// Verify user exists and uses LDAP config
	for user, userType := range v.Users {
		userName := strings.ToLower(user)
		rtfUser, ok := rtfUserStore[userName]
		require.True(t, ok, "user exists")
		require.Equal(t, *rtfUser.Name, userName, "user name matches")
		require.True(t, *rtfUser.InternalPasswordDisabled, "user must use LDAP")
		require.NotNil(t, rtfUser.Groups, "user group exists")
		require.True(t, contains(*rtfUser.Groups, getArtifactoryName(v.Org)), "user must belong to org")

		if objType == MCObj {
			usrPerm, ok := (*rtfPerm.Principals.Users)[userName]
			if userType == RoleDeveloperViewer {
				require.False(t, ok, fmt.Sprintf("User permission for %s should not exist", userName))
			} else {
				require.True(t, ok, fmt.Sprintf("User permission for %s exists", userName))
				require.True(t, contains(usrPerm, "r"), "User should have read permission")
				require.True(t, contains(usrPerm, "w"), "User should have write permission")
				require.True(t, contains(usrPerm, "d"), "User should have delete permission")
				if userType == RoleDeveloperManager {
					require.True(t, contains(usrPerm, "m"), "User should have manage permission")
				}
			}
		}
	}
}

func TestArtifactoryApi(t *testing.T) {
	var status int

	log.SetDebugLevel(log.DebugLevelApi)
	log.InitTracer("")
	defer log.FinishTracer()

	ctx := context.Background()

	rtfUserStore = make(map[string]*v1.User)
	rtfGroupStore = make(map[string]*v1.Group)
	rtfRepoStore = make(map[string]*v1.LocalRepository)
	rtfPermStore = make(map[string]*v1.PermissionTargets)

	httpmock.Activate()
	for _, v := range testEntries {
		registerMockResponders(v)
	}

	for _, v := range rtfDummyEntries {
		registerMockResponders(v)
	}

	defer httpmock.DeactivateAndReset()

	addr := "127.0.0.1:9999"
	uri := "http://" + addr + "/api/v1"

	config := ServerConfig{
		ServAddr:        addr,
		SqlAddr:         "127.0.0.1:5445",
		RunLocal:        true,
		InitLocal:       true,
		IgnoreEnv:       true,
		ArtifactoryAddr: artifactoryAddr,
		SkipVerifyEmail: true,
		LocalVault:      true,
	}

	server, err := RunServer(&config)
	require.Nil(t, err, "run server")
	defer server.Stop()

	os.Setenv("VAULT_ROLE_ID", roleID)
	os.Setenv("VAULT_SECRET_ID", secretID)

	rtfuri, err := url.ParseRequestURI(artifactoryAddr)
	require.Nil(t, err, "parse artifactory url")

	path := "secret/registry/" + rtfuri.Host
	server.vault.Run("vault", fmt.Sprintf("kv put %s apikey=%s", path, artifactoryApiKey), &err)
	require.Nil(t, err, "added secret to vault")

	err = server.WaitUntilReady()
	require.Nil(t, err, "server online")

	mcClient := &ormclient.Client{}

	// login as super user
	tokenAdmin, err := mcClient.DoLogin(uri, DefaultSuperuser, DefaultSuperpass)
	require.Nil(t, err, "login as superuser")

	// Create new users & orgs from MC
	for _, v := range testEntries {
		token := ""
		for user, userType := range v.Users {
			if userType == RoleDeveloperManager {
				_, token = testCreateUser(t, mcClient, uri, user)
				testCreateOrg(t, mcClient, uri, token, OrgTypeDeveloper, v.Org)
				break
			}
		}
		for user, userType := range v.Users {
			if userType != RoleDeveloperManager {
				worker, _ := testCreateUser(t, mcClient, uri, user)
				testAddUserRole(t, mcClient, uri, token, v.Org, userType, worker.Name, Success)
			}
		}
		verifyRtfStore(t, v, MCObj)
	}

	// Create rtf users & orgs which are not present in MC
	for _, v := range rtfDummyEntries {
		artifactoryCreateGroupObjects(ctx, v.Org)
		rtfGroups := []string{getArtifactoryName(v.Org)}
		for user, userType := range v.Users {
			userObj := ormapi.User{
				Name: user,
			}
			if userType == RoleDeveloperManager {
				artifactoryCreateUser(ctx, &userObj, nil)
				roleArg := ormapi.Role{
					Username: user,
					Org:      v.Org,
					Role:     userType,
				}
				artifactoryAddUserToGroup(ctx, &roleArg)
			} else {
				artifactoryCreateUser(ctx, &userObj, &rtfGroups)
			}
		}
		verifyRtfStore(t, v, DummyObj)
	}

	// Resync should trigger sync and delete above created dummy objects
	status, err = mcClient.ArtifactoryResync(uri, tokenAdmin)
	require.Nil(t, err, "artifactory resync")
	require.Equal(t, http.StatusOK, status, "artifactory resync status")

	// Delete MC created Objects
	for _, v := range testEntries {
		for user, userType := range v.Users {
			if userType == RoleDeveloperManager {
				continue
			}
			roleArg := ormapi.Role{
				Username: user,
				Org:      v.Org,
				Role:     userType,
			}
			// admin user can remove role
			status, err = mcClient.RemoveUserRole(uri, tokenAdmin, &roleArg)
			require.Nil(t, err, "remove user role")
			require.Equal(t, http.StatusOK, status)
		}

		// delete org
		org := ormapi.Organization{
			Name: v.Org,
		}
		status, err = mcClient.DeleteOrg(uri, tokenAdmin, &org)
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

	// By now, artifactory Sync thread should delete all extra objects as well
	require.Equal(t, 0, len(rtfUserStore), "deleted all users")
	require.Equal(t, 0, len(rtfGroupStore), "deleted all groups")
	require.Equal(t, 0, len(rtfRepoStore), "deleted all repos")
	require.Equal(t, 0, len(rtfPermStore), "deleted all permission targets")
}
