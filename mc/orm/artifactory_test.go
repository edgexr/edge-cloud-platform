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

var (
	rtfUserStore  map[string]*v1.User
	rtfGroupStore map[string]*v1.Group
	rtfRepoStore  map[string]*v1.LocalRepository
	rtfPermStore  map[string]*v1.PermissionTargets

	testEntries []entry = []entry{
		entry{
			Org:      "bigorg1",
			UserMain: "orgman1",
			UserContrib: []string{
				"worker1",
			},
		},
		entry{
			Org:      "bigorg2",
			UserMain: "orgman2",
			UserContrib: []string{
				"worker2", "worker2.1",
			},
		},
	}

	// Entries only present in Artifactory but not in MC
	rtfDummyEntries []entry = []entry{
		entry{
			Org:      "dummyOrg1",
			UserMain: "dummyUser1",
			UserContrib: []string{
				"dummyWorker1",
			},
		},
	}
)

type entry struct {
	Org         string   // Organization/Developer
	UserMain    string   // Developer Maintainer
	UserContrib []string // Developer Contributors
}

const (
	artifactoryAddr   string = "https://dummy-artifactory.mobiledgex.net"
	artifactoryApiKey string = "dummyKey"

	userApi  string = "/api/security/users/"
	groupApi string = "/api/security/groups/"
	repoApi  string = "/api/repositories/"
	permApi  string = "/api/security/permissions/"
)

func getApiPath(api, name string) string {
	if name == "" {
		return artifactoryAddr + strings.TrimSuffix(api, "/")
	} else {
		return artifactoryAddr + api + name
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
			rtfUser.Realm = &realm
			rtfUserStore[*rtfUser.Name] = &rtfUser

			return httpmock.NewStringResponse(200, "Success"), nil
		},
	)
}

func registerDeleteUser(userName string) {
	httpmock.RegisterResponder("DELETE", getApiPath(userApi, userName),
		func(req *http.Request) (*http.Response, error) {
			if _, ok := rtfUserStore[userName]; ok {
				delete(rtfUserStore, userName)
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
			if rtfUser, ok := rtfUserStore[userName]; ok {
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
			if rtfUser, ok := rtfUserStore[userName]; ok {
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
	registerCreateUser(e.UserMain)
	registerDeleteUser(e.UserMain)
	for _, userContrib := range e.UserContrib {
		registerCreateUser(userContrib)
		registerDeleteUser(userContrib)
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
	registerGetUser(e.UserMain)
	for _, userContrib := range e.UserContrib {
		registerGetUser(userContrib)
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
	registerUpdateUser(e.UserMain, e.Org)
	for _, userContrib := range e.UserContrib {
		registerUpdateUser(userContrib, e.Org)
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

func verifyRtfStore(t *testing.T, v entry) {
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
	for grp, grpPerm := range *rtfPerm.Principals.Groups {
		require.Equal(t, grp, groupName, "Group is part of permission target")
		require.True(t, contains(grpPerm, "w"), "Write permission exists")
		require.True(t, contains(grpPerm, "d"), "Delete permission exists")
		require.True(t, contains(grpPerm, "r"), "Read permission exists")
		break
	}

	// Verify user exists and uses LDAP config
	rtfUser, ok := rtfUserStore[v.UserMain]
	require.True(t, ok, "user exists")
	require.Equal(t, *rtfUser.Name, v.UserMain, "user name matches")
	require.True(t, *rtfUser.InternalPasswordDisabled, "user must use LDAP")
	require.Equal(t, (*rtfUser.Groups)[0], getArtifactoryName(v.Org), "user must belong to org")

	for _, userContrib := range v.UserContrib {
		rtfUser, ok = rtfUserStore[userContrib]
		require.True(t, ok, "user exists")
		require.Equal(t, *rtfUser.Name, userContrib, "user name matches")
		require.True(t, *rtfUser.InternalPasswordDisabled, "user must use LDAP")
		require.True(t, contains(*rtfUser.Groups, getArtifactoryName(v.Org)), "user must belong to org")
	}
}

func TestArtifactoryApi(t *testing.T) {
	var status int

	log.SetDebugLevel(log.DebugLevelApi)
	log.InitTracer()
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
		_, token := testCreateUser(t, mcClient, uri, v.UserMain)
		org := testCreateOrg(t, mcClient, uri, token, OrgTypeDeveloper, v.Org)
		for _, userContrib := range v.UserContrib {
			worker, _ := testCreateUser(t, mcClient, uri, userContrib)
			testAddUserRole(t, mcClient, uri, token, org.Name, RoleDeveloperContributor, worker.Name, Success)
		}
		verifyRtfStore(t, v)
	}

	// Create rtf users & orgs which are not present in MC
	for _, v := range rtfDummyEntries {
		artifactoryCreateGroupObjects(ctx, v.Org)

		userMain := ormapi.User{
			Name: v.UserMain,
		}
		artifactoryCreateUser(ctx, &userMain, nil)

		roleArg := ormapi.Role{
			Username: v.UserMain,
			Org:      v.Org,
			Role:     RoleDeveloperManager,
		}
		artifactoryAddUserToGroup(ctx, &roleArg)

		rtfGroups := []string{getArtifactoryName(v.Org)}
		for _, userContrib := range v.UserContrib {
			userContrib := ormapi.User{
				Name: userContrib,
			}
			artifactoryCreateUser(ctx, &userContrib, &rtfGroups)
		}
		verifyRtfStore(t, v)
	}

	// Resync should trigger sync and delete above created dummy objects
	status, err = mcClient.ArtifactoryResync(uri, tokenAdmin)
	require.Nil(t, err, "artifactory resync")
	require.Equal(t, http.StatusOK, status, "artifactory resync status")

	// Delete MC created Objects
	for _, v := range testEntries {
		for _, userContrib := range v.UserContrib {
			roleArg := ormapi.Role{
				Username: userContrib,
				Org:      v.Org,
				Role:     RoleDeveloperContributor,
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

		// delete user maintainer
		userMain := ormapi.User{
			Name: v.UserMain,
		}
		status, err = mcClient.DeleteUser(uri, tokenAdmin, &userMain)
		require.Nil(t, err)
		require.Equal(t, http.StatusOK, status)

		// delete user contributors
		for _, userContrib := range v.UserContrib {
			userCont := ormapi.User{
				Name: userContrib,
			}
			status, err = mcClient.DeleteUser(uri, tokenAdmin, &userCont)
			require.Nil(t, err)
			require.Equal(t, http.StatusOK, status)
		}
	}

	// By now, artifactory Sync thread should delete all extra objects as well
	require.Equal(t, len(rtfUserStore), 0, "deleted all users")
	require.Equal(t, len(rtfGroupStore), 0, "deleted all groups")
	require.Equal(t, len(rtfRepoStore), 0, "deleted all repos")
	require.Equal(t, len(rtfPermStore), 0, "deleted all permission targets")
}
