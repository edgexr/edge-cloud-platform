package orm

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"

	v1 "github.com/atlassian/go-artifactory/v2/artifactory/v1"
	"github.com/jarcoal/httpmock"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormclient"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
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
	return artifactoryAddr + api + name
}

func registerCreateUser(userName string) {
	httpmock.RegisterResponder("PUT", getApiPath(userApi, userName),
		func(req *http.Request) (*http.Response, error) {
			rtfUser := v1.User{}
			err := json.NewDecoder(req.Body).Decode(&rtfUser)
			if err != nil {
				return httpmock.NewStringResponse(500, "Unable to decode JSON body"), nil
			}
			rtfUserStore[*rtfUser.Name] = &rtfUser

			return httpmock.NewStringResponse(200, "Success"), nil
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

func registerGetUsers(userName string) {
	httpmock.RegisterResponder("GET", getApiPath(userApi, userName),
		func(req *http.Request) (*http.Response, error) {
			if rtfUser, ok := rtfUserStore[userName]; ok {
				return httpmock.NewJsonResponse(200, rtfUser)
			} else {
				return httpmock.NewStringResponse(404, "Unable to find user"), nil
			}
		},
	)
}

func registerAddUserToGroup(userName, orgName string) {
	httpmock.RegisterResponder("POST", getApiPath(userApi, userName),
		func(req *http.Request) (*http.Response, error) {
			if rtfUser, ok := rtfUserStore[userName]; ok {
				var groups []string
				if rtfUser.Groups != nil {
					groups = *rtfUser.Groups
				}
				groups = append(groups, getArtifactoryName(orgName))
				rtfUser.Groups = &groups
				return httpmock.NewStringResponse(200, ""), nil
			} else {
				return httpmock.NewStringResponse(404, "Unable to find user"), nil
			}
		},
	)
}

func registerMockResponders(e entry) {
	// any requests that don't have a registered URL will be fetched normally
	httpmock.RegisterNoResponder(httpmock.InitialTransport.RoundTrip)

	// Create User
	registerCreateUser(e.UserMain)
	for _, userContrib := range e.UserContrib {
		registerCreateUser(userContrib)
	}

	// Create Group/Repo/Permission-Target
	registerCreateGroup(e.Org)
	registerCreateRepo(e.Org)
	registerCreatePerm(e.Org)

	// Get User
	registerGetUsers(e.UserMain)
	for _, userContrib := range e.UserContrib {
		registerGetUsers(userContrib)
	}

	// Add user to group
	registerAddUserToGroup(e.UserMain, e.Org)
	for _, userContrib := range e.UserContrib {
		registerAddUserToGroup(userContrib, e.Org)
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

func TestArtifactoryApi(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelApi)
	log.InitTracer()
	defer log.FinishTracer()

	rtfUserStore = make(map[string]*v1.User)
	rtfGroupStore = make(map[string]*v1.Group)
	rtfRepoStore = make(map[string]*v1.LocalRepository)
	rtfPermStore = make(map[string]*v1.PermissionTargets)

	httpmock.Activate()
	for _, v := range testEntries {
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
	}

	os.Setenv("artifactory_apikey", artifactoryApiKey)

	server, err := RunServer(&config)
	require.Nil(t, err, "run server")
	defer server.Stop()

	Jwks.Init("addr", "region", "mcorm", "roleID", "secretID")
	Jwks.Meta.CurrentVersion = 1
	Jwks.Keys[1] = &vault.JWK{
		Secret:  "12345",
		Refresh: "1s",
	}

	err = server.WaitUntilReady()
	require.Nil(t, err, "server online")

	mcClient := &ormclient.Client{}

	// login as super user
	_, err = mcClient.DoLogin(uri, DefaultSuperuser, DefaultSuperpass)
	require.Nil(t, err, "login as superuser")

	// create new users & orgs
	for _, v := range testEntries {
		_, token := testCreateUser(t, mcClient, uri, v.UserMain)
		org := testCreateOrg(t, mcClient, uri, token, "developer", v.Org)
		for _, userContrib := range v.UserContrib {
			worker, _ := testCreateUser(t, mcClient, uri, userContrib)
			testAddUserRole(t, mcClient, uri, token, org.Name, "DeveloperContributor", worker.Name, Success)
		}

		groupName := getArtifactoryName(v.Org)
		rtfGroup, ok := rtfGroupStore[groupName]
		require.True(t, ok, "Group exists")
		require.Equal(t, *rtfGroup.Name, groupName, "Group name matches")

		repoName := getArtifactoryRepoName(v.Org)
		rtfRepo, ok := rtfRepoStore[repoName]
		require.True(t, ok, "repo exists")
		require.Equal(t, *rtfRepo.Key, repoName, "Repo key matches")
		require.Equal(t, *rtfRepo.RClass, "local", "Repo must be local")

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
}
