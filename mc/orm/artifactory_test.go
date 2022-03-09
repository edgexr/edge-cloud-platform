package orm

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	v1 "github.com/atlassian/go-artifactory/v2/artifactory/v1"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/require"
)

type ArtifactoryMock struct {
	addr       string
	userStore  map[string]*v1.User
	groupStore map[string]*v1.Group
	repoStore  map[string]*v1.LocalRepository
	permStore  map[string]*v1.PermissionTargets
}

const (
	userApi  string = "api/security/users"
	groupApi string = "api/security/groups"
	repoApi  string = "api/repositories"
	permApi  string = "api/security/permissions"
)

func NewArtifactoryMock(addr string) *ArtifactoryMock {
	rtf := ArtifactoryMock{}
	rtf.addr = addr
	rtf.initData()
	rtf.registerMockResponders()
	return &rtf
}

func (s *ArtifactoryMock) initData() {
	s.userStore = make(map[string]*v1.User)
	s.groupStore = make(map[string]*v1.Group)
	s.repoStore = make(map[string]*v1.LocalRepository)
	s.permStore = make(map[string]*v1.PermissionTargets)
}

func (s *ArtifactoryMock) getApiPath(api string) string {
	return fmt.Sprintf("%s/%s", s.addr, api)
}

func (s *ArtifactoryMock) getApiPathArg(api string) string {
	return fmt.Sprintf(`=~^%s/%s/(.+?)\z`, s.addr, api)
}

func (s *ArtifactoryMock) registerCreateUser() {
	httpmock.RegisterResponder("PUT", s.getApiPathArg(userApi),
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
			s.userStore[username] = &rtfUser

			return httpmock.NewStringResponse(200, "Success"), nil
		},
	)
}

func (s *ArtifactoryMock) registerDeleteUser() {
	httpmock.RegisterResponder("DELETE", s.getApiPathArg(userApi),
		func(req *http.Request) (*http.Response, error) {
			username := strings.ToLower(httpmock.MustGetSubmatch(req, 1))
			if _, ok := s.userStore[username]; ok {
				delete(s.userStore, username)
				return httpmock.NewStringResponse(200, "Success"), nil
			}
			return httpmock.NewStringResponse(404, "Unable to find user"), nil
		},
	)
}

func (s *ArtifactoryMock) registerCreateGroup() {
	httpmock.RegisterResponder("PUT", s.getApiPathArg(groupApi),
		func(req *http.Request) (*http.Response, error) {
			rtfGroup := v1.Group{}
			err := json.NewDecoder(req.Body).Decode(&rtfGroup)
			if err != nil {
				return httpmock.NewStringResponse(500, "Unable to decode JSON body"), nil
			}
			s.groupStore[*rtfGroup.Name] = &rtfGroup

			return httpmock.NewStringResponse(200, "Success"), nil
		},
	)
}

func (s *ArtifactoryMock) registerDeleteGroup() {
	httpmock.RegisterResponder("DELETE", s.getApiPathArg(groupApi),
		func(req *http.Request) (*http.Response, error) {
			groupName := httpmock.MustGetSubmatch(req, 1)
			if _, ok := s.groupStore[groupName]; ok {
				delete(s.groupStore, groupName)
				return httpmock.NewStringResponse(200, "Success"), nil
			}
			return httpmock.NewStringResponse(404, "Unable to find group"), nil
		},
	)
}

func (s *ArtifactoryMock) registerCreateRepo() {
	httpmock.RegisterResponder("PUT", s.getApiPathArg(repoApi),
		func(req *http.Request) (*http.Response, error) {
			rtfRepo := v1.LocalRepository{}
			err := json.NewDecoder(req.Body).Decode(&rtfRepo)
			if err != nil {
				return httpmock.NewStringResponse(500, "Unable to decode JSON body"), nil
			}
			s.repoStore[*rtfRepo.Key] = &rtfRepo

			return httpmock.NewStringResponse(200, "Success"), nil
		},
	)
}

func (s *ArtifactoryMock) registerDeleteRepo() {
	httpmock.RegisterResponder("DELETE", s.getApiPathArg(repoApi),
		func(req *http.Request) (*http.Response, error) {
			repoName := httpmock.MustGetSubmatch(req, 1)
			if _, ok := s.repoStore[repoName]; ok {
				delete(s.repoStore, repoName)
				return httpmock.NewStringResponse(200, "Success"), nil
			}
			return httpmock.NewStringResponse(404, "Unable to find repo"), nil
		},
	)
}

func (s *ArtifactoryMock) registerCreatePerm() {
	httpmock.RegisterResponder("PUT", s.getApiPathArg(permApi),
		func(req *http.Request) (*http.Response, error) {
			rtfPerm := v1.PermissionTargets{}
			err := json.NewDecoder(req.Body).Decode(&rtfPerm)
			if err != nil {
				return httpmock.NewStringResponse(500, "Unable to decode JSON body"), nil
			}
			s.permStore[*rtfPerm.Name] = &rtfPerm

			return httpmock.NewStringResponse(200, "Success"), nil
		},
	)
}

func (s *ArtifactoryMock) registerDeletePerm() {
	httpmock.RegisterResponder("DELETE", s.getApiPathArg(permApi),
		func(req *http.Request) (*http.Response, error) {
			permName := httpmock.MustGetSubmatch(req, 1)
			if _, ok := s.permStore[permName]; ok {
				delete(s.permStore, permName)
				return httpmock.NewStringResponse(200, "Success"), nil
			}
			return httpmock.NewStringResponse(404, "Unable to find permission target"), nil
		},
	)
}

func (s *ArtifactoryMock) registerGetUser() {
	httpmock.RegisterResponder("GET", s.getApiPathArg(userApi),
		func(req *http.Request) (*http.Response, error) {
			userName := httpmock.MustGetSubmatch(req, 1)
			if rtfUser, ok := s.userStore[strings.ToLower(userName)]; ok {
				return httpmock.NewJsonResponse(200, rtfUser)
			}
			return httpmock.NewStringResponse(404, "Unable to find user"), nil
		},
	)
}

func (s *ArtifactoryMock) registerGetUsers() {
	httpmock.RegisterResponder("GET", s.getApiPath(userApi),
		func(req *http.Request) (*http.Response, error) {
			users := []v1.UserDetails{}
			for _, v := range s.userStore {
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

func (s *ArtifactoryMock) registerGetGroups() {
	httpmock.RegisterResponder("GET", s.getApiPath(groupApi),
		func(req *http.Request) (*http.Response, error) {
			groups := []v1.GroupDetails{}
			for _, v := range s.groupStore {
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

func (s *ArtifactoryMock) registerGetRepos() {
	httpmock.RegisterResponder("GET", s.getApiPath(repoApi),
		func(req *http.Request) (*http.Response, error) {
			repos := []v1.RepositoryDetails{}
			repoType := "local"
			for _, v := range s.repoStore {
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

func (s *ArtifactoryMock) registerGetPerms() {
	httpmock.RegisterResponder("GET", s.getApiPath(permApi),
		func(req *http.Request) (*http.Response, error) {
			perms := []v1.PermissionTargetsDetails{}
			for _, v := range s.permStore {
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

func (s *ArtifactoryMock) registerUpdateUser() {
	httpmock.RegisterResponder("POST", s.getApiPathArg(userApi),
		func(req *http.Request) (*http.Response, error) {
			userName := httpmock.MustGetSubmatch(req, 1)
			updateUser := v1.User{}
			err := json.NewDecoder(req.Body).Decode(&updateUser)
			if err != nil {
				return httpmock.NewStringResponse(500, "Unable to decode JSON body"), nil
			}
			if rtfUser, ok := s.userStore[strings.ToLower(userName)]; ok {
				rtfUser.Groups = updateUser.Groups
				return httpmock.NewStringResponse(200, ""), nil
			}
			return httpmock.NewStringResponse(404, "Unable to find user"), nil
		},
	)
}

func (s *ArtifactoryMock) registerMockResponders() {
	// Create User
	s.registerCreateUser()
	s.registerDeleteUser()

	// Create Group/Repo/Permission-Target
	s.registerCreateGroup()
	s.registerCreateRepo()
	s.registerCreatePerm()

	// Delete Group/Repo/Permission-Target
	s.registerDeleteGroup()
	s.registerDeleteRepo()
	s.registerDeletePerm()

	// Get User
	s.registerGetUser()

	// List all users
	s.registerGetUsers()

	// List all groups
	s.registerGetGroups()

	// List all repos
	s.registerGetRepos()

	// List all perms
	s.registerGetPerms()

	// Add user to group
	s.registerUpdateUser()
}

func contains(objects []string, e string) bool {
	for _, obj := range objects {
		if obj == e {
			return true
		}
	}
	return false
}

func (s *ArtifactoryMock) verify(t *testing.T, v entry, objType string) {
	// Verify group exists and group name starts with required prefix
	groupName := getArtifactoryName(v.Org)
	rtfGroup, ok := s.groupStore[groupName]
	if v.OrgType == OrgTypeOperator && objType != OldOperObj {
		require.False(t, ok, "Group does not exist")
	} else {
		require.True(t, ok, "Group exists")
		require.Equal(t, *rtfGroup.Name, groupName, "Group name matches")
	}

	// Verify repo exists and repo name starts with required prefix
	repoName := getArtifactoryRepoName(v.Org)
	rtfRepo, ok := s.repoStore[repoName]
	if v.OrgType == OrgTypeOperator && objType != OldOperObj {
		require.False(t, ok, "repo does not exist")
	} else {
		require.True(t, ok, "repo exists")
		require.Equal(t, *rtfRepo.Key, repoName, "Repo key matches")
		require.Equal(t, *rtfRepo.RClass, "local", "Repo must be local")
	}

	// Verify perm exists and  perm name starts with required prefix
	permName := getArtifactoryName(v.Org)
	rtfPerm, ok := s.permStore[permName]
	if v.OrgType == OrgTypeOperator && objType != OldOperObj {
		require.False(t, ok, "Permission target does not exist")
	} else {
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
		// Since rtfPerms uses MC grouping info for adding users, extraObj can't have users in rtfPerms
		if objType != ExtraObj {
			fmt.Println(permName, s.groupStore, s.permStore)
			require.Equal(t, len(v.Users), len(*rtfPerm.Principals.Users), "permission target has right number of users")
		}
		require.Equal(t, 1, len(*rtfPerm.Principals.Groups), "permission target has right number of groups")
		require.Equal(t, 1, len(*rtfPerm.Repositories), "permission target has right number of repos")
	}
	// Verify user exists and uses LDAP config
	for user, userType := range v.Users {
		userName := strings.ToLower(user)
		rtfUser, ok := s.userStore[userName]
		require.True(t, ok, "user exists")
		require.Equal(t, *rtfUser.Name, userName, "user name matches")
		require.True(t, *rtfUser.InternalPasswordDisabled, "user must use LDAP")
		if v.OrgType == OrgTypeOperator && objType != OldOperObj {
			if rtfUser.Groups != nil {
				require.False(t, contains(*rtfUser.Groups, getArtifactoryName(v.Org)), "user does not belong to org")
			}
		} else {
			require.NotNil(t, rtfUser.Groups, "user group exists")
			require.True(t, contains(*rtfUser.Groups, getArtifactoryName(v.Org)), "user must belong to org")
		}
		if objType == MCObj && v.OrgType != OrgTypeOperator {
			usrPerm, ok := (*rtfPerm.Principals.Users)[userName]
			require.True(t, ok, fmt.Sprintf("User permission for %s exists", userName))
			switch userType {
			case RoleDeveloperManager:
				checkRtfPerms(t, usrPerm, "r", "w", "d", "m")
			case RoleDeveloperContributor:
				checkRtfPerms(t, usrPerm, "r", "w", "d")
			case RoleDeveloperViewer:
				checkRtfPerms(t, usrPerm, "r")
			}
		}
	}
}

func (s *ArtifactoryMock) verifyCount(t *testing.T, entries []entry, objType string) {
	userCount := 0
	groupObjCount := 0
	for _, v := range entries {
		userCount += len(v.Users)
		if v.OrgType == OrgTypeDeveloper {
			groupObjCount += 1
		}
	}
	fmt.Println(s.userStore)
	require.Equal(t, groupObjCount, len(s.groupStore), "group count is consistent")
	require.Equal(t, groupObjCount, len(s.repoStore), "repo count is consistent")
	require.Equal(t, groupObjCount, len(s.permStore), "repo perm count is consistent")
	require.Equal(t, userCount, len(s.userStore), "user count is consistent")
}

func (s *ArtifactoryMock) verifyEmpty(t *testing.T) {
	require.Equal(t, 0, len(s.userStore), "deleted all artifactory users")
	require.Equal(t, 0, len(s.groupStore), "deleted all artifactory groups")
	require.Equal(t, 0, len(s.repoStore), "deleted all artifactory repos")
	require.Equal(t, 0, len(s.permStore), "deleted all artifactory permission targets")
}

func checkRtfPerms(t *testing.T, perms []string, expected ...string) {
	for _, p := range expected {
		require.True(t, contains(perms, p), "User should have perm %s", p)
	}
	require.Equal(t, len(expected), len(perms), "User should not have extra perms")
}
