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
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/edgexr/edge-cloud/log"
	"github.com/stretchr/testify/require"
	gitlab "github.com/xanzy/go-gitlab"
)

type GitlabMock struct {
	addr          string
	users         map[int]*gitlab.User
	groups        map[int]*gitlab.Group
	projects      map[int]*gitlab.Project
	groupMembers  map[int][]gitlab.GroupMember // key is GroupID
	nextUserID    int
	nextGroupID   int
	nextProjectID int
}

func NewGitlabMock(addr string) *GitlabMock {
	gm := GitlabMock{}
	gm.addr = addr + "/api/v4"
	gm.initData()

	gm.registerCreateUser()
	gm.registerDeleteUser()
	gm.registerListUsers()

	gm.registerCreateGroup()
	gm.registerDeleteGroup()
	gm.registerListGroups()

	gm.registerAddGroupMember()
	gm.registerRemoveGroupMember()
	gm.registerListGroupMembers()

	gm.registerCreateProject()

	gm.registerSetCustomGroupAttribute()
	gm.registerGetCustomGroupAttribute()
	return &gm
}

func (s *GitlabMock) initData() {
	s.users = make(map[int]*gitlab.User)
	s.groups = make(map[int]*gitlab.Group)
	s.groupMembers = make(map[int][]gitlab.GroupMember)
	s.projects = make(map[int]*gitlab.Project)
	s.nextUserID = 1
	s.nextGroupID = 1
	s.nextProjectID = 1
}

func (s *GitlabMock) verify(t *testing.T, v entry, objType string) {
	// verify groups
	fmt.Printf("gitlab mock verify entry %s %v\n", objType, v)
	group := s.getGroup(v.Org)
	if v.OrgType == OrgTypeOperator && objType != OldOperObj {
		require.Nil(t, group, "group does not exist")
	} else {
		require.NotNil(t, group, "group exists")
		require.Equal(t, v.Org, group.Name)
		require.True(t, s.hasGroupAttribute(group, "createdby", GitlabMCTag), "has createdby group attribute")

		// verify project
		var myproj *gitlab.Project
		for _, proj := range s.projects {
			require.NotNil(t, proj.Namespace, "all projects must have groupID namespace")
			if proj.Namespace.ID == group.ID {
				myproj = proj
				break
			}
		}
		require.NotNil(t, myproj, "project exists")
		require.Equal(t, DefaultProjectName, myproj.Name, "project name")
	}

	// verify user and group perms
	for username, userType := range v.Users {
		fmt.Printf("  gitlab mock verify user %s %s\n", username, userType)
		user := s.getUser(username)
		require.NotNil(t, user, "find user")
		require.NotNil(t, user.Identities, "has user identities")
		require.Equal(t, 1, len(user.Identities), "has one user identity")
		require.Equal(t, LDAPProvider, user.Identities[0].Provider, "ldap provider")

		if v.OrgType == OrgTypeOperator && objType != OldOperObj {
			continue
		}
		var mygm *gitlab.GroupMember
		for _, gm := range s.groupMembers[group.ID] {
			if gm.ID == user.ID {
				mygm = &gm
				break
			}
		}
		require.NotNil(t, mygm, "user group membership")
		if userType == RoleDeveloperManager {
			require.Equal(t, gitlab.OwnerPermissions, mygm.AccessLevel, "org manager")
		} else if userType == RoleDeveloperContributor {
			require.Equal(t, gitlab.DeveloperPermissions, mygm.AccessLevel, "org contributor")
		} else {
			require.Equal(t, gitlab.ReporterPermissions, mygm.AccessLevel, "org viewer")
		}
	}
}

func (s *GitlabMock) verifyEmpty(t *testing.T) {
	// one user is mexadmin
	require.Equal(t, 1, len(s.users), "deleted all gitlab users")
	require.Equal(t, 0, len(s.groups), "deleted all gitlab groups")
	require.Equal(t, 0, len(s.projects), "deleted all gitlab projects")
	require.Equal(t, 0, len(s.groupMembers), "deleted all gitlab group members")
}

func (s *GitlabMock) registerCreateUser() {
	u := fmt.Sprintf("%s/users", s.addr)
	httpmock.RegisterResponder("POST", u,
		func(req *http.Request) (*http.Response, error) {
			opt := gitlab.CreateUserOptions{}
			err := json.NewDecoder(req.Body).Decode(&opt)
			if err != nil {
				return s.fail(req, err)
			}
			for _, u := range s.users {
				if u.Name == *opt.Name {
					return s.replyMessage(req, 409, "Username has already been taken")
				}
				if u.Email == *opt.Email {
					return s.replyMessage(req, 409, "Email has already been taken")
				}
			}
			user := gitlab.User{
				ID: s.nextUserID,
			}
			s.nextUserID++
			if opt.Username != nil {
				user.Username = *opt.Username
			}
			if opt.Name != nil {
				user.Name = *opt.Name
			}
			if opt.Email != nil {
				user.Email = *opt.Email
			}
			// gitlab does not set the provider in the user.Provider
			// field, it is set with the Identities.Provider field.
			// Leave user.Provider blank.
			if opt.Provider != nil && opt.ExternUID != nil {
				identity := gitlab.UserIdentity{
					Provider:  *opt.Provider,
					ExternUID: *opt.ExternUID,
				}
				ids := make([]*gitlab.UserIdentity, 0)
				ids = append(ids, &identity)
				user.Identities = ids
			}
			s.users[user.ID] = &user
			log.DebugLog(log.DebugLevelApi, "gitlab mock created user", "user", user)
			return httpmock.NewJsonResponse(201, user)
		},
	)
}

func (s *GitlabMock) registerDeleteUser() {
	u := fmt.Sprintf(`=~^%s/users/(\d+)\z`, s.addr)
	httpmock.RegisterResponder("DELETE", u,
		func(req *http.Request) (*http.Response, error) {
			userID := int(httpmock.MustGetSubmatchAsInt(req, 1))
			user, found := s.users[userID]
			delete(s.users, userID)
			log.DebugLog(log.DebugLevelApi, "gitlab mock deleted user", "user", user, "found", found)
			if found {
				return httpmock.NewJsonResponse(200, user)
			}
			return httpmock.NewStringResponse(200, ""), nil
		},
	)
}

func (s *GitlabMock) registerListUsers() {
	u := fmt.Sprintf("%s/users", s.addr)
	httpmock.RegisterResponder("GET", u,
		func(req *http.Request) (*http.Response, error) {
			queries := req.URL.Query()
			username, filter := queries["username"]
			provider, hasProvider := queries["provider"]

			retUsers := make([]*gitlab.User, 0)
			for _, user := range s.users {
				if filter && len(username) > 0 && user.Username != username[0] {
					continue
				}
				if hasProvider && len(provider) > 0 {
					providerFound := false
					for _, id := range user.Identities {
						if id.Provider == provider[0] {
							providerFound = true
							break
						}
					}
					if !providerFound {
						continue
					}
				}
				retUsers = append(retUsers, user)
			}
			return httpmock.NewJsonResponse(200, retUsers)
		},
	)
}

func (s *GitlabMock) registerCreateGroup() {
	u := fmt.Sprintf("%s/groups", s.addr)
	httpmock.RegisterResponder("POST", u,
		func(req *http.Request) (*http.Response, error) {
			opt := gitlab.CreateGroupOptions{}
			err := json.NewDecoder(req.Body).Decode(&opt)
			if err != nil {
				return s.fail(req, err)
			}
			group := gitlab.Group{
				ID: s.nextGroupID,
			}
			s.nextGroupID++
			if opt.Name != nil {
				group.Name = *opt.Name
			}
			if opt.Path != nil {
				group.Path = *opt.Path
			}
			group.Visibility = opt.Visibility
			s.groups[group.ID] = &group
			s.groupMembers[group.ID] = make([]gitlab.GroupMember, 0)

			log.DebugLog(log.DebugLevelApi, "gitlab mock created group", "group", group)
			return httpmock.NewJsonResponse(200, group)
		},
	)

}

func (s *GitlabMock) registerDeleteGroup() {
	u := fmt.Sprintf(`=~^%s/groups/(.+?)\z`, s.addr)
	httpmock.RegisterResponder("DELETE", u,
		func(req *http.Request) (*http.Response, error) {
			groupNameOrID := httpmock.MustGetSubmatch(req, 1)
			group := s.getGroup(groupNameOrID)
			if group == nil {
				return s.fail(req, fmt.Errorf("group %s not found", groupNameOrID))
			}
			groupID := group.ID
			delete(s.groups, groupID)
			delete(s.groupMembers, groupID)

			// remove any associated projects
			for _, proj := range s.projects {
				if proj.Namespace != nil && proj.Namespace.ID == groupID {
					delete(s.projects, proj.ID)
				}
			}
			log.DebugLog(log.DebugLevelApi, "gitlab mock deleted group", "group", group)
			return httpmock.NewStringResponse(200, ""), nil
		},
	)
}

func (s *GitlabMock) registerListGroups() {
	u := fmt.Sprintf("%s/groups", s.addr)
	httpmock.RegisterResponder("GET", u,
		func(req *http.Request) (*http.Response, error) {
			retGroups := make([]*gitlab.Group, 0)
			for _, group := range s.groups {
				retGroups = append(retGroups, group)
			}
			return httpmock.NewJsonResponse(200, retGroups)
		},
	)
}

func (s *GitlabMock) registerAddGroupMember() {
	u := fmt.Sprintf(`=~^%s/groups/(.+?)/members\z`, s.addr)
	httpmock.RegisterResponder("POST", u,
		func(req *http.Request) (*http.Response, error) {
			groupNameOrID := httpmock.MustGetSubmatch(req, 1)
			group := s.getGroup(groupNameOrID)
			if group == nil {
				return s.fail(req, fmt.Errorf("group %s not found", groupNameOrID))
			}
			groupID := group.ID

			opt := gitlab.AddGroupMemberOptions{}
			err := json.NewDecoder(req.Body).Decode(&opt)
			if err != nil {
				return s.fail(req, err)
			}
			if opt.UserID == nil {
				return s.fail(req, fmt.Errorf("userid not specified"))
			}
			user, ok := s.users[*opt.UserID]
			if !ok {
				return s.fail(req, fmt.Errorf("user %d not found", *opt.UserID))
			}
			members := s.groupMembers[groupID]
			for _, gm := range members {
				if gm.Username == user.Name {
					return s.fail(req, fmt.Errorf("user already member of group"))
				}
			}

			gm := gitlab.GroupMember{
				ID:       user.ID,
				Name:     user.Name,
				Username: user.Username,
			}
			if opt.AccessLevel != nil {
				gm.AccessLevel = *opt.AccessLevel
			}
			members = append(members, gm)
			s.groupMembers[groupID] = members

			log.DebugLog(log.DebugLevelApi, "gitlab mock add group member", "groupID", groupID, "member", gm)
			return httpmock.NewStringResponse(200, ""), nil
		},
	)
}

func (s *GitlabMock) registerRemoveGroupMember() {
	u := fmt.Sprintf(`=~^%s/groups/(.+?)/members/(\d+)\z`, s.addr)
	httpmock.RegisterResponder("DELETE", u,
		func(req *http.Request) (*http.Response, error) {
			groupNameOrID := httpmock.MustGetSubmatch(req, 1)
			group := s.getGroup(groupNameOrID)
			if group == nil {
				return s.fail(req, fmt.Errorf("group %s not found", groupNameOrID))
			}
			groupID := group.ID
			userID := int(httpmock.MustGetSubmatchAsInt(req, 2))
			members := s.groupMembers[groupID]
			for ii, gm := range members {
				if gm.ID == userID {
					members = append(members[:ii], members[ii+1:]...)
					break
				}
			}
			s.groupMembers[groupID] = members
			log.DebugLog(log.DebugLevelApi, "gitlab mock remove group member", "groupID", groupID, "userID", userID)
			return httpmock.NewStringResponse(200, "Success"), nil
		},
	)
}

func (s *GitlabMock) registerListGroupMembers() {
	u := fmt.Sprintf(`=~^%s/groups/(.+?)/members`, s.addr)
	httpmock.RegisterResponder("GET", u,
		func(req *http.Request) (*http.Response, error) {
			groupNameOrID := httpmock.MustGetSubmatch(req, 1)
			group := s.getGroup(groupNameOrID)
			if group == nil {
				return s.fail(req, fmt.Errorf("group %s not found", groupNameOrID))
			}
			groupID := group.ID
			members, _ := s.groupMembers[groupID]
			return httpmock.NewJsonResponse(200, members)
		},
	)
}

func (s *GitlabMock) registerCreateProject() {
	u := fmt.Sprintf("%s/projects", s.addr)
	httpmock.RegisterResponder("POST", u,
		func(req *http.Request) (*http.Response, error) {
			opt := gitlab.CreateProjectOptions{}
			err := json.NewDecoder(req.Body).Decode(&opt)
			if err != nil {
				return s.fail(req, err)
			}
			project := gitlab.Project{
				ID: s.nextProjectID,
			}
			s.nextProjectID++
			if opt.Name != nil {
				project.Name = *opt.Name
			}
			if opt.NamespaceID != nil {
				// it looks like gitlab's ID may be in a flat
				// namespace, as there's nothing in the
				// CreateProjectOptions that specifies the
				// namespace id is a group ID. So in GitlabMock
				// we just assume the namespace ID is always
				// a groupID (which is not true, projects can
				// be tied to users or groups).
				project.Namespace = &gitlab.ProjectNamespace{
					ID: *opt.NamespaceID,
				}
			}
			if opt.ApprovalsBeforeMerge != nil {
				project.ApprovalsBeforeMerge = *opt.ApprovalsBeforeMerge
			}
			s.projects[project.ID] = &project
			log.DebugLog(log.DebugLevelApi, "gitlab mock create project", "project", project)
			return httpmock.NewJsonResponse(200, project)
		},
	)

}

func (s *GitlabMock) registerSetCustomGroupAttribute() {
	u := fmt.Sprintf(`=~^%s/groups/(\d+)/custom_attributes/(.+)\z`, s.addr)
	httpmock.RegisterResponder("PUT", u,
		func(req *http.Request) (*http.Response, error) {
			groupID := int(httpmock.MustGetSubmatchAsInt(req, 1))
			key := httpmock.MustGetSubmatch(req, 2)
			group, ok := s.groups[groupID]
			if !ok {
				return s.fail(req, fmt.Errorf("group %d not found", groupID))
			}
			attr := gitlab.CustomAttribute{}
			err := json.NewDecoder(req.Body).Decode(&attr)
			if err != nil {
				return s.fail(req, err)
			}
			attr.Key = key
			if group.CustomAttributes == nil {
				group.CustomAttributes = make([]*gitlab.CustomAttribute, 0)
			}
			group.CustomAttributes = append(group.CustomAttributes, &attr)
			log.DebugLog(log.DebugLevelApi, "gitlab mock set custom group attribute", "groupID", groupID, "attr", attr)
			return httpmock.NewJsonResponse(200, attr)
		},
	)
}

func (s *GitlabMock) registerGetCustomGroupAttribute() {
	u := fmt.Sprintf(`=~^%s/groups/(\d+)/custom_attributes/(.+)\z`, s.addr)
	httpmock.RegisterResponder("GET", u,
		func(req *http.Request) (*http.Response, error) {
			groupID := int(httpmock.MustGetSubmatchAsInt(req, 1))
			key := httpmock.MustGetSubmatch(req, 2)
			group, ok := s.groups[groupID]
			if !ok {
				return s.fail(req, fmt.Errorf("group %d not found", groupID))
			}
			var attr *gitlab.CustomAttribute
			if group.CustomAttributes != nil {
				for _, at := range group.CustomAttributes {
					if at.Key == key {
						attr = at
						break
					}
				}
			}
			if attr == nil {
				return httpmock.NewStringResponse(404, "attribute not found"), nil
			}
			return httpmock.NewJsonResponse(200, attr)
		},
	)
}

func (s *GitlabMock) getUser(name string) *gitlab.User {
	for _, user := range s.users {
		if name == user.Username {
			return user
		}
	}
	return nil
}

func (s *GitlabMock) getGroup(nameOrID string) *gitlab.Group {
	id, err := strconv.Atoi(nameOrID)
	if err == nil {
		if group, ok := s.groups[id]; ok {
			return group
		}
	}
	for _, group := range s.groups {
		if nameOrID == group.Name {
			return group
		}
	}
	return nil
}

func (s *GitlabMock) hasGroupAttribute(group *gitlab.Group, key, val string) bool {
	if group.CustomAttributes == nil {
		return false
	}
	for _, attr := range group.CustomAttributes {
		if attr.Key == key && attr.Value == val {
			return true
		}
	}
	return false
}

func (s *GitlabMock) fail(req *http.Request, err error) (*http.Response, error) {
	// gitlab error handling assumes req is filled into resp,
	// which only happens in the go http client-side code which
	// is bypassed by the mock code. If it's not filled in,
	// converting error to string will crash.
	resp, err := httpmock.NewStringResponse(500, err.Error()), nil
	resp.Request = req
	return resp, err
}

func (s *GitlabMock) replyMessage(req *http.Request, code int, message string) (*http.Response, error) {
	// gitlab error handling assumes req is filled into resp,
	// which only happens in the go http client-side code which
	// is bypassed by the mock code. If it's not filled in,
	// converting error to string will crash.
	m := map[string]string{
		"message": message,
	}
	resp, _ := httpmock.NewJsonResponse(code, m)
	resp.Request = req
	return resp, nil
}
