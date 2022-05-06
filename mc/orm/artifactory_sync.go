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
	"net/http"
	"strings"

	"github.com/labstack/echo"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud-infra/mc/ormutil"
	"github.com/edgexr/edge-cloud/log"
)

func ArtifactoryNewSync() *AppStoreSync {
	aSync := AppStoreNewSync("artifactory")
	aSync.syncObjects = aSync.syncArtifactoryObjects
	return aSync
}

func (s *AppStoreSync) syncArtifactoryObjects(ctx context.Context) {
	// Refresh auth cache on sync
	rtfAuth = nil

	s.syncRtfUsers(ctx)
	allOrgs := s.syncGroupObjects(ctx)
	s.syncGroupUsers(ctx, allOrgs)
}

func getMCUsers(ctx context.Context) (map[string]*ormapi.User, error) {
	// Get MC users
	mcusers := []ormapi.User{}
	db := loggedDB(ctx)
	err := db.Find(&mcusers).Error
	if err != nil {
		return nil, err
	}
	mcusersT := make(map[string]*ormapi.User)
	for ii, _ := range mcusers {
		if mcusers[ii].Name == Superuser {
			continue
		}
		// Store username in lowercase format as Artifactory stores it in lowercase
		userName := strings.ToLower(mcusers[ii].Name)
		mcusersT[userName] = &mcusers[ii]
	}
	return mcusersT, nil
}

func getMCGroupMembers(allOrgs map[string]*ormapi.Organization) (map[string]map[string]*ormapi.Role, error) {
	// Get MC group members info
	groupings, err := enforcer.GetGroupingPolicy()
	if err != nil {
		return nil, err
	}
	mcGroupMembers := make(map[string]map[string]*ormapi.Role)
	for ii, _ := range groupings {
		role := parseRole(groupings[ii])
		if role == nil || role.Org == "" {
			continue
		}
		if org, ok := allOrgs[role.Org]; !ok || org.Type == OrgTypeOperator {
			continue
		}
		if role.Username == Superuser {
			continue
		}
		orgName := role.Org
		userName := strings.ToLower(role.Username)
		if _, ok := mcGroupMembers[userName]; !ok {
			mcGroupMembers[userName] = map[string]*ormapi.Role{}
		}
		mcGroupMembers[userName][orgName] = role
	}
	return mcGroupMembers, nil
}

func (s *AppStoreSync) syncRtfUsers(ctx context.Context) {
	// Get MC users
	mcusersT, err := getMCUsers(ctx)
	if err != nil {
		s.syncErr(ctx, err)
		return
	}

	// Get Artifactory users
	rtfUsers, err := artifactoryListUsers(ctx)
	if err != nil {
		s.syncErr(ctx, err)
		return
	}
	log.SpanLog(ctx, log.DebugLevelApi, "artifactory sync users", "artifactory users", len(rtfUsers), "mc users", len(mcusersT))

	// Create missing users
	for name, user := range mcusersT {
		if _, found := rtfUsers[name]; found {
			// in sync
			delete(rtfUsers, name)
		} else {
			// missing from Artifactory, so create
			log.SpanLog(ctx, log.DebugLevelApi,
				"Artifactory Sync create missing LDAP user",
				"user", name)
			artifactoryCreateLDAPUser(ctx, user)
		}
	}

	// Delete extra users
	for user, _ := range rtfUsers {
		log.SpanLog(ctx, log.DebugLevelApi,
			"Artifactory Sync delete extra user",
			"name", user)
		artifactoryDeleteLDAPUser(ctx, user)
	}
}

func (s *AppStoreSync) syncGroupObjects(ctx context.Context) map[string]*ormapi.Organization {
	orgsT, err := GetAllOrgs(ctx)
	if err != nil {
		s.syncErr(ctx, err)
		return nil
	}

	// Get Artifactory Objects:
	//     Groups, Repos, Permission Targets

	groups, err := artifactoryListGroups(ctx)
	if err != nil {
		s.syncErr(ctx, err)
		return orgsT
	}
	repos, err := artifactoryListRepos(ctx)
	if err != nil {
		s.syncErr(ctx, err)
		return orgsT
	}
	perms, err := artifactoryListPerms(ctx)
	if err != nil {
		s.syncErr(ctx, err)
		return orgsT
	}
	devOrgsCount := 0
	for _, org := range orgsT {
		if org.Type == OrgTypeOperator {
			continue
		}
		devOrgsCount++
	}
	log.SpanLog(ctx, log.DebugLevelApi, "artifactory sync group objs", "artifactory groups", len(groups), "mc dev groups", devOrgsCount)

	// Create missing objects
	for orgname, org := range orgsT {
		if org.Type == OrgTypeOperator {
			continue
		}
		groupName := getArtifactoryName(orgname)
		if _, ok := groups[groupName]; ok {
			delete(groups, groupName)
		} else {
			log.SpanLog(ctx, log.DebugLevelApi,
				"Artifactory Sync create missing group",
				"name", groupName)
			err = artifactoryCreateGroup(ctx, orgname, org.Type)
			if err != nil {
				s.syncErr(ctx, err)
			}
		}

		repoName := getArtifactoryRepoName(orgname)
		if _, ok := repos[repoName]; ok {
			delete(repos, repoName)
		} else {
			log.SpanLog(ctx, log.DebugLevelApi,
				"Artifactory Sync create missing repository",
				"name", repoName)
			err = artifactoryCreateRepo(ctx, orgname, org.Type)
			if err != nil {
				s.syncErr(ctx, err)
			}
		}

		permName := getArtifactoryName(orgname)
		if _, ok := perms[permName]; ok {
			delete(perms, permName)
		} else {
			log.SpanLog(ctx, log.DebugLevelApi,
				"Artifactory Sync create missing permission targets",
				"name", permName)
			err := artifactoryCreateRepoPerms(ctx, orgname, org.Type)
			if err != nil {
				s.syncErr(ctx, err)
			}
		}
	}

	// Delete extra objects
	for group, _ := range groups {
		log.SpanLog(ctx, log.DebugLevelApi,
			"Artifactory Sync delete extra group",
			"name", group)
		orgName := strings.TrimPrefix(group, ArtifactoryPrefix)
		err = artifactoryDeleteGroup(ctx, orgName, "")
		if err != nil {
			s.syncErr(ctx, err)
		}
	}
	for repo, _ := range repos {
		log.SpanLog(ctx, log.DebugLevelApi,
			"Artifactory Sync delete extra repository",
			"name", repo)
		orgName := strings.TrimPrefix(repo, ArtifactoryRepoPrefix)
		err = artifactoryDeleteRepo(ctx, orgName, "")
		if err != nil {
			s.syncErr(ctx, err)
		}
	}
	for perm, _ := range perms {
		log.SpanLog(ctx, log.DebugLevelApi,
			"Artifactory Sync delete extra permission target",
			"name", perm)
		orgName := strings.TrimPrefix(perm, ArtifactoryPrefix)
		err = artifactoryDeleteRepoPerms(ctx, orgName, "")
		if err != nil {
			s.syncErr(ctx, err)
		}
	}
	return orgsT
}

func (s *AppStoreSync) syncGroupUsers(ctx context.Context, allOrgs map[string]*ormapi.Organization) {
	// Get MC group members info
	mcGroupMembers, err := getMCGroupMembers(allOrgs)
	if err != nil {
		s.syncErr(ctx, err)
		return
	}

	for userName, mcUserRoles := range mcGroupMembers {
		// Get Artifactory roles
		rtfGroups, err := artifactoryListUserGroups(ctx, userName)
		if err != nil {
			s.syncErr(ctx, err)
			return
		}
		for mcGroup, mcRole := range mcUserRoles {
			rtfGroup := getArtifactoryName(mcGroup)
			if _, ok := rtfGroups[rtfGroup]; !ok {
				// Group not part of Artifactory user
				// Add user to the group
				log.SpanLog(ctx, log.DebugLevelApi,
					"Artifactory Sync add missing user to group",
					"user", userName, "group", rtfGroup,
					"role", mcRole)
				orgType := getOrgType(mcRole.Org, allOrgs)
				artifactoryAddUserToGroup(ctx, mcRole, orgType)
			}
		}
		for rtfGroup, _ := range rtfGroups {
			mcGroup := strings.TrimPrefix(rtfGroup, ArtifactoryPrefix)
			if _, ok := mcUserRoles[mcGroup]; !ok {
				// User is part of extra group
				// Remove user from the group
				role := ormapi.Role{}
				role.Username = userName
				role.Org = mcGroup
				orgType := getOrgType(role.Org, allOrgs)
				log.SpanLog(ctx, log.DebugLevelApi,
					"Artifactory Sync remove extra user from group",
					"user", userName, "group", rtfGroup,
					"role", role)
				artifactoryRemoveUserFromGroup(ctx, &role, orgType)
			}
		}
	}
}

func ArtifactoryResync(c echo.Context) error {
	err := AdminAccessCheck(c)
	if err != nil {
		return err
	}
	artifactorySync.NeedsSync()
	artifactorySync.wakeup()
	return err
}

func ArtifactorySummary(c echo.Context) error {
	err := AdminAccessCheck(c)
	if err != nil {
		return err
	}
	var summary AppStoreSummary

	// Get MC users
	ctx := ormutil.GetContext(c)
	mcUsers, err := getMCUsers(ctx)
	if err != nil {
		return err
	}
	summary.Users.MCUsers = len(mcUsers)

	// Artifactory users
	rtfUsers, err := artifactoryListUsers(ctx)
	if err != nil {
		return err
	}
	summary.Users.AppStoreUsers = len(rtfUsers)

	for name, _ := range mcUsers {
		if _, found := rtfUsers[name]; !found {
			summary.Users.MissingUsers = append(summary.Users.MissingUsers, name)
		}
	}

	for user, _ := range rtfUsers {
		if _, found := mcUsers[user]; !found {
			summary.Users.ExtraUsers = append(summary.Users.ExtraUsers, user)
		}
	}

	orgsT, err := GetAllOrgs(ctx)
	if err != nil {
		return err
	}
	summary.Groups.MCGroups = len(orgsT)

	// Artifactory Objects:
	//     Groups, Repos, Permission Targets

	groups, err := artifactoryListGroups(ctx)
	if err != nil {
		return err
	}
	summary.Groups.AppStoreGroups = len(groups)

	repos, err := artifactoryListRepos(ctx)
	if err != nil {
		return err
	}
	summary.Groups.AppStoreRepos = len(repos)

	perms, err := artifactoryListPerms(ctx)
	if err != nil {
		return err
	}
	summary.Groups.AppStorePerms = len(perms)

	for orgname, org := range orgsT {
		if org.Type == OrgTypeOperator {
			continue
		}
		groupName := getArtifactoryName(orgname)
		if _, ok := groups[groupName]; !ok {
			summary.Groups.MissingGroups = append(summary.Groups.MissingGroups, groupName)
		}
		repoName := getArtifactoryRepoName(orgname)
		if _, ok := repos[repoName]; !ok {
			summary.Groups.MissingRepos = append(summary.Groups.MissingRepos, repoName)
		}
		permName := getArtifactoryName(orgname)
		if _, ok := perms[permName]; !ok {
			summary.Groups.MissingPerms = append(summary.Groups.MissingPerms, permName)
		}
	}
	for group, _ := range groups {
		groupName := strings.TrimPrefix(group, ArtifactoryPrefix)
		if _, found := orgsT[groupName]; !found {
			summary.Groups.ExtraGroups = append(summary.Groups.ExtraGroups, groupName)
		}
	}

	// Get MC group members info
	mcGroupMembers, err := getMCGroupMembers(orgsT)
	if err != nil {
		return err
	}

	for userName, mcUserRoles := range mcGroupMembers {
		// Get Artifactory roles
		rtfGroups, err := artifactoryListUserGroups(ctx, userName)
		if err != nil {
			return err
		}
		for mcGroup, _ := range mcUserRoles {
			rtfGroup := getArtifactoryName(mcGroup)
			if _, ok := rtfGroups[rtfGroup]; !ok {
				// Group not part of Artifactory user
				summary.GroupMembers.MissingGroupMembers = append(summary.GroupMembers.MissingGroupMembers, GroupMember{
					Group: rtfGroup,
					User:  userName,
				})
			}
		}
		for rtfGroup, _ := range rtfGroups {
			mcGroup := strings.TrimPrefix(rtfGroup, ArtifactoryPrefix)
			if _, ok := mcUserRoles[mcGroup]; !ok {
				// User is part of extra group
				summary.GroupMembers.ExtraGroupMembers = append(summary.GroupMembers.ExtraGroupMembers, GroupMember{
					Group: rtfGroup,
					User:  userName,
				})
			}
		}
	}

	return c.JSON(http.StatusOK, summary)
}
