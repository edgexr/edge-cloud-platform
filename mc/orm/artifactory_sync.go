package orm

import (
	"context"
	"strings"

	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/log"
)

func ArtifactoryNewSync() *AppStoreSync {
	aSync := AppStoreNewSync("artifactory")
	aSync.syncObjects = aSync.syncArtifactoryObjects
	return aSync
}

func (s *AppStoreSync) syncArtifactoryObjects(ctx context.Context) {
	// Refresh auth cache on sync
	rtfAuth = nil

	allOrgs := s.syncGroupObjects(ctx)
	s.syncGroupUsers(ctx, allOrgs)
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
	// Get MC users
	mcusers := []ormapi.User{}
	db := loggedDB(ctx)
	err := db.Find(&mcusers).Error
	if err != nil {
		s.syncErr(ctx, err)
		return
	}
	mcusersT := make(map[string]*ormapi.User)
	for ii, _ := range mcusers {
		if mcusers[ii].Name == Superuser {
			continue
		}
		// Store username is lowercase format as Artifactory stores it in lowercase
		userName := getArtifactoryName(strings.ToLower(mcusers[ii].Name))
		mcusersT[userName] = &mcusers[ii]
	}

	// Get MC group members info
	groupings, err := enforcer.GetGroupingPolicy()
	if err != nil {
		s.syncErr(ctx, err)
		return
	}
	groupMembers := make(map[string]map[string]*ormapi.Role)
	for ii, _ := range groupings {
		role := parseRole(groupings[ii])
		if role == nil || role.Org == "" {
			continue
		}
		if org, ok := allOrgs[role.Org]; !ok || org.Type == OrgTypeOperator {
			continue
		}
		userName := getArtifactoryName(strings.ToLower(role.Username))
		orgName := getArtifactoryName(role.Org)
		if _, ok := groupMembers[userName]; !ok {
			groupMembers[userName] = map[string]*ormapi.Role{}
		}
		groupMembers[userName][orgName] = role
	}

	// Get Artifactory users
	rtfUsers, err := artifactoryListUsers(ctx)
	if err != nil {
		s.syncErr(ctx, err)
		return
	}

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
			if groups, ok := groupMembers[name]; ok {
				rtfGroups := []string{}
				for group, _ := range groups {
					rtfGroups = append(rtfGroups, group)
				}
				artifactoryCreateUser(ctx, user, &rtfGroups, allOrgs)
			} else {
				artifactoryCreateUser(ctx, user, nil, allOrgs)
			}
		}
	}

	// Delete extra users
	for user, _ := range rtfUsers {
		log.SpanLog(ctx, log.DebugLevelApi,
			"Artifactory Sync delete extra user",
			"name", user)
		userName := strings.TrimPrefix(user, ArtifactoryPrefix)
		artifactoryDeleteUser(ctx, userName)
	}

	// Add missing roles
	for name, _ := range mcusersT {
		// Get Artifactory roles
		userName := strings.TrimPrefix(name, ArtifactoryPrefix)
		rtfGroups, err := artifactoryListUserGroups(ctx, userName)
		if err != nil {
			s.syncErr(ctx, err)
			return
		}
		for mcgroup, mcrole := range groupMembers[name] {
			if _, ok := rtfGroups[mcgroup]; !ok {
				// Group not part of Artifactory user
				// Add user to the group
				log.SpanLog(ctx, log.DebugLevelApi,
					"Artifactory Sync add missing user to group",
					"user", name, "group", mcgroup,
					"role", mcrole)
				orgType := getOrgType(mcrole.Org, allOrgs)
				artifactoryAddUserToGroup(ctx, mcrole, orgType)
			}
		}
		for rtfgroup, _ := range rtfGroups {
			if _, ok := groupMembers[name][rtfgroup]; !ok {
				// User is part of extra group
				// Remove user from the group
				role := ormapi.Role{}
				role.Username = strings.TrimPrefix(name, ArtifactoryPrefix)
				role.Org = strings.TrimPrefix(rtfgroup, ArtifactoryPrefix)
				orgType := getOrgType(role.Org, allOrgs)
				log.SpanLog(ctx, log.DebugLevelApi,
					"Artifactory Sync remove extra user from group",
					"user", name, "group", rtfgroup,
					"role", role)
				artifactoryRemoveUserFromGroup(ctx, &role, orgType)
			}
		}
	}
}

func ArtifactoryResync(c echo.Context) error {
	err := SyncAccessCheck(c)
	if err != nil {
		return err
	}
	artifactorySync.NeedsSync()
	artifactorySync.wakeup()
	return err
}
