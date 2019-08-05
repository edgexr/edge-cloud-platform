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
	s.syncGroupObjects(ctx)
	s.syncGroupUsers(ctx)
}

func (s *AppStoreSync) syncGroupObjects(ctx context.Context) {
	orgsT, err := GetAllOrgs(ctx)
	if err != nil {
		s.syncErr(ctx, err)
		return
	}

	// Get Artifactory Objects:
	//     Groups, Repos, Permission Targets

	groups, err := artifactoryListGroups(ctx)
	if err != nil {
		s.syncErr(ctx, err)
		return
	}
	repos, err := artifactoryListRepos(ctx)
	if err != nil {
		s.syncErr(ctx, err)
		return
	}
	perms, err := artifactoryListPerms(ctx)
	if err != nil {
		s.syncErr(ctx, err)
		return
	}

	// Create missing objects
	for org, _ := range orgsT {
		if _, ok := groups[org]; ok {
			delete(groups, org)
		} else {
			log.SpanLog(ctx, log.DebugLevelApi,
				"Artifactory Sync create missing group",
				"name", org)
			err = artifactoryCreateGroup(ctx, org)
			if err != nil {
				s.syncErr(ctx, err)
			}
		}

		repoName := getArtifactoryRepoName(org)
		if _, ok := repos[repoName]; ok {
			delete(repos, repoName)
		} else {
			log.SpanLog(ctx, log.DebugLevelApi,
				"Artifactory Sync create missing repository",
				"name", repoName)
			err = artifactoryCreateRepo(ctx, org)
			if err != nil {
				s.syncErr(ctx, err)
			}
		}

		permName := getArtifactoryName(org)
		if _, ok := perms[permName]; ok {
			delete(perms, permName)
		} else {
			log.SpanLog(ctx, log.DebugLevelApi,
				"Artifactory Sync create missing permission targets",
				"name", permName)
			err := artifactoryCreateRepoPerms(ctx, org)
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
		err = artifactoryDeleteGroup(ctx, strings.TrimPrefix(group, ArtifactoryPrefix))
		if err != nil {
			s.syncErr(ctx, err)
		}
	}
	for repo, _ := range repos {
		log.SpanLog(ctx, log.DebugLevelApi,
			"Artifactory Sync delete extra repository",
			"name", repo)
		err = artifactoryDeleteRepo(ctx, strings.TrimPrefix(repo, ArtifactoryRepoPrefix))
		if err != nil {
			s.syncErr(ctx, err)
		}
	}
	for perm, _ := range perms {
		log.SpanLog(ctx, log.DebugLevelApi,
			"Artifactory Sync delete extra permission target",
			"name", perm)
		err = artifactoryDeleteRepoPerms(ctx, strings.TrimPrefix(perm, ArtifactoryPrefix))
		if err != nil {
			s.syncErr(ctx, err)
		}
	}
}

func (s *AppStoreSync) syncGroupUsers(ctx context.Context) {
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
		mcusersT[mcusers[ii].Name] = &mcusers[ii]
	}

	// Get MC group members info
	groupings := enforcer.GetGroupingPolicy()
	groupMembers := make(map[string]map[string]*ormapi.Role)
	for ii, _ := range groupings {
		role := parseRole(groupings[ii])
		if role == nil || role.Org == "" {
			continue
		}
		if _, ok := groupMembers[role.Username]; !ok {
			groupMembers[role.Username] = map[string]*ormapi.Role{}
		}
		groupMembers[role.Username][getArtifactoryName(role.Org)] = role
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
				artifactoryCreateUser(ctx, user, &rtfGroups)
			} else {
				artifactoryCreateUser(ctx, user, nil)
			}
		}
	}

	// Delete extra users
	for user, _ := range rtfUsers {
		log.SpanLog(ctx, log.DebugLevelApi,
			"Artifactory Sync delete extra user",
			"name", user)
		artifactoryDeleteUser(ctx, user)
	}

	// Add missing roles
	for name, _ := range mcusersT {
		// Get Artifactory roles
		rtfGroups, err := artifactoryListUserGroups(ctx, name)
		if err != nil {
			s.syncErr(ctx, err)
			return
		}
		for mcgroup, mcrole := range groupMembers[name] {
			if _, ok := rtfGroups[mcgroup]; !ok {
				// Group not part of Artifactory user
				// Add user to the group
				artifactoryAddUserToGroup(ctx, mcrole)
			}
		}
		for rtfgroup, _ := range rtfGroups {
			if _, ok := groupMembers[name][rtfgroup]; !ok {
				// User is part of extra group
				// Remove user from the group
				role := ormapi.Role{}
				role.Username = name
				role.Org = rtfgroup
				artifactoryRemoveUserFromGroup(ctx, &role)
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
