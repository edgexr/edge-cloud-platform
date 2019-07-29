package orm

import (
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

func (s *AppStoreSync) syncArtifactoryObjects() {
	s.syncGroupObjects()
	s.syncGroupUsers()
}

func (s *AppStoreSync) syncGroupObjects() {
	orgsT, err := GetAllOrgs()
	if err != nil {
		s.syncErr(err)
		return
	}

	// Get Artifactory Objects:
	//     Groups, Repos, Permission Targets

	groups, err := artifactoryListGroups()
	if err != nil {
		s.syncErr(err)
		return
	}
	repos, err := artifactoryListRepos()
	if err != nil {
		s.syncErr(err)
		return
	}
	perms, err := artifactoryListPerms()
	if err != nil {
		s.syncErr(err)
		return
	}

	// Create missing objects
	for org, _ := range orgsT {
		if _, ok := groups[org]; ok {
			delete(groups, org)
		} else {
			log.DebugLog(log.DebugLevelApi,
				"Artifactory Sync create missing group",
				"name", org)
			err = artifactoryCreateGroup(org)
			if err != nil {
				s.syncErr(err)
			}
		}

		repoName := getArtifactoryRepoName(org)
		if _, ok := repos[repoName]; ok {
			delete(repos, repoName)
		} else {
			log.DebugLog(log.DebugLevelApi,
				"Artifactory Sync create missing repository",
				"name", repoName)
			err = artifactoryCreateRepo(org)
			if err != nil {
				s.syncErr(err)
			}
		}

		permName := getArtifactoryName(org)
		if _, ok := perms[permName]; ok {
			delete(perms, permName)
		} else {
			log.DebugLog(log.DebugLevelApi,
				"Artifactory Sync create missing permission targets",
				"name", permName)
			err := artifactoryCreateRepoPerms(org)
			if err != nil {
				s.syncErr(err)
			}
		}
	}

	// Delete extra objects
	for group, _ := range groups {
		log.DebugLog(log.DebugLevelApi,
			"Artifactory Sync delete extra group",
			"name", group)
		err = artifactoryDeleteGroup(strings.TrimPrefix(group, ArtifactoryPrefix))
		if err != nil {
			s.syncErr(err)
		}
	}
	for repo, _ := range repos {
		log.DebugLog(log.DebugLevelApi,
			"Artifactory Sync delete extra repository",
			"name", repo)
		err = artifactoryDeleteRepo(strings.TrimPrefix(repo, ArtifactoryRepoPrefix))
		if err != nil {
			s.syncErr(err)
		}
	}
	for perm, _ := range perms {
		log.DebugLog(log.DebugLevelApi,
			"Artifactory Sync delete extra permission target",
			"name", perm)
		err = artifactoryDeleteRepoPerms(strings.TrimPrefix(perm, ArtifactoryPrefix))
		if err != nil {
			s.syncErr(err)
		}
	}
}

func (s *AppStoreSync) syncGroupUsers() {
	// Get MC users
	mcusers := []ormapi.User{}
	err := db.Find(&mcusers).Error
	if err != nil {
		s.syncErr(err)
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
		groupMembers[role.Username][role.Org] = role
	}

	// Get Artifactory users
	rtfUsers, err := artifactoryListUsers()
	if err != nil {
		s.syncErr(err)
		return
	}

	// Create missing users
	for name, user := range mcusersT {
		if _, found := rtfUsers[name]; found {
			// in sync
			delete(rtfUsers, name)
		} else {
			// missing from Artifactory, so create
			log.DebugLog(log.DebugLevelApi,
				"Artifactory Sync create missing LDAP user",
				"user", name)
			if groups, ok := groupMembers[name]; ok {
				rtfGroups := []string{}
				for group, _ := range groups {
					rtfGroups = append(rtfGroups, group)
				}
				artifactoryCreateUser(user, &rtfGroups)
			} else {
				artifactoryCreateUser(user, nil)
			}
		}
	}

	// Delete extra users
	for user, _ := range rtfUsers {
		log.DebugLog(log.DebugLevelApi,
			"Artifactory Sync delete extra user",
			"name", user)
		artifactoryDeleteUser(user)
	}

	// Add missing roles
	for name, _ := range mcusersT {
		// Get Artifactory roles
		rtfGroups, err := artifactoryListUserGroups(name)
		if err != nil {
			s.syncErr(err)
			return
		}
		for mcgroup, mcrole := range groupMembers[name] {
			if _, ok := rtfGroups[mcgroup]; !ok {
				// Group not part of Artifactory user
				// Add user to the group
				artifactoryAddUserToGroup(mcrole)
			}
		}
		for rtfgroup, _ := range rtfGroups {
			if _, ok := groupMembers[name][rtfgroup]; !ok {
				// User is part of extra group
				// Remove user from the group
				role := ormapi.Role{}
				role.Username = name
				role.Org = rtfgroup
				artifactoryRemoveUserFromGroup(&role)
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
