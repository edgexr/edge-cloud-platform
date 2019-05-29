package orm

import (
	"strings"

	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud/log"
)

func ArtifactoryNewSync() *AppStoreSync {
	aSync := AppStoreNewSync("artifactory")
	aSync.syncObjects = aSync.syncArtifactoryObjects
	return aSync
}

func (s *AppStoreSync) syncArtifactoryObjects() {
	orgsT, err := GetAllOrgs()
	if err != nil {
		s.syncErr(err)
		return
	}

	// Get Artifactory Objects: Groups, Repos, Permission Targets
	// no users sync required for Artifactory as LDAP users are transient
	// i.e. they exists only till they are logged in

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

		permName := getArtifactoryPermName(org)
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
		err = artifactoryDeleteGroup(group)
		if err != nil {
			s.syncErr(err)
		}
	}
	for repo, _ := range repos {
		log.DebugLog(log.DebugLevelApi,
			"Artifactory Sync delete extra repository",
			"name", repo)
		err = artifactoryDeleteRepo(strings.TrimPrefix(repo, getArtifactoryRepoPrefix()))
		if err != nil {
			s.syncErr(err)
		}
	}
	for perm, _ := range perms {
		log.DebugLog(log.DebugLevelApi,
			"Artifactory Sync delete extra permission target",
			"name", perm)
		err = artifactoryDeleteRepoPerms(strings.TrimPrefix(perm, getArtifactoryPermPrefix()))
		if err != nil {
			s.syncErr(err)
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
