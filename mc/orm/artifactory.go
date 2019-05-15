package orm

import (
	"context"
	"strings"

	"github.com/atlassian/go-artifactory/v2/artifactory"
	"github.com/atlassian/go-artifactory/v2/artifactory/transport"
	"github.com/atlassian/go-artifactory/v2/artifactory/v1"
	rtf "github.com/mobiledgex/edge-cloud-infra/artifactory"
	"github.com/mobiledgex/edge-cloud/log"
)

const (
	ArtifactoryRepoPrefix string = "mc-repo-"
	ArtifactoryPermPrefix string = "mc-perm-"
)

func artifactoryClient() (*artifactory.Artifactory, error) {
	artifactoryApiKey, err := rtf.GetArtifactoryApiKey()
	if err != nil {
		return nil, err
	}
	tp := transport.ApiKeyAuth{
		ApiKey: artifactoryApiKey,
	}
	client, err := artifactory.NewClient(serverConfig.ArtifactoryAddr, tp.Client())
	if err != nil {
		log.InfoLog("Note: Failed to connect to artifactory", "addr",
			serverConfig.ArtifactoryAddr, "err", err)
		return nil, err
	}
	return client, nil
}

func getArtifactoryRepoName(orgName string) string {
	return ArtifactoryRepoPrefix + orgName
}

func getArtifactoryPermName(orgName string) string {
	return ArtifactoryPermPrefix + orgName
}

func getArtifactoryRealmAttr(orgName string) string {
	return "ldapGroupName=" + orgName + ";groupsStrategy=STATIC;groupDn=cn=" + orgName + ",ou=orgs"
}

func artifactoryListGroups() (map[string]bool, error) {
	client, err := artifactoryClient()
	if err != nil {
		return nil, err
	}
	groups, _, err := client.V1.Security.ListGroups(context.Background())
	if err != nil {
		return nil, err
	}
	tmp := make(map[string]bool)
	for _, group := range *groups {
		groupName := *group.Name
		groupInfo, _, err := client.V1.Security.GetGroup(context.Background(), groupName)
		if err == nil && *groupInfo.Realm == "ldap" {
			if *groupInfo.RealmAttributes == getArtifactoryRealmAttr(groupName) {
				tmp[groupName] = true
			}
		}
	}
	return tmp, nil
}

func artifactoryCreateGroup(groupName string) error {
	client, err := artifactoryClient()
	if err != nil {
		return err
	}
	group := v1.Group{
		Name:            artifactory.String(groupName),
		Description:     artifactory.String("Group maintained by master-controller"),
		Realm:           artifactory.String("ldap"),
		RealmAttributes: artifactory.String(getArtifactoryRealmAttr(groupName)),
	}
	_, err = client.V1.Security.CreateOrReplaceGroup(context.Background(), groupName, &group)
	if err != nil {
		log.DebugLog(log.DebugLevelApi, "artifactory create group",
			"group", groupName, "err", err)
	}
	return err
}

func artifactoryDeleteGroup(groupName string) error {
	client, err := artifactoryClient()
	if err != nil {
		return err
	}
	_, _, err = client.V1.Security.DeleteGroup(context.Background(), groupName)
	if err != nil {
		if strings.Contains(err.Error(), "Status:404") {
			log.DebugLog(log.DebugLevelApi, "artifactory delete group",
				"group", groupName, "err", "group does not exists")
			return nil
		}
		log.DebugLog(log.DebugLevelApi, "artifactory delete group",
			"group", groupName, "err", err)
	}
	return err
}

func artifactoryListRepos() (map[string]bool, error) {
	client, err := artifactoryClient()
	if err != nil {
		return nil, err
	}
	repos, _, err := client.V1.Repositories.ListRepositories(context.Background(), nil)
	if err != nil {
		return nil, err
	}
	tmp := make(map[string]bool)
	for _, repo := range *repos {
		repoName := *repo.Key
		if strings.HasPrefix(repoName, ArtifactoryRepoPrefix) {
			tmp[repoName] = true
		}
	}
	return tmp, nil
}

func artifactoryCreateRepo(orgName string) error {
	client, err := artifactoryClient()
	if err != nil {
		return err
	}
	repoName := getArtifactoryRepoName(orgName)
	repo := v1.LocalRepository{
		Key:             artifactory.String(repoName),
		RClass:          artifactory.String("local"),
		PackageType:     artifactory.String("generic"),
		HandleSnapshots: artifactory.Bool(false),
	}

	_, err = client.V1.Repositories.CreateLocal(context.Background(), &repo)
	if err != nil {
		if strings.Contains(err.Error(), "key already exists") {
			log.DebugLog(log.DebugLevelApi, "artifactory create repository",
				"repository", repoName, "err", "already exists")
			return nil
		}
		log.DebugLog(log.DebugLevelApi, "artifactory create repository",
			"repository", repoName, "err", err)
	}
	return err
}

func artifactoryDeleteRepo(orgName string) error {
	client, err := artifactoryClient()
	if err != nil {
		return err
	}
	repoName := getArtifactoryRepoName(orgName)
	_, err = client.V1.Repositories.DeleteLocal(context.Background(), repoName)
	if err != nil {
		if strings.Contains(err.Error(), "Status:404") {
			log.DebugLog(log.DebugLevelApi, "artifactory delete repository",
				"repository", repoName, "err", "repository does not exists")
			return nil
		}
		log.DebugLog(log.DebugLevelApi, "artifactory delete repository",
			"repository", repoName, "err", err)
	}
	return err
}

func artifactoryListPerms() (map[string]bool, error) {
	client, err := artifactoryClient()
	if err != nil {
		return nil, err
	}
	perms, _, err := client.V1.Security.ListPermissionTargets(context.Background())
	if err != nil {
		return nil, err
	}
	tmp := make(map[string]bool)
	for _, perm := range perms {
		permName := *perm.Name
		if strings.HasPrefix(permName, ArtifactoryPermPrefix) {
			tmp[permName] = true
		}
	}
	return tmp, nil
}

func artifactoryCreateRepoPerms(orgName string) error {
	client, err := artifactoryClient()
	if err != nil {
		return err
	}
	groupName := orgName
	repoName := getArtifactoryRepoName(orgName)
	permTargetName := getArtifactoryPermName(orgName)
	// create permission target
	permTargets := v1.PermissionTargets{
		Name:         artifactory.String(permTargetName),
		Repositories: &[]string{repoName},
		Principals: &v1.Principals{
			Groups: &map[string][]string{
				groupName: []string{"m", "w", "n", "d", "r"},
			},
		},
	}
	_, err = client.V1.Security.CreateOrReplacePermissionTargets(context.Background(), permTargetName, &permTargets)
	if err != nil {
		log.DebugLog(log.DebugLevelApi, "artifactory create repo perms",
			"permission target", permTargetName, "repository", repoName, "group", groupName, "err", err)
	}
	return err
}

func artifactoryDeleteRepoPerms(orgName string) error {
	client, err := artifactoryClient()
	if err != nil {
		return err
	}
	permTargetName := getArtifactoryPermName(orgName)
	_, _, err = client.V1.Security.DeletePermissionTargets(context.Background(), permTargetName)
	if err != nil {
		if strings.Contains(err.Error(), "Status:404") {
			log.DebugLog(log.DebugLevelApi, "artifactory delete repo perms",
				"repo perms", permTargetName, "err", "repo perms does not exists")
			return nil
		}
		log.DebugLog(log.DebugLevelApi, "artifactory delete repo perms",
			"permission target", permTargetName, "err", err)
	}
	return err
}

func artifactoryCreateGroupObjects(orgName string) {
	err := artifactoryCreateGroup(orgName)
	if err != nil {
		artifactorySync.NeedsSync()
		return
	}
	err = artifactoryCreateRepo(orgName)
	if err != nil {
		artifactorySync.NeedsSync()
		return
	}
	err = artifactoryCreateRepoPerms(orgName)
	if err != nil {
		artifactorySync.NeedsSync()
		return
	}
}

func artifactoryDeleteGroupObjects(orgName string) {
	err := artifactoryDeleteGroup(orgName)
	if err != nil {
		artifactorySync.NeedsSync()
		return
	}
	err = artifactoryDeleteRepo(orgName)
	if err != nil {
		artifactorySync.NeedsSync()
		return
	}
	err = artifactoryDeleteRepoPerms(orgName)
	if err != nil {
		artifactorySync.NeedsSync()
		return
	}
}
