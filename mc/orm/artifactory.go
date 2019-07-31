package orm

import (
	"context"
	"strings"

	"github.com/atlassian/go-artifactory/v2/artifactory"
	"github.com/atlassian/go-artifactory/v2/artifactory/transport"
	v1 "github.com/atlassian/go-artifactory/v2/artifactory/v1"
	rtf "github.com/mobiledgex/edge-cloud-infra/artifactory"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/log"
)

const (
	ArtifactoryPrefix     string = "mc-"
	ArtifactoryRepoPrefix string = "repo-"
)

func getArtifactoryName(orgName string) string {
	return ArtifactoryPrefix + orgName
}

func getArtifactoryRepoName(orgName string) string {
	return ArtifactoryRepoPrefix + orgName
}

func artifactoryClient(ctx context.Context) (*artifactory.Artifactory, error) {
	artifactoryApiKey, err := rtf.GetArtifactoryApiKey()
	if err != nil {
		return nil, err
	}
	tp := transport.ApiKeyAuth{
		ApiKey: artifactoryApiKey,
	}
	client, err := artifactory.NewClient(serverConfig.ArtifactoryAddr, tp.Client())
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to connect to artifactory", "addr",
			serverConfig.ArtifactoryAddr, "err", err)
		return nil, err
	}
	return client, nil
}

func artifactoryListUsers(ctx context.Context) (map[string]struct{}, error) {
	client, err := artifactoryClient(ctx)
	if err != nil {
		return nil, err
	}
	users, _, err := client.V1.Security.ListUsers(context.Background())
	if err != nil {
		return nil, err
	}
	tmp := make(map[string]struct{})
	for _, user := range *users {
		userName := *user.Name
		if *user.Realm == "ldap" && userName != "admin" {
			tmp[userName] = struct{}{}
			continue
		}
		userInfo, _, err := client.V1.Security.GetUser(context.Background(), userName)
		if err == nil && *userInfo.InternalPasswordDisabled {
			tmp[userName] = struct{}{}
		}
	}
	return tmp, nil
}

func artifactoryListUserGroups(ctx context.Context, userName string) (map[string]struct{}, error) {
	client, err := artifactoryClient(ctx)
	if err != nil {
		return nil, err
	}

	tmp := make(map[string]struct{})
	userInfo, _, err := client.V1.Security.GetUser(context.Background(), userName)
	if err == nil && userInfo.Groups != nil {
		for _, group := range *userInfo.Groups {
			tmp[group] = struct{}{}
		}
	}
	return tmp, nil
}

func artifactoryCreateUser(ctx context.Context, user *ormapi.User, groups *[]string) {
	client, err := artifactoryClient(ctx)
	userName := user.Name
	if err == nil {
		rtfUser := v1.User{
			Name:                     artifactory.String(userName),
			Email:                    artifactory.String(user.Email),
			ProfileUpdatable:         artifactory.Bool(false),
			Groups:                   groups,
			InternalPasswordDisabled: artifactory.Bool(true),
		}
		_, err = client.V1.Security.CreateOrReplaceUser(context.Background(), userName, &rtfUser)
	}
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "artifactory create user",
			"user", userName, "err", err)
		artifactorySync.NeedsSync()
		return
	}
}

func artifactoryDeleteUser(ctx context.Context, userName string) {
	client, err := artifactoryClient(ctx)
	if err == nil {
		_, _, err = client.V1.Security.DeleteUser(context.Background(), userName)
	}
	if err != nil {
		if strings.Contains(err.Error(), "Status:404") {
			log.DebugLog(log.DebugLevelApi, "artifactory delete user",
				"user", userName, "err", "user does not exists")
			return
		}
		log.DebugLog(log.DebugLevelApi, "artifactory delete user",
			"user", userName, "err", err)
		artifactorySync.NeedsSync()
		return
	}
}

func artifactoryAddUserToGroup(ctx context.Context, role *ormapi.Role) {
	client, err := artifactoryClient(ctx)
	userName := role.Username
	orgName := getArtifactoryName(role.Org)
	log.DebugLog(log.DebugLevelApi, "artifactory add user to group",
		"user", userName, "group", orgName)
	if err == nil {
		var userInfo *v1.User
		userInfo, _, err = client.V1.Security.GetUser(context.Background(), userName)
		if err == nil {
			var groups []string
			if userInfo.Groups != nil {
				groups = *userInfo.Groups
			}
			groups = append(groups, orgName)
			rtfUser := v1.User{
				Name:   artifactory.String(userName),
				Groups: &groups,
			}
			_, err = client.V1.Security.UpdateUser(context.Background(), userName, &rtfUser)
		}
	}
	if err != nil {
		log.DebugLog(log.DebugLevelApi, "artifactory add user to group",
			"user", userName, "group", orgName, "err", err)
		artifactorySync.NeedsSync()
		return
	}
}

func artifactoryRemoveUserFromGroup(ctx context.Context, role *ormapi.Role) {
	client, err := artifactoryClient(ctx)
	userName := role.Username
	orgName := getArtifactoryName(role.Org)
	log.SpanLog(ctx, log.DebugLevelApi, "artifactory remove user from group",
		"user", userName)
	if err == nil {
		var userInfo *v1.User
		userInfo, _, err = client.V1.Security.GetUser(context.Background(), userName)
		if err == nil && userInfo.Groups != nil {
			var groups []string
			for _, group := range *userInfo.Groups {
				if group != orgName {
					groups = append(groups, group)
				}
			}
			rtfUser := v1.User{
				Name:   artifactory.String(userName),
				Groups: &groups,
			}
			_, err = client.V1.Security.UpdateUser(context.Background(), userName, &rtfUser)
		}
	}
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "artifactory remove user from group",
			"user", userName, "err", err)
		artifactorySync.NeedsSync()
		return
	}
}

func artifactoryListGroups(ctx context.Context) (map[string]struct{}, error) {
	client, err := artifactoryClient(ctx)
	if err != nil {
		return nil, err
	}
	groups, _, err := client.V1.Security.ListGroups(context.Background())
	if err != nil {
		return nil, err
	}
	tmp := make(map[string]struct{})
	for _, group := range *groups {
		groupName := *group.Name
		if strings.HasPrefix(groupName, ArtifactoryPrefix) {
			tmp[groupName] = struct{}{}
		}
	}
	return tmp, nil
}

func artifactoryCreateGroup(ctx context.Context, orgName string) error {
	client, err := artifactoryClient(ctx)
	if err != nil {
		return err
	}
	groupName := getArtifactoryName(orgName)
	group := v1.Group{
		Name:        artifactory.String(groupName),
		Description: artifactory.String("Group maintained by master-controller"),
	}
	_, err = client.V1.Security.CreateOrReplaceGroup(context.Background(), groupName, &group)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "artifactory create group",
			"group", groupName, "err", err)
	}
	return err
}

func artifactoryDeleteGroup(ctx context.Context, orgName string) error {
	client, err := artifactoryClient(ctx)
	if err != nil {
		return err
	}
	groupName := getArtifactoryName(orgName)
	_, _, err = client.V1.Security.DeleteGroup(context.Background(), groupName)
	if err != nil {
		if strings.Contains(err.Error(), "Status:404") {
			log.SpanLog(ctx, log.DebugLevelApi, "artifactory delete group",
				"group", groupName, "err", "group does not exists")
			return nil
		}
		log.SpanLog(ctx, log.DebugLevelApi, "artifactory delete group",
			"group", groupName, "err", err)
	}
	return err
}

func artifactoryListRepos(ctx context.Context) (map[string]struct{}, error) {
	client, err := artifactoryClient(ctx)
	if err != nil {
		return nil, err
	}
	repos, _, err := client.V1.Repositories.ListRepositories(context.Background(), nil)
	if err != nil {
		return nil, err
	}
	tmp := make(map[string]struct{})
	for _, repo := range *repos {
		repoName := *repo.Key
		if strings.HasPrefix(repoName, ArtifactoryRepoPrefix) {
			tmp[repoName] = struct{}{}
		}
	}
	return tmp, nil
}

func artifactoryCreateRepo(ctx context.Context, orgName string) error {
	client, err := artifactoryClient(ctx)
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
			log.SpanLog(ctx, log.DebugLevelApi, "artifactory create repository",
				"repository", repoName, "err", "already exists")
			return nil
		}
		log.SpanLog(ctx, log.DebugLevelApi, "artifactory create repository",
			"repository", repoName, "err", err)
	}
	return err
}

func artifactoryDeleteRepo(ctx context.Context, orgName string) error {
	client, err := artifactoryClient(ctx)
	if err != nil {
		return err
	}
	repoName := getArtifactoryRepoName(orgName)
	_, err = client.V1.Repositories.DeleteLocal(context.Background(), repoName)
	if err != nil {
		if strings.Contains(err.Error(), "Status:404") {
			log.SpanLog(ctx, log.DebugLevelApi, "artifactory delete repository",
				"repository", repoName, "err", "repository does not exists")
			return nil
		}
		log.SpanLog(ctx, log.DebugLevelApi, "artifactory delete repository",
			"repository", repoName, "err", err)
	}
	return err
}

func artifactoryListPerms(ctx context.Context) (map[string]struct{}, error) {
	client, err := artifactoryClient(ctx)
	if err != nil {
		return nil, err
	}
	perms, _, err := client.V1.Security.ListPermissionTargets(context.Background())
	if err != nil {
		return nil, err
	}
	tmp := make(map[string]struct{})
	for _, perm := range perms {
		permName := *perm.Name
		if strings.HasPrefix(permName, ArtifactoryPrefix) {
			tmp[permName] = struct{}{}
		}
	}
	return tmp, nil
}

func artifactoryCreateRepoPerms(ctx context.Context, orgName string) error {
	client, err := artifactoryClient(ctx)
	if err != nil {
		return err
	}
	groupName := getArtifactoryName(orgName)
	repoName := getArtifactoryRepoName(orgName)
	permTargetName := getArtifactoryName(orgName)
	// create permission target
	permTargets := v1.PermissionTargets{
		Name:         artifactory.String(permTargetName),
		Repositories: &[]string{repoName},
		Principals: &v1.Principals{
			Groups: &map[string][]string{
				groupName: []string{"w", "d", "r"},
			},
		},
	}
	_, err = client.V1.Security.CreateOrReplacePermissionTargets(context.Background(), permTargetName, &permTargets)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "artifactory create repo perms",
			"permission target", permTargetName, "repository", repoName, "group", groupName, "err", err)
	}
	return err
}

func artifactoryDeleteRepoPerms(ctx context.Context, orgName string) error {
	client, err := artifactoryClient(ctx)
	if err != nil {
		return err
	}
	permTargetName := getArtifactoryName(orgName)
	_, _, err = client.V1.Security.DeletePermissionTargets(context.Background(), permTargetName)
	if err != nil {
		if strings.Contains(err.Error(), "Status:404") {
			log.SpanLog(ctx, log.DebugLevelApi, "artifactory delete repo perms",
				"repo perms", permTargetName, "err", "repo perms does not exists")
			return nil
		}
		log.SpanLog(ctx, log.DebugLevelApi, "artifactory delete repo perms",
			"permission target", permTargetName, "err", err)
	}
	return err
}

func artifactoryCreateGroupObjects(ctx context.Context, orgName string) {
	err := artifactoryCreateGroup(ctx, orgName)
	if err != nil {
		artifactorySync.NeedsSync()
		return
	}
	err = artifactoryCreateRepo(ctx, orgName)
	if err != nil {
		artifactorySync.NeedsSync()
		return
	}
	err = artifactoryCreateRepoPerms(ctx, orgName)
	if err != nil {
		artifactorySync.NeedsSync()
		return
	}
}

func artifactoryDeleteGroupObjects(ctx context.Context, orgName string) {
	err := artifactoryDeleteGroup(ctx, orgName)
	if err != nil {
		artifactorySync.NeedsSync()
		return
	}
	err = artifactoryDeleteRepo(ctx, orgName)
	if err != nil {
		artifactorySync.NeedsSync()
		return
	}
	err = artifactoryDeleteRepoPerms(ctx, orgName)
	if err != nil {
		artifactorySync.NeedsSync()
		return
	}
}
