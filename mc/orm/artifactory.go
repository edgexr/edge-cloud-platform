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
	"fmt"
	"net/http"
	"strings"

	"github.com/atlassian/go-artifactory/v2/artifactory"
	"github.com/atlassian/go-artifactory/v2/artifactory/transport"
	v1 "github.com/atlassian/go-artifactory/v2/artifactory/v1"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/log"
)

const (
	ArtifactoryPrefix     string = "mc-"
	ArtifactoryRepoPrefix string = "repo-"
)

// Cache Artifactory Auth Key
var rtfAuth *cloudcommon.RegistryAuth

func getArtifactoryName(orgName string) string {
	return ArtifactoryPrefix + orgName
}

func getArtifactoryRepoName(orgName string) string {
	return ArtifactoryRepoPrefix + orgName
}

func artifactoryClient(ctx context.Context) (*artifactory.Artifactory, error) {
	if serverConfig.ArtifactoryAddr == "" {
		return nil, fmt.Errorf("no artifactory addr specified")
	}
	if rtfAuth == nil {
		auth, err := cloudcommon.GetRegistryAuth(ctx, serverConfig.ArtifactoryAddr, serverConfig.vaultConfig)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfo, "Failed to fetch artifactory AuthKey from Vault",
				"artifactoryAddr", serverConfig.ArtifactoryAddr,
				"vaultAddr", serverConfig.VaultAddr,
				"err", err)
			return nil, err
		}
		if auth.AuthType != cloudcommon.ApiKeyAuth {
			log.SpanLog(ctx, log.DebugLevelInfo, "Invalid auth type for artifactory",
				"artifactoryAddr", serverConfig.ArtifactoryAddr,
				"authType", auth.AuthType)
			return nil, fmt.Errorf("Invalid auth type for Artifactory")
		}
		rtfAuth = auth
	}
	tp := transport.ApiKeyAuth{
		ApiKey: rtfAuth.ApiKey,
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
	if serverConfig.ArtifactoryAddr == "" {
		return map[string]struct{}{}, nil
	}
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
		userInfo, _, err := client.V1.Security.GetUser(context.Background(), userName)
		if err == nil && *userInfo.InternalPasswordDisabled {
			tmp[userName] = struct{}{}
		}
	}
	return tmp, nil
}

func artifactoryListUserGroups(ctx context.Context, userName string) (map[string]struct{}, error) {
	if serverConfig.ArtifactoryAddr == "" {
		return map[string]struct{}{}, nil
	}
	client, err := artifactoryClient(ctx)
	if err != nil {
		return nil, err
	}

	tmp := make(map[string]struct{})
	userInfo, _, err := client.V1.Security.GetUser(context.Background(), userName)
	if err == nil && userInfo.Groups != nil {
		for _, group := range *userInfo.Groups {
			if strings.HasPrefix(group, ArtifactoryPrefix) {
				tmp[group] = struct{}{}
			}
		}
	}
	return tmp, nil
}

func artifactoryCreateLDAPUser(ctx context.Context, user *ormapi.User) (reterr error) {
	if serverConfig.ArtifactoryAddr == "" {
		return nil
	}
	if user.Name == Superuser {
		return nil
	}
	userName := user.Name
	defer func() {
		log.SpanLog(ctx, log.DebugLevelApi, "artifactory create user", "user", userName, "err", reterr)
	}()
	client, err := artifactoryClient(ctx)
	if err != nil {
		return err
	}
	// do not overwrite existing user
	_, resp, err := client.V1.Security.GetUser(context.Background(), userName)
	if err == nil && resp != nil && resp.StatusCode == http.StatusOK {
		// user already exists
		return fmt.Errorf("Artifactory user %s already exists", userName)
	}
	if err == nil && resp != nil && resp.StatusCode != http.StatusNotFound {
		// we expect a 404 if the user doesn't exist
		// without a 404 response, we don't actually know if the
		// user exists or not
		return fmt.Errorf("Unable to determine if artifactory user already exists or not: %d", resp.StatusCode)
	}
	rtfUser := v1.User{
		Name:                     artifactory.String(userName),
		Email:                    artifactory.String(user.Email),
		ProfileUpdatable:         artifactory.Bool(false),
		InternalPasswordDisabled: artifactory.Bool(true),
	}
	_, err = client.V1.Security.CreateOrReplaceUser(context.Background(), userName, &rtfUser)
	return err
}

func artifactoryDeleteLDAPUser(ctx context.Context, userName string) (reterr error) {
	if serverConfig.ArtifactoryAddr == "" {
		return nil
	}
	defer func() {
		log.SpanLog(ctx, log.DebugLevelApi, "artifactory delete user", "user", userName, "err", reterr)
	}()
	client, err := artifactoryClient(ctx)
	if err != nil {
		return err
	}
	// check that user to delete is an LDAP user
	existingUser, resp, err := client.V1.Security.GetUser(context.Background(), userName)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusNotFound {
		// no user to delete
		log.SpanLog(ctx, log.DebugLevelApi, "artifactory delete user not found", "user", userName)
		return nil
	} else if resp.StatusCode == http.StatusOK && !*existingUser.InternalPasswordDisabled {
		return fmt.Errorf("Artifactory user %s not an LDAP user, cannot delete", userName)
	} else if resp.StatusCode != http.StatusOK {
		// don't issue delete if we don't know that it's an LDAP user
		return fmt.Errorf("Failed to lookup artifactory user %s for delete: %d", userName, resp.StatusCode)
	}
	_, _, err = client.V1.Security.DeleteUser(context.Background(), userName)
	if err != nil {
		artifactorySync.NeedsSync()
		return err
	}
	return nil
}

func artifactoryAddUserToGroup(ctx context.Context, role *ormapi.Role, orgType string) {
	if serverConfig.ArtifactoryAddr == "" {
		return
	}
	if orgType == OrgTypeOperator {
		return
	}
	if role.Username == Superuser {
		return
	}
	client, err := artifactoryClient(ctx)
	userName := role.Username
	orgName := getArtifactoryName(role.Org)
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
	log.SpanLog(ctx, log.DebugLevelApi, "artifactory add user to group",
		"user", userName, "group", orgName, "err", err)
	if err != nil {
		artifactorySync.NeedsSync()
		return
	}
	artifactoryCreateRepoPerms(ctx, role.Org, orgType)
}

func artifactoryRemoveUserFromGroup(ctx context.Context, role *ormapi.Role, orgType string) {
	if serverConfig.ArtifactoryAddr == "" {
		return
	}
	if orgType == OrgTypeOperator {
		return
	}
	client, err := artifactoryClient(ctx)
	userName := role.Username
	orgName := getArtifactoryName(role.Org)
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
	log.SpanLog(ctx, log.DebugLevelApi, "artifactory remove user from group",
		"user", userName, "group", orgName, "err", err)
	if err != nil {
		artifactorySync.NeedsSync()
		return
	}
	artifactoryCreateRepoPerms(ctx, role.Org, orgType)
}

func artifactoryListGroups(ctx context.Context) (map[string]struct{}, error) {
	if serverConfig.ArtifactoryAddr == "" {
		return map[string]struct{}{}, nil
	}
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

func artifactoryCreateGroup(ctx context.Context, orgName, orgType string) error {
	if serverConfig.ArtifactoryAddr == "" {
		return nil
	}
	if orgType == OrgTypeOperator {
		return nil
	}
	groupName := getArtifactoryName(orgName)
	group := v1.Group{
		Name:        artifactory.String(groupName),
		Description: artifactory.String("Group maintained by master-controller"),
	}
	client, err := artifactoryClient(ctx)
	if err == nil {
		_, err = client.V1.Security.CreateOrReplaceGroup(context.Background(), groupName, &group)
	}
	log.SpanLog(ctx, log.DebugLevelApi, "artifactory create group", "group", groupName, "err", err)
	return err
}

func artifactoryDeleteGroup(ctx context.Context, orgName, orgType string) error {
	if serverConfig.ArtifactoryAddr == "" {
		return nil
	}
	if orgType == OrgTypeOperator {
		return nil
	}
	groupName := getArtifactoryName(orgName)
	client, err := artifactoryClient(ctx)
	if err == nil {
		_, _, err = client.V1.Security.DeleteGroup(context.Background(), groupName)
	}
	log.SpanLog(ctx, log.DebugLevelApi, "artifactory delete group", "group", groupName, "err", err)
	return err
}

func artifactoryListRepos(ctx context.Context) (map[string]struct{}, error) {
	if serverConfig.ArtifactoryAddr == "" {
		return map[string]struct{}{}, nil
	}
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

func artifactoryCreateRepo(ctx context.Context, orgName, orgType string) error {
	if serverConfig.ArtifactoryAddr == "" {
		return nil
	}
	if orgType == OrgTypeOperator {
		return nil
	}
	repoName := getArtifactoryRepoName(orgName)
	repo := v1.LocalRepository{
		Key:             artifactory.String(repoName),
		RClass:          artifactory.String("local"),
		PackageType:     artifactory.String("generic"),
		HandleSnapshots: artifactory.Bool(false),
	}
	client, err := artifactoryClient(ctx)
	if err == nil {
		_, err = client.V1.Repositories.CreateLocal(context.Background(), &repo)
	}
	log.SpanLog(ctx, log.DebugLevelApi, "artifactory create repository",
		"repository", repoName, "err", err)
	return err
}

func artifactoryDeleteRepo(ctx context.Context, orgName, orgType string) error {
	if serverConfig.ArtifactoryAddr == "" {
		return nil
	}
	if orgType == OrgTypeOperator {
		return nil
	}
	repoName := getArtifactoryRepoName(orgName)
	client, err := artifactoryClient(ctx)
	if err == nil {
		_, err = client.V1.Repositories.DeleteLocal(context.Background(), repoName)
	}
	log.SpanLog(ctx, log.DebugLevelApi, "artifactory delete repository",
		"repository", repoName, "err", err)
	return err
}

func artifactoryListPerms(ctx context.Context) (map[string]struct{}, error) {
	if serverConfig.ArtifactoryAddr == "" {
		return map[string]struct{}{}, nil
	}
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

func artifactoryCreateRepoPerms(ctx context.Context, orgName, orgType string) error {
	if serverConfig.ArtifactoryAddr == "" {
		return nil
	}
	if orgType == OrgTypeOperator {
		return nil
	}
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
				groupName: []string{"r"},
			},
		},
	}

	userPerms := map[string][]string{}
	groupings, err := enforcer.GetGroupingPolicy()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "artifactory create repo perms failed",
			"permission target", permTargetName, "repository", repoName, "group", groupName, "err", err)
		return err
	}
	var permUsers []string
	for ii, _ := range groupings {
		role := parseRole(groupings[ii])
		if role == nil {
			continue
		}
		if role.Org != orgName {
			continue
		}
		if role.Username == Superuser {
			continue
		}
		userName := strings.ToLower(role.Username)
		if role.Role == RoleDeveloperManager {
			userPerms[userName] = []string{"w", "d", "r", "m"}
		}
		if role.Role == RoleDeveloperContributor {
			userPerms[userName] = []string{"w", "d", "r"}
		}
		if role.Role == RoleDeveloperViewer {
			userPerms[userName] = []string{"r"}
		}
		permUsers = append(permUsers, userName)
	}
	permTargets.Principals.Users = &userPerms

	_, err = client.V1.Security.CreateOrReplacePermissionTargets(context.Background(), permTargetName, &permTargets)

	log.SpanLog(ctx, log.DebugLevelApi, "artifactory create repo perms",
		"permission target", permTargetName, "repository", repoName, "group", groupName,
		"users", permUsers, "err", err)
	return err
}

func artifactoryDeleteRepoPerms(ctx context.Context, orgName, orgType string) error {
	if serverConfig.ArtifactoryAddr == "" {
		return nil
	}
	if orgType == OrgTypeOperator {
		return nil
	}
	permTargetName := getArtifactoryName(orgName)
	client, err := artifactoryClient(ctx)
	if err == nil {
		_, _, err = client.V1.Security.DeletePermissionTargets(context.Background(), permTargetName)
	}

	log.SpanLog(ctx, log.DebugLevelApi, "artifactory delete repo perms", "permission target", permTargetName, "err", err)
	return err
}

func artifactoryCreateGroupObjects(ctx context.Context, orgName, orgType string) {
	err := artifactoryCreateGroup(ctx, orgName, orgType)
	if err != nil {
		artifactorySync.NeedsSync()
		return
	}
	err = artifactoryCreateRepo(ctx, orgName, orgType)
	if err != nil {
		artifactorySync.NeedsSync()
		return
	}
	err = artifactoryCreateRepoPerms(ctx, orgName, orgType)
	if err != nil {
		artifactorySync.NeedsSync()
		return
	}
}

func artifactoryDeleteGroupObjects(ctx context.Context, orgName, orgType string) {
	err := artifactoryDeleteGroup(ctx, orgName, orgType)
	if err != nil {
		artifactorySync.NeedsSync()
		return
	}
	err = artifactoryDeleteRepo(ctx, orgName, orgType)
	if err != nil {
		artifactorySync.NeedsSync()
		return
	}
	err = artifactoryDeleteRepoPerms(ctx, orgName, orgType)
	if err != nil {
		artifactorySync.NeedsSync()
		return
	}
}
