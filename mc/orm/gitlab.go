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

	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/util"
	gitlab "github.com/xanzy/go-gitlab"
)

/*
gitlab.rb ldap config (hostnames and ports should be replaced):

gitlab_rails['ldap_enabled'] = true

###! **remember to close this block with 'EOS' below**
gitlab_rails['ldap_servers'] = YAML.load <<-'EOS'
  main: # 'main' is the GitLab 'provider ID' of this LDAP server
    label: 'LDAP'
    host: 'host.docker.internal'
    port: 9389
    uid: 'sAMAccountName'
    bind_dn: 'cn=gitlab,ou=users'
    password: 'gitlab'
    encryption: 'plain' # "start_tls" or "simple_tls" or "plain"
    verify_certificates: true
    smartcard_auth: false
    active_directory: true
    allow_username_or_email_login: false
    lowercase_usernames: false
    block_auto_created_users: false
    base: ''
    user_filter: ''
    ## EE only
    group_base: 'ou=orgs'
    admin_group: ''
    sync_ssh_keys: false
EOS
*/

var LDAPProvider = "ldapmain"
var DefaultProjectName = "images"
var gitlabIgnoreForUnitTest bool

func gitlabCreateLDAPUser(ctx context.Context, user *ormapi.User) error {
	if gitlabClient == nil {
		return nil
	}
	dn := ldapdn{
		cn: user.Name,
		ou: OUusers,
	}
	euid := dn.String()
	// generate long random password for LDAP users, effectively disabling it
	pw := string(util.RandAscii(128))
	_true := true
	_false := false
	opts := gitlab.CreateUserOptions{
		Email:            &user.Email,
		Name:             &user.Name,
		Username:         &user.Name,
		ExternUID:        &euid,
		Provider:         &LDAPProvider,
		Password:         &pw,
		SkipConfirmation: &_true,
		CanCreateGroup:   &_false,
	}
	var logErr error
	_, resp, err := gitlabClient.Users.CreateUser(&opts)
	if err == nil && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		err = fmt.Errorf("gitlab user create failed (%d)", resp.StatusCode)
	}
	if err != nil {
		// override gitlab error to remove gitlab address in error message
		logErr = err
		errResp, ok := err.(*gitlab.ErrorResponse)
		if ok && strings.Contains(errResp.Message, "Email has already been taken") {
			err = fmt.Errorf("gitlab user create failed, email conflict")
		} else if ok && strings.Contains(errResp.Message, "Username has already been taken") {
			err = fmt.Errorf("gitlab user create failed, user name conflict")
		} else {
			err = fmt.Errorf("gitlab user create failed")
		}
	}
	log.SpanLog(ctx, log.DebugLevelApi, "gitlab create user", "user", user.Name, "err", err, "logErr", logErr)
	return err
}

func gitlabDeleteLDAPUser(ctx context.Context, username string) (reterr error) {
	if gitlabClient == nil {
		return nil
	}
	defer func() {
		log.SpanLog(ctx, log.DebugLevelApi, "gitlab delete user", "user", username, "err", reterr)
	}()
	user, err := gitlabGetLDAPUser(username)
	if err != nil {
		gitlabSync.NeedsSync()
		return fmt.Errorf("failed to get LDAP user: %s", err)
	}
	_, err = gitlabClient.Users.DeleteUser(user.ID)
	if err != nil {
		gitlabSync.NeedsSync()
		return fmt.Errorf("delete user failed: %s", err)
	}
	return nil
}

func gitlabCreateGroup(ctx context.Context, org *ormapi.Organization) {
	if gitlabClient == nil {
		return
	}
	if org.Type == OrgTypeOperator {
		// no operator orgs needed in gitlab
		return
	}
	name := GitlabGroupSanitize(org.Name)
	groupOpts := gitlab.CreateGroupOptions{
		Name:       &name,
		Path:       &name,
		Visibility: gitlab.Visibility(gitlab.PublicVisibility),
	}
	grp, _, err := gitlabClient.Groups.CreateGroup(&groupOpts)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "gitlab create group",
			"org", org, "name", name, "err", err)
		gitlabSync.NeedsSync()
		return
	}

	attr := gitlab.CustomAttribute{
		Key:   "createdby",
		Value: GitlabMCTag,
	}
	_, _, err = gitlabClient.CustomAttribute.SetCustomGroupAttribute(grp.ID, attr)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "gitlab set group attr",
			"grp", grp, "attr", attr, "err", err)
		gitlabSync.NeedsSync()
		return
	}
	gitlabCreateProject(ctx, grp.ID, DefaultProjectName, org.PublicImages)
}

func gitlabDeleteGroup(ctx context.Context, org *ormapi.Organization) {
	if gitlabClient == nil {
		return
	}
	if org.Type == OrgTypeOperator {
		// no operator orgs needed in gitlab
		return
	}
	name := GitlabGroupSanitize(org.Name)
	_, err := gitlabClient.Groups.DeleteGroup(name)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "gitlab delete group",
			"org", org, "name", name, "err", err)
		gitlabSync.NeedsSync()
		return
	}
}

func gitlabAddGroupMember(ctx context.Context, role *ormapi.Role, orgType string) {
	if gitlabClient == nil {
		return
	}
	if orgType == OrgTypeOperator {
		return
	}
	user, err := gitlabGetLDAPUser(role.Username)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "gitlab get user",
			"user", role.Username, "err", err)
		gitlabSync.NeedsSync()
		return
	}
	var access *gitlab.AccessLevelValue
	if role.Role == RoleDeveloperManager {
		access = gitlab.AccessLevel(gitlab.OwnerPermissions)
	} else if role.Role == RoleDeveloperContributor {
		access = gitlab.AccessLevel(gitlab.DeveloperPermissions)
	} else {
		access = gitlab.AccessLevel(gitlab.ReporterPermissions)
	}
	opts := gitlab.AddGroupMemberOptions{
		UserID:      &user.ID,
		AccessLevel: access,
	}
	orgname := GitlabGroupSanitize(role.Org)
	_, _, err = gitlabClient.GroupMembers.AddGroupMember(orgname, &opts)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "gitlab add group member",
			"role", role, "err", err)
		gitlabSync.NeedsSync()
		return
	}
}

func gitlabRemoveGroupMember(ctx context.Context, role *ormapi.Role, orgType string) {
	if gitlabClient == nil {
		return
	}
	if orgType == OrgTypeOperator {
		return
	}
	user, err := gitlabGetLDAPUser(role.Username)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "gitlab get user",
			"user", role.Username, "err", err)
		gitlabSync.NeedsSync()
		return
	}
	orgname := GitlabGroupSanitize(role.Org)
	_, err = gitlabClient.GroupMembers.RemoveGroupMember(orgname, user.ID)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "gitlab remove group member",
			"role", role, "err", err)
		gitlabSync.NeedsSync()
		return
	}
}

func getGitlabProjects(ctx context.Context) (map[string]*gitlab.Project, error) {
	// get Gitlab projects
	projsT := make(map[string]*gitlab.Project)
	if gitlabClient == nil {
		return projsT, nil
	}
	opts := gitlab.ListProjectsOptions{
		ListOptions: ListOptions,
	}
	for {
		projs, resp, err := gitlabClient.Projects.ListProjects(&opts)
		if err != nil {
			return nil, err
		}
		for ii, _ := range projs {
			projsT[projs[ii].Namespace.Name] = projs[ii]
		}
		// Exit the loop when we've seen all pages.
		if resp.CurrentPage >= resp.TotalPages {
			break
		}
		opts.Page = resp.NextPage
	}
	return projsT, nil
}

func gitlabUpdateVisibility(ctx context.Context, org *ormapi.Organization) error {
	if gitlabClient == nil {
		return nil
	}
	projs, err := getGitlabProjects(ctx)
	if err != nil {
		return fmt.Errorf("failed to get list of gitlab projects: %v", err)
	}
	name := GitlabGroupSanitize(org.Name)
	proj, ok := projs[name]
	if !ok {
		return fmt.Errorf("gitlab project %s not found", name)
	}
	// update project
	approvals := 0
	opts := gitlab.EditProjectOptions{
		Name:                 &DefaultProjectName,
		NamespaceID:          &proj.Namespace.ID,
		ApprovalsBeforeMerge: &approvals,
		Visibility:           gitlab.Visibility(gitlab.PrivateVisibility),
	}
	if org.PublicImages {
		opts.Visibility = gitlab.Visibility(gitlab.PublicVisibility)
	}
	_, _, err = gitlabClient.Projects.EditProject(proj.ID, &opts)
	if err != nil {
		return fmt.Errorf("failed to update gitlab project: %v", err)
	}
	return nil
}

func gitlabCreateProject(ctx context.Context, groupID int, name string, publicAccess bool) {
	if gitlabClient == nil {
		return
	}
	approvals := 0
	opts := gitlab.CreateProjectOptions{
		Name:                 &name,
		NamespaceID:          &groupID,
		ApprovalsBeforeMerge: &approvals,
		Visibility:           gitlab.Visibility(gitlab.PrivateVisibility),
	}
	if publicAccess {
		opts.Visibility = gitlab.Visibility(gitlab.PublicVisibility)
	}
	_, _, err := gitlabClient.Projects.CreateProject(&opts)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "gitlab create project",
			"opts", opts, "err", err)
		gitlabSync.NeedsSync()
		return
	}
}

func gitlabGetLDAPUser(username string) (*gitlab.User, error) {
	if gitlabClient == nil {
		return &gitlab.User{}, nil
	}
	// Note: if provider is specified, externalUID must also be specified.
	opts := gitlab.ListUsersOptions{
		Username: &username,
	}
	users, _, err := gitlabClient.Users.ListUsers(&opts)
	if err != nil {
		return nil, err
	}
	if len(users) == 0 || users[0] == nil {
		return nil, fmt.Errorf("Gitlab user %s not found", username)
	}
	if len(users) > 1 {
		return nil, fmt.Errorf("Gitlab more than one user with name %s", username)
	}
	if users[0].Identities == nil || len(users[0].Identities) == 0 || users[0].Identities[0].Provider != LDAPProvider {
		return nil, fmt.Errorf("LDAP User %s not found", username)
	}
	return users[0], nil
}
