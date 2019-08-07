package orm

import (
	"context"
	"fmt"
	"net/http"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/util"
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

func gitlabCreateLDAPUser(ctx context.Context, user *ormapi.User) {
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
	_, _, err := gitlabClient.Users.CreateUser(&opts)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "gitlab create user",
			"user", user.Name, "err", err)
		gitlabSync.NeedsSync()
		return
	}
}

func gitlabDeleteLDAPUser(ctx context.Context, username string) {
	user, err := gitlabGetUser(username)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "gitlab get user",
			"user", username, "err", err)
		gitlabSync.NeedsSync()
		return
	}
	_, err = gitlabClient.Users.DeleteUser(user.ID)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "gitlab delete user",
			"user", username, "err", err)
		gitlabSync.NeedsSync()
		return
	}
}

func gitlabCreateGroup(ctx context.Context, org *ormapi.Organization) {
	name := util.GitlabGroupSanitize(org.Name)
	groupOpts := gitlab.CreateGroupOptions{
		Name:       &name,
		Path:       &name,
		Visibility: gitlab.Visibility(gitlab.PrivateVisibility),
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
	gitlabCreateProject(ctx, grp.ID, DefaultProjectName)
}

func gitlabDeleteGroup(ctx context.Context, org *ormapi.Organization) {
	name := util.GitlabGroupSanitize(org.Name)
	_, err := gitlabClient.Groups.DeleteGroup(name)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "gitlab delete group",
			"org", org, "name", name, "err", err)
		gitlabSync.NeedsSync()
		return
	}
}

func gitlabAddGroupMember(ctx context.Context, role *ormapi.Role) {
	user, err := gitlabGetUser(role.Username)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "gitlab get user",
			"user", role.Username, "err", err)
		gitlabSync.NeedsSync()
		return
	}
	var access *gitlab.AccessLevelValue
	if enforcer.Enforce(role.Username, role.Org, ResourceUsers, ActionManage) {
		access = gitlab.AccessLevel(gitlab.OwnerPermissions)
	} else {
		access = gitlab.AccessLevel(gitlab.ReporterPermissions)
	}
	opts := gitlab.AddGroupMemberOptions{
		UserID:      &user.ID,
		AccessLevel: access,
	}
	orgname := util.GitlabGroupSanitize(role.Org)
	_, _, err = gitlabClient.GroupMembers.AddGroupMember(orgname, &opts)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "gitlab add group member",
			"role", role, "err", err)
		gitlabSync.NeedsSync()
		return
	}
}

func gitlabRemoveGroupMember(ctx context.Context, role *ormapi.Role) {
	user, err := gitlabGetUser(role.Username)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "gitlab get user",
			"user", role.Username, "err", err)
		gitlabSync.NeedsSync()
		return
	}
	orgname := util.GitlabGroupSanitize(role.Org)
	_, err = gitlabClient.GroupMembers.RemoveGroupMember(orgname, user.ID)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "gitlab remove group member",
			"role", role, "err", err)
		gitlabSync.NeedsSync()
		return
	}
}

func gitlabCreateProject(ctx context.Context, groupID int, name string) {
	approvals := 0
	opts := gitlab.CreateProjectOptions{
		Name:                 &name,
		NamespaceID:          &groupID,
		ApprovalsBeforeMerge: &approvals,
	}
	_, _, err := gitlabClient.Projects.CreateProject(&opts)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "gitlab create project",
			"opts", opts, "err", err)
		gitlabSync.NeedsSync()
		return
	}
}

func gitlabGetUser(username string) (*gitlab.User, error) {
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
	return users[0], nil
}

// Wrap default http transport for logging
type GitlabTransport struct {
	Transport http.RoundTripper
}

func NewGitlabTransport() *GitlabTransport {
	// TODO: caller skip 7
	return &GitlabTransport{
		Transport: http.DefaultTransport,
	}
}

func (s *GitlabTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	span := log.StartSpan(log.DebugLevelApi, "gitlab transport")
	span.SetTag("url", req.URL)
	span.SetTag("method", req.Method)
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	resp, err := s.transport().RoundTrip(req)
	status := ""
	if resp != nil {
		status = resp.Status
	}
	log.SpanLog(ctx, log.DebugLevelApi, "Call gitlab",
		"status", status, "err", err)
	return resp, err
}

func (s *GitlabTransport) transport() http.RoundTripper {
	if s.Transport != nil {
		return s.Transport
	}
	return http.DefaultTransport
}
