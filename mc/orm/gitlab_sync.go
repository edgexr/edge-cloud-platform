package orm

import (
	"context"

	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/util"
	gitlab "github.com/xanzy/go-gitlab"
)

// MC tag is used to tag groups/projects created by master controller
var GitlabMCTag = "mastercontroller"
var GitlabAdminID = 1

func GitlabNewSync() *AppStoreSync {
	gSync := AppStoreNewSync("gitlab")
	gSync.syncObjects = gSync.syncGitlabObjects
	return gSync
}

func (s *AppStoreSync) syncGitlabObjects(ctx context.Context) {
	s.syncUsers(ctx)
	allOrgs := s.syncGroups(ctx)
	s.syncGroupMembers(ctx, allOrgs)
}

func (s *AppStoreSync) syncUsers(ctx context.Context) {
	// get Gitlab users
	gusers, _, err := gitlabClient.Users.ListUsers(&gitlab.ListUsersOptions{})
	log.SpanLog(ctx, log.DebugLevelApi, "Gitlab Sync list users",
		"users", gusers)
	if err != nil {
		s.syncErr(ctx, err)
		return
	}
	gusersT := make(map[string]*gitlab.User)
	for ii, _ := range gusers {
		gusersT[gusers[ii].Name] = gusers[ii]
	}
	// get MC users
	mcusers := []ormapi.User{}
	db := loggedDB(ctx)
	err = db.Find(&mcusers).Error
	if err != nil {
		s.syncErr(ctx, err)
		return
	}
	mcusersT := make(map[string]*ormapi.User)
	for ii, _ := range mcusers {
		mcusersT[mcusers[ii].Name] = &mcusers[ii]
	}

	for name, user := range mcusersT {
		if _, found := gusersT[name]; found {
			// in sync
			delete(gusersT, name)
		} else {
			// missing from gitlab, so create
			log.SpanLog(ctx, log.DebugLevelApi,
				"Gitlab Sync create missing LDAP user",
				"user", name)
			gitlabCreateLDAPUser(ctx, user)
		}
	}
	for _, guser := range gusersT {
		// delete extra LDAP users - first confirm it's an LDAP user
		if guser.Identities == nil {
			continue
		}
		ldapuser := false
		for _, id := range guser.Identities {
			if id.Provider == LDAPProvider {
				ldapuser = true
				break
			}
		}
		if !ldapuser {
			continue
		}
		log.SpanLog(ctx, log.DebugLevelApi,
			"Gitlab Sync delete extra LDAP user",
			"name", guser.Name)
		_, err = gitlabClient.Users.DeleteUser(guser.ID)
		if err != nil {
			s.syncErr(ctx, err)
		}
	}
}

func (s *AppStoreSync) syncGroups(ctx context.Context) map[string]*ormapi.Organization {
	orgsT, err := GetAllOrgs(ctx)
	if err != nil {
		s.syncErr(ctx, err)
		return nil
	}
	// get Gitlab groups
	groups, _, err := gitlabClient.Groups.ListGroups(&gitlab.ListGroupsOptions{})
	if err != nil {
		s.syncErr(ctx, err)
		return orgsT
	}
	groupsT := make(map[string]*gitlab.Group)
	for ii, _ := range groups {
		groupsT[groups[ii].Name] = groups[ii]
	}
	for name, org := range orgsT {
		if org.Type == OrgTypeOperator {
			continue
		}
		name = util.GitlabGroupSanitize(name)
		if _, found := groupsT[name]; found {
			delete(groupsT, name)
		} else {
			// missing from gitlab, so create
			log.SpanLog(ctx, log.DebugLevelApi,
				"Gitlab Sync create missing group",
				"org", name)
			gitlabCreateGroup(ctx, org)
		}
	}
	for _, group := range groupsT {
		ca, _, err := gitlabClient.CustomAttribute.GetCustomGroupAttribute(group.ID, "createdby")
		if err != nil {
			continue
		}
		if ca.Value != GitlabMCTag {
			continue
		}
		// delete extra group created by master controller
		log.SpanLog(ctx, log.DebugLevelApi,
			"Gitlab Sync delete extra group",
			"name", group.Name)
		_, err = gitlabClient.Groups.DeleteGroup(group.ID)
		if err != nil {
			s.syncErr(ctx, err)
		}
	}
	return orgsT
}

func (s *AppStoreSync) syncGroupMembers(ctx context.Context, allOrgs map[string]*ormapi.Organization) {
	members := make(map[string]map[string]*gitlab.GroupMember)
	var err error

	groupings, err := enforcer.GetGroupingPolicy()
	if err != nil {
		s.syncErr(ctx, err)
		return
	}
	for ii, _ := range groupings {
		role := parseRole(groupings[ii])
		if role == nil || role.Org == "" {
			continue
		}
		if org, ok := allOrgs[role.Org]; !ok || org.Type == OrgTypeOperator {
			continue
		}
		// get cached group
		memberTable, found := members[role.Org]
		if !found {
			gname := util.GitlabGroupSanitize(role.Org)
			memberlist, _, err := gitlabClient.Groups.ListGroupMembers(gname, &gitlab.ListGroupMembersOptions{})
			if err != nil {
				s.syncErr(ctx, err)
				continue
			}
			// convert list to table for easier processing
			memberTable = make(map[string]*gitlab.GroupMember)
			for _, member := range memberlist {
				memberTable[member.Username] = member
			}
			members[role.Org] = memberTable
		}
		found = false
		for name, _ := range memberTable {
			if name == role.Username {
				found = true
				delete(memberTable, name)
				break
			}
		}
		if found {
			continue
		}
		orgType := getOrgType(role.Org, allOrgs)
		// add member back to group
		log.SpanLog(ctx, log.DebugLevelApi,
			"Gitlab Sync restore role", "role", role, "orgType", orgType)
		gitlabAddGroupMember(ctx, role, orgType)
	}
	// delete members that shouldn't be part of the group anymore
	for roleOrg, memberTable := range members {
		for _, groupMember := range memberTable {
			if groupMember.ID == GitlabAdminID {
				// root is always member of a group
				continue
			}
			log.SpanLog(ctx, log.DebugLevelApi,
				"Gitlab Sync remove extra role",
				"org", roleOrg, "member", groupMember.Username)
			gname := util.GitlabGroupSanitize(roleOrg)
			_, err = gitlabClient.GroupMembers.RemoveGroupMember(gname, groupMember.ID)
			if err != nil {
				s.syncErr(ctx, err)
			}
		}
	}
}

func GitlabResync(c echo.Context) error {
	err := SyncAccessCheck(c)
	if err != nil {
		return err
	}
	gitlabSync.NeedsSync()
	gitlabSync.wakeup()
	return err
}
