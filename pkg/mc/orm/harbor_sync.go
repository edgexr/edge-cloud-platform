package orm

import (
	"context"
	"strconv"

	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/harbor-api/models"
	"github.com/labstack/echo/v4"
)

func HarborNewSync() *AppStoreSync {
	hSync := AppStoreNewSync("harbor")
	hSync.syncObjects = hSync.syncHarborObjects
	return hSync
}

func (s *AppStoreSync) syncHarborObjects(ctx context.Context) {
	err := harborInit(ctx)
	if err != nil {
		s.syncErr(ctx, err)
	}
	s.syncHarborProjects(ctx)
}

func (s *AppStoreSync) syncHarborProjects(ctx context.Context) {
	orgsT, err := GetAllOrgs(ctx)
	if err != nil {
		s.syncErr(ctx, err)
		return
	}
	orgsT[harborEdgeCloudOrg.Name] = &harborEdgeCloudOrg

	projects, err := harborGetProjects(ctx)
	if err != nil {
		s.syncErr(ctx, err)
		return
	}
	projectsT := make(map[string]*models.Project)
	for ii := range projects {
		projectsT[projects[ii].Name] = &projects[ii]
	}

	devOrgsCount := 0
	for _, org := range orgsT {
		if org.Type == OrgTypeOperator {
			continue
		}
		devOrgsCount++
	}
	groupings, err := enforcer.GetGroupingPolicy()
	if err != nil {
		s.syncErr(ctx, err)
		return
	}
	orgusers := make(map[string]map[string]*ormapi.Role)
	for ii, _ := range groupings {
		role := parseRole(groupings[ii])
		if role == nil {
			continue
		}
		orgName := HarborProjectSanitize(role.Org)
		users, ok := orgusers[orgName]
		if !ok {
			users = make(map[string]*ormapi.Role)
			orgusers[orgName] = users
		}
		users[role.Username] = role
	}
	log.SpanLog(ctx, log.DebugLevelApi, "harbor sync projects", "harbor projects", len(projects), "mc dev orgs", devOrgsCount)
	for name, org := range orgsT {
		if org.Type == OrgTypeOperator {
			continue
		}
		name = HarborProjectSanitize(name)
		if proj, found := projectsT[name]; found {
			delete(projectsT, name)

			hasLabel, err := harborHasProjectLabel(ctx, proj.ProjectID)
			if err != nil || !hasLabel {
				err := harborSetProjectLabel(ctx, proj.ProjectID)
				if err != nil {
					s.syncErr(ctx, err)
				}
			}
			err = harborEnsureRobotAccount(ctx, serverConfig.HarborAddr, org.Name)
			if err != nil {
				s.syncErr(ctx, err)
			}
		} else {
			// missing from Harbor, so create
			log.SpanLog(ctx, log.DebugLevelApi, "harbor sync create missing project", "org", name)
			harborCreateProject(ctx, org)
		}
		s.syncHarborProjectMembers(ctx, org, orgusers[name])
	}
	for name, proj := range projectsT {
		managed, err := harborHasProjectLabel(ctx, proj.ProjectID)
		if err != nil {
			continue
		}
		if !managed {
			// not created by Edge Cloud
			continue
		}
		// delete orphaned project
		log.SpanLog(ctx, log.DebugLevelApi, "harbor sync delete extra project", "org", name)
		harborDeleteProject(ctx, name)
	}
}

func (s *AppStoreSync) syncHarborProjectMembers(ctx context.Context, org *ormapi.Organization, orgRoles map[string]*ormapi.Role) {
	mems, err := harborGetProjectMembers(ctx, org.Name)
	if err != nil {
		s.syncErr(ctx, err)
		return
	}
	members := make(map[string]*models.ProjectMemberEntity)
	for ii := range mems {
		members[mems[ii].EntityName] = &mems[ii]
	}
	log.SpanLog(ctx, log.DebugLevelApi, "harbor sync project members", "members", members, "mcRoles", orgRoles)
	for _, role := range orgRoles {
		if _, found := members[role.Username]; found {
			delete(members, role.Username)
			continue
		}
		// add missing role
		log.SpanLog(ctx, log.DebugLevelApi, "harbor sync create missing project member", "role", role)
		harborAddProjectMember(ctx, role, org.Type)
		delete(members, role.Username)
	}
	for _, member := range members {
		// delete extra member
		log.SpanLog(ctx, log.DebugLevelApi, "harbor sync delete extra project member", "org", org.Name, "user", member.EntityName)
		projID := strconv.FormatInt(member.ProjectID, 10)
		err := harborRemoveProjectMemberId(ctx, projID, member.EntityID)
		if err != nil {
			s.syncErr(ctx, err)
		}
	}
}

func HarborResync(c echo.Context) error {
	err := AdminAccessCheck(c)
	if err != nil {
		return err
	}
	harborSync.NeedsSync()
	harborSync.wakeup()
	return err
}
