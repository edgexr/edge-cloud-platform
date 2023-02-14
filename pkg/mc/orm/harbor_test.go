package orm

import (
	"encoding/json"
	fmt "fmt"
	"net/http"
	"sort"
	"strconv"
	"testing"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/harbor-api/models"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/require"
)

type HarborMock struct {
	bareAddr       string
	addr           string
	admin          string
	password       string
	projects       map[int32]*models.Project
	projectMembers map[int32]map[int64]*models.ProjectMemberEntity
	labels         map[int64]*models.Label
	robots         map[int64]*models.Robot
	config         models.Configurations
	nextProjectID  int32
	nextMemberID   int64
	nextLabelID    int64
	nextRobotID    int64
	mockTransport  *httpmock.MockTransport
}

func NewHarborMock(addr string, tr *httpmock.MockTransport, admin, password string) *HarborMock {
	hm := HarborMock{}
	hm.bareAddr = addr
	hm.addr = addr + "/api/v2.0"
	hm.admin = admin
	hm.password = password
	hm.mockTransport = tr
	hm.initData()

	hm.registerProjects()
	hm.registerProjectMembers()
	hm.registerLabels()
	hm.registerRobots()
	hm.registerConfigurations()
	return &hm
}

func (s *HarborMock) initData() {
	s.projects = make(map[int32]*models.Project)
	s.projectMembers = make(map[int32]map[int64]*models.ProjectMemberEntity)
	s.labels = make(map[int64]*models.Label)
	s.robots = make(map[int64]*models.Robot)
	s.config.RobotNamePrefix = stringRef("robot$")
	s.nextProjectID = 1
	s.nextMemberID = 1
	s.nextLabelID = 1
	s.nextRobotID = 1
}

func (s *HarborMock) registerProjects() {
	u := fmt.Sprintf("%s/projects", s.addr)
	log.DebugLog(log.DebugLevelApi, "harbor register projects", "url", u)
	s.mockTransport.RegisterResponder("POST", u,
		func(req *http.Request) (*http.Response, error) {
			if err := s.checkAuth(req); err != nil {
				return s.fail(403, err)
			}
			projReq := models.ProjectReq{}
			err := json.NewDecoder(req.Body).Decode(&projReq)
			if err != nil {
				return s.fail(400, err)
			}
			// check if name already exists
			for _, proj := range s.projects {
				if projReq.ProjectName == proj.Name {
					return s.fail(400, fmt.Errorf("project name already exists"))
				}
			}
			proj := models.Project{}
			proj.ProjectID = s.nextProjectID
			proj.Name = projReq.ProjectName
			proj.Metadata = projReq.Metadata
			s.nextProjectID++
			s.projects[proj.ProjectID] = &proj
			s.projectMembers[proj.ProjectID] = make(map[int64]*models.ProjectMemberEntity)
			log.DebugLog(log.DebugLevelApi, "harbor mock created project", "project", proj.Name)
			return httpmock.NewBytesResponse(201, []byte{}), nil
		},
	)
	s.mockTransport.RegisterResponder("GET", u,
		func(req *http.Request) (*http.Response, error) {
			if err := s.checkAuth(req); err != nil {
				return s.fail(403, err)
			}
			page, pageSize, err := getPageParams(req)
			if err != nil {
				return s.fail(400, err)
			}
			projects := []*models.Project{}
			for _, proj := range s.projects {
				projects = append(projects, proj)
			}
			sort.Slice(projects, func(i, j int) bool {
				return projects[i].ProjectID < projects[j].ProjectID
			})
			ret := []*models.Project{}
			for ii := pageSize * (page - 1); ii < pageSize*page && ii < len(projects); ii++ {
				ret = append(ret, projects[ii])
			}
			log.DebugLog(log.DebugLevelApi, "harbor mock get projects", "projects", ret)
			return httpmock.NewJsonResponse(200, ret)
		},
	)
	u = fmt.Sprintf(`=~^%s/projects/([^/]+)\z`, s.addr)
	s.mockTransport.RegisterResponder("GET", u,
		func(req *http.Request) (*http.Response, error) {
			if err := s.checkAuth(req); err != nil {
				return s.fail(403, err)
			}
			nameOrId := httpmock.MustGetSubmatch(req, 1)
			if id, err := strconv.ParseInt(nameOrId, 10, 64); err == nil {
				proj, ok := s.projects[int32(id)]
				if ok {
					return httpmock.NewJsonResponse(200, proj)
				}
			}
			for _, proj := range s.projects {
				if proj.Name == nameOrId {
					return httpmock.NewJsonResponse(200, proj)
				}
			}
			return s.fail(400, fmt.Errorf("project %s not found", nameOrId))
		},
	)
	s.mockTransport.RegisterResponder("DELETE", u,
		func(req *http.Request) (*http.Response, error) {
			if err := s.checkAuth(req); err != nil {
				return s.fail(403, err)
			}
			nameOrId := httpmock.MustGetSubmatch(req, 1)
			proj, code, err := s.lookupProj(nameOrId)
			if err != nil {
				return s.fail(code, err)
			}
			delete(s.projects, proj.ProjectID)
			delete(s.projectMembers, proj.ProjectID)
			for _, label := range s.labels {
				if label.Scope == "p" && int32(label.ProjectID) == proj.ProjectID {
					log.DebugLog(log.DebugLevelApi, "harbor mock deleted label", "label", label)
					delete(s.labels, label.ID)
				}
			}
			log.DebugLog(log.DebugLevelApi, "harbor mock deleted project", "project", nameOrId, "projectID", proj.ProjectID)
			for _, proj := range s.projects {
				log.DebugLog(log.DebugLevelApi, "remaining projects", "name", proj.Name)
			}
			return httpmock.NewJsonResponse(200, proj)
		},
	)
	s.mockTransport.RegisterResponder("PUT", u,
		func(req *http.Request) (*http.Response, error) {
			if err := s.checkAuth(req); err != nil {
				return s.fail(403, err)
			}
			projReq := models.ProjectReq{}
			err := json.NewDecoder(req.Body).Decode(&projReq)
			if err != nil {
				return s.fail(400, err)
			}
			nameOrId := httpmock.MustGetSubmatch(req, 1)
			proj, code, err := s.lookupProj(nameOrId)
			if err != nil {
				return s.fail(code, err)
			}
			// only support updating public visiblity now
			if projReq.Metadata.Public == harborTrue {
				proj.Metadata.Public = harborTrue
			} else if projReq.Metadata.Public == harborFalse {
				proj.Metadata.Public = harborFalse
			}
			log.DebugLog(log.DebugLevelApi, "harbor mock update project", "project", nameOrId)
			return httpmock.NewBytesResponse(200, []byte{}), nil
		},
	)
	u = fmt.Sprintf(`%s/service/token`, s.bareAddr)
	s.mockTransport.RegisterResponder("GET", u,
		func(req *http.Request) (*http.Response, error) {
			return httpmock.NewBytesResponse(200, []byte{}), nil
		},
	)
}

func (s *HarborMock) registerProjectMembers() {
	u := fmt.Sprintf(`=~^%s/projects/([^/]+)/members\z`, s.addr)
	s.mockTransport.RegisterResponder("POST", u,
		func(req *http.Request) (*http.Response, error) {
			if err := s.checkAuth(req); err != nil {
				return s.fail(403, err)
			}
			nameOrId := httpmock.MustGetSubmatch(req, 1)
			proj, code, err := s.lookupProj(nameOrId)
			if err != nil {
				return s.fail(code, err)
			}
			memberReq := models.ProjectMember{}
			err = json.NewDecoder(req.Body).Decode(&memberReq)
			if err != nil {
				return s.fail(400, err)
			}
			member := models.ProjectMemberEntity{}
			member.ProjectID = int64(proj.ProjectID)
			member.RoleID = memberReq.RoleID
			member.ID = s.nextMemberID
			s.nextMemberID++
			if memberReq.MemberUser != nil {
				member.EntityType = "u"
				member.EntityID = memberReq.MemberUser.UserID
				member.EntityName = memberReq.MemberUser.Username
			} else if memberReq.MemberGroup != nil {
				member.EntityType = "g"
				member.EntityID = memberReq.MemberGroup.ID
				member.EntityName = memberReq.MemberGroup.GroupName
			} else {
				return s.fail(400, fmt.Errorf("either member user or member group must be specified"))
			}
			log.DebugLog(log.DebugLevelApi, "harbor mock created project member", "member", member)
			members, _ := s.projectMembers[proj.ProjectID]
			members[member.ID] = &member
			return httpmock.NewBytesResponse(201, []byte{}), nil
		},
	)
	s.mockTransport.RegisterResponder("GET", u,
		func(req *http.Request) (*http.Response, error) {
			if err := s.checkAuth(req); err != nil {
				return s.fail(403, err)
			}
			nameOrId := httpmock.MustGetSubmatch(req, 1)
			proj, code, err := s.lookupProj(nameOrId)
			if err != nil {
				return s.fail(code, err)
			}
			page, pageSize, err := getPageParams(req)
			if err != nil {
				return s.fail(400, err)
			}
			members := []*models.ProjectMemberEntity{}
			m, _ := s.projectMembers[proj.ProjectID]
			for _, member := range m {
				members = append(members, member)
			}
			sort.Slice(members, func(i, j int) bool {
				return members[i].ID < members[j].ID
			})
			ret := []*models.ProjectMemberEntity{}
			for ii := pageSize * (page - 1); ii < pageSize*page && ii < len(members); ii++ {
				ret = append(ret, members[ii])
			}
			log.DebugLog(log.DebugLevelApi, "harbor mock get project members", "project", proj.Name, "page", page, "pagesize", pageSize, "members", ret)
			return httpmock.NewJsonResponse(200, ret)
		},
	)
	u = fmt.Sprintf(`=~^%s/projects/([^/]+)/members/([^/]+)\z`, s.addr)
	s.mockTransport.RegisterResponder("DELETE", u,
		func(req *http.Request) (*http.Response, error) {
			if err := s.checkAuth(req); err != nil {
				return s.fail(403, err)
			}
			nameOrId := httpmock.MustGetSubmatch(req, 1)
			mid := httpmock.MustGetSubmatch(req, 2)
			entity, code, err := s.lookupProjMember(nameOrId, mid)
			if err != nil {
				return s.fail(code, err)
			}
			members, ok := s.projectMembers[int32(entity.ProjectID)]
			if !ok {
				return s.fail(404, fmt.Errorf("MemberID not found"))
			}
			delete(members, entity.EntityID)
			log.DebugLog(log.DebugLevelApi, "harbor mock deleted project member", "project", nameOrId, "member", entity)
			return httpmock.NewBytesResponse(200, []byte{}), nil
		},
	)

}

func (s *HarborMock) registerLabels() {
	u := fmt.Sprintf("%s/labels", s.addr)
	s.mockTransport.RegisterResponder("POST", u,
		func(req *http.Request) (*http.Response, error) {
			if err := s.checkAuth(req); err != nil {
				return s.fail(403, err)
			}
			label := models.Label{}
			err := json.NewDecoder(req.Body).Decode(&label)
			if err != nil {
				return s.fail(400, err)
			}
			if label.Scope == "p" {
				if _, ok := s.projects[int32(label.ProjectID)]; !ok {
					return s.fail(404, fmt.Errorf("project not found"))
				}
			}
			label.ID = s.nextLabelID
			s.nextLabelID++
			s.labels[label.ID] = &label
			log.DebugLog(log.DebugLevelApi, "harbor mock created label", "label", label)
			return httpmock.NewBytesResponse(201, []byte{}), nil
		},
	)
	s.mockTransport.RegisterResponder("GET", u,
		func(req *http.Request) (*http.Response, error) {
			if err := s.checkAuth(req); err != nil {
				return s.fail(403, err)
			}
			params := req.URL.Query()
			name, _ := getQParam(params, "name")
			scope, _ := getQParam(params, "scope")
			var projectID int64
			if str, ok := getQParam(params, "project_id"); ok {
				val, err := strconv.ParseInt(str, 10, 64)
				if err != nil {
					return s.fail(400, err)
				}
				projectID = val
			}
			ret := []*models.Label{}
			for _, label := range s.labels {
				if name != "" && name != label.Name {
					continue
				}
				if scope != "" && scope != label.Scope {
					continue
				}
				if scope == "p" && projectID != 0 && projectID != label.ProjectID {
					continue
				}
				ret = append(ret, label)
			}
			log.DebugLog(log.DebugLevelApi, "harbor mock get labels", "name", name, "scope", scope, "projectID", projectID, "labels", ret)
			return httpmock.NewJsonResponse(200, ret)
		},
	)
}

func (s *HarborMock) lookupProj(nameOrId string) (*models.Project, int, error) {
	id, err := strconv.ParseInt(nameOrId, 10, 32)
	// look up by id
	if err == nil {
		proj, found := s.projects[int32(id)]
		if found {
			return proj, 200, nil
		}
	}
	// look up by name
	for _, proj := range s.projects {
		if proj.Name == nameOrId {
			return proj, 200, nil
		}
	}
	return nil, 404, fmt.Errorf("project %s not found", nameOrId)
}

func (s *HarborMock) registerRobots() {
	u := fmt.Sprintf("%s/robots", s.addr)
	log.DebugLog(log.DebugLevelApi, "harbor register projects", "url", u)
	s.mockTransport.RegisterResponder("POST", u,
		func(req *http.Request) (*http.Response, error) {
			if err := s.checkAuth(req); err != nil {
				return s.fail(403, err)
			}
			in := models.RobotCreate{}
			err := json.NewDecoder(req.Body).Decode(&in)
			if err != nil {
				return s.fail(400, err)
			}
			robot := models.Robot{}
			robot.ID = s.nextRobotID
			robot.Name = *s.config.RobotNamePrefix + in.Name
			robot.Description = in.Description
			robot.Secret = in.Secret
			robot.Level = in.Level
			robot.Duration = in.Duration
			robot.Permissions = in.Permissions
			s.nextRobotID++
			s.robots[robot.ID] = &robot
			log.DebugLog(log.DebugLevelApi, "harbor mock created robot", "robot", robot.Name)
			return httpmock.NewBytesResponse(201, []byte{}), nil
		},
	)
	s.mockTransport.RegisterResponder("GET", u,
		func(req *http.Request) (*http.Response, error) {
			if err := s.checkAuth(req); err != nil {
				return s.fail(403, err)
			}
			page, pageSize, err := getPageParams(req)
			if err != nil {
				return s.fail(400, err)
			}
			robots := []*models.Robot{}
			for _, r := range s.robots {
				robots = append(robots, r)
			}
			sort.Slice(robots, func(i, j int) bool {
				return robots[i].ID < robots[j].ID
			})
			ret := []*models.Robot{}
			for ii := pageSize * (page - 1); ii < pageSize*page && ii < len(robots); ii++ {
				ret = append(ret, robots[ii])
			}
			log.DebugLog(log.DebugLevelApi, "harbor mock get robots", "robots", robots)
			return httpmock.NewJsonResponse(200, ret)
		},
	)
	u = fmt.Sprintf(`=~^%s/robots/([^/]+)\z`, s.addr)
	s.mockTransport.RegisterResponder("PUT", u,
		func(req *http.Request) (*http.Response, error) {
			if err := s.checkAuth(req); err != nil {
				return s.fail(403, err)
			}
			idstr := httpmock.MustGetSubmatch(req, 1)
			id, err := strconv.ParseInt(idstr, 10, 64)
			if err != nil {
				return s.fail(400, err)
			}
			in := models.Robot{}
			err = json.NewDecoder(req.Body).Decode(&in)
			if err != nil {
				return s.fail(400, err)
			}
			robot, found := s.robots[id]
			if !found {
				return s.fail(400, fmt.Errorf("robot not found"))
			}
			if in.Permissions != nil {
				robot.Permissions = in.Permissions
			}
			log.DebugLog(log.DebugLevelApi, "harbor mock updated robot permissions", "robot", idstr)
			return httpmock.NewBytesResponse(200, []byte{}), nil
		},
	)
	s.mockTransport.RegisterResponder("PATCH", u,
		func(req *http.Request) (*http.Response, error) {
			if err := s.checkAuth(req); err != nil {
				return s.fail(403, err)
			}
			idstr := httpmock.MustGetSubmatch(req, 1)
			id, err := strconv.ParseInt(idstr, 10, 64)
			if err != nil {
				return s.fail(400, err)
			}
			in := models.RobotSec{}
			err = json.NewDecoder(req.Body).Decode(&in)
			if err != nil {
				return s.fail(400, err)
			}
			robot, found := s.robots[id]
			if !found {
				return s.fail(400, fmt.Errorf("robot not found"))
			}
			robot.Secret = in.Secret
			log.DebugLog(log.DebugLevelApi, "harbor mock updated robot secret", "robot", idstr)
			return httpmock.NewBytesResponse(200, []byte{}), nil
		},
	)
}

func (s *HarborMock) registerConfigurations() {
	u := fmt.Sprintf("%s/configurations", s.addr)
	log.DebugLog(log.DebugLevelApi, "harbor register projects", "url", u)
	s.mockTransport.RegisterResponder("PUT", u,
		func(req *http.Request) (*http.Response, error) {
			if err := s.checkAuth(req); err != nil {
				return s.fail(403, err)
			}
			in := models.Configurations{}
			err := json.NewDecoder(req.Body).Decode(&in)
			if err != nil {
				return s.fail(400, err)
			}
			// ignore fields that don't matter for testing
			if in.RobotNamePrefix != nil {
				s.config.RobotNamePrefix = in.RobotNamePrefix
			}
			return httpmock.NewBytesResponse(200, []byte{}), nil
		},
	)
}

func (s *HarborMock) lookupProjMember(projNameOrId string, memberId string) (*models.ProjectMemberEntity, int, error) {
	proj, code, err := s.lookupProj(projNameOrId)
	if err != nil {
		return nil, code, err
	}
	mid, err := strconv.ParseInt(memberId, 10, 64)
	if err != nil {
		return nil, 400, fmt.Errorf("Parse memberID as int64 failed, %s", err)
	}
	members, ok := s.projectMembers[proj.ProjectID]
	if !ok {
		return nil, 400, fmt.Errorf("MemberID not found")
	}
	member, found := members[mid]
	if !found {
		return nil, 404, fmt.Errorf("MemberID not found")
	}
	return member, 200, nil
}

func (s *HarborMock) checkAuth(req *http.Request) error {
	u, p, ok := req.BasicAuth()
	if !ok {
		return fmt.Errorf("no basic auth")
	}
	if u != s.admin && p != s.password {
		return fmt.Errorf("invalid username or password")
	}
	return nil
}

type harborErrMsg struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type harborErr struct {
	Errors []harborErrMsg `json:"errors"`
}

func (s *HarborMock) fail(code int, err error) (*http.Response, error) {
	obj := harborErr{
		Errors: []harborErrMsg{{
			Code:    code,
			Message: err.Error(),
		}},
	}
	return httpmock.NewJsonResponse(code, &obj)
}

func getPageParams(req *http.Request) (int, int, error) {
	params := req.URL.Query()
	page := 1
	pageSize := 10
	if val, ok := getQParamInt(params, "page"); ok {
		if val <= 0 {
			return 0, 0, fmt.Errorf("page must be > 0")
		}
		page = int(val)
	}
	if val, ok := getQParamInt(params, "page_size"); ok {
		if val <= 0 {
			return 0, 0, fmt.Errorf("page size must be > 0")
		}
		pageSize = int(val)
	}
	return page, pageSize, nil
}

func getQParam(values map[string][]string, key string) (string, bool) {
	if p, ok := values[key]; ok && len(p) > 0 {
		return p[0], true
	}
	return "", false
}

func getQParamInt(values map[string][]string, key string) (int64, bool) {
	if str, ok := getQParam(values, key); ok {
		if val, err := strconv.ParseInt(str, 10, 64); err == nil {
			return val, true
		}
	}
	return 0, false
}

func (s *HarborMock) verify(t *testing.T, v entry, objType string) {
	// verify projects
	log.DebugLog(log.DebugLevelApi, "harbor mock verify entry", "entry", v)
	orgName := HarborProjectSanitize(v.Org)
	proj := s.getProject(orgName)
	if v.OrgType == OrgTypeOperator && objType != OldOperObj {
		require.Nil(t, proj, "no project for operator org")
		return
	}
	require.NotNil(t, proj, "project exists")
	require.Equal(t, orgName, proj.Name)
	// project must have edge cloud label
	found := false
	for _, label := range s.labels {
		if label.Scope == "p" && label.Name == HarborProjectManaged && label.ProjectID == int64(proj.ProjectID) {
			found = true
			break
		}
	}
	require.True(t, found, "managed project label")

	// verify project members
	for username, userType := range v.Users {
		log.DebugLog(log.DebugLevelApi, "harbor mock verify user", "user", username, "type", userType)
		member, found := s.getProjectMember(proj.ProjectID, username)
		require.True(t, found, "member found")
		roleID := harborGetRoleID(userType)
		require.Equal(t, roleID, member.RoleID)
	}
}

func (s *HarborMock) verifyCount(t *testing.T, entries []entry, objType string) {
	// extra edgecloudorg project
	numProj := 1
	for _, v := range entries {
		orgName := HarborProjectSanitize(v.Org)
		proj := s.getProject(orgName)
		if v.OrgType == OrgTypeOperator {
			require.Nil(t, proj, "project not exists")
			continue
		}
		require.NotNil(t, proj, "project exists")
		numProj++
		numMembers := len(v.Users)
		require.Equal(t, numMembers, len(s.projectMembers[proj.ProjectID]), "project members")
	}
	require.Equal(t, numProj, len(s.projects), "projects")
	// one label per project
	require.Equal(t, numProj, len(s.labels), "labels")
}

func (s *HarborMock) verifyEmpty(t *testing.T) {
	for _, proj := range s.projects {
		log.DebugLog(log.DebugLevelApi, "verifyEmpty", "project", proj.Name)
	}
	numMembers := 0
	for _, members := range s.projectMembers {
		for _, member := range members {
			numMembers++
			log.DebugLog(log.DebugLevelApi, "verifyEmpty", "projectMember", *member)
		}
	}
	for _, label := range s.labels {
		log.DebugLog(log.DebugLevelApi, "verifyEmpty", "label", *label)
	}

	require.Equal(t, 1, len(s.projects), "no projects")
	require.Equal(t, 0, numMembers, "no members")
	require.Equal(t, 1, len(s.labels), "no labels")
}

func (s *HarborMock) getProject(nameOrID string) *models.Project {
	id, err := strconv.ParseInt(nameOrID, 10, 64)
	if err == nil {
		if proj, ok := s.projects[int32(id)]; ok {
			return proj
		}
	}
	for _, proj := range s.projects {
		if nameOrID == proj.Name {
			return proj
		}
	}
	return nil
}

func (s *HarborMock) getProjectMember(projectID int32, username string) (*models.ProjectMemberEntity, bool) {
	members, ok := s.projectMembers[projectID]
	if !ok {
		return nil, false
	}
	for _, member := range members {
		if member.EntityName == username {
			return member, true
		}
	}
	return nil, false
}

func TestHarborSanitize(t *testing.T) {
	data := []struct {
		in  string
		out string
	}{
		{"-foo_", "foo"},
		{".bar-", "bar"},
		{"_CAT.", "cat"},
		{"._-", ""},
		{"", ""},
		{"fOO_-.bAR", "foo_-.bar"},
		{"foo$%^bar", "foo---bar"},
		{"%$_foo_$%", "foo"},
	}
	for _, d := range data {
		out := HarborProjectSanitize(d.in)
		require.Equal(t, d.out, out)
	}
}