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
	addr           string
	admin          string
	password       string
	projects       map[int32]*models.Project
	projectMembers map[int32]map[int64]*models.ProjectMemberEntity
	labels         map[int64]*models.Label
	nextProjectID  int32
	nextMemberID   int64
	nextLabelID    int64
	mockTransport  *httpmock.MockTransport
}

func NewHarborMock(addr string, tr *httpmock.MockTransport, admin, password string) *HarborMock {
	hm := HarborMock{}
	hm.addr = addr + "/api/v2.0"
	hm.admin = admin
	hm.password = password
	hm.mockTransport = tr
	hm.initData()

	hm.registerProjects()
	hm.registerProjectMembers()
	hm.registerLabels()
	return &hm
}

func (s *HarborMock) initData() {
	s.projects = make(map[int32]*models.Project)
	s.projectMembers = make(map[int32]map[int64]*models.ProjectMemberEntity)
	s.labels = make(map[int64]*models.Label)
	s.nextProjectID = 1
	s.nextMemberID = 1
	s.nextLabelID = 1
}

func (s *HarborMock) registerProjects() {
	u := fmt.Sprintf("%s/projects", s.addr)
	fmt.Printf("harbor register projects %s\n", u)
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
			params := req.URL.Query()
			page := 1
			pageSize := 10
			if val, ok := getQParamInt(params, "page"); ok {
				if val <= 0 {
					return s.fail(400, fmt.Errorf("page must be > 0"))
				}
				page = int(val)
			}
			if val, ok := getQParamInt(params, "page_size"); ok {
				if val <= 0 {
					return s.fail(400, fmt.Errorf("page size must be > 0"))
				}
				pageSize = int(val)
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
			log.DebugLog(log.DebugLevelApi, "harbor mock get projects", "projects", projects)
			return httpmock.NewJsonResponse(200, projects)
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
				s.fail(code, err)
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
			for id, label := range s.labels {
				log.DebugLog(log.DebugLevelApi, "remaining labels", "id", id, "label", *label)
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
				s.fail(code, err)
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
				s.fail(code, err)
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
				s.fail(400, fmt.Errorf("either member user or member group must be specified"))
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
				s.fail(code, err)
			}
			params := req.URL.Query()
			page := 1
			pageSize := 10
			if val, ok := getQParamInt(params, "page"); ok {
				if val <= 0 {
					return s.fail(400, fmt.Errorf("page must be > 0"))
				}
				page = int(val)
			}
			if val, ok := getQParamInt(params, "page_size"); ok {
				if val <= 0 {
					return s.fail(400, fmt.Errorf("page size must be > 0"))
				}
				pageSize = int(val)
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
				s.fail(code, err)
			}
			members, ok := s.projectMembers[int32(entity.ProjectID)]
			if !ok {
				s.fail(404, fmt.Errorf("MemberID not found"))
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
	fmt.Printf("harbor mock verify entry %s\n", v)
	proj := s.getProject(v.Org)
	if v.OrgType == OrgTypeOperator && objType != OldOperObj {
		require.Nil(t, proj, "no project for operator org")
		return
	}
	require.NotNil(t, proj, "project exists")
	require.Equal(t, v.Org, proj.Name)
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
		fmt.Printf("  harbor mock verify user %s %s\n", username, userType)
		member, found := s.getProjectMember(proj.ProjectID, username)
		require.True(t, found, "member found")
		roleID := harborGetRoleID(userType)
		require.Equal(t, roleID, member.RoleID)
	}
}

func (s *HarborMock) verifyCount(t *testing.T, entries []entry, objType string) {
	numProj := 0
	for _, v := range entries {
		proj := s.getProject(v.Org)
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
	require.Equal(t, 0, len(s.projects), "no projects")
	require.Equal(t, 0, len(s.projectMembers), "no members")
	require.Equal(t, 0, len(s.labels), "no labels")
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
