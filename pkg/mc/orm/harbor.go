package orm

import (
	"bytes"
	"context"
	"encoding/json"
	fmt "fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/harbor-api/models"
)

const (
	HarborProjectManaged = "ManagedByEdgeCloud"
)

var harborFalse = "false"
var harborTrue = "true"
var harborAuth *cloudcommon.RegistryAuth
var harborClient = &http.Client{
	Timeout: 5 * time.Second,
}

func harborEnabled(ctx context.Context) bool {
	if serverConfig.HarborAddr == "" {
		return false
	}
	return true
}

func harborGetAddr() string {
	return serverConfig.HarborAddr + "/api/v2.0"
}

func harborNewAuthReq(ctx context.Context, method, url string, body io.Reader) (*http.Request, error) {
	if harborAuth == nil {
		// env vars should be used for testing only
		username := os.Getenv("HARBOR_USERNAME")
		password := os.Getenv("HARBOR_PASSWORD")
		if username != "" && password != "" {
			harborAuth = &cloudcommon.RegistryAuth{
				AuthType: cloudcommon.BasicAuth,
				Username: username,
				Password: password,
			}
		}
	}
	if harborAuth == nil {
		auth, err := cloudcommon.GetRegistryAuth(ctx, "docker."+serverConfig.DomainName, serverConfig.vaultConfig)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfo, "failed to get harbor Auth from Vault", "harborAddr", serverConfig.HarborAddr, "vaultAddr", serverConfig.VaultAddr, "err", err)
			return nil, fmt.Errorf("failed to get harbor Auth from Vault")
		}
		if auth.AuthType != cloudcommon.BasicAuth {
			log.SpanLog(ctx, log.DebugLevelInfo, "invalid auth type for harbor", "harborAddr", serverConfig.HarborAddr, "vaultAddr", serverConfig.VaultAddr, "authType", auth.AuthType)
			return nil, fmt.Errorf("invalid auth type for harbor from Vault")
		}
		harborAuth = auth
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.SetBasicAuth(harborAuth.Username, harborAuth.Password)
	return req, nil
}

func harborCreateProject(ctx context.Context, org *ormapi.Organization) {
	if !harborEnabled(ctx) {
		return
	}
	if org.Type == OrgTypeOperator {
		return
	}
	public := "false"
	if org.PublicImages {
		public = "true"
	}
	severity := "critical"

	projReq := models.ProjectReq{
		ProjectName: org.Name,
		Metadata: &models.ProjectMetadata{
			Public:                   public,
			EnableContentTrust:       &harborFalse, // TODO: support signed images
			EnableContentTrustCosign: &harborFalse, // TODO: support cosign images
			Severity:                 &severity,    // vulnerability severity for image pull block
			AutoScan:                 &harborTrue,
		},
	}
	jsonData, err := json.Marshal(&projReq)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "harbor create project marshal data", "org", org.Name, "err", err)
		harborSync.NeedsSync()
		return
	}
	bodyReader := bytes.NewReader(jsonData)

	reqUrl := harborGetAddr() + "/projects"
	req, err := harborNewAuthReq(ctx, http.MethodPost, reqUrl, bodyReader)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "harbor create project new req", "org", org.Name, "err", err)
		harborSync.NeedsSync()
		return
	}
	resp, err := harborClient.Do(req)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "harbor create project do req", "org", org.Name, "err", err)
		harborSync.NeedsSync()
		return
	}
	defer resp.Body.Close()
	resBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "harbor create project read resp", "org", org.Name, "err", err)
		harborSync.NeedsSync()
		return
	}
	if resp.StatusCode != http.StatusCreated {
		log.SpanLog(ctx, log.DebugLevelApi, "harbor create project failed", "org", org.Name, "code", resp.StatusCode, "resp", string(resBody))
		harborSync.NeedsSync()
		return
	}
	var proj *models.Project
	proj, err = harborGetProject(ctx, org.Name)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "harbor create project get created proj", "org", org.Name, "err", err)
		harborSync.NeedsSync()
		return
	}
	// add metadata to track it was created by EdgeCloud
	err = harborSetProjectLabel(ctx, proj.ProjectID)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "harbor create project set label", "org", org.Name, "err", err)
		harborSync.NeedsSync()
		return
	}
}

func harborDeleteProject(ctx context.Context, orgName string) {
	if !harborEnabled(ctx) {
		return
	}

	reqUrl := fmt.Sprintf("%s/projects/%s", harborGetAddr(), orgName)
	req, err := harborNewAuthReq(ctx, http.MethodDelete, reqUrl, nil)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "harbor delete project new req", "org", orgName, "err", err)
		harborSync.NeedsSync()
		return
	}
	resp, err := harborClient.Do(req)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "harbor delete project do req", "org", orgName, "err", err)
		harborSync.NeedsSync()
		return
	}
	defer resp.Body.Close()
	resBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "harbor delete project read resp", "org", orgName, "err", err)
		harborSync.NeedsSync()
		return
	}
	if resp.StatusCode != http.StatusOK {
		log.SpanLog(ctx, log.DebugLevelApi, "harbor delete project failed", "org", orgName, "code", resp.StatusCode, "resp", string(resBody))
		harborSync.NeedsSync()
		return
	}
}

func harborUpdateProjectVisibility(ctx context.Context, org *ormapi.Organization) error {
	if !harborEnabled(ctx) {
		return nil
	}
	public := "false"
	if org.PublicImages {
		public = "true"
	}

	projReq := models.ProjectReq{
		ProjectName: org.Name,
		Metadata: &models.ProjectMetadata{
			Public: public,
		},
	}
	jsonData, err := json.Marshal(projReq)
	if err != nil {
		return err
	}
	bodyReader := bytes.NewReader(jsonData)

	reqUrl := harborGetAddr() + "/projects/" + org.Name
	req, err := harborNewAuthReq(ctx, http.MethodPut, reqUrl, bodyReader)
	if err != nil {
		return err
	}
	resp, err := harborClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	defer resp.Body.Close()
	resBody, err := ioutil.ReadAll(resp.Body)
	if err == nil {
		err = fmt.Errorf("code %d, resp %s", resp.StatusCode, string(resBody))
	}
	return err
}

func harborGetRoleID(mcRole string) int64 {
	if mcRole == RoleDeveloperManager {
		return 1 // projectAdmin
	} else if mcRole == RoleDeveloperContributor {
		return 2 // developer
	}
	return 3 // guest
}

func harborAddProjectMember(ctx context.Context, role *ormapi.Role, orgType string) {
	if !harborEnabled(ctx) {
		return
	}
	if orgType == OrgTypeOperator {
		return
	}

	member := models.ProjectMember{
		RoleID: harborGetRoleID(role.Role),
		MemberUser: &models.UserEntity{
			Username: role.Username,
		},
	}
	jsonData, err := json.Marshal(member)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "harbor add project member marshal json", "org", role.Org, "user", role.Username, "err", err)
		harborSync.NeedsSync()
		return
	}
	bodyReader := bytes.NewReader(jsonData)

	reqUrl := harborGetAddr() + "/projects/" + role.Org + "/members"
	req, err := harborNewAuthReq(ctx, http.MethodPost, reqUrl, bodyReader)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "harbor add project member new req", "org", role.Org, "user", role.Username, "err", err)
		harborSync.NeedsSync()
		return
	}
	resp, err := harborClient.Do(req)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "harbor add project member do req", "org", role.Org, "user", role.Username, "err", err)
		harborSync.NeedsSync()
		return
	}
	defer resp.Body.Close()
	resBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "harbor add project member read resp", "org", role.Org, "user", role.Username, "err", err)
		harborSync.NeedsSync()
		return
	}
	if resp.StatusCode != http.StatusCreated {
		log.SpanLog(ctx, log.DebugLevelApi, "harbor add project member failed", "org", role.Org, "user", role.Username, "code", resp.StatusCode, "resp", string(resBody))
		harborSync.NeedsSync()
		return
	}
}

func harborRemoveProjectMember(ctx context.Context, role *ormapi.Role, orgType string) {
	if !harborEnabled(ctx) {
		return
	}
	if orgType == OrgTypeOperator {
		return
	}

	// need to look up member id from name
	members, err := harborGetProjectMembers(ctx, role.Org)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "harbor remove project member lookup members", "org", role.Org, "user", role.Username, "err", err)
		harborSync.NeedsSync()
		return
	}
	var memberID int64
	for _, member := range members {
		if member.EntityName == role.Username {
			memberID = member.ID
			break
		}
	}
	if memberID == 0 {
		log.SpanLog(ctx, log.DebugLevelApi, "harbor remove project member ID not found", "org", role.Org, "user", role.Username)
		harborSync.NeedsSync()
		return
	}
	err = harborRemoveProjectMemberId(ctx, role.Org, memberID)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "harbor remove project member failed", "org", role.Org, "user", role.Username, "err", err)
		harborSync.NeedsSync()
	}
}

func harborRemoveProjectMemberId(ctx context.Context, projectName string, memberID int64) error {
	reqUrl := fmt.Sprintf("%s/projects/%s/members/%d", harborGetAddr(), projectName, memberID)
	req, err := harborNewAuthReq(ctx, http.MethodDelete, reqUrl, nil)
	if err != nil {
		return err
	}
	resp, err := harborClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	defer resp.Body.Close()
	resBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return fmt.Errorf("code %d, resp %s", resp.StatusCode, string(resBody))
}

func harborSetProjectLabel(ctx context.Context, projectID int32) error {
	if !harborEnabled(ctx) {
		return fmt.Errorf("harbor address not configured")
	}
	label := models.Label{
		Name:        HarborProjectManaged,
		Description: "Project is managed by Edge Cloud",
		Color:       "#343DAC",
		Scope:       "p",
		ProjectID:   int64(projectID),
	}
	jsonData, err := json.Marshal(label)
	if err != nil {
		return err
	}
	bodyReader := bytes.NewReader(jsonData)
	reqUrl := harborGetAddr() + "/labels"
	req, err := harborNewAuthReq(ctx, http.MethodPost, reqUrl, bodyReader)
	if err != nil {
		return err
	}
	resp, err := harborClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusCreated {
		return nil
	}
	defer resp.Body.Close()
	resBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return fmt.Errorf("code %d, resp %s", resp.StatusCode, string(resBody))
}

func harborHasProjectLabel(ctx context.Context, projectID int32) (bool, error) {
	if !harborEnabled(ctx) {
		return false, fmt.Errorf("harbor address not configured")
	}

	reqUrl := harborGetAddr() + "/labels"
	req, err := harborNewAuthReq(ctx, http.MethodGet, reqUrl, nil)
	if err != nil {
		return false, err
	}
	query := req.URL.Query()
	query.Add("name", HarborProjectManaged)
	query.Add("scope", "p")
	query.Add("project_id", strconv.FormatInt(int64(projectID), 10))
	req.URL.RawQuery = query.Encode()

	resp, err := harborClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	resBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("code %d, resp %s", resp.StatusCode, string(resBody))
	}

	labels := []models.Label{}
	err = json.Unmarshal(resBody, &labels)
	if err != nil {
		return false, err
	}
	for _, label := range labels {
		if label.Name == HarborProjectManaged {
			return true, nil
		}
	}
	return false, nil
}

func harborGetProject(ctx context.Context, nameOrId string) (*models.Project, error) {
	if !harborEnabled(ctx) {
		return nil, fmt.Errorf("harbor address not configured")
	}
	reqUrl := harborGetAddr() + "/projects/" + nameOrId
	req, err := harborNewAuthReq(ctx, http.MethodGet, reqUrl, nil)
	if err != nil {
		return nil, err
	}
	resp, err := harborClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	resBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("code %d, resp %s", resp.StatusCode, string(resBody))
	}

	proj := models.Project{}
	err = json.Unmarshal(resBody, &proj)
	if err != nil {
		return nil, err
	}
	return &proj, err
}

func harborGetProjects(ctx context.Context) ([]models.Project, error) {
	if !harborEnabled(ctx) {
		return nil, fmt.Errorf("harbor address not configured")
	}
	reqUrl := harborGetAddr() + "/projects"
	projects := []models.Project{}
	err := harborGetPages(ctx, reqUrl, func(resBody []byte) (int, error) {
		ps := []models.Project{}
		err := json.Unmarshal(resBody, &ps)
		if err != nil {
			return 0, err
		}
		projects = append(projects, ps...)
		return len(ps), nil
	})
	if err != nil {
		return nil, err
	}
	return projects, nil
}

func harborGetProjectMembers(ctx context.Context, orgName string) ([]models.ProjectMemberEntity, error) {
	if !harborEnabled(ctx) {
		return nil, fmt.Errorf("harbor address not configured")
	}
	reqUrl := harborGetAddr() + "/projects/" + orgName + "/members"
	members := []models.ProjectMemberEntity{}
	err := harborGetPages(ctx, reqUrl, func(resBody []byte) (int, error) {
		mems := []models.ProjectMemberEntity{}
		err := json.Unmarshal(resBody, &mems)
		if err != nil {
			return 0, err
		}
		members = append(members, mems...)
		return len(mems), nil
	})
	if err != nil {
		return nil, err
	}
	return members, err
}

func harborGetPages(ctx context.Context, reqUrl string, callback func(bodyData []byte) (int, error)) error {
	page := 1
	pageSize := 50
	pageSizeStr := strconv.Itoa(pageSize)
	pageLimit := 100 // prevent infinite loop
	for ; page < pageLimit; page++ {
		req, err := harborNewAuthReq(ctx, http.MethodGet, reqUrl, nil)
		if err != nil {
			return fmt.Errorf("harbor get pages failed to create request for %s: %s", reqUrl, err)
		}
		query := req.URL.Query()
		query.Add("page", strconv.Itoa(page))
		query.Add("page_size", pageSizeStr)
		req.URL.RawQuery = query.Encode()

		resp, err := harborClient.Do(req)
		if err != nil {
			return fmt.Errorf("harbor get pages do %s: %s", reqUrl, err)
		}
		defer resp.Body.Close()
		resBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("harbor get pages read body %s: %s", reqUrl, err)
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("harbor get pages status %d %s: %s", resp.StatusCode, reqUrl, string(resBody))
		}
		count, err := callback(resBody)
		if err != nil {
			return fmt.Errorf("harbor get pages callback %s: %s", reqUrl, err)
		}
		if count < pageSize {
			break
		}
	}
	return nil
}
