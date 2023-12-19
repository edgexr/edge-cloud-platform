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
	"strings"
	"time"

	edgeproto "github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
	"github.com/edgexr/harbor-api/models"
	"github.com/google/uuid"
)

const (
	HarborProjectManaged     = "ManagedByEdgeCloud"
	HarborRobotName          = "edgecloudpull"
	HarborProjectRobotName   = "projpull"
	HarborRobotPrefix        = "robot$"
	HarborAdminAuthVaultPath = "/accounts/harbor"
)

var harborFalse = "false"
var harborTrue = "true"
var harborScopeProject = "p"
var harborLdapScopeSubtree = int64(2)
var harborAuth *cloudcommon.RegistryAuth
var harborClient *http.Client
var harborEdgeCloudOrg = ormapi.Organization{
	Name: edgeproto.OrganizationEdgeCloud,
	Type: OrgTypeDeveloper,
}

func harborEnabled(ctx context.Context) bool {
	if serverConfig.HarborAddr == "" || harborClient == nil {
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
		auth := cloudcommon.RegistryAuth{}
		vaultPath := "/secret/data" + HarborAdminAuthVaultPath
		err := vault.GetData(serverConfig.vaultConfig, vaultPath, 0, &auth)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfo, "failed to get harbor Auth from Vault", "vaultPath", vaultPath, "vaultAddr", serverConfig.VaultAddr, "err", err)
			return nil, fmt.Errorf("failed to get harbor Auth from Vault")
		}
		auth.AuthType = cloudcommon.BasicAuth
		harborAuth = &auth
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

func harborDoReq(ctx context.Context, method, url string, obj interface{}) (int, []byte, error) {
	bodyReader := bytes.NewReader([]byte{})
	reqUrl := harborGetAddr() + url
	if obj != nil {
		jsonData, err := json.Marshal(obj)
		if err != nil {
			return 0, nil, err
		}
		bodyReader = bytes.NewReader(jsonData)
	}
	req, err := harborNewAuthReq(ctx, method, reqUrl, bodyReader)
	if err != nil {
		return 0, nil, err
	}
	resp, err := harborClient.Do(req)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "harbor req failed", "method", method, "url", reqUrl, "err", err)
		return 0, nil, err
	}
	log.SpanLog(ctx, log.DebugLevelApi, "harbor req", "method", method, "url", reqUrl, "status", resp.StatusCode)
	defer resp.Body.Close()
	resBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, resBody, nil
}

func harborCreateProject(ctx context.Context, org *ormapi.Organization) {
	if !harborEnabled(ctx) {
		return
	}
	if org.Type == OrgTypeOperator {
		return
	}
	orgName := HarborProjectSanitize(org.Name)

	public := "false"
	if org.PublicImages {
		public = "true"
	}
	severity := "critical"

	projReq := models.ProjectReq{
		ProjectName: orgName,
		Metadata: &models.ProjectMetadata{
			Public:                   public,
			EnableContentTrust:       &harborFalse, // TODO: support signed images
			EnableContentTrustCosign: &harborFalse, // TODO: support cosign images
			Severity:                 &severity,    // vulnerability severity for image pull block
			AutoScan:                 &harborTrue,
		},
	}
	code, resBody, err := harborDoReq(ctx, http.MethodPost, "/projects", &projReq)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "harbor create project err", "org", org.Name, "err", err)
		harborSync.NeedsSync()
		return
	}
	if code != http.StatusCreated {
		if strings.Contains(string(resBody), "already exists") {
			log.SpanLog(ctx, log.DebugLevelApi, "harbor create project already exists", "org", org.Name, "code", code, "resp", string(resBody))
			return
		}
		log.SpanLog(ctx, log.DebugLevelApi, "harbor create project failed", "org", org.Name, "code", code, "resp", string(resBody))
		harborSync.NeedsSync()
		return
	}
	var proj *models.Project
	proj, err = harborGetProject(ctx, orgName)
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
	// create robot account for pulling
	err = harborEnsureRobotAccount(ctx, serverConfig.HarborAddr, org.Name)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "harbor create project ensure robot account", "org", org.Name, "err", err)
		harborSync.NeedsSync()
	}
}

func harborDeleteProject(ctx context.Context, orgName string) {
	if !harborEnabled(ctx) {
		return
	}
	orgName = HarborProjectSanitize(orgName)
	code, resBody, err := harborDoReq(ctx, http.MethodDelete, "/projects/"+orgName, nil)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "harbor delete project err", "org", orgName, "err", err)
		harborSync.NeedsSync()
		return
	}
	if code != http.StatusOK {
		log.SpanLog(ctx, log.DebugLevelApi, "harbor delete project failed", "org", orgName, "code", code, "resp", string(resBody))
		harborSync.NeedsSync()
		return
	}
}

func harborUpdateProjectVisibility(ctx context.Context, org *ormapi.Organization) error {
	if !harborEnabled(ctx) {
		return nil
	}
	public := harborFalse
	if org.PublicImages {
		public = harborTrue
	}

	orgName := HarborProjectSanitize(org.Name)
	projReq := models.ProjectReq{
		ProjectName: orgName,
		Metadata: &models.ProjectMetadata{
			Public: public,
		},
	}
	code, resBody, err := harborDoReq(ctx, http.MethodPut, "/projects/"+orgName, &projReq)
	if err != nil {
		return err
	}
	if code == http.StatusOK {
		return nil
	}
	return fmt.Errorf("update project failed: code %d, resp %s", code, string(resBody))
}

func harborGetRoleID(mcRole string) int64 {
	// 1: Project Admin
	// 2: Developer
	// 3: Guest
	// 4: Maintainer
	if mcRole == RoleDeveloperManager {
		return 4 // maintainer
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
	orgName := HarborProjectSanitize(role.Org)

	member := models.ProjectMember{
		RoleID: harborGetRoleID(role.Role),
		MemberUser: &models.UserEntity{
			Username: role.Username,
		},
	}
	path := "/projects/" + orgName + "/members"
	code, resBody, err := harborDoReq(ctx, http.MethodPost, path, &member)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "harbor add project member err", "org", role.Org, "user", role.Username, "err", err)
		harborSync.NeedsSync()
		return
	}
	if code != http.StatusCreated {
		log.SpanLog(ctx, log.DebugLevelApi, "harbor add project member failed", "org", role.Org, "user", role.Username, "code", code, "resp", string(resBody))
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
	projectName = HarborProjectSanitize(projectName)
	path := fmt.Sprintf("/projects/%s/members/%d", projectName, memberID)
	code, resBody, err := harborDoReq(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return err
	}
	if code == http.StatusOK {
		return nil
	}
	return fmt.Errorf("remove project member id %d failed: code %d, resp %s", memberID, code, string(resBody))
}

func harborSetProjectLabel(ctx context.Context, projectID int32) error {
	if !harborEnabled(ctx) {
		return fmt.Errorf("harbor address not configured")
	}
	label := models.Label{
		Name:        HarborProjectManaged,
		Description: "Project is managed by Edge Cloud",
		Color:       "#343DAC",
		Scope:       harborScopeProject,
		ProjectID:   int64(projectID),
	}
	code, resBody, err := harborDoReq(ctx, http.MethodPost, "/labels", &label)
	if err != nil {
		return err
	}
	if code == http.StatusCreated {
		return nil
	}
	return fmt.Errorf("set project label failed: code %d, resp %s", code, string(resBody))
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
	query.Add("scope", harborScopeProject)
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
	path := "/projects/" + strings.ToLower(nameOrId)
	code, resBody, err := harborDoReq(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("code %d, resp %s", code, string(resBody))
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
	err := harborGetPages(ctx, reqUrl, nil, func(resBody []byte) (int, error) {
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
	orgName = HarborProjectSanitize(orgName)
	reqUrl := harborGetAddr() + "/projects/" + orgName + "/members"
	members := []models.ProjectMemberEntity{}
	err := harborGetPages(ctx, reqUrl, nil, func(resBody []byte) (int, error) {
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

func harborGetRobots(ctx context.Context, projID int64) ([]models.Robot, error) {
	if !harborEnabled(ctx) {
		return nil, fmt.Errorf("harbor address not configured")
	}
	reqUrl := harborGetAddr() + "/robots"
	queryParams := map[string]string{}
	if projID != int64(-1) {
		queryParams["q"] = fmt.Sprintf("Level=project,ProjectID=%d", projID)
	}
	robots := []models.Robot{}
	err := harborGetPages(ctx, reqUrl, queryParams, func(resBody []byte) (int, error) {
		rs := []models.Robot{}
		err := json.Unmarshal(resBody, &rs)
		if err != nil {
			return 0, err
		}
		robots = append(robots, rs...)
		return len(rs), nil
	})
	if err != nil {
		return nil, err
	}
	return robots, err
}

func harborGetRobotPull(ctx context.Context, org string) (*models.Robot, error) {
	if !harborEnabled(ctx) {
		return nil, fmt.Errorf("harbor address not configured")
	}
	projID := int64(-1)
	name := getHarborRobotName(org, harborRobotPostCreate)
	if org != cloudcommon.AllOrgs {
		// project level
		proj, err := harborGetProject(ctx, org)
		if err != nil {
			return nil, err
		}
		projID = int64(proj.ProjectID)
	}
	robots, err := harborGetRobots(ctx, projID)
	if err != nil {
		return nil, err
	}
	for _, r := range robots {
		log.SpanLog(ctx, log.DebugLevelApi, "harbor get robot account", "robot", r)
		if r.Name == name {
			return &r, nil
		}
	}
	return nil, fmt.Errorf("robot pull account not found")
}

func harborGetPages(ctx context.Context, reqUrl string, queryParams map[string]string, callback func(bodyData []byte) (int, error)) error {
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
		if queryParams != nil {
			for k, v := range queryParams {
				query.Set(k, v)
			}
		}
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

func harborEnsureApiKey(ctx context.Context, harborHostPort, org string) (*cloudcommon.RegistryAuth, error) {
	err := serverConfig.regAuthMgr.UpgradeRegistryAuth(ctx, cloudcommon.InternalDockerRegistry, org)
	if err != nil {
		return nil, err
	}
	auth, err := serverConfig.regAuthMgr.GetRegistryOrgAuth(ctx, harborHostPort, org)
	if err != nil {
		return nil, err
	}
	if auth.AuthType != cloudcommon.NoAuth {
		return auth, nil
	}
	// does not exist, create it now
	key := uuid.New().String()
	// harbor key requires > 8 chars, at least 1 lower case letter,
	// 1 upper case letter, and one digit. To ensure we're compliant
	// (UUID doesn't use upper case), add a suffix.
	key += "-Harb0r"
	auth = &cloudcommon.RegistryAuth{
		AuthType: cloudcommon.BasicAuth,
		Username: getHarborRobotName(org, harborRobotPostCreate),
		Password: key,
	}
	// will not overwrite existing secret, avoids race condition with another
	// process calling GetHarborApiKey.
	err = serverConfig.regAuthMgr.PutRegistryAuth(ctx, harborHostPort, org, auth, 0)
	if vault.IsCheckAndSetError(err) {
		// already exists
		err = nil
	}
	if err != nil {
		return nil, err
	}
	return auth, nil
}

func harborEnsureRobotAccount(ctx context.Context, harborHostPort, org string) error {
	if !harborEnabled(ctx) {
		return nil
	}
	name := getHarborRobotName(org, harborRobotPreCreate)
	level := "system"
	namespace := "*"
	if org != cloudcommon.AllOrgs {
		level = "project"
		namespace = HarborProjectSanitize(org)
	}

	// ensure api key is present in Vault
	auth, err := harborEnsureApiKey(ctx, harborHostPort, org)
	if err != nil {
		return err
	}
	if auth.AuthType != cloudcommon.BasicAuth {
		return fmt.Errorf("unexpected auth type %s from %s vault key, expected %s", auth.AuthType, harborHostPort, cloudcommon.BasicAuth)
	}

	// setup up permissions
	access := []*models.Access{{
		Resource: "repository",
		Action:   "pull",
	}, {
		Resource: "artifact",
		Action:   "read",
	}, {
		Resource: "helm-chart",
		Action:   "read",
	}, {
		Resource: "tag",
		Action:   "list",
	}}

	// Try to create the account, it may already exist
	robot := models.RobotCreate{
		Name:        name,
		Description: "Account for cloudlets to pull images",
		Level:       level,
		Duration:    -1,
		Permissions: []*models.RobotPermission{{
			Kind:      "project",
			Namespace: namespace,
			Access:    access,
		}},
	}
	log.SpanLog(ctx, log.DebugLevelApi, "creating harbor robot account", "name", name, "org", org, "payload", robot)
	code, resBody, err := harborDoReq(ctx, http.MethodPost, "/robots", &robot)
	if err != nil {
		return err
	}
	var id int64
	ensureFailed := false
	if code == http.StatusOK || code == http.StatusCreated {
		created := models.RobotCreated{}
		err = json.Unmarshal(resBody, &created)
		if err != nil {
			return fmt.Errorf("failed to unmarshal robot account created response: %s", err)
		}
		id = created.ID
	} else if code == http.StatusConflict {
		// account exists, make sure permissions are set correctly
		updateRobot, err := harborGetRobotPull(ctx, org)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "lookup harbor robot account failed", "name", name, "org", org, "err", err)
			return err
		}
		updateRobot.Permissions = robot.Permissions
		updateRobot.Editable = true
		id = updateRobot.ID
		path := fmt.Sprintf("/robots/%d", updateRobot.ID)
		code, resBody, err = harborDoReq(ctx, http.MethodPut, path, updateRobot)
		if err != nil {
			return fmt.Errorf("update robot account failed, %v", err)
		}
		// even if failed, continue to update password
		if code != http.StatusOK {
			ensureFailed = true
			log.SpanLog(ctx, log.DebugLevelApi, "harbor update robot account permissions failed", "payload", updateRobot, "status", code, "resp", resBody)
		}
	} else {
		// continue on failure
		log.SpanLog(ctx, log.DebugLevelApi, "harbor create robot unhandled response", "status", code, "resp", resBody, "payload", robot)
		ensureFailed = true
	}

	// there's no way to read the secret, so in case the secret changed
	// in Vault, re-write it to Harbor.
	rsec := models.RobotSec{
		Secret: auth.Password,
	}
	path := fmt.Sprintf("/robots/%d", id)
	code, resBody, err = harborDoReq(ctx, http.MethodPatch, path, &rsec)
	if err != nil {
		return fmt.Errorf("update robot secret failed, %v", err)
	}
	if code != http.StatusOK {
		return fmt.Errorf("update robot secret failed, code %d, resp %s", code, string(resBody))
	}
	if ensureFailed {
		return fmt.Errorf("ensure robot account encountered failure(s)")
	}
	return nil
}

func stringRef(str string) *string {
	return &str
}

const (
	harborRobotPreCreate  = "pre"
	harborRobotPostCreate = "post"
)

// Get the harbor robot name for the org.
// Harbor adds a bunch of stuff to the name after the robot is created.
func getHarborRobotName(org, createState string) string {
	// we have one robot account for all orgs,
	// and one robot account per org for reduced perms.
	var name string
	if org == cloudcommon.AllOrgs {
		name = HarborRobotName
	} else {
		name = HarborProjectRobotName
	}
	if createState == harborRobotPreCreate {
		return name
	}

	// If account was already created, then name has the prefix
	// added, and if it's a project-based account, the project name
	// is also automatically added by harbor.
	if org == cloudcommon.AllOrgs {
		return HarborRobotPrefix + name
	} else {
		// project based account
		return HarborRobotPrefix + strings.ToLower(org) + "+" + name
	}
}

func harborEnsureConfiguration(ctx context.Context) error {
	// use internal connection within the operator, otherwise
	// get url from env var.
	harborLdapUrl := "ldap://mc-internal.default:9389"
	if u := os.Getenv("HARBOR_LDAP_URL"); u != "" {
		harborLdapUrl = u
	}
	ldapUsername := "cn=" + serverConfig.LDAPUsername + ",ou=users"
	ldapPassword := serverConfig.LDAPPassword

	log.SpanLog(ctx, log.DebugLevelApi, "harbor ensure config")
	config := models.Configurations{
		AuthMode:                     stringRef("ldap_auth"),
		LdapURL:                      &harborLdapUrl,
		LdapSearchDn:                 stringRef(ldapUsername),
		LdapSearchPassword:           stringRef(ldapPassword),
		LdapBaseDn:                   stringRef("ou=users"),
		LdapFilter:                   stringRef(""),
		LdapUID:                      stringRef("cn"),
		LdapScope:                    &harborLdapScopeSubtree,
		LdapGroupBaseDn:              stringRef("ou=orgs"),
		LdapGroupSearchFilter:        stringRef("objectclass=groupOfUniqueNames"),
		LdapGroupAttributeName:       stringRef("cn"),
		LdapGroupAdminDn:             stringRef(fmt.Sprintf("cn=%s,ou=orgs", edgeproto.OrganizationEdgeCloud)),
		LdapGroupMembershipAttribute: stringRef(LdapGroupMembership),
		LdapGroupSearchScope:         &harborLdapScopeSubtree,
		ProjectCreationRestriction:   stringRef("adminonly"),
		RobotNamePrefix:              stringRef(HarborRobotPrefix),
	}
	code, resBody, err := harborDoReq(ctx, http.MethodPut, "/configurations", &config)
	if err != nil {
		return err
	}
	if code == http.StatusOK {
		return nil
	}
	return fmt.Errorf("harbor update config failed: code %d, resp %s", code, string(resBody))
}

func harborInit(ctx context.Context) error {
	if serverConfig.HarborAddr == "" {
		return nil
	}
	if harborClient == nil {
		harborClient = &http.Client{
			Timeout: 5 * time.Second,
		}
	}

	harborHostPort := serverConfig.HarborAddr
	log.SpanLog(ctx, log.DebugLevelApi, "harbor init", "hostport", harborHostPort)

	// ensure api key is registered in harbor as a robot account
	err := harborEnsureRobotAccount(ctx, harborHostPort, cloudcommon.AllOrgs)
	if err != nil {
		return err
	}
	// ensure correct Harbor configuration
	err = harborEnsureConfiguration(ctx)
	if err != nil {
		return err
	}
	// ensure EdgeCloud project exists, as it will hold the
	// crm and shepherd container images.
	harborCreateProject(ctx, &harborEdgeCloudOrg)
	return nil
}
