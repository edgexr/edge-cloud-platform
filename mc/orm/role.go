package orm

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/log"
)

const ActionView = "view"
const ActionManage = "manage"

const ResourceControllers = "controllers"
const ResourceUsers = "users"
const ResourceApps = "apps"
const ResourceAppInsts = "appinsts"
const ResourceClusters = "clusters"
const ResourceClusterInsts = "clusterinsts"
const ResourceAppAnalytics = "appanalytics"
const ResourceClusterAnalytics = "clusteranalytics"
const ResourcePlatforms = "platforms"
const ResourceCloudlets = "cloudlets"
const ResourceCloudletAnalytics = "cloudletanalytics"
const ResourceClusterFlavors = "clusterflavors"
const ResourceFlavors = "flavors"
const ResourceConfig = "config"

var DeveloperResources = []string{
	ResourceApps,
	ResourceAppInsts,
	ResourceClusters,
	ResourceClusterInsts,
	ResourceAppAnalytics,
	ResourceClusterAnalytics,
}
var OperatorResources = []string{
	ResourceCloudlets,
	ResourceCloudletAnalytics,
}

// built-in roles
const RoleDeveloperManager = "DeveloperManager"
const RoleDeveloperContributor = "DeveloperContributor"
const RoleDeveloperViewer = "DeveloperViewer"
const RoleOperatorManager = "OperatorManager"
const RoleOperatorContributor = "OperatorContributor"
const RoleOperatorViewer = "OperatorViewer"
const RoleAdminManager = "AdminManager"
const RoleAdminContributor = "AdminContributor"
const RoleAdminViewer = "AdminViewer"

var AdminRoleID int64

func InitRolePerms(ctx context.Context) error {
	log.SpanLog(ctx, log.DebugLevelApi, "init roleperms")

	enforcer.AddPolicy(RoleAdminManager, ResourceControllers, ActionManage)
	enforcer.AddPolicy(RoleAdminManager, ResourceControllers, ActionView)
	enforcer.AddPolicy(RoleAdminManager, ResourceClusterFlavors, ActionManage)
	enforcer.AddPolicy(RoleAdminManager, ResourceClusterFlavors, ActionView)
	enforcer.AddPolicy(RoleAdminManager, ResourceFlavors, ActionManage)
	enforcer.AddPolicy(RoleAdminManager, ResourceFlavors, ActionView)
	enforcer.AddPolicy(RoleAdminManager, ResourceConfig, ActionManage)
	enforcer.AddPolicy(RoleAdminManager, ResourceConfig, ActionView)

	enforcer.AddPolicy(RoleDeveloperManager, ResourceUsers, ActionManage)
	enforcer.AddPolicy(RoleDeveloperManager, ResourceUsers, ActionView)
	enforcer.AddPolicy(RoleDeveloperContributor, ResourceUsers, ActionView)
	enforcer.AddPolicy(RoleDeveloperViewer, ResourceUsers, ActionView)

	enforcer.AddPolicy(RoleOperatorManager, ResourceUsers, ActionManage)
	enforcer.AddPolicy(RoleOperatorManager, ResourceUsers, ActionView)
	enforcer.AddPolicy(RoleOperatorContributor, ResourceUsers, ActionView)
	enforcer.AddPolicy(RoleOperatorViewer, ResourceUsers, ActionView)

	enforcer.AddPolicy(RoleAdminManager, ResourceUsers, ActionManage)
	enforcer.AddPolicy(RoleAdminManager, ResourceUsers, ActionView)
	enforcer.AddPolicy(RoleAdminContributor, ResourceUsers, ActionView)
	enforcer.AddPolicy(RoleAdminViewer, ResourceUsers, ActionView)

	for _, str := range DeveloperResources {
		enforcer.AddPolicy(RoleDeveloperManager, str, ActionManage)
		enforcer.AddPolicy(RoleDeveloperManager, str, ActionView)
		enforcer.AddPolicy(RoleDeveloperContributor, str, ActionManage)
		enforcer.AddPolicy(RoleDeveloperContributor, str, ActionView)
		enforcer.AddPolicy(RoleDeveloperViewer, str, ActionView)
		enforcer.AddPolicy(RoleAdminManager, str, ActionManage)
		enforcer.AddPolicy(RoleAdminManager, str, ActionView)
		enforcer.AddPolicy(RoleAdminContributor, str, ActionManage)
		enforcer.AddPolicy(RoleAdminContributor, str, ActionView)
		enforcer.AddPolicy(RoleAdminViewer, str, ActionView)
	}
	enforcer.AddPolicy(RoleDeveloperManager, ResourceCloudlets, ActionView)
	enforcer.AddPolicy(RoleDeveloperContributor, ResourceCloudlets, ActionView)
	enforcer.AddPolicy(RoleDeveloperViewer, ResourceCloudlets, ActionView)

	enforcer.AddPolicy(RoleDeveloperManager, ResourceFlavors, ActionView)
	enforcer.AddPolicy(RoleDeveloperContributor, ResourceFlavors, ActionView)
	enforcer.AddPolicy(RoleDeveloperViewer, ResourceFlavors, ActionView)

	enforcer.AddPolicy(RoleDeveloperManager, ResourceClusterFlavors, ActionView)
	enforcer.AddPolicy(RoleDeveloperContributor, ResourceClusterFlavors, ActionView)
	enforcer.AddPolicy(RoleDeveloperViewer, ResourceClusterFlavors, ActionView)

	for _, str := range OperatorResources {
		enforcer.AddPolicy(RoleOperatorManager, str, ActionManage)
		enforcer.AddPolicy(RoleOperatorManager, str, ActionView)
		enforcer.AddPolicy(RoleOperatorContributor, str, ActionManage)
		enforcer.AddPolicy(RoleOperatorContributor, str, ActionView)
		enforcer.AddPolicy(RoleOperatorViewer, str, ActionView)
		enforcer.AddPolicy(RoleAdminManager, str, ActionManage)
		enforcer.AddPolicy(RoleAdminManager, str, ActionView)
		enforcer.AddPolicy(RoleAdminContributor, str, ActionManage)
		enforcer.AddPolicy(RoleAdminContributor, str, ActionView)
		enforcer.AddPolicy(RoleAdminViewer, str, ActionView)
	}
	return nil
}

func ShowRolePerms(c echo.Context) error {
	_, err := getClaims(c)
	if err != nil {
		return nil
	}
	policies := enforcer.GetPolicy()
	ret := []*ormapi.RolePerm{}
	for ii, _ := range policies {
		if len(policies[ii]) < 3 {
			continue
		}
		perm := ormapi.RolePerm{
			Role:     policies[ii][0],
			Resource: policies[ii][1],
			Action:   policies[ii][2],
		}
		ret = append(ret, &perm)
	}
	return c.JSON(http.StatusOK, ret)
}

// Show roles assigned to the current user
func ShowRoleAssignment(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return nil
	}

	super := false
	if enforcer.Enforce(claims.Username, "", ResourceUsers, ActionView) {
		// super user, show all roles
		super = true
	}

	groupings := enforcer.GetGroupingPolicy()
	ret := []*ormapi.Role{}
	for ii, _ := range groupings {
		role := parseRole(groupings[ii])
		if role == nil {
			continue
		}
		if !super && claims.Username != role.Username {
			continue
		}
		ret = append(ret, role)
	}
	return c.JSON(http.StatusOK, ret)
}

// Parse out the roles stored by Casbin.
// The "group" in Casbin is really the Organization
// combined (via "::") with the Username. See the notes
// for userauth.go:createRbacModel().
func parseRole(grp []string) *ormapi.Role {
	if len(grp) < 2 {
		return nil
	}
	role := ormapi.Role{Role: grp[1]}
	domuser := strings.Split(grp[0], "::")
	if len(domuser) > 1 {
		role.Org = domuser[0]
		role.Username = domuser[1]
	} else {
		role.Username = grp[0]
	}
	return &role
}

func getCasbinGroup(org, username string) string {
	if org == "" {
		return username
	}
	return org + "::" + username
}

func ShowRole(c echo.Context) error {
	rolemap := make(map[string]struct{})
	policies := enforcer.GetPolicy()
	for _, policy := range policies {
		if len(policy) < 1 {
			continue
		}
		rolemap[policy[0]] = struct{}{}
	}
	roles := make([]string, 0)
	for role, _ := range rolemap {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	return c.JSON(http.StatusOK, roles)
}

func AddUserRole(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	role := ormapi.Role{}
	if err := c.Bind(&role); err != nil {
		return c.JSON(http.StatusBadRequest, Msg("Invalid POST data"))
	}
	err = AddUserRoleObj(GetContext(c), claims, &role)
	return setReply(c, err, Msg("Role added to user"))
}

func AddUserRoleObj(ctx context.Context, claims *UserClaims, role *ormapi.Role) error {
	if role.Username == "" {
		return fmt.Errorf("Username not specified")
	}
	if role.Role == "" {
		return fmt.Errorf("Role not specified")
	}
	if role.Org != "" {
		span := log.SpanFromContext(ctx)
		span.SetTag("org", role.Org)
	}
	// check that user/org/role exists
	targetUser := ormapi.User{}
	db := loggedDB(ctx)
	res := db.Where(&ormapi.User{Name: role.Username}).First(&targetUser)
	if res.RecordNotFound() {
		return fmt.Errorf("Username not found")
	}
	if res.Error != nil {
		return dbErr(res.Error)
	}
	policies := enforcer.GetPolicy()
	roleFound := false
	for _, policy := range policies {
		if len(policy) < 1 {
			continue
		}
		if policy[0] == role.Role {
			roleFound = true
			break
		}
	}
	if !roleFound {
		return fmt.Errorf("Role not found")
	}
	if role.Org != "" {
		org := &ormapi.Organization{}
		res = db.Where(&ormapi.Organization{Name: role.Org}).First(&org)
		if res.RecordNotFound() {
			return fmt.Errorf("Organization not found")
		}
		if res.Error != nil {
			return dbErr(res.Error)
		}
		// Restricting role types to match org types isn't strictly
		// necessary. For example, giving role AdminManager for
		// org foobar won't allow that user to modify controllers
		// or flavors or clusterflavors, because those perms are
		// tied to the blank org, "". But it does probably confuse
		// the user, so disallow it to prevent confusion.
		if org.Type == OrgTypeDeveloper && !isDeveloperRole(role.Role) {
			return fmt.Errorf("Can only assign developer roles for developer organization")
		}
		if org.Type == OrgTypeOperator && !isOperatorRole(role.Role) {
			return fmt.Errorf("Can only assign operator roles for operator organization")
		}
	}

	// make sure caller has perms to modify users of target org
	if !enforcer.Enforce(claims.Username, role.Org, ResourceUsers, ActionManage) {
		if role.Org == "" {
			return fmt.Errorf("Organization not specified or no permissions")
		}
		return echo.ErrForbidden
	}
	psub := getCasbinGroup(role.Org, role.Username)
	enforcer.AddGroupingPolicy(psub, role.Role)
	// notify recipient that they were added. don't fail on error
	senderr := sendAddedEmail(ctx, claims.Username, targetUser.Name, targetUser.Email, role.Org, role.Role)
	if senderr != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "failed to send role added email", "err", senderr)
	}

	gitlabAddGroupMember(ctx, role)
	artifactoryAddUserToGroup(ctx, role)
	return nil
}

func RemoveUserRole(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := GetContext(c)

	role := ormapi.Role{}
	if err := c.Bind(&role); err != nil {
		return c.JSON(http.StatusBadRequest, Msg("Invalid POST data"))
	}
	err = RemoveUserRoleObj(ctx, claims, &role)
	return setReply(c, err, Msg("Role removed from user"))
}

func RemoveUserRoleObj(ctx context.Context, claims *UserClaims, role *ormapi.Role) error {
	if role.Username == "" {
		return fmt.Errorf("Username not specified")
	}
	if role.Role == "" {
		return fmt.Errorf("Role not specified")
	}
	if role.Org != "" {
		span := log.SpanFromContext(ctx)
		span.SetTag("org", role.Org)
	}

	// Special case: if policy does not exist, return success.
	// This deals with a case in e2e-testing, where we delete the
	// Org first (which deletes all associated roles), and then try
	// to delete the manager role for the Org (which has already
	// been delete). Since it's deleted, the enforcer fails, causing
	// a forbidden error.
	psub := getCasbinGroup(role.Org, role.Username)
	if !enforcer.HasGroupingPolicy(psub, role.Role) {
		return nil
	}

	// make sure caller has perms to modify users of target org
	if !enforcer.Enforce(claims.Username, role.Org, ResourceUsers, ActionManage) {
		return echo.ErrForbidden
	}

	enforcer.RemoveGroupingPolicy(psub, role.Role)

	gitlabRemoveGroupMember(ctx, role)
	artifactoryRemoveUserFromGroup(ctx, role)

	return nil
}

func ShowUserRole(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	roles, err := ShowUserRoleObj(claims.Username)
	return setReply(c, err, roles)
}

// show roles for organizations the current user has permission to
// add/remove roles to. This "shows" all the actions taken by
// Add/RemoveUserRole.
func ShowUserRoleObj(username string) ([]ormapi.Role, error) {
	roles := []ormapi.Role{}

	groupings := enforcer.GetGroupingPolicy()
	for ii, _ := range groupings {
		role := parseRole(groupings[ii])
		if role == nil {
			continue
		}
		if !enforcer.Enforce(username, role.Org, ResourceUsers, ActionView) {
			continue
		}
		roles = append(roles, *role)
	}
	return roles, nil
}

func SyncAccessCheck(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	if !enforcer.Enforce(claims.Username, "", ResourceControllers, ActionManage) {
		return echo.ErrForbidden
	}
	return nil
}

// for debugging
func dumpRbac() {
	policies := enforcer.GetPolicy()
	for _, p := range policies {
		fmt.Printf("policy: %+v\n", p)
	}
	groups := enforcer.GetGroupingPolicy()
	for _, grp := range groups {
		fmt.Printf("group: %+v\n", grp)
	}
}

func isDeveloperRole(role string) bool {
	if role == RoleDeveloperManager ||
		role == RoleDeveloperContributor ||
		role == RoleDeveloperViewer {
		return true
	}
	return false
}

func isOperatorRole(role string) bool {
	if role == RoleOperatorManager ||
		role == RoleOperatorContributor ||
		role == RoleOperatorViewer {
		return true
	}
	return false
}
