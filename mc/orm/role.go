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
	"sort"
	"strings"

	"github.com/labstack/echo"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud-infra/mc/ormutil"
	"github.com/edgexr/edge-cloud-infra/mc/rbac"
	"github.com/edgexr/edge-cloud/log"
)

const ActionView = "view"
const ActionManage = "manage"

const ResourceBilling = "billing"
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
const ResourceCloudletPools = "cloudletpools"
const ResourceCloudletAnalytics = "cloudletanalytics"
const ResourceClusterFlavors = "clusterflavors"
const ResourceFlavors = "flavors"
const ResourceConfig = "config"
const ResourceAlert = "alert"
const ResourceDeveloperPolicy = "developerpolicy"
const ResourceResTagTable = "restagtbl"

const ApiKeyRoleSuffix = "-role"

var DeveloperResources = []string{
	ResourceApps,
	ResourceAppInsts,
	ResourceClusters,
	ResourceClusterInsts,
	ResourceAppAnalytics,
	ResourceClusterAnalytics,
	ResourceDeveloperPolicy,
	ResourceAlert,
}
var OperatorResources = []string{
	ResourceCloudlets,
	ResourceCloudletAnalytics,
	ResourceResTagTable,
	ResourceCloudletPools,
	ResourceAlert,
}
var DeveloperResourcesMap map[string]struct{}
var OperatorResourcesMap map[string]struct{}

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
const RoleBillingManager = "BillingManager"

var AdminRoleID int64

func init() {
	DeveloperResourcesMap = make(map[string]struct{})
	OperatorResourcesMap = make(map[string]struct{})
	for _, res := range DeveloperResources {
		DeveloperResourcesMap[res] = struct{}{}
	}
	for _, res := range OperatorResources {
		OperatorResourcesMap[res] = struct{}{}
	}
}

func InitRolePerms(ctx context.Context) error {
	log.SpanLog(ctx, log.DebugLevelApi, "init roleperms")
	var err error

	addPolicy(ctx, &err, RoleAdminManager, ResourceControllers, ActionManage)
	addPolicy(ctx, &err, RoleAdminManager, ResourceControllers, ActionView)
	addPolicy(ctx, &err, RoleAdminManager, ResourceClusterFlavors, ActionManage)
	addPolicy(ctx, &err, RoleAdminManager, ResourceClusterFlavors, ActionView)
	addPolicy(ctx, &err, RoleAdminManager, ResourceFlavors, ActionManage)
	addPolicy(ctx, &err, RoleAdminManager, ResourceFlavors, ActionView)
	addPolicy(ctx, &err, RoleAdminManager, ResourceConfig, ActionManage)
	addPolicy(ctx, &err, RoleAdminManager, ResourceConfig, ActionView)
	addPolicy(ctx, &err, RoleAdminManager, ResourceCloudletPools, ActionManage)
	addPolicy(ctx, &err, RoleAdminManager, ResourceCloudletPools, ActionView)
	addPolicy(ctx, &err, RoleAdminManager, ResourceAlert, ActionManage)
	addPolicy(ctx, &err, RoleAdminManager, ResourceAlert, ActionView)

	addPolicy(ctx, &err, RoleDeveloperManager, ResourceBilling, ActionManage)
	addPolicy(ctx, &err, RoleDeveloperManager, ResourceBilling, ActionView)
	addPolicy(ctx, &err, RoleBillingManager, ResourceBilling, ActionManage)
	addPolicy(ctx, &err, RoleBillingManager, ResourceBilling, ActionView)
	addPolicy(ctx, &err, RoleBillingManager, ResourceUsers, ActionManage)
	addPolicy(ctx, &err, RoleBillingManager, ResourceUsers, ActionView)
	addPolicy(ctx, &err, RoleAdminManager, ResourceBilling, ActionManage)
	addPolicy(ctx, &err, RoleAdminManager, ResourceBilling, ActionView)
	addPolicy(ctx, &err, RoleAdminContributor, ResourceBilling, ActionView)

	addPolicy(ctx, &err, RoleDeveloperManager, ResourceUsers, ActionManage)
	addPolicy(ctx, &err, RoleDeveloperManager, ResourceUsers, ActionView)
	addPolicy(ctx, &err, RoleDeveloperContributor, ResourceUsers, ActionView)
	addPolicy(ctx, &err, RoleDeveloperViewer, ResourceUsers, ActionView)

	addPolicy(ctx, &err, RoleOperatorManager, ResourceUsers, ActionManage)
	addPolicy(ctx, &err, RoleOperatorManager, ResourceUsers, ActionView)
	addPolicy(ctx, &err, RoleOperatorContributor, ResourceUsers, ActionView)
	addPolicy(ctx, &err, RoleOperatorViewer, ResourceUsers, ActionView)

	addPolicy(ctx, &err, RoleAdminManager, ResourceUsers, ActionManage)
	addPolicy(ctx, &err, RoleAdminManager, ResourceUsers, ActionView)
	addPolicy(ctx, &err, RoleAdminContributor, ResourceUsers, ActionView)
	addPolicy(ctx, &err, RoleAdminViewer, ResourceUsers, ActionView)
	addPolicy(ctx, &err, RoleAdminManager, ResourceResTagTable, ActionManage)
	addPolicy(ctx, &err, RoleAdminManager, ResourceResTagTable, ActionView)

	for _, str := range DeveloperResources {
		addPolicy(ctx, &err, RoleDeveloperManager, str, ActionManage)
		addPolicy(ctx, &err, RoleDeveloperManager, str, ActionView)
		addPolicy(ctx, &err, RoleDeveloperContributor, str, ActionManage)
		addPolicy(ctx, &err, RoleDeveloperContributor, str, ActionView)
		addPolicy(ctx, &err, RoleDeveloperViewer, str, ActionView)
		addPolicy(ctx, &err, RoleAdminManager, str, ActionManage)
		addPolicy(ctx, &err, RoleAdminManager, str, ActionView)
		addPolicy(ctx, &err, RoleAdminContributor, str, ActionManage)
		addPolicy(ctx, &err, RoleAdminContributor, str, ActionView)
		addPolicy(ctx, &err, RoleAdminViewer, str, ActionView)
	}
	addPolicy(ctx, &err, RoleDeveloperManager, ResourceCloudlets, ActionView)
	addPolicy(ctx, &err, RoleDeveloperContributor, ResourceCloudlets, ActionView)
	addPolicy(ctx, &err, RoleDeveloperViewer, ResourceCloudlets, ActionView)

	addPolicy(ctx, &err, RoleDeveloperManager, ResourceFlavors, ActionView)
	addPolicy(ctx, &err, RoleDeveloperContributor, ResourceFlavors, ActionView)
	addPolicy(ctx, &err, RoleDeveloperViewer, ResourceFlavors, ActionView)

	addPolicy(ctx, &err, RoleDeveloperManager, ResourceClusterFlavors, ActionView)
	addPolicy(ctx, &err, RoleDeveloperContributor, ResourceClusterFlavors, ActionView)
	addPolicy(ctx, &err, RoleDeveloperViewer, ResourceClusterFlavors, ActionView)

	for _, str := range OperatorResources {
		addPolicy(ctx, &err, RoleOperatorManager, str, ActionManage)
		addPolicy(ctx, &err, RoleOperatorManager, str, ActionView)
		addPolicy(ctx, &err, RoleOperatorContributor, str, ActionManage)
		addPolicy(ctx, &err, RoleOperatorContributor, str, ActionView)
		addPolicy(ctx, &err, RoleOperatorViewer, str, ActionView)
		addPolicy(ctx, &err, RoleAdminManager, str, ActionManage)
		addPolicy(ctx, &err, RoleAdminManager, str, ActionView)
		addPolicy(ctx, &err, RoleAdminContributor, str, ActionManage)
		addPolicy(ctx, &err, RoleAdminContributor, str, ActionView)
		addPolicy(ctx, &err, RoleAdminViewer, str, ActionView)
	}
	return err
}

func addPolicy(ctx context.Context, err *error, params ...string) {
	if *err == nil {
		*err = enforcer.AddPolicy(ctx, params...)
	}
}

func ShowRolePerms(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := ormutil.GetContext(c)
	// admin user can see all roles
	isAdmin, err := isUserAdmin(ctx, claims.Username)
	if err != nil {
		return err
	}
	filter, err := bindMap(c)
	if err != nil {
		return err
	}

	policies, err := enforcer.GetPolicy()
	if err != nil {
		return ormutil.DbErr(err)
	}
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
		if !isAdmin {
			if isApiKeyRole(perm.Role) || isAdminRole(perm.Role) {
				continue
			}
		}
		if !rolePermMatchesFilter(&perm, filter) {
			continue
		}
		ret = append(ret, &perm)
	}
	return c.JSON(http.StatusOK, ret)
}

// Show roles assigned to the current user
func ShowRoleAssignment(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := ormutil.GetContext(c)

	filter, err := bindMap(c)
	if err != nil {
		return err
	}
	super := false
	if authorized(ctx, claims.Username, "", ResourceUsers, ActionView) == nil {
		// super user, show all roles
		super = true
	}

	groupings, err := enforcer.GetGroupingPolicy()
	if err != nil {
		return ormutil.DbErr(err)
	}
	ret := []*ormapi.Role{}
	for ii, _ := range groupings {
		role := parseRole(groupings[ii])
		if role == nil {
			continue
		}
		if !super && claims.Username != role.Username {
			continue
		}
		if !roleMatchesFilter(role, filter) {
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

func roleMatchesFilter(in *ormapi.Role, jsonFilter map[string]interface{}) bool {
	for k, v := range jsonFilter {
		switch strings.ToLower(k) {
		case "org":
			org, ok := v.(string)
			if !ok || org != in.Org {
				return false
			}
		case "username":
			username, ok := v.(string)
			if !ok || username != in.Username {
				return false
			}
		case "role":
			role, ok := v.(string)
			if !ok || role != in.Role {
				return false
			}
		}
	}
	return true
}

func rolePermMatchesFilter(in *ormapi.RolePerm, jsonFilter map[string]interface{}) bool {
	for k, v := range jsonFilter {
		switch strings.ToLower(k) {
		case "role":
			role, ok := v.(string)
			if !ok || role != in.Role {
				return false
			}
		case "resource":
			resource, ok := v.(string)
			if !ok || resource != in.Resource {
				return false
			}
		case "action":
			action, ok := v.(string)
			if !ok || action != in.Action {
				return false
			}
		}
	}
	return true
}

func ShowRole(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := ormutil.GetContext(c)
	// admin user can see all roles
	isAdmin, err := isUserAdmin(ctx, claims.Username)
	if err != nil {
		return err
	}

	rolemap := make(map[string]struct{})
	policies, err := enforcer.GetPolicy()
	if err != nil {
		return ormutil.DbErr(err)
	}
	for _, policy := range policies {
		if len(policy) < 1 {
			continue
		}
		rolemap[policy[0]] = struct{}{}
	}
	roles := make([]string, 0)
	for role, _ := range rolemap {
		if !isAdmin {
			if isApiKeyRole(role) || isAdminRole(role) {
				continue
			}
		}
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
		return ormutil.BindErr(err)
	}
	err = AddUserRoleObj(ormutil.GetContext(c), claims, &role)
	if err != nil {
		return err
	}
	return ormutil.SetReply(c, ormutil.Msg("Role added to user"))
}

func AddUserRoleObj(ctx context.Context, claims *UserClaims, role *ormapi.Role) error {
	if role.Username == "" {
		return fmt.Errorf("Username not specified")
	}
	if role.Role == "" {
		return fmt.Errorf("Role not specified")
	}
	if strings.ToLower(role.Username) == strings.ToLower(role.Org) {
		return fmt.Errorf("org name cannot be same as existing user name")
	}
	if role.Org != "" {
		span := log.SpanFromContext(ctx)
		span.SetTag("org", role.Org)
	}
	// Special case Admin roles and the empty org (which implies all orgs).
	// AdminRoles may only be associated to the empty org, and the
	// empty org may only be associated with Admin roles.
	adminRole := false
	if role.Role == RoleAdminManager || role.Role == RoleAdminContributor || role.Role == RoleAdminViewer {
		if role.Org != "" {
			return fmt.Errorf("Admin roles cannot be associated with an org, please specify the empty org \"\"")
		}
		adminRole = true
	} else {
		if role.Org == "" {
			return fmt.Errorf("Org name must be specified for the specified role")
		}
	}

	// check that user/org/role exists
	targetUser := ormapi.User{}
	db := loggedDB(ctx)
	res := db.Where(&ormapi.User{Name: role.Username}).First(&targetUser)
	if res.RecordNotFound() {
		return fmt.Errorf("Username not found")
	}
	if res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	if adminRole {
		if targetUser.PassCrackTimeSec == 0 {
			return fmt.Errorf("Target user password strength not verified, please have user log in to verify password strength")
		}
		// more stringent password strength requirements
		err := checkPasswordStrength(ctx, &targetUser, nil, adminRole)
		if err != nil {
			return err
		}
	}
	policies, err := enforcer.GetPolicy()
	if err != nil {
		return ormutil.DbErr(err)
	}
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
	orgType := ""
	if role.Org != "" {
		org := ormapi.Organization{}
		res = db.Where(&ormapi.Organization{Name: role.Org}).First(&org)
		if res.RecordNotFound() {
			return fmt.Errorf("Organization not found")
		}
		if res.Error != nil {
			return ormutil.DbErr(res.Error)
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
		orgType = org.Type

		groupings, err := enforcer.GetGroupingPolicy()
		if err != nil {
			return ormutil.DbErr(err)
		}
		for ii, _ := range groupings {
			existingRole := parseRole(groupings[ii])
			if existingRole == nil {
				continue
			}
			// avoid gitlab error of member already exists if multiple roles are assigned to the same org
			if existingRole.Org == role.Org && existingRole.Username == role.Username {
				return fmt.Errorf(
					"User already has a role %s for org %s, please remove existing role first",
					existingRole.Role, existingRole.Org,
				)
			}
		}
	}

	// make sure caller has perms to modify users of target org
	if err := authorized(ctx, claims.Username, role.Org, ResourceUsers, ActionManage); err != nil {
		if role.Org == "" {
			return fmt.Errorf("Organization not specified or no permissions")
		}
		return err
	}
	psub := rbac.GetCasbinGroup(role.Org, role.Username)
	err = enforcer.AddGroupingPolicy(ctx, psub, role.Role)
	if err != nil {
		return ormutil.DbErr(err)
	}
	// notify recipient that they were added. don't fail on error
	senderr := sendAddedEmail(ctx, claims.Username, targetUser.Name, targetUser.Email, role.Org, role.Role)
	if senderr != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "failed to send role added email", "err", senderr)
	}

	gitlabAddGroupMember(ctx, role, orgType)
	artifactoryAddUserToGroup(ctx, role, orgType)
	return nil
}

func RemoveUserRole(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := ormutil.GetContext(c)

	role := ormapi.Role{}
	if err := c.Bind(&role); err != nil {
		return ormutil.BindErr(err)
	}
	err = RemoveUserRoleObj(ctx, claims, &role)
	if err != nil {
		return err
	}
	return ormutil.SetReply(c, ormutil.Msg("Role removed from user"))
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
	psub := rbac.GetCasbinGroup(role.Org, role.Username)
	found, err := enforcer.HasGroupingPolicy(psub, role.Role)
	if err != nil {
		return ormutil.DbErr(err)
	}
	if !found {
		return nil
	}

	// make sure caller has perms to modify users of target org
	if err := authorized(ctx, claims.Username, role.Org, ResourceUsers, ActionManage); err != nil {
		return err
	}

	// if we are removing a manager role, make sure we are not deleting the last manager of an org
	if role.Role == RoleAdminManager || role.Role == RoleDeveloperManager || role.Role == RoleOperatorManager {
		managerCount := 0
		groups, err := enforcer.GetGroupingPolicy()
		if err != nil {
			return ormutil.DbErr(err)
		}
		for _, grp := range groups {
			r := parseRole(grp)
			if r.Role == role.Role && r.Org == role.Org {
				managerCount = managerCount + 1
			}
		}
		if managerCount < 2 {
			return fmt.Errorf("Error: Cannot remove the last remaining manager of an org")
		}
	}

	err = enforcer.RemoveGroupingPolicy(ctx, psub, role.Role)
	if err != nil {
		return ormutil.DbErr(err)
	}

	org := ormapi.Organization{}
	// ignore any error
	db := loggedDB(ctx)
	db.Where(&ormapi.Organization{Name: role.Org}).First(&org)

	gitlabRemoveGroupMember(ctx, role, org.Type)
	artifactoryRemoveUserFromGroup(ctx, role, org.Type)

	return nil
}

func ShowUserRole(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := ormutil.GetContext(c)

	filter, err := bindMap(c)
	if err != nil {
		return err
	}
	roles, err := ShowUserRoleObj(ctx, claims.Username, filter)
	if err != nil {
		return err
	}
	return ormutil.SetReply(c, roles)
}

// show roles for organizations the current user has permission to
// add/remove roles to. This "shows" all the actions taken by
// Add/RemoveUserRole.
func ShowUserRoleObj(ctx context.Context, username string, filter map[string]interface{}) ([]ormapi.Role, error) {
	roles := []ormapi.Role{}

	groupings, err := enforcer.GetGroupingPolicy()
	if err != nil {
		return nil, ormutil.DbErr(err)
	}
	authz, err := newShowAuthz(ctx, "", username, ResourceUsers, ActionView)
	if err != nil {
		return nil, err
	}

	for ii, _ := range groupings {
		role := parseRole(groupings[ii])
		if role == nil {
			continue
		}
		if isApiKeyRole(role.Role) {
			// hide API key role from users as it is managed internally
			continue
		}
		if !authz.Ok(role.Org) {
			continue
		}
		if !roleMatchesFilter(role, filter) {
			continue
		}
		roles = append(roles, *role)
	}
	return roles, nil
}

func AdminAccessCheck(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := ormutil.GetContext(c)

	if err := authorized(ctx, claims.Username, "", ResourceControllers, ActionManage); err != nil {
		return err
	}
	return nil
}

// for debugging
func dumpRbac() {
	policies, err := enforcer.GetPolicy()
	if err != nil {
		fmt.Printf("get policy failed: %v\n", err)
	} else {
		for _, p := range policies {
			fmt.Printf("policy: %+v\n", p)
		}
	}
	groups, err := enforcer.GetGroupingPolicy()
	if err != nil {
		fmt.Printf("get grouping policy failed: %v\n", err)
	} else {
		for _, grp := range groups {
			fmt.Printf("group: %+v\n", grp)
		}
	}
}

func isAdminRole(role string) bool {
	if role == RoleAdminManager ||
		role == RoleAdminContributor ||
		role == RoleAdminViewer {
		return true
	}
	return false
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

func getApiKeyRoleName(apiKeyId string) string {
	return apiKeyId + ApiKeyRoleSuffix
}

func isApiKeyRole(role string) bool {
	if strings.HasSuffix(role, ApiKeyRoleSuffix) {
		return true
	}
	return false
}

func isAdmin(ctx context.Context, username string) bool {
	roles, err := ShowUserRoleObj(ctx, username, map[string]interface{}{})
	if err != nil {
		return false
	}
	for _, role := range roles {
		if isAdminRole(role.Role) {
			return true
		}
	}
	return false
}
