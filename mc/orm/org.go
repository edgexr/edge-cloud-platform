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
	"io/ioutil"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/jinzhu/gorm"
	"github.com/labstack/echo"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud-infra/mc/ormutil"
	"github.com/edgexr/edge-cloud-infra/mc/rbac"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/cloudcommon/node"
	edgeproto "github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
)

// Organization Type names for ORM database
var OrgTypeAdmin = "admin"
var OrgTypeDeveloper = "developer"
var OrgTypeOperator = "operator"
var OrgTypeAny = ""

type UpdateType int

const (
	NormalUpdate UpdateType = iota
	AdminUpdate
)

func CreateOrg(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := ormutil.GetContext(c)
	org := ormapi.Organization{}
	if err := c.Bind(&org); err != nil {
		return ormutil.BindErr(err)
	}
	span := log.SpanFromContext(ctx)
	span.SetTag("org", org.Name)
	// make sure createdAt is the same as event start, so that
	// it will show up in event show api.
	org.CreatedAt = ormutil.GetEventStart(c)

	err = CreateOrgObj(ctx, claims, &org)
	if err != nil {
		return err
	}
	return ormutil.SetReply(c, ormutil.Msg("Organization created"))
}

func CreateOrgObj(ctx context.Context, claims *UserClaims, org *ormapi.Organization) error {
	if org.Name == "" {
		return fmt.Errorf("Name not specified")
	}
	err := ValidName(org.Name)
	if err != nil {
		return err
	}
	if orgCheck, _ := billingOrgExists(ctx, org.Name); orgCheck != nil {
		return fmt.Errorf("A BillingOrganization with this name already exists")
	}
	// any user can create their own organization

	role := ""
	if org.Type == OrgTypeDeveloper {
		role = RoleDeveloperManager
	} else if org.Type == OrgTypeOperator {
		role = RoleOperatorManager
		org.EdgeboxOnly = true
	} else {
		return fmt.Errorf("Organization type must be %s, or %s", OrgTypeDeveloper, OrgTypeOperator)
	}
	if strings.ToLower(org.Name) == strings.ToLower(cloudcommon.OrganizationMobiledgeX) || strings.ToLower(org.Name) == strings.ToLower(cloudcommon.OrganizationEdgeBox) {
		if err := authorized(ctx, claims.Username, "", ResourceUsers, ActionManage); err != nil {
			return fmt.Errorf("Not authorized to create reserved org %s", org.Name)
		}
	}
	// set the billingOrg parent to none
	org.Parent = ""

	db := loggedDB(ctx)

	users := []ormapi.User{}
	err = db.Find(&users).Error
	if err != nil {
		return err
	}
	for _, user := range users {
		if strings.ToLower(user.Name) == strings.ToLower(org.Name) {
			return fmt.Errorf("org name cannot be same as existing user name")
		}
	}
	err = db.Create(&org).Error
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint \"organizations_pkey") {
			return fmt.Errorf("Organization with name %s (case-insensitive) already exists", org.Name)
		}
		return ormutil.DbErr(err)
	}
	// set user to admin role of organization
	psub := rbac.GetCasbinGroup(org.Name, claims.Username)
	err = enforcer.AddGroupingPolicy(ctx, psub, role)
	if err != nil {
		return ormutil.DbErr(err)
	}

	gitlabCreateGroup(ctx, org)
	r := ormapi.Role{
		Org:      org.Name,
		Username: claims.Username,
		Role:     role,
	}
	gitlabAddGroupMember(ctx, &r, org.Type)

	artifactoryCreateGroupObjects(ctx, org.Name, org.Type)
	artifactoryAddUserToGroup(ctx, &r, org.Type)

	return nil
}

func DeleteOrg(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := ormutil.GetContext(c)
	org := ormapi.Organization{}
	if err := c.Bind(&org); err != nil {
		return ormutil.BindErr(err)
	}
	span := log.SpanFromContext(ctx)
	span.SetTag("org", org.Name)

	err = DeleteOrgObj(ctx, claims, &org)
	if err != nil {
		return err
	}
	return ormutil.SetReply(c, ormutil.Msg("Organization deleted"))
}

func DeleteOrgObj(ctx context.Context, claims *UserClaims, org *ormapi.Organization) error {
	if org.Name == "" {
		return fmt.Errorf("Organization name not specified")
	}
	if err := authorized(ctx, claims.Username, org.Name, ResourceUsers, ActionManage); err != nil {
		return err
	}

	// get org details
	orgCheck, err := orgExists(ctx, org.Name)
	if err != nil {
		return err
	}

	// mark org for delete in progress
	db := loggedDB(ctx)
	doMark := true
	err = markOrgForDelete(db, org.Name, doMark)
	if err != nil {
		return err
	}

	// check for Controller objects belonging to org or if it is part of a parent billing org
	err = orgInUse(ctx, org.Name)
	if err != nil {
		undoerr := markOrgForDelete(db, org.Name, !doMark)
		if undoerr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "undo mark org for delete", "undoerr", undoerr)
		}
		return err
	}

	// check for if org is in use by federator
	err = orgInUseByFederatorCheck(ctx, org.Name)
	if err != nil {
		undoerr := markOrgForDelete(db, org.Name, !doMark)
		if undoerr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "undo mark org for delete", "undoerr", undoerr)
		}
		return err
	}

	// check to see if this org has a billingOrg attached
	if orgCheck.Parent != "" {
		undoerr := markOrgForDelete(db, org.Name, !doMark)
		if undoerr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "undo mark org for delete", "undoerr", undoerr)
		}
		return fmt.Errorf("Organization is still part of Parent BillingOrganization %s", orgCheck.Parent)
	}

	// delete org
	err = db.Delete(&org).Error
	if err != nil {
		undoerr := markOrgForDelete(db, org.Name, !doMark)
		if undoerr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "undo mark org for delete", "undoerr", undoerr)
		}
		if strings.Contains(err.Error(), "violates foreign key constraint \"org_cloudlet_pools_org_fkey\"") {
			return fmt.Errorf("Cannot delete organization because it is referenced by some cloudletpool invitation or response")
		}
		return ormutil.DbErr(err)
	}

	// delete all casbin groups associated with org
	groups, err := enforcer.GetGroupingPolicy()
	if err != nil {
		return ormutil.DbErr(err)
	}
	for _, grp := range groups {
		if len(grp) < 2 {
			continue
		}
		strs := strings.Split(grp[0], "::")
		if len(strs) == 2 && strs[0] == org.Name {
			err = enforcer.RemoveGroupingPolicy(ctx, grp[0], grp[1])
			if err != nil {
				return ormutil.DbErr(err)
			}
		}
	}

	gitlabDeleteGroup(ctx, org)
	artifactoryDeleteGroupObjects(ctx, org.Name, "")
	return nil
}

func UpdateOrg(c echo.Context) error {
	return updateOrg(c, NormalUpdate)
}

func RestrictedUpdateOrg(c echo.Context) error {
	return updateOrg(c, AdminUpdate)
}

func updateOrg(c echo.Context, updateType UpdateType) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	// Pull json directly so we can unmarshal twice.
	// First time is to do lookup, second time is to apply
	// modified fields.
	body, err := ioutil.ReadAll(c.Request().Body)
	in := ormapi.Organization{}
	err = BindJson(body, &in)
	if err != nil {
		return ormutil.BindErr(err)
	}
	if in.Name == "" {
		return fmt.Errorf("Organization name not specified")
	}

	lookup := ormapi.Organization{
		Name: in.Name,
	}
	org := ormapi.Organization{}
	db := loggedDB(ctx)
	res := db.Where(&lookup).First(&org)
	if res.RecordNotFound() {
		return fmt.Errorf("Organization not found")
	}
	if res.Error != nil {
		return ormutil.NewHTTPError(http.StatusInternalServerError, ormutil.DbErr(res.Error).Error())
	}

	if updateType == AdminUpdate {
		// Only admin user allowed to update org data.
		if err := authorized(ctx, claims.Username, "", ResourceUsers, ActionManage); err != nil {
			return err
		}
	} else {
		if err := authorized(ctx, claims.Username, in.Name, ResourceUsers, ActionManage); err != nil {
			return err
		}
	}

	old := org
	// apply specified fields
	err = BindJson(body, &org)
	if err != nil {
		return ormutil.BindErr(err)
	}
	if org.Type != old.Type {
		return fmt.Errorf("Cannot change Organization type")
	}
	if org.PublicImages != old.PublicImages {
		err := gitlabUpdateVisibility(ctx, &org)
		if err != nil {
			return err
		}
	}
	if org.CreatedAt != old.CreatedAt {
		return fmt.Errorf("Cannot update created at")
	}
	if updateType != AdminUpdate {
		if org.EdgeboxOnly != old.EdgeboxOnly {
			return fmt.Errorf("Cannot update edgeboxonly field for Organization")
		}
		if org.Parent != old.Parent {
			return fmt.Errorf("Cannot update parent")
		}
	}

	err = db.Save(&org).Error
	if err != nil {
		return ormutil.NewHTTPError(http.StatusInternalServerError, ormutil.DbErr(err).Error())
	}
	return nil
}

// Show Organizations that current user belongs to.
func ShowOrg(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	filter, err := bindDbFilter(c, &ormapi.Organization{})
	if err != nil {
		return err
	}
	orgs, err := ShowOrgObj(ctx, claims, filter)
	if err != nil {
		return err
	}
	return ormutil.SetReply(c, orgs)
}

func ShowOrgObj(ctx context.Context, claims *UserClaims, filter map[string]interface{}) ([]ormapi.Organization, error) {
	orgs := []ormapi.Organization{}
	db := loggedDB(ctx)
	err := db.Where(filter).Find(&orgs).Error
	if err != nil {
		return nil, ormutil.DbErr(err)
	}
	err = authorized(ctx, claims.Username, "", ResourceUsers, ActionView)
	if err == nil {
		// super user, show all orgs
		return orgs, nil
	}
	// show orgs for current user
	authOrgs := make(map[string]struct{})
	groupings, err := enforcer.GetGroupingPolicy()
	if err != nil {
		return nil, ormutil.DbErr(err)
	}
	for _, grp := range groupings {
		if len(grp) < 2 {
			continue
		}
		orguser := strings.Split(grp[0], "::")
		if len(orguser) > 1 && orguser[1] == claims.Username {
			authOrgs[orguser[0]] = struct{}{}
		}
	}
	allowedOrgs := []ormapi.Organization{}
	for _, org := range orgs {
		if _, ok := authOrgs[org.Name]; ok {
			allowedOrgs = append(allowedOrgs, org)
		}
	}
	return allowedOrgs, nil
}

func GetAllOrgs(ctx context.Context) (map[string]*ormapi.Organization, error) {
	orgsT := make(map[string]*ormapi.Organization)
	orgs := []ormapi.Organization{}

	db := loggedDB(ctx)
	err := db.Find(&orgs).Error
	if err != nil {
		return orgsT, err
	}
	for ii, _ := range orgs {
		orgsT[orgs[ii].Name] = &orgs[ii]
	}
	return orgsT, err
}

func getOrgType(orgName string, allOrgs map[string]*ormapi.Organization) string {
	if allOrgs != nil {
		if org, ok := allOrgs[orgName]; ok {
			return org.Type
		}
	}
	return ""
}

func orgExists(ctx context.Context, orgName string) (*ormapi.Organization, error) {
	lookup := ormapi.Organization{
		Name: orgName,
	}
	db := loggedDB(ctx)
	org := ormapi.Organization{}
	res := db.Where(&lookup).First(&org)
	if res.RecordNotFound() {
		return nil, fmt.Errorf("org %s not found", lookup.Name)
	}
	if res.Error != nil {
		return nil, res.Error
	}
	// SQL lookup by org name is case-insensitive.
	// Make sure org name matches (case-sensitive).
	if org.Name != orgName {
		return nil, fmt.Errorf("lookup %s but found %s", orgName, org.Name)
	}
	return &org, nil
}

// Marking an org for delete must be done transactionally so other threads
// cannot accidentally run the delete in parallel.
func markOrgForDelete(db *gorm.DB, name string, mark bool) (reterr error) {
	tx := db.Begin()
	defer func() {
		if reterr != nil {
			tx.Rollback()
		}
	}()
	// lookup org
	lookup := ormapi.Organization{
		Name: name,
	}
	findOrg := ormapi.Organization{}
	res := tx.Where(&lookup).First(&findOrg)
	if res.RecordNotFound() {
		return fmt.Errorf("org not found")
	}
	if res.Error != nil {
		return ormutil.NewHTTPError(http.StatusInternalServerError, res.Error.Error())
	}
	if mark {
		if findOrg.DeleteInProgress {
			return fmt.Errorf("org already being deleted")
		}
		findOrg.DeleteInProgress = true
	} else {
		findOrg.DeleteInProgress = false
	}
	err := tx.Save(&findOrg).Error
	if err != nil {
		return ormutil.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	return tx.Commit().Error
}

func orgInUse(ctx context.Context, orgName string) error {
	ctrls, err := ShowControllerObj(ctx, NoUserClaims, NoShowFilter)
	if err != nil {
		return err
	}
	errs := make([]string, 0)
	var mux sync.Mutex
	var wg sync.WaitGroup

	for _, ctrl := range ctrls {
		wg.Add(1)
		go func(c ormapi.Controller) {
			err := orgInUseRegion(ctx, c, orgName)
			if err != nil {
				mux.Lock()
				errs = append(errs, fmt.Sprintf("region %s: %v", c.Region, err))
				mux.Unlock()
			}
			wg.Done()
		}(ctrl)
	}
	wg.Wait()
	if len(errs) == 0 {
		return nil
	}
	sort.Strings(errs)
	return fmt.Errorf("Organization %s in use or check failed: %s", orgName, strings.Join(errs, "; "))
}

func orgInUseRegion(ctx context.Context, c ormapi.Controller, orgName string) error {
	conn, err := connectGrpcAddr(ctx, c.Address, []node.MatchCA{node.AnyRegionalMatchCA()})
	if err != nil {
		return err
	}
	defer conn.Close()

	api := edgeproto.NewOrganizationApiClient(conn)
	org := edgeproto.Organization{
		Name: orgName,
	}
	res, err := api.OrganizationInUse(ctx, &org)
	if err != nil {
		return err
	}
	if res.Code == 0 {
		return nil
	}
	return fmt.Errorf(res.Message)
}
