package orm

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud-infra/mc/rbac"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/log"
)

// Organization Type names for ORM database
var OrgTypeAdmin = "admin"
var OrgTypeDeveloper = "developer"
var OrgTypeOperator = "operator"

func CreateOrg(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := GetContext(c)
	org := ormapi.Organization{}
	if err := c.Bind(&org); err != nil {
		return c.JSON(http.StatusBadRequest, Msg("Invalid POST data"))
	}
	span := log.SpanFromContext(ctx)
	span.SetTag("org", org.Name)

	err = CreateOrgObj(ctx, claims, &org)
	return setReply(c, err, Msg("Organization created"))
}

func CreateOrgObj(ctx context.Context, claims *UserClaims, org *ormapi.Organization) error {
	if org.Name == "" {
		return fmt.Errorf("Name not specified")
	}
	err := ValidName(org.Name)
	if err != nil {
		return err
	}
	// any user can create their own organization

	role := ""
	if org.Type == OrgTypeDeveloper {
		role = RoleDeveloperManager
	} else if org.Type == OrgTypeOperator {
		role = RoleOperatorManager
	} else {
		return fmt.Errorf("Organization type must be %s, or %s", OrgTypeDeveloper, OrgTypeOperator)
	}
	if org.Address == "" {
		return fmt.Errorf("Address not specified")
	}
	if org.Phone == "" {
		return fmt.Errorf("Phone number not specified")
	}
	if strings.ToLower(claims.Username) == strings.ToLower(org.Name) {
		return fmt.Errorf("org name cannot be same as existing user name")
	}
	if strings.ToLower(org.Name) == strings.ToLower(cloudcommon.DeveloperMobiledgeX) {
		if !authorized(ctx, claims.Username, "", ResourceUsers, ActionManage) {
			return fmt.Errorf("Not authorized to create reserved org %s", org.Name)
		}
	}
	db := loggedDB(ctx)
	err = db.Create(&org).Error
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint \"organizations_pkey") {
			return fmt.Errorf("Organization with name %s (case-insensitive) already exists", org.Name)
		}
		return dbErr(err)
	}
	// set user to admin role of organization
	psub := rbac.GetCasbinGroup(org.Name, claims.Username)
	err = enforcer.AddGroupingPolicy(ctx, psub, role)
	if err != nil {
		return dbErr(err)
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
	ctx := GetContext(c)
	org := ormapi.Organization{}
	if err := c.Bind(&org); err != nil {
		return c.JSON(http.StatusBadRequest, Msg("Invalid POST data"))
	}
	span := log.SpanFromContext(ctx)
	span.SetTag("org", org.Name)

	err = DeleteOrgObj(ctx, claims, &org)
	return setReply(c, err, Msg("Organization deleted"))
}

func DeleteOrgObj(ctx context.Context, claims *UserClaims, org *ormapi.Organization) error {
	if org.Name == "" {
		return fmt.Errorf("Organization name not specified")
	}
	if !authorized(ctx, claims.Username, org.Name, ResourceUsers, ActionManage) {
		return echo.ErrForbidden
	}
	// delete org
	db := loggedDB(ctx)
	err := db.Delete(&org).Error
	if err != nil {
		if strings.Contains(err.Error(), "violates foreign key constraint \"org_cloudlet_pools_org_fkey\"") {
			return fmt.Errorf("Cannot delete organization because it is referenced by an OrgCloudletPool")
		}
		return dbErr(err)
	}
	// delete all casbin groups associated with org
	groups, err := enforcer.GetGroupingPolicy()
	if err != nil {
		return dbErr(err)
	}
	for _, grp := range groups {
		if len(grp) < 2 {
			continue
		}
		strs := strings.Split(grp[0], "::")
		if len(strs) == 2 && strs[0] == org.Name {
			err = enforcer.RemoveGroupingPolicy(ctx, grp[0], grp[1])
			if err != nil {
				return dbErr(err)
			}
		}
	}
	gitlabDeleteGroup(ctx, org)
	artifactoryDeleteGroupObjects(ctx, org.Name, "")
	return nil
}

func UpdateOrg(c echo.Context) error {
	ctx := GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	// Pull json directly so we can unmarshal twice.
	// First time is to do lookup, second time is to apply
	// modified fields.
	body, err := ioutil.ReadAll(c.Request().Body)
	in := ormapi.Organization{}
	err = json.Unmarshal(body, &in)
	if err != nil {
		return bindErr(c, err)
	}
	if in.Name == "" {
		return c.JSON(http.StatusBadRequest, Msg("Organization name not specified"))
	}

	lookup := ormapi.Organization{
		Name: in.Name,
	}
	org := ormapi.Organization{}
	db := loggedDB(ctx)
	res := db.Where(&lookup).First(&org)
	if res.RecordNotFound() {
		return c.JSON(http.StatusBadRequest, Msg("Organization not found"))
	}
	if res.Error != nil {
		return c.JSON(http.StatusInternalServerError, MsgErr(dbErr(res.Error)))
	}
	oldType := org.Type

	if !authorized(ctx, claims.Username, in.Name, ResourceUsers, ActionManage) {
		return echo.ErrForbidden
	}

	// apply specified fields
	err = json.Unmarshal(body, &org)
	if err != nil {
		return bindErr(c, err)
	}
	if org.Type != oldType {
		return c.JSON(http.StatusBadRequest, Msg("Cannot change Organization type"))
	}

	err = db.Save(&org).Error
	if err != nil {
		return c.JSON(http.StatusInternalServerError, MsgErr(dbErr(err)))
	}
	return nil
}

// Show Organizations that current user belongs to.
func ShowOrg(c echo.Context) error {
	ctx := GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	orgs, err := ShowOrgObj(ctx, claims)
	return setReply(c, err, orgs)
}

func ShowOrgObj(ctx context.Context, claims *UserClaims) ([]ormapi.Organization, error) {
	orgs := []ormapi.Organization{}
	db := loggedDB(ctx)
	if authorized(ctx, claims.Username, "", ResourceUsers, ActionView) {
		// super user, show all orgs
		err := db.Find(&orgs).Error
		if err != nil {
			return nil, dbErr(err)
		}
	} else {
		// show orgs for current user
		groupings, err := enforcer.GetGroupingPolicy()
		if err != nil {
			return nil, dbErr(err)
		}
		for _, grp := range groupings {
			if len(grp) < 2 {
				continue
			}
			orguser := strings.Split(grp[0], "::")
			if len(orguser) > 1 && orguser[1] == claims.Username {
				org := ormapi.Organization{}
				org.Name = orguser[0]
				err := db.Where(&org).First(&org).Error
				if err != nil {
					return nil, dbErr(err)
				}
				orgs = append(orgs, org)
			}
		}
	}
	return orgs, nil
}

// getUserOrgnames gets a map of all the org names the user belongs to.
// If this is an admin, return boolean will be true.
func getUserOrgnames(username string) (bool, map[string]struct{}, error) {
	orgnames := make(map[string]struct{})
	admin := false

	groupings, err := enforcer.GetGroupingPolicy()
	if err != nil {
		return false, nil, err
	}
	for _, grp := range groupings {
		if len(grp) < 2 {
			continue
		}
		if grp[0] == username {
			admin = true
			continue
		}
		orguser := strings.Split(grp[0], "::")
		if len(orguser) > 1 && orguser[1] == username {
			orgnames[orguser[0]] = struct{}{}
		}
	}
	return admin, orgnames, nil
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
