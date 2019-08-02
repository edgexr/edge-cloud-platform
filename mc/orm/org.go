package orm

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/util"
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
	err := util.ValidOrgName(org.Name)
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
		return fmt.Errorf(fmt.Sprintf("Organization type must be %s, or %s", OrgTypeDeveloper, OrgTypeOperator))
	}
	if org.Address == "" {
		return fmt.Errorf("Address not specified")
	}
	if org.Phone == "" {
		return fmt.Errorf("Phone number not specified")
	}
	org.AdminUsername = claims.Username
	db := loggedDB(ctx)
	err = db.Create(&org).Error
	if err != nil {
		return dbErr(err)
	}
	// set user to admin role of organization
	psub := getCasbinGroup(org.Name, claims.Username)
	enforcer.AddGroupingPolicy(psub, role)

	gitlabCreateGroup(ctx, org)
	r := ormapi.Role{
		Org:      org.Name,
		Username: claims.Username,
		Role:     role,
	}
	gitlabAddGroupMember(ctx, &r)

	artifactoryCreateGroupObjects(ctx, org.Name)
	artifactoryAddUserToGroup(ctx, &r)

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
	if !enforcer.Enforce(claims.Username, org.Name, ResourceUsers, ActionManage) {
		return echo.ErrForbidden
	}
	// delete org
	db := loggedDB(ctx)
	err := db.Delete(&org).Error
	if err != nil {
		return dbErr(err)
	}
	// delete all casbin groups associated with org
	groups := enforcer.GetGroupingPolicy()
	for _, grp := range groups {
		if len(grp) < 2 {
			continue
		}
		strs := strings.Split(grp[0], "::")
		if len(strs) == 2 && strs[0] == org.Name {
			enforcer.RemoveGroupingPolicy(grp[0], grp[1])
		}
	}
	gitlabDeleteGroup(ctx, org)
	artifactoryDeleteGroupObjects(ctx, org.Name)
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
	if enforcer.Enforce(claims.Username, "", ResourceUsers, ActionView) {
		// super user, show all orgs
		err := db.Find(&orgs).Error
		if err != nil {
			return nil, dbErr(err)
		}
	} else {
		// show orgs for current user
		groupings := enforcer.GetGroupingPolicy()
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
