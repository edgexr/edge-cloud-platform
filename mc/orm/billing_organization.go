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
	"strings"

	"github.com/jinzhu/gorm"
	"github.com/labstack/echo"
	"github.com/edgexr/edge-cloud-infra/billing"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud-infra/mc/ormutil"
	"github.com/edgexr/edge-cloud-infra/mc/rbac"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/log"
)

var deleteTypeChild = "child"
var deleteTypeSelf = "self"

func CreateBillingOrg(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := ormutil.GetContext(c)
	org := ormapi.BillingOrganization{}
	if err := c.Bind(&org); err != nil {
		return ormutil.BindErr(err)
	}
	span := log.SpanFromContext(ctx)
	span.SetTag("billing org", org.Name)

	err = CreateBillingOrgObj(ctx, claims, &org)
	if err != nil {
		return err
	}
	return ormutil.SetReply(c, ormutil.Msg("Billing Organization created"))
}

// Parent billing orgs will have a billing Group, self billing orgs will just use the existing developer group from the org
func CreateBillingOrgObj(ctx context.Context, claims *UserClaims, org *ormapi.BillingOrganization) error {
	// TODO: remove this later, for now only mexadmin the permission to create billingOrgs
	if !isAdmin(ctx, claims.Username) && billingEnabled(ctx) {
		return fmt.Errorf("Currently only admins may create and commit billingOrgs")
	}
	if org.Name == "" {
		return fmt.Errorf("Name not specified")
	}
	err := ValidName(org.Name)
	if err != nil {
		return err
	}
	orgCheck, err := orgExists(ctx, org.Name)
	if err != nil {
		return err
	}
	db := loggedDB(ctx)
	if org.Type == billing.CUSTOMER_TYPE_SELF {
		if orgCheck == nil {
			return fmt.Errorf("Organization %s not found, cannot create a self BillingOrganization for it", org.Name)
		}
		if orgCheck.Type != OrgTypeDeveloper {
			return fmt.Errorf("Cannot create BillingOrganizations for operator orgs")
		}
		// for self billing orgs, the user must be an admin of the org hes adding billing info for. Anyone can create a Parent billing org
		if err := authorized(ctx, claims.Username, org.Name, ResourceBilling, ActionManage); err != nil {
			return fmt.Errorf("Not authorized to create a Billing Organization")
		}
		if orgCheck.Parent != "" {
			return fmt.Errorf("There is already a Billing Org (%s) assigned to this %s, please remove it before adding another", orgCheck.Parent, orgCheck.Name)
		}
		org.Children = org.Name
		// set the parent org of the organization
		orgCheck.Parent = org.Name
		err = db.Save(&orgCheck).Error
		if err != nil {
			return fmt.Errorf("Unable to set billing org in Organization: %v", ormutil.DbErr(err))
		}
	} else if org.Type == billing.CUSTOMER_TYPE_PARENT {
		if orgCheck != nil {
			return fmt.Errorf("Cannot create a parent BillingOrganization. Name %s is already in use by an Organization", org.Name)
		}
	} else {
		return fmt.Errorf("Invalid type: %s. Type must be either \"%s\" or \"%s\"", org.Type, billing.CUSTOMER_TYPE_SELF, billing.CUSTOMER_TYPE_PARENT)
	}

	err = db.Create(&org).Error
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint \"organizations_pkey") {
			return fmt.Errorf("Billing Organization with name %s (case-insensitive) already exists", org.Name)
		}
		return ormutil.DbErr(err)
	}

	// If its a self billing org, just use the same group that was created for the regular org.
	if org.Type == billing.CUSTOMER_TYPE_PARENT {
		// set user to admin role of organization
		psub := rbac.GetCasbinGroup(org.Name, claims.Username)
		err = enforcer.AddGroupingPolicy(ctx, psub, RoleBillingManager)
		if err != nil {
			return ormutil.DbErr(err)
		}
	}

	err = createBillingAccount(ctx, org)
	if err != nil {
		// reset
		db.Delete(&org)
		if orgCheck != nil {
			orgCheck.Parent = ""
			db.Save(orgCheck)
		}
		enforcer.RemoveGroupingPolicy(ctx, rbac.GetCasbinGroup(org.Name, claims.Username), RoleBillingManager)
		return err
	}
	return nil
}

func createBillingAccount(ctx context.Context, info *ormapi.BillingOrganization) error {
	if !billingEnabled(ctx) {
		return nil
	}
	accountInfo := ormapi.AccountInfo{OrgName: info.Name}
	billTo := billing.CustomerDetails{
		FirstName: info.FirstName,
		LastName:  info.LastName,
		OrgName:   info.Name,
		Email:     info.Email,
		Address1:  info.Address,
		Address2:  info.Address2,
		City:      info.City,
		Country:   info.Country,
		State:     info.State,
		Zip:       info.PostalCode,
		Phone:     info.Phone,
		Type:      info.Type,
	}
	var err error
	err = serverConfig.BillingService.CreateCustomer(ctx, &billTo, &accountInfo)
	if err != nil {
		return err
	}

	//put the account info in the db
	db := loggedDB(ctx)
	err = db.Create(&accountInfo).Error
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint \"accountinfo_pkey") {
			return fmt.Errorf("AccountInfo with name %s (case-insensitive) already exists", info.Name)
		}
		return ormutil.DbErr(err)
	}
	return nil
}

func UpdateBillingOrg(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	// Pull json directly so we can unmarshal twice.
	// First time is to do lookup, second time is to apply
	// modified fields.
	body, err := ioutil.ReadAll(c.Request().Body)
	in := ormapi.BillingOrganization{}
	err = BindJson(body, &in)
	if err != nil {
		return ormutil.BindErr(err)
	}
	if in.Name == "" {
		return fmt.Errorf("BillingOrganization name not specified")
	}

	lookup := ormapi.BillingOrganization{
		Name: in.Name,
	}
	org := ormapi.BillingOrganization{}
	db := loggedDB(ctx)
	res := db.Where(&lookup).First(&org)
	if res.RecordNotFound() {
		return fmt.Errorf("BillingOrganization not found")
	}
	if res.Error != nil {
		return ormutil.NewHTTPError(http.StatusInternalServerError, ormutil.DbErr(res.Error).Error())
	}
	oldType := org.Type

	if err := authorized(ctx, claims.Username, in.Name, ResourceUsers, ActionManage); err != nil {
		return err
	}

	// apply specified fields
	err = BindJson(body, &org)
	if err != nil {
		return ormutil.BindErr(err)
	}
	if org.Type != oldType {
		return fmt.Errorf("Cannot change BillingOrganization type")
	}

	err = updateBillingInfo(ctx, &org)
	if err != nil {
		return err
	}

	err = db.Save(&org).Error
	if err != nil {
		return ormutil.NewHTTPError(http.StatusInternalServerError, ormutil.DbErr(err).Error())
	}
	return nil
}

func AddChildOrg(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := ormutil.GetContext(c)
	org := ormapi.BillingOrganization{}
	if err := c.Bind(&org); err != nil {
		return ormutil.BindErr(err)
	}
	span := log.SpanFromContext(ctx)
	span.SetTag("billing org", org.Name)

	err = AddChildOrgObj(ctx, claims, &org)
	if err != nil {
		return err
	}
	return ormutil.SetReply(c, ormutil.Msg("Organization added"))
}

func AddChildOrgObj(ctx context.Context, claims *UserClaims, parentOrg *ormapi.BillingOrganization) error {
	if err := authorized(ctx, claims.Username, parentOrg.Name, ResourceBilling, ActionManage); err != nil {
		return err
	}
	// get the parent and child
	parent, err := billingOrgExists(ctx, parentOrg.Name)
	if err != nil || parent == nil {
		return fmt.Errorf("Unable to find BillingOrganization: %s", parentOrg.Name)
	}
	if parent.Type != billing.CUSTOMER_TYPE_PARENT {
		return fmt.Errorf("Cannot add children to a non-parent Billing Org")
	}

	childrenNames := strings.Split(parentOrg.Children, ",")
	children := []*ormapi.Organization{}
	for _, childrenName := range childrenNames {
		child, err := orgExists(ctx, childrenName)
		if err != nil || child == nil {
			return fmt.Errorf("Unable to find Organization: %s", parentOrg.Children)
		}
		children = append(children, child)
	}

	addErrors := make(map[string]error)
	for _, child := range children {
		err = addChild(ctx, child, parent)
		if err != nil {
			addErrors[child.Name] = err
		}
	}
	if len(addErrors) > 0 {
		return fmt.Errorf("Unable to add one or more children: %v", addErrors)
	}
	return nil
}

func addChild(ctx context.Context, child *ormapi.Organization, parent *ormapi.BillingOrganization) error {
	if child.Type != OrgTypeDeveloper {
		return fmt.Errorf("Can only add %s orgs to a billing org", OrgTypeDeveloper)
	}
	if child.Parent != "" {
		return fmt.Errorf("Organization %s is already linked to a billing org: %s.", child.Name, child.Parent)
	}

	err := linkChildAccount(ctx, parent, child.Name)
	if err != nil {
		return err
	}

	child.Parent = parent.Name
	if parent.Children == "" {
		parent.Children = child.Name
	} else {
		parent.Children = parent.Children + "," + child.Name
	}

	db := loggedDB(ctx)
	err = db.Save(&child).Error
	if err != nil {
		return ormutil.DbErr(err)
	}
	err = db.Save(&parent).Error
	if err != nil {
		return ormutil.DbErr(err)
	}
	return nil
}

func RemoveChildOrg(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := ormutil.GetContext(c)
	org := ormapi.BillingOrganization{}
	if err := c.Bind(&org); err != nil {
		return ormutil.BindErr(err)
	}
	span := log.SpanFromContext(ctx)
	span.SetTag("billing org", org.Name)

	err = RemoveChildOrgObj(ctx, claims, &org)
	if err != nil {
		return err
	}
	return ormutil.SetReply(c, ormutil.Msg("Organization removed"))
}

func RemoveChildOrgObj(ctx context.Context, claims *UserClaims, billing *ormapi.BillingOrganization) error {
	if err := authorized(ctx, claims.Username, billing.Name, ResourceBilling, ActionManage); err != nil {
		return err
	}
	// get the parent and child
	parent, err := billingOrgExists(ctx, billing.Name)
	if err != nil || parent == nil {
		return fmt.Errorf("Unable to find BillingOrganization: %s", billing.Name)
	}

	childrenNames := strings.Split(billing.Children, ",")
	children := []*ormapi.Organization{}
	for _, childrenName := range childrenNames {
		child, err := orgExists(ctx, childrenName)
		if err != nil || child == nil {
			return fmt.Errorf("Unable to find Organization: %s", billing.Children)
		}
		children = append(children, child)
	}

	remErrors := make(map[string]error)
	for _, child := range children {
		err = removeChild(ctx, child, parent)
		if err != nil {
			remErrors[child.Name] = err
		}
	}
	if len(remErrors) > 0 {
		return fmt.Errorf("Unable to add one or more children: %v", remErrors)
	}
	return nil
}

func removeChild(ctx context.Context, child *ormapi.Organization, parent *ormapi.BillingOrganization) error {
	// check to make sure the child is really a child of the billingOrg
	isChild := false
	var index int
	children := strings.Split(parent.Children, ",")
	for i, childName := range children {
		if childName == child.Name && child.Parent == parent.Name {
			isChild = true
			index = i
			break
		}
	}
	if !isChild {
		return fmt.Errorf("Org %s and BillingOrg %s are not of the same billing family", child.Name, parent.Name)
	}

	inUse := orgInUse(ctx, child.Name)
	if inUse != nil {
		return inUse
	}

	child.Parent = ""
	parent.Children = strings.Join(append(children[0:index], children[index+1:len(children)]...), ",")
	db := loggedDB(ctx)
	err := db.Save(&child).Error
	if err != nil {
		return ormutil.DbErr(err)
	}
	err = db.Save(&parent).Error
	if err != nil {
		return ormutil.DbErr(err)
	}

	err = deleteBillingAccount(ctx, child.Name, deleteTypeChild)
	if err != nil {
		return err
	}

	return nil
}

func DeleteBillingOrg(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := ormutil.GetContext(c)
	org := ormapi.BillingOrganization{}
	if err := c.Bind(&org); err != nil {
		return ormutil.BindErr(err)
	}
	span := log.SpanFromContext(ctx)
	span.SetTag("billing org", org.Name)

	err = DeleteBillingOrgObj(ctx, claims, &org)
	if err != nil {
		return err
	}
	return ormutil.SetReply(c, ormutil.Msg("Billing Organization deleted"))
}

func DeleteBillingOrgObj(ctx context.Context, claims *UserClaims, org *ormapi.BillingOrganization) error {
	// TODO: remove this check later, for now to keep consistent with create, only allow admins to delete billingOrgs
	if !isAdmin(ctx, claims.Username) && billingEnabled(ctx) {
		return fmt.Errorf("Currently only admins may create and commit billingOrgs")
	}
	if org.Name == "" {
		return fmt.Errorf("Organization name not specified")
	}
	if err := authorized(ctx, claims.Username, org.Name, ResourceBilling, ActionManage); err != nil {
		return err
	}
	orgDetails, err := billingOrgExists(ctx, org.Name)
	// mark org for delete in progress
	db := loggedDB(ctx)
	doMark := true
	err = markBillingOrgForDelete(db, org.Name, doMark)
	if err != nil {
		return err
	}

	// check to see if orgs related to this BillingOrg are still up
	err = billingOrgDeletable(ctx, org.Name)
	if err != nil {
		undoerr := markBillingOrgForDelete(db, org.Name, !doMark)
		if undoerr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "undo mark org for delete", "undoerr", undoerr)
		}
		return err
	}

	// delete org
	err = db.Delete(&org).Error
	if err != nil {
		undoerr := markBillingOrgForDelete(db, org.Name, !doMark)
		if undoerr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "undo mark org for delete", "undoerr", undoerr)
		}
		return ormutil.DbErr(err)
	}

	err = deleteBillingAccount(ctx, org.Name, deleteTypeSelf)
	if err != nil {
		return err
	}

	// delete all casbin groups associated with org if the org was a parent org
	if orgDetails.Type == billing.CUSTOMER_TYPE_PARENT {
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
	} else {
		lookup := ormapi.Organization{
			Name: org.Name,
		}
		org := ormapi.Organization{}
		db := loggedDB(ctx)
		res := db.Where(&lookup).First(&org)
		if res.RecordNotFound() {
			return fmt.Errorf("unable to find corresponding Organization")
		}
		org.Parent = ""
		err = db.Save(&org).Error
		if err != nil {
			return ormutil.DbErr(err)
		}
	}
	return nil
}

// Show BillingOrganizations that current user belongs to.
func ShowBillingOrg(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	orgs, err := ShowBillingOrgObj(ctx, claims)
	if err != nil {
		return err
	}
	return ormutil.SetReply(c, orgs)
}

func ShowBillingOrgObj(ctx context.Context, claims *UserClaims) ([]ormapi.BillingOrganization, error) {
	orgs := []ormapi.BillingOrganization{}
	db := loggedDB(ctx)
	authOrgs, err := enforcer.GetAuthorizedOrgs(ctx, claims.Username, ResourceBilling, ActionView)
	if err != nil {
		return nil, err
	}
	if len(authOrgs) == 0 {
		return nil, echo.ErrForbidden
	}
	_, isAdmin := authOrgs[""]
	if isAdmin {
		// super user, show all orgs
		err := db.Find(&orgs).Error
		if err != nil {
			return nil, ormutil.DbErr(err)
		}
	} else {
		// show orgs for current user
		for orgName, _ := range authOrgs {
			org := ormapi.BillingOrganization{}
			org.Name = orgName
			err := db.Where(&org).First(&org).Error
			show := true
			if err != nil {
				// check to make sure it wasnt a regular org with no billing before throwing an error
				regOrg := ormapi.Organization{Name: orgName}
				regErr := db.Where(&regOrg).First(&regOrg).Error
				if regErr == nil {
					show = false
				} else {
					return nil, ormutil.DbErr(err)
				}
			}
			if show {
				orgs = append(orgs, org)
			}
		}
	}
	return orgs, nil
}

func ShowAccountInfo(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	accs, err := ShowAccountInfoObj(ctx, claims)
	if err != nil {
		return err
	}
	return ormutil.SetReply(c, accs)
}

func ShowAccountInfoObj(ctx context.Context, claims *UserClaims) ([]ormapi.AccountInfo, error) {
	accs := []ormapi.AccountInfo{}
	db := loggedDB(ctx)
	authOrgs, err := enforcer.GetAuthorizedOrgs(ctx, claims.Username, ResourceBilling, ActionManage)
	if err != nil {
		return nil, err
	}
	if len(authOrgs) == 0 {
		return nil, echo.ErrForbidden
	}
	_, isAdmin := authOrgs[""]
	if isAdmin {
		// super user, show all accs
		err := db.Find(&accs).Error
		if err != nil {
			return nil, ormutil.DbErr(err)
		}
	} else {
		// show accs for current user
		for org, _ := range authOrgs {
			acc := ormapi.AccountInfo{}
			acc.OrgName = org
			err = db.Where(&acc).First(&acc).Error
			show := true
			if err != nil {
				// check to make sure it wasnt a regular orge with no billing before throwing an error
				regOrg := ormapi.Organization{Name: org}
				regErr := db.Where(&regOrg).First(&regOrg).Error
				if regErr == nil {
					show = false
				} else {
					return nil, ormutil.DbErr(err)
				}
			}
			if show {
				accs = append(accs, acc)
			}
		}
	}
	return accs, nil
}

func ShowPaymentInfo(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := ormutil.GetContext(c)
	org := ormapi.BillingOrganization{}
	if err := c.Bind(&org); err != nil {
		return ormutil.BindErr(err)
	}
	profiles, err := ShowPaymentInfoObj(ctx, claims, &org)
	if err != nil {
		return err
	}
	return ormutil.SetReply(c, profiles)
}

func ShowPaymentInfoObj(ctx context.Context, claims *UserClaims, org *ormapi.BillingOrganization) ([]billing.PaymentProfile, error) {
	// TODO: remove this later, for now only mexadmin has the permission to manipulate payment info
	isAdmin, err := isUserAdmin(ctx, claims.Username)
	if err != nil {
		return nil, err
	}
	if !isAdmin && billingEnabled(ctx) {
		return nil, fmt.Errorf("Currently only admins may create and commit billingOrgs")
	}
	if err := authorized(ctx, claims.Username, org.Name, ResourceBilling, ActionView); err != nil {
		return nil, err
	}
	acc, err := GetAccountObj(ctx, org.Name)
	if err != nil {
		return nil, err
	}
	profiles, err := serverConfig.BillingService.ShowPaymentProfiles(ctx, acc)
	return profiles, err
}

func DeletePaymentInfo(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := ormutil.GetContext(c)
	profile := ormapi.PaymentProfileDeletion{}
	if err := c.Bind(&profile); err != nil {
		return ormutil.BindErr(err)
	}
	err = deletePaymentProfileObj(ctx, claims, &profile)
	if err != nil {
		return err
	}
	return ormutil.SetReply(c, nil)
}

func deletePaymentProfileObj(ctx context.Context, claims *UserClaims, profile *ormapi.PaymentProfileDeletion) error {
	// TODO: remove this later, for now only mexadmin has the permission to manipulare payment info
	isAdmin, err := isUserAdmin(ctx, claims.Username)
	if err != nil {
		return err
	}
	if !isAdmin && billingEnabled(ctx) {
		return fmt.Errorf("Currently only admins may create and commit billingOrgs")
	}
	if err := authorized(ctx, claims.Username, profile.Org, ResourceBilling, ActionManage); err != nil {
		return err
	}
	acc, err := GetAccountObj(ctx, profile.Org)
	if err != nil {
		return err
	}
	return serverConfig.BillingService.DeletePaymentProfile(ctx, acc, &billing.PaymentProfile{ProfileId: profile.Id})
}

func billingOrgExists(ctx context.Context, orgName string) (*ormapi.BillingOrganization, error) {
	lookup := ormapi.BillingOrganization{
		Name: orgName,
	}
	db := loggedDB(ctx)
	org := ormapi.BillingOrganization{}
	res := db.Where(&lookup).First(&org)
	if res.RecordNotFound() {
		return nil, nil
	}
	if res.Error != nil {
		return nil, res.Error
	}
	return &org, nil
}

func accountInfoExists(ctx context.Context, orgName string) (*ormapi.AccountInfo, error) {
	lookup := ormapi.AccountInfo{
		OrgName: orgName,
	}
	db := loggedDB(ctx)
	info := ormapi.AccountInfo{}
	res := db.Where(&lookup).First(&info)
	if res.RecordNotFound() {
		return nil, nil
	}
	if res.Error != nil {
		return nil, res.Error
	}
	return &info, nil
}

func deleteBillingAccount(ctx context.Context, orgName, deleteType string) error {
	if !billingEnabled(ctx) {
		return nil
	}
	// and remove the customer from the db and the billing service
	// get the full accountInfo
	info, err := GetAccountObj(ctx, orgName)
	if err != nil {
		return err
	}
	// remove account from db
	db := loggedDB(ctx)
	err = db.Delete(info).Error
	if err != nil {
		return ormutil.DbErr(err)
	}
	if deleteType == deleteTypeSelf {
		err = serverConfig.BillingService.DeleteCustomer(ctx, info)
		if err != nil {
			return err
		}
	} else if deleteType == deleteTypeChild {
		err = serverConfig.BillingService.DeleteCustomer(ctx, info)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("unknown delete type")
	}
	return nil
}

func GetAccountObj(ctx context.Context, orgName string) (*ormapi.AccountInfo, error) {
	if orgName == "" {
		return nil, fmt.Errorf("no orgName specified")
	}
	acc := ormapi.AccountInfo{
		OrgName: orgName,
	}
	db := loggedDB(ctx)
	res := db.Where(&acc).First(&acc)
	if res.Error != nil {
		if res.RecordNotFound() {
			return nil, fmt.Errorf("account \"%s\" not found", orgName)
		}
		return nil, res.Error
	}
	return &acc, nil
}

// Marking an org for delete must be done transactionally so other threads
// cannot accidentally run the delete in parallel.
func markBillingOrgForDelete(db *gorm.DB, name string, mark bool) (reterr error) {
	tx := db.Begin()
	defer func() {
		if reterr != nil {
			tx.Rollback()
		}
	}()
	// lookup org
	lookup := ormapi.BillingOrganization{
		Name: name,
	}
	findOrg := ormapi.BillingOrganization{}
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

func billingOrgDeletable(ctx context.Context, orgName string) error {
	org, err := billingOrgExists(ctx, orgName)
	if err != nil {
		return fmt.Errorf("Unable to find Billing Org")
	}
	// When a self org is being deleted, check to see if the child is either:
	// 1. nonexistent(already deleted and DeleteOrg is calling DeleteBillingOrg)
	// 2. the child org is not in use(cant be racking up charges if we cant charge them anymore)
	if org.Type == billing.CUSTOMER_TYPE_SELF {
		child, err := orgExists(ctx, org.Children)
		if err != nil {
			// maybe should still allow deletion to go through in case parent-child relationships got corrupted?
			return fmt.Errorf("Unable to locate linked child organization")
		}
		if child == nil {
			return nil
		}
		return orgInUse(ctx, child.Name)
	}
	if org.Type == billing.CUSTOMER_TYPE_PARENT && org.Children != "" {
		return fmt.Errorf("BillingOrg in use by Organizations: %s", org.Children)
	}
	return nil
}

// Check to make sure Organization is attached able to be charged
func isBillable(ctx context.Context, orgName string) bool {
	if !billingEnabled(ctx) {
		return true
	}
	if strings.ToLower(orgName) == strings.ToLower(cloudcommon.OrganizationMobiledgeX) || strings.ToLower(orgName) == strings.ToLower(cloudcommon.OrganizationEdgeBox) {
		return true
	}
	org, _ := orgExists(ctx, orgName)
	if org == nil || org.Parent == "" {
		return false
	}
	// this should always pass but just in case
	bOrg, _ := billingOrgExists(ctx, org.Parent)
	if bOrg == nil {
		return false
	}
	return true
}

func linkChildAccount(ctx context.Context, parent *ormapi.BillingOrganization, child string) error {
	if !billingEnabled(ctx) {
		return nil
	}
	parentAcc, err := GetAccountObj(ctx, parent.Name)
	if err != nil {
		return err
	}

	// chargify (and zuora) requires you to have billToContact info even if you are linked to a parent
	// so for now just use parent first and last name
	childAccountInfo := ormapi.AccountInfo{OrgName: child}
	billTo := billing.CustomerDetails{
		OrgName:   child,
		FirstName: parent.FirstName,
		LastName:  parent.LastName,
		Email:     parent.Email,
		Address1:  parent.Address,
		Address2:  parent.Address2,
		City:      parent.City,
		Country:   parent.Country,
		State:     parent.State,
		Zip:       parent.PostalCode,
		Phone:     parent.Phone,
	}
	err = serverConfig.BillingService.AddChild(ctx, parentAcc, &childAccountInfo, &billTo)
	if err != nil {
		return err
	}

	//put the account info in the db
	db := loggedDB(ctx)
	err = db.Create(&childAccountInfo).Error
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint \"accountinfo_pkey") {
			return fmt.Errorf("AccountInfo with name %s (case-insensitive) already exists", child)
		}
		return ormutil.DbErr(err)
	}
	err = db.Save(parentAcc).Error
	if err != nil {
		return ormutil.DbErr(err)
	}
	return nil
}

func updateBillingInfo(ctx context.Context, info *ormapi.BillingOrganization) error {
	if !billingEnabled(ctx) {
		return nil
	}
	// get the accountInfo for this billingOrg
	acc, err := GetAccountObj(ctx, info.Name)
	if err != nil {
		return err
	}
	billTo := billing.CustomerDetails{
		FirstName: info.FirstName,
		LastName:  info.LastName,
		Email:     info.Email,
		Address1:  info.Address,
		Address2:  info.Address2,
		City:      info.City,
		Country:   info.Country,
		State:     info.State,
		Zip:       info.PostalCode,
		Phone:     info.Phone,
	}
	// update it
	return serverConfig.BillingService.UpdateCustomer(ctx, acc, &billTo)
}

func billingEnabled(ctx context.Context) bool {
	config, _ := getConfig(ctx)
	if config == nil {
		return false
	}
	return config.BillingEnable
}

func GetInvoice(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := ormutil.GetContext(c)
	req := ormapi.InvoiceRequest{}
	if err := c.Bind(&req); err != nil {
		return ormutil.BindErr(err)
	}
	span := log.SpanFromContext(ctx)
	span.SetTag("invoice", req.Name)
	if err := authorized(ctx, claims.Username, req.Name, ResourceBilling, ActionView); err != nil {
		return err
	}
	acc, err := GetAccountObj(ctx, req.Name)
	if err != nil {
		return err
	}
	invoice, err := serverConfig.BillingService.GetInvoice(ctx, acc, req.StartDate, req.EndDate)
	if err != nil {
		return err
	}
	return ormutil.SetReply(c, invoice)
}
