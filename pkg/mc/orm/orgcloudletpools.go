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
	"io"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ctrlclient"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormutil"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	"github.com/labstack/echo/v4"
)

func validateOrgCloudletPool(op *ormapi.OrgCloudletPool) error {
	if op.Org == "" {
		return fmt.Errorf("Organization name not specified")
	}
	if op.Region == "" {
		return fmt.Errorf("Region not specified")
	}
	if op.CloudletPool == "" {
		return fmt.Errorf("CloudletPool name not specified")
	}
	if op.CloudletPoolOrg == "" {
		return fmt.Errorf("CloudletPool organization not specified")
	}
	return nil
}

func createOrgCloudletPool(ctx context.Context, op *ormapi.OrgCloudletPool) error {
	db := loggedDB(ctx)
	// lookup org to validate type against invitation type
	org := ormapi.Organization{}
	org.Name = op.Org
	res := db.Where(&org).First(&org)
	if res.RecordNotFound() {
		return fmt.Errorf("Specified developer organization not found")
	}
	if res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	if org.Type != OrgTypeDeveloper {
		return fmt.Errorf("Specified organization is not a developer organization")
	}

	found, err := hasCloudletPool(ctx, op.Region, op.CloudletPool, op.CloudletPoolOrg)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("Specified CloudletPool %s org %s for region %s not found", op.CloudletPool, op.CloudletPoolOrg, op.Region)
	}
	// create org cloudletpool
	err = db.Create(&op).Error
	if err != nil {
		if strings.Contains(err.Error(), "violates foreign key constraint \"org_cloudlet_pools_org_fkey\"") {
			return fmt.Errorf("Specified Organization %s does not exist", op.Org)
		}
		if strings.Contains(err.Error(), "violates foreign key constraint \"org_cloudlet_pools_region_fkey\"") {
			return fmt.Errorf("Specified Region %s does not exist", op.Region)
		}
		if strings.Contains(err.Error(), "violates foreign key constraint \"org_cloudlet_pools_cloudletpoolorg_fkey\"") {
			return fmt.Errorf("Specified CloudletPoolOrg %s does not exist", op.CloudletPoolOrg)
		}
		if strings.Contains(err.Error(), "duplicate key value violates unique") {
			return fmt.Errorf("CloudletPool %s for org %s, region %s, pool %s poolorg %s already exists", op.Type, op.Org, op.Region, op.CloudletPool, op.CloudletPoolOrg)
		}
		return ormutil.DbErr(err)
	}
	return nil
}

func hasCloudletPool(ctx context.Context, region, pool, org string) (bool, error) {
	conn, err := connectController(ctx, region)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	obj := edgeproto.CloudletPool{
		Key: edgeproto.CloudletPoolKey{
			Name:         pool,
			Organization: org,
		},
	}

	api := edgeproto.NewCloudletPoolApiClient(conn)
	stream, err := api.ShowCloudletPool(ctx, &obj)
	if err != nil {
		return false, err
	}
	found := false
	for {
		res, err := stream.Recv()
		if err == io.EOF {
			err = nil
			break
		}
		if err != nil {
			return false, err
		}
		if res.Key.Name == pool {
			found = true
		}
	}
	return found, nil
}

func deleteOrgCloudletPool(ctx context.Context, op *ormapi.OrgCloudletPool) error {
	db := loggedDB(ctx)

	// can't use db.Delete as we're not using primary key
	// see http://jinzhu.me/gorm/crud.html#delete
	args := []interface{}{
		"org = ? and region = ? and cloudlet_pool = ? and cloudlet_pool_org = ? and type = ?",
		op.Org,
		op.Region,
		op.CloudletPool,
		op.CloudletPoolOrg,
		op.Type,
	}
	res := db.Delete(op, args...)
	if res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("%s not found", util.CapitalizeMessage(op.Type))
	}
	return nil
}

// Used by UI to show cloudlets for the current organization
func ShowOrgCloudlet(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := ormutil.GetContext(c)
	oc := ormapi.OrgCloudlet{}
	_, err = ReadConn(c, &oc)
	if err != nil {
		return err
	}

	log.SpanLog(ctx, log.DebugLevelApi, "ShowOrgCloudlet", "oc", oc)
	if oc.Org == "" {
		return fmt.Errorf("Organization must be specified")
	}
	if oc.Region == "" {
		return fmt.Errorf("Region must be specified")
	}

	db := loggedDB(ctx)
	org := ormapi.Organization{}
	res := db.Where(&ormapi.Organization{Name: oc.Org}).First(&org)
	if res.RecordNotFound() {
		return fmt.Errorf("Specified Organization not found")
	}
	if res.Error != nil {
		return ormutil.DbErr(res.Error)
	}

	authzCloudlet := AuthzCloudlet{}
	err = authzCloudlet.populate(ctx, oc.Region, claims.Username, oc.Org, ResourceCloudlets, ActionView)
	if err != nil {
		return err
	}

	rc := ormutil.RegionContext{
		Region:    oc.Region,
		Username:  claims.Username,
		SkipAuthz: true,
		Database:  database,
	}
	show := make([]*edgeproto.Cloudlet, 0)
	err = ctrlclient.ShowCloudletStream(ctx, &rc, &edgeproto.Cloudlet{}, connCache, nil, func(cloudlet *edgeproto.Cloudlet) error {
		authzOk, filterOutput := authzCloudlet.Ok(cloudlet)
		if authzOk {
			if filterOutput {
				authzCloudlet.Filter(cloudlet)
			}
			show = append(show, cloudlet)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return ormutil.SetReply(c, show)
}

// Used by UI to show cloudlets for the current organization
func ShowOrgCloudletInfo(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := ormutil.GetContext(c)
	oc := ormapi.OrgCloudlet{}
	_, err = ReadConn(c, &oc)
	if err != nil {
		return err
	}

	if oc.Org == "" {
		return fmt.Errorf("Organization must be specified")
	}
	if oc.Region == "" {
		return fmt.Errorf("Region must be specified")
	}

	db := loggedDB(ctx)
	org := ormapi.Organization{}
	res := db.Where(&ormapi.Organization{Name: oc.Org}).First(&org)
	if res.RecordNotFound() {
		return fmt.Errorf("Specified Organization not found")
	}
	if res.Error != nil {
		return ormutil.DbErr(res.Error)
	}

	authzCloudlet := AuthzCloudlet{}
	err = authzCloudlet.populate(ctx, oc.Region, claims.Username, oc.Org, ResourceCloudlets, ActionView)
	if err != nil {
		return err
	}

	rc := ormutil.RegionContext{
		Region:    oc.Region,
		Username:  claims.Username,
		SkipAuthz: true,
		Database:  database,
	}
	show := make([]*edgeproto.CloudletInfo, 0)
	err = ctrlclient.ShowCloudletInfoStream(ctx, &rc, &edgeproto.CloudletInfo{}, connCache, nil, func(CloudletInfo *edgeproto.CloudletInfo) error {
		cloudlet := edgeproto.Cloudlet{
			Key: CloudletInfo.Key,
		}
		authzOk, filterOutput := authzCloudlet.Ok(&cloudlet)
		if authzOk {
			if filterOutput {
				output := *CloudletInfo
				*CloudletInfo = edgeproto.CloudletInfo{}
				CloudletInfo.Key = output.Key
				CloudletInfo.State = output.State
				CloudletInfo.Errors = output.Errors
				CloudletInfo.Flavors = output.Flavors
				CloudletInfo.MaintenanceState = output.MaintenanceState
				CloudletInfo.TrustPolicyState = output.TrustPolicyState
				CloudletInfo.CompatibilityVersion = output.CompatibilityVersion
			} else {
				// ResourcesSnapshot is used for internal resource tracking and is not meant for
				// operator user
				if !authzCloudlet.admin {
					CloudletInfo.ResourcesSnapshot = edgeproto.InfraResourcesSnapshot{}
					// Do not show controller pod's address to non-admin users
					CloudletInfo.Controller = ""
				}
			}
			show = append(show, CloudletInfo)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return ormutil.SetReply(c, show)
}

// Operators invite Developers to their CloudletPool
func CreateCloudletPoolAccessInvitation(c echo.Context) error {
	return createDeleteCloudletPoolAccess(c, cloudcommon.Create, ormapi.CloudletPoolAccessInvitation)
}

func DeleteCloudletPoolAccessInvitation(c echo.Context) error {
	return createDeleteCloudletPoolAccess(c, cloudcommon.Delete, ormapi.CloudletPoolAccessInvitation)
}

func ShowCloudletPoolAccessInvitation(c echo.Context) error {
	return showCloudletPoolAccess(c, ormapi.CloudletPoolAccessInvitation)
}

// Developers respond to Operator invitations
func CreateCloudletPoolAccessResponse(c echo.Context) error {
	return createDeleteCloudletPoolAccess(c, cloudcommon.Create, ormapi.CloudletPoolAccessResponse)
}

func DeleteCloudletPoolAccessResponse(c echo.Context) error {
	return createDeleteCloudletPoolAccess(c, cloudcommon.Delete, ormapi.CloudletPoolAccessResponse)
}

func ShowCloudletPoolAccessResponse(c echo.Context) error {
	return showCloudletPoolAccess(c, ormapi.CloudletPoolAccessResponse)
}

const (
	accessTypeGranted = "granted"
	accessTypePending = "pending"
)

// Show access granted
func ShowCloudletPoolAccessGranted(c echo.Context) error {
	return showCloudletPoolAccess(c, accessTypeGranted)
}

// Show access pending (invitation without response)
func ShowCloudletPoolAccessPending(c echo.Context) error {
	return showCloudletPoolAccess(c, accessTypePending)
}

func createDeleteCloudletPoolAccess(c echo.Context, action cloudcommon.Action, typ string) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := ormutil.GetContext(c)

	in := ormapi.OrgCloudletPool{}
	if err := c.Bind(&in); err != nil {
		return ormutil.BindErr(err)
	}
	if err := validateOrgCloudletPool(&in); err != nil {
		return err
	}
	span := log.SpanFromContext(ctx)

	if typ == ormapi.CloudletPoolAccessInvitation {
		// make sure caller is authorized for operator org
		span.SetTag("org", in.CloudletPoolOrg)
		if err := authorized(ctx, claims.Username, in.CloudletPoolOrg, ResourceCloudletPools, ActionManage); err != nil {
			return err
		}
		in.Decision = ""
	} else if typ == ormapi.CloudletPoolAccessResponse {
		// make sure caller is authorized for developer org
		span.SetTag("org", in.Org)
		if err := authorized(ctx, claims.Username, in.Org, ResourceUsers, ActionManage); err != nil {
			return err
		}
		if action == cloudcommon.Create {
			// decision field is requried
			if in.Decision != ormapi.CloudletPoolAccessDecisionAccept && in.Decision != ormapi.CloudletPoolAccessDecisionReject {
				return fmt.Errorf("Decision must be either %s or %s", ormapi.CloudletPoolAccessDecisionAccept, ormapi.CloudletPoolAccessDecisionReject)
			}
			// make sure invitation exists for create
			lookup := in
			lookup.Type = ormapi.CloudletPoolAccessInvitation
			lookup.Decision = ""
			db := loggedDB(ctx)
			res := db.Where(&lookup).Find(&lookup)
			if res.RecordNotFound() {
				return fmt.Errorf("No invitation for specified cloudlet pool access")
			}
			if res.Error != nil {
				return ormutil.DbErr(res.Error)
			}
		}
	} else {
		return fmt.Errorf("Internal error: invalid type")
	}

	in.Type = typ
	msg := ""
	if action == cloudcommon.Create {
		err = createOrgCloudletPool(ctx, &in)
		msg = fmt.Sprintf("%s created", typ)
	} else if action == cloudcommon.Delete {
		err = deleteOrgCloudletPool(ctx, &in)
		msg = fmt.Sprintf("%s deleted", typ)
		if typ == ormapi.CloudletPoolAccessInvitation {
			// also delete any response, as we have decided
			// that response should not exist without invitation.
			in.Type = ormapi.CloudletPoolAccessResponse
			deleteOrgCloudletPool(ctx, &in)
		}
	} else {
		return fmt.Errorf("Internal error: invalid action")
	}
	if err != nil {
		return err
	}
	// TODO: trigger email or slack to notify other party
	return ormutil.SetReply(c, ormutil.Msg(msg))
}

func showCloudletPoolAccess(c echo.Context, typ string) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := ormutil.GetContext(c)

	filter, err := bindDbFilter(c, &ormapi.OrgCloudletPool{})
	if err != nil {
		return err
	}
	out, err := showCloudletPoolAccessObj(ctx, claims.Username, filter, typ)
	if err != nil {
		return err
	}
	return ormutil.SetReply(c, out)
}

func showCloudletPoolAccessObj(ctx context.Context, username string, filter map[string]interface{}, typ string) ([]ormapi.OrgCloudletPool, error) {
	// granted and pending are not types in the database,
	// they're just used here for special cases.
	if typ != accessTypeGranted && typ != accessTypePending {
		filter["type"] = typ
	} else {
		delete(filter, "type")
	}
	region := ""
	if v, ok := filter["region"]; ok {
		if str, ok := v.(string); ok {
			region = str
		}
	}
	authz, err := newAuthzOrgCloudletPool(ctx, region, username, ActionView)
	if err != nil {
		return nil, err
	}

	ops := []ormapi.OrgCloudletPool{}
	db := loggedDB(ctx)
	err = db.Where(filter).Find(&ops).Error
	if err != nil {
		return nil, ormutil.DbErr(err)
	}

	retops := []ormapi.OrgCloudletPool{}
	for _, op := range ops {
		if !authz.Ok(&op) {
			continue
		}
		if typ != accessTypeGranted && typ != accessTypePending {
			// hide type as it is an internal-only field
			op.Type = ""
		}
		retops = append(retops, op)
	}
	if typ == accessTypeGranted {
		// reduce invitations and responses to single granted
		retops = getAccessGranted(retops)
	} else if typ == accessTypePending {
		// filter invitations to ones without responses
		retops = getAccessPending(retops)
	}
	return retops, nil

}

func getAccessGranted(ops []ormapi.OrgCloudletPool) []ormapi.OrgCloudletPool {
	tracker := make(map[ormapi.OrgCloudletPool]int)
	granted := make([]ormapi.OrgCloudletPool, 0)
	for _, op := range ops {
		lookup := op
		lookup.Type = ""
		lookup.Decision = ""
		val := tracker[lookup]
		if op.Type == ormapi.CloudletPoolAccessInvitation {
			val |= 0x1
		} else if op.Type == ormapi.CloudletPoolAccessResponse && op.Decision == ormapi.CloudletPoolAccessDecisionAccept {
			val |= 0x2
		} else {
			continue
		}
		// can never hit 3 more than once because you can't have
		// duplicate entries because the unique key is based on all
		// the fields (except decision).
		if val == 3 {
			granted = append(granted, lookup)
		}
		tracker[lookup] = val
	}
	return granted
}

func getAccessPending(ops []ormapi.OrgCloudletPool) []ormapi.OrgCloudletPool {
	tracker := make(map[ormapi.OrgCloudletPool]int)
	pending := make([]ormapi.OrgCloudletPool, 0)
	for _, op := range ops {
		lookup := op
		lookup.Type = ""
		lookup.Decision = ""
		val := tracker[lookup]
		if op.Type == ormapi.CloudletPoolAccessInvitation {
			val |= 0x1
		} else if op.Type == ormapi.CloudletPoolAccessResponse {
			val |= 0x2
		} else {
			continue
		}
		tracker[lookup] = val
	}
	for _, op := range ops {
		if op.Type != ormapi.CloudletPoolAccessInvitation {
			continue
		}
		lookup := op
		lookup.Type = ""
		lookup.Decision = ""
		val := tracker[lookup]
		if val == 0x1 {
			// invitation without response
			pending = append(pending, lookup)
		}
	}
	return pending
}
