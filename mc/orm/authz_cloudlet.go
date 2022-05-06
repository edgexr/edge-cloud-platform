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
	fmt "fmt"

	"github.com/labstack/echo"
	"github.com/edgexr/edge-cloud-infra/mc/ctrlclient"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud-infra/mc/ormutil"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
)

// AuthzCloudlet provides an efficient way to check if the user
// can see the Cloudlet and Create/Delete ClusterInsts/AppInsts on the Cloudlet,
// based on an Organization's cloudlet pool associations.
type AuthzCloudlet struct {
	orgs             map[string]struct{}
	operOrgs         map[string]struct{}
	cloudletPoolSide map[edgeproto.CloudletKey]int
	allowAll         bool
	admin            bool
	billable         bool
}

const myPool int = 1
const notMyPool int = 2

func (s *AuthzCloudlet) populate(ctx context.Context, region, username, orgfilter, resource, action string, authops ...authOp) error {
	opts := authOptions{}
	for _, op := range authops {
		op(&opts)
	}

	// Get all orgs user has specified resource+action permissions for
	orgs, err := enforcer.GetAuthorizedOrgs(ctx, username, resource, action)
	if err != nil {
		return err
	}

	// Get all operator orgs user has access to
	operOrgs, err := enforcer.GetAuthorizedOrgs(ctx, username, ResourceCloudletPools, ActionView)
	if err != nil {
		return err
	}
	s.operOrgs = operOrgs

	// special cases
	if _, found := orgs[""]; found {
		// User is an admin. If no filter is specified,
		// then access for all cloudlets is provided.
		s.admin = true
		if orgfilter == "" {
			s.allowAll = true
			return nil
		} else {
			// ensure access (admin may not have explicit perms
			// for specified org).
			orgs[orgfilter] = struct{}{}
		}
	}
	if orgfilter != "" {
		// Filter only cloudlets for specified org.
		if _, found := orgs[orgfilter]; !found {
			return echo.ErrForbidden
		}
		orgs = make(map[string]struct{})
		orgs[orgfilter] = struct{}{}
	}

	if len(orgs) == 0 {
		// no access to any orgs for given resource/action
		return echo.ErrForbidden
	}

	if opts.requiresOrg != "" {
		// edgeboxOnly check is not required for Show command
		noEdgeboxOnly := false
		if err := checkRequiresOrg(ctx, opts.requiresOrg, resource, s.admin, noEdgeboxOnly); err != nil {
			return err
		}
	}

	if opts.requiresBillingOrg != "" {
		if isBillable(ctx, opts.requiresBillingOrg) {
			s.billable = true
		}
	} else {
		// if billing org check is not required, then set billable to true
		// so that no restrictions are made for the users of those org
		s.billable = true
	}

	s.orgs = orgs

	// get pools associated with orgs
	db := loggedDB(ctx)
	op := ormapi.OrgCloudletPool{}
	op.Region = region
	if orgfilter != "" {
		op.Org = orgfilter
	}
	ops := []ormapi.OrgCloudletPool{}
	err = db.Where(&op).Find(&ops).Error
	if err != nil {
		return err
	}
	ops = getAccessGranted(ops)

	mypools := make(map[edgeproto.CloudletPoolKey]struct{})
	for _, op := range ops {
		if _, found := orgs[op.Org]; !found {
			// no perms for org
			continue
		}
		poolKey := edgeproto.CloudletPoolKey{
			Name:         op.CloudletPool,
			Organization: op.CloudletPoolOrg,
		}
		mypools[poolKey] = struct{}{}
	}

	// get pools membership
	rc := ormutil.RegionContext{
		Region:    region,
		Username:  username,
		SkipAuthz: true,
		Database:  database,
	}
	// build map of cloudlets associated with all cloudlet pools
	s.cloudletPoolSide = make(map[edgeproto.CloudletKey]int)
	err = ctrlclient.ShowCloudletPoolStream(ctx, &rc, &edgeproto.CloudletPool{}, connCache, nil, func(pool *edgeproto.CloudletPool) error {
		for _, cloudletKey := range pool.Cloudlets {
			// cloudlet may belong to multiple pools, if any pool
			// is ours, allow access.
			side, found := s.cloudletPoolSide[cloudletKey]
			if !found {
				side = notMyPool
			}
			if _, found := mypools[pool.Key]; found {
				side = myPool
			}
			s.cloudletPoolSide[cloudletKey] = side
		}
		return nil
	})

	// if dev org is not a billing org, then perform authz here
	// to return appropriate error msg
	if opts.requiresBillingOrg != "" && !s.billable {
		allowed, _ := s.Ok(opts.targetCloudlet)
		if !allowed {
			poolSide, found := s.cloudletPoolSide[opts.targetCloudlet.Key]
			if found {
				if poolSide != myPool {
					return echo.ErrForbidden
				}
			} else {
				return fmt.Errorf("Billing Org must be set up to deploy to public cloudlets, please contact MobiledgeX support")
			}
		}
	}
	return err
}

// Ok checks if user is authorized to perform resource+action on cloudlet.
// Ok may be called many times, once for each cloudlet in a show command,
// so operates on the cached database data, rather than having to call into
// the database/regional controller each time.
func (s *AuthzCloudlet) Ok(obj *edgeproto.Cloudlet) (bool, bool) {
	filterOutput := false
	if s.allowAll {
		return true, filterOutput
	}
	if _, found := s.orgs[obj.Key.Organization]; found {
		// operator has access to cloudlets created by their org,
		// regardless of whether that cloudlet belongs to
		// developer pools or not.
		return true, filterOutput
	}

	if _, found := s.operOrgs[obj.Key.Organization]; found {
		// if developer is part of operator org as well, then they
		// can access those cloudlets
		return true, filterOutput
	}

	// if user doesn't belong to operator role for this cloudlet and is not admin,
	// then set filterOutput to true, so that operator data which is meant to be hidden
	// is filtered for that user
	filterOutput = true

	// First determine if cloudlet is "public" or "private".
	// "Public" cloudlets do not belong to any cloudlet pool.
	// "Private" cloudlets belong to one or more cloudlet pools.
	poolSide, found := s.cloudletPoolSide[obj.Key]
	if found {
		// "Private" cloudlet, accessible if it belongs to one
		// of our pools
		return poolSide == myPool, filterOutput
	} else {
		// "Public" cloudlet, accessible by all billable orgs
		return s.billable, filterOutput
	}
}

func (s *AuthzCloudlet) Filter(obj *edgeproto.Cloudlet) {
	// filter cloudlet details not required for developer role
	output := *obj
	*obj = edgeproto.Cloudlet{}
	obj.Key = output.Key
	obj.Location = output.Location
	obj.State = output.State
	obj.IpSupport = output.IpSupport
	obj.NumDynamicIps = output.NumDynamicIps
	obj.MaintenanceState = output.MaintenanceState
	obj.PlatformType = output.PlatformType
	obj.ResTagMap = output.ResTagMap
	obj.TrustPolicy = output.TrustPolicy
	obj.TrustPolicyState = output.TrustPolicyState
	obj.GpuConfig = output.GpuConfig
}

// Satisfy interface for ShowCloudletsForAppDeploymentAuthz which uses CloudletKey

type AuthzCloudletKey struct {
	authzCloudlet AuthzCloudlet
}

func (s *AuthzCloudletKey) Ok(key *edgeproto.CloudletKey) (bool, bool) {
	cloudlet := edgeproto.Cloudlet{
		Key: *key,
	}
	return s.authzCloudlet.Ok(&cloudlet)
}

func (s *AuthzCloudletKey) Filter(key *edgeproto.CloudletKey) {
	cloudlet := edgeproto.Cloudlet{
		Key: *key,
	}
	s.authzCloudlet.Filter(&cloudlet)
}

func (s *AuthzCloudletKey) populate(ctx context.Context, region, username, orgfilter, resource, action string, authops ...authOp) error {

	err := s.authzCloudlet.populate(ctx, region, username, orgfilter, resource, action, authops...)
	return err
}

const allianceDesc = "alliance"

func authzCreateCloudlet(ctx context.Context, region, username string, obj *edgeproto.Cloudlet, resource, action string) error {
	ops := []authOp{withRequiresOrg(obj.Key.Organization)}
	for _, org := range obj.AllianceOrgs {
		if org == obj.Key.FederatedOrganization {
			// validation is not required as it is a partner operator
			continue
		}
		ops = append(ops, withReferenceOrg(org, allianceDesc, OrgTypeOperator))
	}
	if obj.SingleKubernetesClusterOwner != "" {
		ops = append(ops, withReferenceOrg(obj.SingleKubernetesClusterOwner, "single kubernetes cluster owner", OrgTypeDeveloper))
	}
	if obj.PlatformType != edgeproto.PlatformType_PLATFORM_TYPE_EDGEBOX {
		ops = append(ops, withNoEdgeboxOnly())
	}
	return authorized(ctx, username, obj.Key.Organization, resource, action, ops...)
}

func authzUpdateCloudlet(ctx context.Context, region, username string, obj *edgeproto.Cloudlet, resource, action string) error {
	ops := []authOp{}
	for _, org := range obj.AllianceOrgs {
		if org == obj.Key.FederatedOrganization {
			// validation is not required as it is a partner operator
			continue
		}
		ops = append(ops, withReferenceOrg(org, allianceDesc, OrgTypeOperator))
	}
	return authorized(ctx, username, obj.Key.Organization, resource, action, ops...)
}

func authzAddCloudletAllianceOrg(ctx context.Context, region, username string, obj *edgeproto.CloudletAllianceOrg, resource, action string) error {
	ops := []authOp{withReferenceOrg(obj.Organization, allianceDesc, OrgTypeOperator)}
	return authorized(ctx, username, obj.Key.Organization, resource, action, ops...)
}

func authzCreateClusterInst(ctx context.Context, region, username string, obj *edgeproto.ClusterInst, resource, action string) error {
	authzCloudlet := AuthzCloudlet{}
	cloudlet := edgeproto.Cloudlet{
		Key: obj.Key.CloudletKey,
	}
	err := authzCloudlet.populate(ctx, region, username, obj.Key.Organization, resource, action, withRequiresOrg(obj.Key.Organization), withRequiresBillingOrg(obj.Key.Organization, &cloudlet))
	if err != nil {
		return err
	}
	if authzOk, _ := authzCloudlet.Ok(&cloudlet); !authzOk {
		return echo.ErrForbidden
	}
	return nil
}

func authzCreateAppInst(ctx context.Context, region, username string, obj *edgeproto.AppInst, resource, action string) error {
	authzCloudlet := AuthzCloudlet{}
	cloudlet := edgeproto.Cloudlet{
		Key: obj.Key.ClusterInstKey.CloudletKey,
	}
	err := authzCloudlet.populate(ctx, region, username, obj.Key.AppKey.Organization, resource, action, withRequiresOrg(obj.Key.AppKey.Organization), withRequiresBillingOrg(obj.Key.AppKey.Organization, &cloudlet))
	if err != nil {
		return err
	}
	if authzOk, _ := authzCloudlet.Ok(&cloudlet); !authzOk {
		return echo.ErrForbidden
	}
	// The autocluster organization checks are now dependent on the CRM version,
	// so these checks are left to the Controller. The MC is only
	// concerned about RBAC permissions, so only ensures that different
	// organizations are not encroaching on each other.
	if obj.Key.AppKey.Organization != obj.Key.ClusterInstKey.Organization && obj.Key.ClusterInstKey.Organization != "" {
		// Sidecar apps may have MobiledgeX organization, or
		// target ClusterInst may be MobiledgeX reservable/multitenant.
		// So one of the orgs must be MobiledgeX to pass RBAC.
		if obj.Key.AppKey.Organization != cloudcommon.OrganizationMobiledgeX && obj.Key.ClusterInstKey.Organization != cloudcommon.OrganizationMobiledgeX {
			return echo.ErrForbidden
		}
	}
	return nil
}

func authzCreateAutoProvPolicy(ctx context.Context, region, username string, obj *edgeproto.AutoProvPolicy, resource, action string) error {
	authzCloudlet := AuthzCloudlet{}
	err := authzCloudlet.populate(ctx, region, username, obj.Key.Organization, resource, action, withRequiresOrg(obj.Key.Organization))
	if err != nil {
		return err
	}
	for _, apCloudlet := range obj.Cloudlets {
		cloudlet := edgeproto.Cloudlet{
			Key: apCloudlet.Key,
		}
		if authzOk, _ := authzCloudlet.Ok(&cloudlet); !authzOk {
			return fmt.Errorf("No permissions for Cloudlet %s", cloudlet.Key.GetKeyString())
		}
	}
	return nil
}

func authzUpdateAutoProvPolicy(ctx context.Context, region, username string, obj *edgeproto.AutoProvPolicy, resource, action string) error {
	// handled the same as create
	return authzCreateAutoProvPolicy(ctx, region, username, obj, resource, action)
}

func authzAddAutoProvPolicyCloudlet(ctx context.Context, region, username string, obj *edgeproto.AutoProvPolicyCloudlet, resource, action string) error {
	authzCloudlet := AuthzCloudlet{}
	err := authzCloudlet.populate(ctx, region, username, obj.Key.Organization, resource, action, withRequiresOrg(obj.Key.Organization))
	if err != nil {
		return err
	}
	cloudlet := edgeproto.Cloudlet{
		Key: obj.CloudletKey,
	}
	if authzOk, _ := authzCloudlet.Ok(&cloudlet); !authzOk {
		return fmt.Errorf("No permissions for Cloudlet %s", cloudlet.Key.GetKeyString())
	}
	return nil
}

func newShowCloudletAuthz(ctx context.Context, region, username, resource, action string) (ctrlclient.ShowCloudletAuthz, error) {
	authzCloudlet := AuthzCloudlet{}
	err := authzCloudlet.populate(ctx, region, username, "", resource, action)
	if err != nil {
		return nil, err
	}
	return &authzCloudlet, nil
}
func newShowCloudletsForAppDeploymentAuthz(ctx context.Context, region, username string, resource, action string) (ctrlclient.ShowCloudletsForAppDeploymentAuthz, error) {
	authzCloudletKey := AuthzCloudletKey{}
	err := authzCloudletKey.populate(ctx, region, username, "", resource, action)
	if err != nil {
		return nil, err
	}
	return &authzCloudletKey, nil
}

func authzShowFlavorsForCloudlet(ctx context.Context, region, username string, obj *edgeproto.CloudletKey, resource, action string) error {
	authzCloudlet := AuthzCloudlet{}
	err := authzCloudlet.populate(ctx, region, username, "", resource, action, withRequiresOrg(obj.Organization))
	if err != nil {
		return err
	}
	cloudlet := edgeproto.Cloudlet{
		Key: *obj,
	}
	if authzOk, _ := authzCloudlet.Ok(&cloudlet); !authzOk {
		return fmt.Errorf("No permissions for Cloudlet %s", obj.GetKeyString())
	}
	return nil
}
