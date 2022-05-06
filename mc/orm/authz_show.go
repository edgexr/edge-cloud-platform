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

	"github.com/labstack/echo"
	"github.com/edgexr/edge-cloud-infra/mc/ctrlclient"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud-infra/mc/ormutil"
	"github.com/edgexr/edge-cloud/edgeproto"
)

type AuthzShow struct {
	allowedOrgs      map[string]struct{}
	allowAll         bool
	allowedCloudlets map[edgeproto.CloudletKey]struct{}
}

func newShowAuthz(ctx context.Context, region, username, resource, action string) (*AuthzShow, error) {
	orgs, err := enforcer.GetAuthorizedOrgs(ctx, username, resource, action)
	if err != nil {
		return nil, err
	}
	if len(orgs) == 0 {
		// no access to any orgs for given resource/action
		return nil, echo.ErrForbidden
	}
	authz := AuthzShow{
		allowedOrgs: orgs,
	}
	if _, found := orgs[""]; found {
		// user is an admin.
		authz.allowAll = true
	}
	return &authz, nil
}

func (s *AuthzShow) Ok(org string) bool {
	if s.allowAll {
		return true
	}
	_, found := s.allowedOrgs[org]
	return found
}

func getOperatorPermToViewDeveloperStuff() (string, string) {
	return ResourceCloudletPools, ActionView
}

func (s *AuthzShow) setCloudletKeysFromPool(ctx context.Context, region, username string) error {
	rc := ormutil.RegionContext{
		Region:    region,
		Username:  username,
		SkipAuthz: true,
		Database:  database,
	}
	operRes, operAction := getOperatorPermToViewDeveloperStuff()
	allowedOperOrgs, err := enforcer.GetAuthorizedOrgs(ctx, username, operRes, operAction)
	if err != nil {
		return err
	}
	s.allowedCloudlets = make(map[edgeproto.CloudletKey]struct{})
	err = ctrlclient.ShowCloudletPoolStream(ctx, &rc, &edgeproto.CloudletPool{}, connCache, nil, func(pool *edgeproto.CloudletPool) error {
		if _, found := allowedOperOrgs[pool.Key.Organization]; !found {
			// skip pools which operator is not allowed to access
			return nil
		}
		for _, cloudletKey := range pool.Cloudlets {
			s.allowedCloudlets[cloudletKey] = struct{}{}
		}
		return nil
	})
	return err
}

func newShowPoolAuthz(ctx context.Context, region, username string, resource, action string) (*AuthzShow, error) {
	orgs, err := enforcer.GetAuthorizedOrgs(ctx, username, resource, action)
	if err != nil {
		return nil, err
	}
	authz := AuthzShow{
		allowedOrgs: orgs,
	}
	if _, found := orgs[""]; found {
		// user is an admin.
		authz.allowAll = true
		return &authz, nil
	}

	// get cloudlet keys associated with pools
	err = authz.setCloudletKeysFromPool(ctx, region, username)
	if err != nil {
		return nil, err
	}
	if len(authz.allowedOrgs) == 0 && len(authz.allowedCloudlets) == 0 {
		// no access to any orgs for given resource/action
		return nil, echo.ErrForbidden
	}
	return &authz, nil
}

func (s *AuthzShow) OkCloudlet(devOrg string, cloudletKey edgeproto.CloudletKey) (bool, bool) {
	filterOutput := false
	if s.Ok(devOrg) {
		return true, filterOutput
	}
	if _, ok := s.allowedCloudlets[cloudletKey]; ok {
		return true, filterOutput
	}
	return false, filterOutput
}

type AuthzClusterInstShow struct {
	*AuthzShow
}

func newShowClusterInstAuthz(ctx context.Context, region, username string, resource, action string) (ctrlclient.ShowClusterInstAuthz, error) {
	authz, err := newShowPoolAuthz(ctx, region, username, resource, action)
	if err != nil {
		return nil, err
	}
	return &AuthzClusterInstShow{authz}, nil
}

func (s *AuthzClusterInstShow) Ok(obj *edgeproto.ClusterInst) (bool, bool) {
	return s.AuthzShow.OkCloudlet(obj.Key.Organization, obj.Key.CloudletKey)
}

func (s *AuthzClusterInstShow) Filter(obj *edgeproto.ClusterInst) {
	// nothing to filter for Operator, show all fields for Developer & Operator
}

type AuthzAppInstShow struct {
	*AuthzShow
}

func newShowAppInstAuthz(ctx context.Context, region, username string, resource, action string) (ctrlclient.ShowAppInstAuthz, error) {
	authz, err := newShowPoolAuthz(ctx, region, username, resource, action)
	if err != nil {
		return nil, err
	}
	return &AuthzAppInstShow{authz}, nil
}

func (s *AuthzAppInstShow) Ok(obj *edgeproto.AppInst) (bool, bool) {
	return s.AuthzShow.OkCloudlet(obj.Key.AppKey.Organization, obj.Key.ClusterInstKey.CloudletKey)
}

func (s *AuthzAppInstShow) Filter(obj *edgeproto.AppInst) {
	// nothing to filter for Operator, show all fields for Developer & Operator
}

type AuthzAppShow struct {
	allowedOrgs       map[string]struct{}
	allowAll          bool
	allowedOrgsByPool map[string]struct{}
}

func newShowAppAuthz(ctx context.Context, region, username string, resource, action string) (ctrlclient.ShowAppAuthz, error) {
	// this gets developer orgs that user can see
	orgs, err := enforcer.GetAuthorizedOrgs(ctx, username, resource, action)
	if err != nil {
		return nil, err
	}
	authz := AuthzAppShow{}
	authz.allowedOrgs = orgs
	if _, found := orgs[""]; found {
		// user is an admin
		authz.allowAll = true
		return &authz, nil
	}
	authz.allowedOrgsByPool = make(map[string]struct{})

	// get operator orgs that user has perms for
	operRes, operAction := getOperatorPermToViewDeveloperStuff()
	operOrgs, err := enforcer.GetAuthorizedOrgs(ctx, username, operRes, operAction)
	if err != nil {
		return nil, err
	}
	if len(orgs) == 0 && len(operOrgs) == 0 {
		return nil, echo.ErrForbidden
	}

	// get all operator orgs that have developer granted access
	db := loggedDB(ctx)
	op := ormapi.OrgCloudletPool{}
	op.Region = region
	ops := []ormapi.OrgCloudletPool{}
	err = db.Where(&op).Find(&ops).Error
	if err != nil {
		return nil, err
	}
	ops = getAccessGranted(ops)

	// get developer orgs that have been granted access by the
	// cloudlet pools.
	for _, op := range ops {
		// skip cloudlet pools that user does not have operator perms for
		if _, found := operOrgs[op.CloudletPoolOrg]; !found {
			continue
		}
		// add developer org associated with cloudlet pool
		authz.allowedOrgsByPool[op.Org] = struct{}{}
	}

	if len(orgs) == 0 && len(authz.allowedOrgsByPool) == 0 {
		return nil, echo.ErrForbidden
	}

	return &authz, nil
}

func (s *AuthzAppShow) Ok(obj *edgeproto.App) (bool, bool) {
	filterOutput := false
	if s.allowAll {
		return true, filterOutput
	}
	if _, found := s.allowedOrgs[obj.Key.Organization]; found {
		return true, filterOutput
	}
	if _, found := s.allowedOrgsByPool[obj.Key.Organization]; found {
		filterOutput = true
		return true, filterOutput
	}
	return false, filterOutput
}

func (s *AuthzAppShow) Filter(obj *edgeproto.App) {
	// nothing to filter for Operator, show all fields for Developer & Operator
}

type AuthzGPUDriverShow struct {
	authzCloudlet     AuthzCloudlet
	allowedGPUDrivers map[edgeproto.GPUDriverKey]struct{}
}

func newShowGPUDriverAuthz(ctx context.Context, region, username string, resource, action string) (ctrlclient.ShowGPUDriverAuthz, error) {
	authzCloudletObj := AuthzCloudlet{}
	err := authzCloudletObj.populate(ctx, region, username, "", resource, action)
	if err != nil {
		return nil, err
	}
	allowedGPUDrivers := make(map[edgeproto.GPUDriverKey]struct{})
	rc := ormutil.RegionContext{
		Region:    region,
		Username:  username,
		SkipAuthz: false,
		Database:  database,
	}
	err = ctrlclient.ShowCloudletStream(ctx, &rc, &edgeproto.Cloudlet{}, connCache, nil, func(cl *edgeproto.Cloudlet) error {
		// ignore non-GPU cloudlets
		if _, ok := cl.ResTagMap["gpu"]; !ok {
			return nil
		}
		// ignore if not authorized to access cloudlet
		if authzOk, _ := authzCloudletObj.Ok(cl); !authzOk {
			return nil
		}
		driverKey := cl.GpuConfig.Driver
		allowedGPUDrivers[driverKey] = struct{}{}
		return nil
	})
	return &AuthzGPUDriverShow{
		authzCloudlet:     authzCloudletObj,
		allowedGPUDrivers: allowedGPUDrivers,
	}, nil
}

func (s *AuthzGPUDriverShow) Ok(obj *edgeproto.GPUDriver) (bool, bool) {
	filterOutput := false
	if s.authzCloudlet.allowAll {
		return true, filterOutput
	}
	filterOutput = true
	if _, found := s.authzCloudlet.orgs[obj.Key.Organization]; found {
		// operator has access to GPU drivers created by their org
		return true, filterOutput
	}
	// All public drivers are accessible by any Developer/Operator
	if obj.Key.Organization == "" {
		return true, filterOutput
	}
	for driverKey, _ := range s.allowedGPUDrivers {
		if obj.Key.Matches(&driverKey) {
			return true, filterOutput
		}
	}
	return false, filterOutput
}

func (s *AuthzGPUDriverShow) Filter(obj *edgeproto.GPUDriver) {
	// nothing to filter for Operator, show all fields for Developer & Operator
	output := *obj
	*obj = edgeproto.GPUDriver{}
	obj.Key = output.Key
	obj.Properties = output.Properties
	obj.Builds = output.Builds
	obj.State = output.State
	if output.LicenseConfig != "" {
		obj.LicenseConfig = "*****"
	}
	for ii := range obj.Builds {
		obj.Builds[ii].DriverPath = ""
		obj.Builds[ii].DriverPathCreds = ""
	}
}

func authzGetGPUDriverBuildURL(ctx context.Context, region, username string, obj *edgeproto.GPUDriverBuildMember, resource, action string) error {
	authz, err := newShowGPUDriverAuthz(ctx, region, username, resource, action)
	if err != nil {
		return err
	}
	gpuDriver := edgeproto.GPUDriver{
		Key: obj.Key,
	}
	if authzOk, _ := authz.Ok(&gpuDriver); !authzOk {
		return echo.ErrForbidden
	}
	return nil
}

type AuthzCloudletInfoShow struct {
	authzShow AuthzShow
}

func newShowCloudletInfoAuthz(ctx context.Context, region, username string, resource, action string) (ctrlclient.ShowCloudletInfoAuthz, error) {
	authzShow, err := newShowAuthz(ctx, region, username, resource, action)
	if err != nil {
		return nil, err
	}
	return &AuthzCloudletInfoShow{
		authzShow: *authzShow,
	}, nil
}

func (s *AuthzCloudletInfoShow) Ok(obj *edgeproto.CloudletInfo) (bool, bool) {
	filterOutput := true
	if s.authzShow.allowAll {
		// do not filter output for admin
		filterOutput = false
	}
	return s.authzShow.Ok(obj.Key.Organization), filterOutput
}

func (s *AuthzCloudletInfoShow) Filter(obj *edgeproto.CloudletInfo) {
	// ResourcesSnapshot is used for internal resource tracking and
	// is not meant for operator user
	obj.ResourcesSnapshot = edgeproto.InfraResourcesSnapshot{}
}
