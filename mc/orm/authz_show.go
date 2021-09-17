package orm

import (
	"context"

	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ctrlapi"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormutil"
	"github.com/mobiledgex/edge-cloud/edgeproto"
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
	}
	operRes, operAction := getOperatorPermToViewDeveloperStuff()
	allowedOperOrgs, err := enforcer.GetAuthorizedOrgs(ctx, username, operRes, operAction)
	if err != nil {
		return err
	}
	s.allowedCloudlets = make(map[edgeproto.CloudletKey]struct{})
	err = ctrlapi.ShowCloudletPoolStream(ctx, &rc, &edgeproto.CloudletPool{}, connCache, nil, func(pool *edgeproto.CloudletPool) error {
		if _, found := allowedOperOrgs[pool.Key.Organization]; !found {
			// skip pools which operator is not allowed to access
			return nil
		}
		for _, name := range pool.Cloudlets {
			cloudletKey := edgeproto.CloudletKey{
				Name:         name,
				Organization: pool.Key.Organization,
			}
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

func newShowClusterInstAuthz(ctx context.Context, region, username string, resource, action string) (ctrlapi.ShowClusterInstAuthz, error) {
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

func newShowAppInstAuthz(ctx context.Context, region, username string, resource, action string) (ctrlapi.ShowAppInstAuthz, error) {
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

func newShowAppAuthz(ctx context.Context, region, username string, resource, action string) (ctrlapi.ShowAppAuthz, error) {
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

func newShowGPUDriverAuthz(ctx context.Context, region, username string, resource, action string) (ctrlapi.ShowGPUDriverAuthz, error) {
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
	}
	err = ctrlapi.ShowCloudletStream(ctx, &rc, &edgeproto.Cloudlet{}, connCache, nil, func(cl *edgeproto.Cloudlet) error {
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
