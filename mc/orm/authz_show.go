package orm

import (
	"context"

	"github.com/labstack/echo"
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

func (s *AuthzShow) setCloudletKeysFromPool(ctx context.Context, region, username string) error {
	rc := RegionContext{
		region:    region,
		username:  username,
		skipAuthz: true,
	}
	allowedOperOrgs, err := enforcer.GetAuthorizedOrgs(ctx, username, ResourceCloudletPools, ActionView)
	if err != nil {
		return err
	}
	s.allowedCloudlets = make(map[edgeproto.CloudletKey]struct{})
	err = ShowCloudletPoolStream(ctx, &rc, &edgeproto.CloudletPool{}, func(pool *edgeproto.CloudletPool) {
		if _, found := allowedOperOrgs[pool.Key.Organization]; !found {
			// skip pools which operator is not allowed to access
			return
		}
		for _, name := range pool.Cloudlets {
			cloudletKey := edgeproto.CloudletKey{
				Name:         name,
				Organization: pool.Key.Organization,
			}
			s.allowedCloudlets[cloudletKey] = struct{}{}
		}
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

func newShowClusterInstAuthz(ctx context.Context, region, username string, resource, action string) (ShowClusterInstAuthz, error) {
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

func newShowAppInstAuthz(ctx context.Context, region, username string, resource, action string) (ShowAppInstAuthz, error) {
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
