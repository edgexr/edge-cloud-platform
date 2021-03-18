package orm

import (
	"context"

	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
)

type AuthzOrgCloudletPool struct {
	allowedOperOrgs map[string]struct{}
	allowedDevOrgs  map[string]struct{}
	allowAll        bool
}

func newAuthzOrgCloudletPool(ctx context.Context, region, username string) (*AuthzOrgCloudletPool, error) {
	// This may be called by either a developer or an operator.
	authOperOrgs, err := enforcer.GetAuthorizedOrgs(ctx, username, ResourceCloudletPools, ActionManage)
	if err != nil {
		return nil, err
	}
	authDevOrgs, err := enforcer.GetAuthorizedOrgs(ctx, username, ResourceUsers, ActionManage)
	if err != nil {
		return nil, err
	}
	if len(authDevOrgs) == 0 && len(authOperOrgs) == 0 {
		return nil, echo.ErrForbidden
	}
	authz := AuthzOrgCloudletPool{
		allowedOperOrgs: authOperOrgs,
		allowedDevOrgs:  authDevOrgs,
	}
	if _, found := authOperOrgs[""]; found {
		// user is an admin
		authz.allowAll = true
	}
	return &authz, nil
}

func (s *AuthzOrgCloudletPool) Ok(in *ormapi.OrgCloudletPool) bool {
	if s.allowAll {
		return true
	}
	if _, found := s.allowedOperOrgs[in.CloudletPoolOrg]; found {
		return true
	}
	if _, found := s.allowedDevOrgs[in.Org]; found {
		return true
	}
	return false
}
