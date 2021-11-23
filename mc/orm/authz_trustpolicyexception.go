package orm

import (
	"context"
	fmt "fmt"

	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ctrlclient"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

type AuthzOrgTpe struct {
	allowedOperOrgs map[string]struct{}
	allowedDevOrgs  map[string]struct{}
	allowAll        bool
}

func (s *AuthzOrgTpe) populate(ctx context.Context, region, username, orgfilter, resource, action string, authops ...authOp) error {
	opts := authOptions{}
	for _, op := range authops {
		op(&opts)
	}
	// This may be called by either a developer or an operator.
	authOperOrgs, err := enforcer.GetAuthorizedOrgs(ctx, username, ResourceCloudletPools, action)
	if err != nil {
		return err
	}
	authDevOrgs, err := enforcer.GetAuthorizedOrgs(ctx, username, ResourceUsers, action)
	if err != nil {
		return err
	}
	if len(authDevOrgs) == 0 && len(authOperOrgs) == 0 {
		return echo.ErrForbidden
	}

	s.allowedDevOrgs = authDevOrgs
	s.allowedOperOrgs = authOperOrgs

	if _, found := authOperOrgs[""]; found {
		// user is an admin
		s.allowAll = true
	}
	return nil
}

func (s *AuthzOrgTpe) Ok(obj *edgeproto.TrustPolicyException) (bool, bool) {
	filterOutput := false
	if s.allowAll {
		return true, filterOutput
	}
	if _, found := s.allowedOperOrgs[obj.Key.CloudletPoolKey.Organization]; found {
		// operator has access to policies created by their org
		return true, filterOutput
	}
	if _, found := s.allowedDevOrgs[obj.Key.AppKey.Organization]; found {
		return true, filterOutput
	}
	filterOutput = true
	return false, filterOutput
}

func (s *AuthzOrgTpe) Filter(obj *edgeproto.TrustPolicyException) {
}

func newShowTrustPolicyExceptionAuthz(ctx context.Context, region, username, resource, action string) (ctrlclient.ShowTrustPolicyExceptionAuthz, error) {
	authzOrgTpe := AuthzOrgTpe{}
	err := authzOrgTpe.populate(ctx, region, username, "", resource, action)
	if err != nil {
		return nil, err
	}
	return &authzOrgTpe, nil
}

func newAuthzGetOrgsTpe(ctx context.Context, region, username, action string) (*AuthzOrgTpe, error) {
	// This may be called by either a developer or an operator.
	authOperOrgs, err := enforcer.GetAuthorizedOrgs(ctx, username, ResourceCloudletPools, action)
	if err != nil {
		return nil, err
	}
	authDevOrgs, err := enforcer.GetAuthorizedOrgs(ctx, username, ResourceUsers, action)
	if err != nil {
		return nil, err
	}
	if len(authDevOrgs) == 0 && len(authOperOrgs) == 0 {
		return nil, echo.ErrForbidden
	}
	authz := AuthzOrgTpe{
		allowedOperOrgs: authOperOrgs,
		allowedDevOrgs:  authDevOrgs,
	}
	if _, found := authOperOrgs[""]; found {
		// user is an admin
		authz.allowAll = true
	}
	return &authz, nil
}

func authzUpdateTrustPolicyException(ctx context.Context, region, username string, tpe *edgeproto.TrustPolicyException, resource, action string) error {
	if err := tpe.Key.ValidateKey(); err != nil {
		return err
	}
	authz, err := newAuthzGetOrgsTpe(ctx, region, username, action)

	if err != nil {
		return err
	}

	if _, found := authz.allowedOperOrgs[tpe.Key.CloudletPoolKey.Organization]; found {
		// Operator
		if err := authorized(ctx, username, tpe.Key.CloudletPoolKey.Organization, resource, action); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("User not allowed to update TrustPolicyException")
}
