package orm

import (
	"context"

	edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
)

type AuthzAlert struct {
	orgs     map[string]struct{}
	allowAll bool
}

func newShowAlertAuthz(ctx context.Context, region, username, resource, action string) (*AuthzAlert, error) {
	orgs, err := enforcer.GetAuthorizedOrgs(ctx, username, resource, action)
	if err != nil {
		return nil, err
	}
	authz := AuthzAlert{
		orgs: orgs,
	}
	if _, found := orgs[""]; found {
		// user is an admin.
		authz.allowAll = true
	}
	return &authz, nil
}

func (s *AuthzAlert) Ok(obj *edgeproto.Alert) (bool, bool) {
	filterOutput := false
	if s.allowAll {
		return true, filterOutput
	}

	org := obj.Labels["apporg"]
	_, found := s.orgs[org]
	return found, filterOutput
}

func (s *AuthzAlert) Filter(obj *edgeproto.Alert) {
}
