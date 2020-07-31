package orm

import "context"

type AuthzShow struct {
	allowedOrgs map[string]struct{}
	allowAll    bool
}

func newShowAuthz(ctx context.Context, region, username, resource, action string) (*AuthzShow, error) {
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
