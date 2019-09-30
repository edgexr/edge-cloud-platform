package orm

import "context"

type ShowAuthz struct {
	orgs     map[string]struct{}
	allowAll bool
}

func NewShowAuthz(ctx context.Context, region, username, resource, action string) (*ShowAuthz, error) {
	orgs, err := enforcer.GetAuthorizedOrgs(ctx, username, resource, action)
	if err != nil {
		return nil, err
	}
	s := ShowAuthz{}
	s.orgs = orgs
	if _, found := orgs[""]; found {
		// admin
		s.allowAll = true
	}
	return &s, nil
}

func (s *ShowAuthz) Ok(org string) bool {
	if s.allowAll {
		return true
	}
	_, found := s.orgs[org]
	return found
}
