package cliwrapper

import "github.com/mobiledgex/edge-cloud-infra/mc/ormapi"

func (s *Client) AddUserRole(uri, token string, role *ormapi.Role) (int, error) {
	args := []string{"role", "add"}
	return s.runObjs(uri, token, args, role, nil)
}

func (s *Client) RemoveUserRole(uri, token string, role *ormapi.Role) (int, error) {
	args := []string{"role", "remove"}
	return s.runObjs(uri, token, args, role, nil)
}

func (s *Client) ShowUserRole(uri, token string) ([]ormapi.Role, int, error) {
	args := []string{"role", "show"}
	roles := []ormapi.Role{}
	st, err := s.runObjs(uri, token, args, nil, &roles)
	return roles, st, err
}

func (s *Client) ShowRoleAssignment(uri, token string) ([]ormapi.Role, int, error) {
	args := []string{"role", "assignment"}
	roles := []ormapi.Role{}
	st, err := s.runObjs(uri, token, args, nil, &roles)
	return roles, st, err
}
