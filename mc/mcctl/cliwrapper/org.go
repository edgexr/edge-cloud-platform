package cliwrapper

import "github.com/mobiledgex/edge-cloud-infra/mc/ormapi"

func (s *Client) CreateOrg(uri, token string, ctrl *ormapi.Organization) (int, error) {
	args := []string{"org", "create"}
	return s.runObjs(uri, token, args, ctrl, nil)
}

func (s *Client) DeleteOrg(uri, token string, ctrl *ormapi.Organization) (int, error) {
	args := []string{"org", "delete"}
	return s.runObjs(uri, token, args, ctrl, nil)
}

func (s *Client) ShowOrg(uri, token string) ([]ormapi.Organization, int, error) {
	args := []string{"org", "show"}
	ctrls := []ormapi.Organization{}
	st, err := s.runObjs(uri, token, args, nil, &ctrls)
	return ctrls, st, err
}
