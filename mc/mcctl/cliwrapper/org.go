package cliwrapper

import "github.com/mobiledgex/edge-cloud-infra/mc/ormapi"

func (s *Client) CreateOrg(uri, token string, org *ormapi.Organization) (int, error) {
	args := []string{"org", "create"}
	return s.runObjs(uri, token, args, org, nil)
}

func (s *Client) DeleteOrg(uri, token string, org *ormapi.Organization) (int, error) {
	args := []string{"org", "delete"}
	return s.runObjs(uri, token, args, org, nil)
}

func (s *Client) UpdateOrg(uri, token string, jsonData string) (int, error) {
	args := []string{"org", "update"}
	return s.runObjs(uri, token, args, jsonData, nil)
}

func (s *Client) ShowOrg(uri, token string) ([]ormapi.Organization, int, error) {
	args := []string{"org", "show"}
	orgs := []ormapi.Organization{}
	st, err := s.runObjs(uri, token, args, nil, &orgs)
	return orgs, st, err
}

func (s *Client) RestrictedUpdateOrg(uri, token string, org map[string]interface{}) (int, error) {
	args := []string{"org", "restrictedupdateorg"}
	return s.runObjs(uri, token, args, org, nil)
}
