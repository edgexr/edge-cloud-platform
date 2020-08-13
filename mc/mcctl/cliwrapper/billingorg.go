package cliwrapper

import "github.com/mobiledgex/edge-cloud-infra/mc/ormapi"

func (s *Client) CreateBillingOrg(uri, token string, org *ormapi.BillingOrganization) (int, error) {
	args := []string{"billingorg", "create"}
	return s.runObjs(uri, token, args, org, nil)
}

func (s *Client) DeleteBillingOrg(uri, token string, org *ormapi.BillingOrganization) (int, error) {
	args := []string{"billingorg", "delete"}
	return s.runObjs(uri, token, args, org, nil)
}

func (s *Client) AddChildOrg(uri, token string, org *ormapi.BillingOrganization) (int, error) {
	args := []string{"billingorg", "addchildorg"}
	return s.runObjs(uri, token, args, org, nil)
}

func (s *Client) RemoveChildOrg(uri, token string, org *ormapi.BillingOrganization) (int, error) {
	args := []string{"billingorg", "removechildorg"}
	return s.runObjs(uri, token, args, org, nil)
}

func (s *Client) UpdateBillingOrg(uri, token string, jsonData string) (int, error) {
	args := []string{"billingorg", "update"}
	return s.runObjs(uri, token, args, jsonData, nil)
}

func (s *Client) ShowBillingOrg(uri, token string) ([]ormapi.BillingOrganization, int, error) {
	args := []string{"billingorg", "show"}
	orgs := []ormapi.BillingOrganization{}
	st, err := s.runObjs(uri, token, args, nil, &orgs)
	return orgs, st, err
}
