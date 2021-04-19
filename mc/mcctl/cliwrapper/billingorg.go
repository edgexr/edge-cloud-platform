package cliwrapper

import "github.com/mobiledgex/edge-cloud-infra/mc/ormapi"

import "github.com/mobiledgex/edge-cloud-infra/billing"

func (s *Client) CreateBillingOrg(uri, token string, org *ormapi.BillingOrganization) (int, error) {
	args := []string{"billingorg", "create"}
	return s.runObjs(uri, token, args, org, nil)
}

func (s *Client) UpdateAccountInfo(uri, token string, acc *billing.AccountInfo) (int, error) {
	args := []string{"billingorg", "updateaccountinfo"}
	return s.runObjs(uri, token, args, acc, nil)
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

func (s *Client) GetInvoice(uri, token string, req *ormapi.InvoiceRequest) ([]billing.InvoiceData, int, error) {
	args := []string{"billingorg", "getinvoice"}
	data := []billing.InvoiceData{}
	st, err := s.runObjs(uri, token, args, req, &data)
	return data, st, err
}
