package cliwrapper

import (
	"github.com/mobiledgex/edge-cloud-infra/billing"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
)

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

func (s *Client) ShowAccountInfo(uri, token string) ([]ormapi.AccountInfo, int, error) {
	args := []string{"billingorg", "showaccountinfo"}
	accs := []ormapi.AccountInfo{}
	st, err := s.runObjs(uri, token, args, nil, &accs)
	return accs, st, err
}

func (s *Client) ShowPaymentProfiles(uri, token string, org *ormapi.BillingOrganization) ([]billing.PaymentProfile, int, error) {
	args := []string{"billingorg", "showpaymentprofiles"}
	pros := []billing.PaymentProfile{}
	st, err := s.runObjs(uri, token, args, org, &pros)
	return pros, st, err
}

func (s *Client) DeletePaymentProfile(uri, token string, profile *ormapi.PaymentProfileDeletion) (int, error) {
	args := []string{"billingorg", "deletepaymentprofile"}
	return s.runObjs(uri, token, args, profile, nil)
}

func (s *Client) GetInvoice(uri, token string, req *ormapi.InvoiceRequest) ([]billing.InvoiceData, int, error) {
	args := []string{"billingorg", "getinvoice"}
	data := []billing.InvoiceData{}
	st, err := s.runObjs(uri, token, args, req, &data)
	return data, st, err
}
