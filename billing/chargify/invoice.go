package chargify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/mobiledgex/edge-cloud-infra/billing"
	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
)

type invoiceResp struct {
	Invoices []billing.InvoiceData `json:"invoices,omitempty"`
	Meta     struct {
		StatusCode int `json:"status_code,omitempty"`
		InvCount   int `json:"total_invoice_count,omitempty"`
		CurPage    int `json:"current_page,omitempty"`
	} `json:"meta,omitempty"`
}

var invoiceEndpoint = "/invoices.json"

func (bs *BillingService) GetInvoice(ctx context.Context, account *ormapi.AccountInfo, startDate, endDate string) ([]billing.InvoiceData, error) {
	base, err := url.Parse(invoiceEndpoint)
	if err != nil {
		return nil, err
	}
	params := url.Values{}
	if startDate != "" {
		params.Add("start_date", startDate)
	}
	if endDate != "" {
		params.Add("end_date", endDate)
	}
	noPayments := false
	switch account.Type {
	case billing.CUSTOMER_TYPE_PARENT:
		params.Add("subscription_group_uid", account.SubscriptionId)
	case billing.CUSTOMER_TYPE_CHILD:
		noPayments = true // dont show parent payment data to children
		fallthrough
	case billing.CUSTOMER_TYPE_SELF:
		params.Add("subscription_id", account.SubscriptionId)
	default:
		return nil, fmt.Errorf("Unsupported customer type: %s", account.Type)
	}

	params.Add("per_page", "200")
	params.Add("line_items", "true")
	params.Add("discounts", "true")
	params.Add("taxes", "true")
	params.Add("credits", "true")
	params.Add("payments", "true")
	params.Add("custom_fields", "true")
	params.Add("refunds", "true")
	base.RawQuery = params.Encode()

	resp, err := newChargifyReq("GET", base.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("Error sending request: %v\n", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, infracommon.GetReqErr(resp.Body)
	}
	invoice := invoiceResp{}
	err = json.NewDecoder(resp.Body).Decode(&invoice)
	if err != nil {
		return nil, fmt.Errorf("error parsing response: %v\n", err)
	}
	if noPayments {
		for _, inv := range invoice.Invoices {
			inv.Payments = nil
		}
	}
	return invoice.Invoices, nil
}
