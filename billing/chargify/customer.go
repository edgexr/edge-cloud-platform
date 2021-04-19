package chargify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/billing"
	"github.com/mobiledgex/edge-cloud-infra/infracommon"
)

var customerEndpoint = "/customers"

func (bs *BillingService) CreateCustomer(ctx context.Context, customer *billing.CustomerDetails, account *billing.AccountInfo) error {
	newCustomer := billingToChargifyCustomer(customer)

	if customer.Type == billing.CUSTOMER_TYPE_CHILD {
		parentId, err := strconv.Atoi(customer.ParentId)
		if err != nil {
			return fmt.Errorf("Unable to parse parentId: %s, err: %v", customer.ParentId, err)
		}
		newCustomer.ParentId = parentId
	}

	resp, err := newChargifyReq("POST", "/customers.json", CustomerWrapper{Customer: &newCustomer})
	if err != nil {
		return fmt.Errorf("Error sending request: %v\n", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return infracommon.GetReqErr(resp.Body)
	}
	custResp := CustomerWrapper{}
	err = json.NewDecoder(resp.Body).Decode(&custResp)
	if err != nil {
		return fmt.Errorf("Error parsing response: %v\n", err)
	}

	// if its a self or child org, create subscription for it to the public_edge product
	if customer.Type != billing.CUSTOMER_TYPE_PARENT {
		newSub := Subscription{
			CustomerId:    strconv.Itoa(custResp.Customer.Id),
			ProductHandle: publicEdgeProductHandle,
		}

		// TODO: remove this and the function when we no longer offer free trials
		addFreeTrial(&newSub)

		newSub.PaymentCollectionMethod = "invoice"

		// set the billing cycle to the first of the month
		y, m, _ := time.Now().UTC().Date()
		// yyyy-mm-dd format
		newSub.NextBillingAt = time.Date(y, m+1, 1, 0, 0, 0, 0, time.UTC).Format("2006-01-02")

		resp, err := newChargifyReq("POST", "/subscriptions.json", SubscriptionWrapper{Subscription: &newSub})
		if err != nil {
			return fmt.Errorf("Error sending request: %v\n", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			return infracommon.GetReqErr(resp.Body)
		}
		subResp := SubscriptionWrapper{}
		err = json.NewDecoder(resp.Body).Decode(&subResp)
		if err != nil {
			return fmt.Errorf("Error parsing response: %v\n", err)
		}
		account.SubscriptionId = strconv.Itoa(subResp.Subscription.Id)
	}
	if customer.Type == billing.CUSTOMER_TYPE_CHILD {
		account.ParentId = strconv.Itoa(custResp.Customer.ParentId)
	}
	account.AccountId = strconv.Itoa(custResp.Customer.Id)
	account.Type = customer.Type
	return nil
}

// This function is temporary, adds a promotion to the sub that is 100% off
func addFreeTrial(sub *Subscription) {
	sub.CouponCode = "FREETRIALS"
}

// this doesnt actually delete the customer, what it does is cancels the subscription associated with the customer
// if we delete the customer, we also have to delete the subscription first which would result in losing the transaction history of that sub
func (bs *BillingService) DeleteCustomer(ctx context.Context, customer *billing.AccountInfo) error {
	switch customer.Type {
	case billing.CUSTOMER_TYPE_SELF:
		endpoint := "/subscriptions/" + customer.SubscriptionId + "/delayed_cancel.json"
		resp, err := newChargifyReq("POST", endpoint, nil)
		if err != nil {
			return err
		}
		if resp.StatusCode == http.StatusOK {
			return nil
		}
		defer resp.Body.Close()
		return infracommon.GetReqErr(resp.Body)

	case billing.CUSTOMER_TYPE_PARENT:
		endpoint := "/subscription_groups/" + customer.SubscriptionId + "/cancel.json"
		resp, err := newChargifyReq("POST", endpoint, SubscriptionGroupCancel{ChargeUnbilledUsage: true})
		if err != nil {
			return err
		}
		if resp.StatusCode == http.StatusOK {
			return nil
		}
		defer resp.Body.Close()
		return infracommon.GetReqErr(resp.Body)

	case billing.CUSTOMER_TYPE_CHILD:
		// for some reason individual subscriptions in groups can only be put on hold, so just do that
		endpoint := "/subscriptions/" + customer.SubscriptionId + "/hold.json"
		resp, err := newChargifyReq("POST", endpoint, nil)
		if err != nil {
			return err
		}
		if resp.StatusCode == http.StatusOK {
			return nil
		}
		defer resp.Body.Close()
		return infracommon.GetReqErr(resp.Body)
	}
	return nil
}

func (bs *BillingService) UpdateCustomer(ctx context.Context, account *billing.AccountInfo, customerDetails *billing.CustomerDetails) error {
	update := billingToChargifyCustomer(customerDetails) // any fields that actually contain a value will be the ones that are updated
	endpoint := "/customers/" + account.AccountId + ".json"
	resp, err := newChargifyReq("POST", endpoint, CustomerWrapper{Customer: &update})
	if err != nil {
		return fmt.Errorf("Error sending request: %v\n", err)
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return infracommon.GetReqErr(resp.Body)
	}

	return nil
}

func (bs *BillingService) AddChild(ctx context.Context, parentAccount, childAccount *billing.AccountInfo, childDetails *billing.CustomerDetails) error {
	// dont modify the existing struct
	childCopy := *childDetails
	childCopy.ParentId = parentAccount.AccountId
	childCopy.Type = billing.CUSTOMER_TYPE_CHILD
	err := bs.CreateCustomer(ctx, &childCopy, childAccount)
	if err != nil {
		return err
	}
	childAccount.Type = billing.CUSTOMER_TYPE_CHILD
	// if this is the first child, get the subscription group uid
	if parentAccount.SubscriptionId == "" {
		endpoint, err := url.Parse("/subscription_groups/lookup.json")
		if err != nil {
			return err
		}
		params := url.Values{}
		params.Add("subscription_id", childAccount.SubscriptionId)
		endpoint.RawQuery = params.Encode()
		resp, err := newChargifyReq("GET", endpoint.String(), nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return infracommon.GetReqErr(resp.Body)
		}
		group := SubscriptionGroup{}
		err = json.NewDecoder(resp.Body).Decode(&group)
		if err != nil {
			return fmt.Errorf("Error parsing response: %v\n", err)
		}
		// ensure this is the right subscription group
		if strconv.Itoa(group.CustomerId) != parentAccount.AccountId {
			return fmt.Errorf("Error setting up subscription group for children")
		}
		parentAccount.SubscriptionId = group.Uid
	}
	return nil
}

func (bs *BillingService) RemoveChild(ctx context.Context, parent, child *billing.AccountInfo) error {
	return bs.DeleteCustomer(ctx, child)
}

func (bs *BillingService) ValidateCustomer(ctx context.Context, account *billing.AccountInfo) error {
	// TODO: check chargify to make sure this account info is for real, and not some bogus from a malicious client
	// need to verify accountId, subId, and if there is a payment method attached to the subscription
	endpoint, err := url.Parse("/customers.json")
	if err != nil {
		return err
	}
	params := url.Values{}
	params.Add("q", account.AccountId)
	endpoint.RawQuery = params.Encode()
	resp, err := newChargifyReq("GET", endpoint.String(), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return infracommon.GetReqErr(resp.Body)
	}
	var cust []CustomerWrapper
	err = json.NewDecoder(resp.Body).Decode(&cust)
	if err != nil {
		return fmt.Errorf("Error parsing response: %v\n", err)
	}
	if len(cust) == 0 {
		return fmt.Errorf("Could not find customer information")
	} else if len(cust) > 1 {
		return fmt.Errorf("Invalid customer query, more than one result")
	}
	if cust[0].Customer.Organization != account.OrgName {
		return fmt.Errorf("Invalid Account details")
	}
	if account.Type != billing.CUSTOMER_TYPE_PARENT {
		// check the subscription
		subEndpoint := fmt.Sprintf("/customers/%s/subscriptions.json", account.AccountId)
		subResp, err := newChargifyReq("GET", subEndpoint, nil)
		if err != nil {
			return err
		}
		defer subResp.Body.Close()
		if subResp.StatusCode != http.StatusOK {
			return infracommon.GetReqErr(subResp.Body)
		}
		var subs []SubscriptionWrapper
		err = json.NewDecoder(subResp.Body).Decode(&subs)
		if err != nil {
			return fmt.Errorf("Error parsing response: %v\n", err)
		}
		if len(subs) == 0 {
			return fmt.Errorf("Customer does not have an attached subscription")
		} else if len(subs) > 1 {
			return fmt.Errorf("Customer is enrolled in more than one subscription")
		}
		sub := subs[0].Subscription
		if strconv.Itoa(sub.Id) != account.SubscriptionId {
			return fmt.Errorf("Invalid subscription information")
		}
		if sub.Product.Handle != publicEdgeProductHandle {
			return fmt.Errorf("Invalid subscription, incorrect product assignment")
		}
		// TODO: when payment info becomes mandatory, check that here EDGECLOUD-4723
	}
	return nil
}

// converts a customerDetails to a chargify specific struct of customer info
func billingToChargifyCustomer(customer *billing.CustomerDetails) Customer {
	chargifyCustomer := Customer{
		FirstName:    customer.FirstName,
		LastName:     customer.LastName,
		Organization: customer.OrgName,
		Email:        customer.Email,
		CcEmails:     customer.CcEmails,
		Address:      customer.Address1,
		Address2:     customer.Address2,
		City:         customer.City,
		State:        customer.State,
		Zip:          customer.Zip,
		Country:      customer.Country,
		Phone:        customer.Phone,
	}
	return chargifyCustomer
}
