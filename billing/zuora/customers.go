package zuora

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

func newZuoraReq(method, url string, payload interface{}) (*http.Response, error) {
	var body io.Reader
	if payload != nil {
		marshalled, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("Could not marshal %+v, err: %v", payload, err)
		}
		body = bytes.NewReader(marshalled)
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("Error creating request: %v\n", err)
	}
	// get oAuth token
	token, tokentype, err := getToken()
	if err != nil {
		return nil, fmt.Errorf("Unable to retrieve oAuth token")
	}
	req.Header.Add("Authorization", tokentype+" "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	return client.Do(req)
}

//Create customer with a empty monthly subscription (with no payment method for now)
func CreateCustomer(name, currency string, billToContact *CustomerBillToContact, parent, info *AccountInfo) error {
	account := NewAccount{
		Name:          name,
		BillToContact: billToContact,
		Currency:      currency,
		PaymentTerm:   "Due Upon Receipt",
		BillCycleDay:  1,
		AutoPay:       false, //required if you dont add a payment method
	}

	// Create an empty subscription for the customer
	newSub := CreateOrder{
		Description: "Creating subscription for " + name,
		OrderDate:   time.Now().Format("2006-01-02"),
	}

	newAction := OrderAction{Type: "CreateSubscription"}
	newAction.TriggerDates = []TriggerDate{
		TriggerDate{
			Name:        "ServiceActivation",
			TriggerDate: time.Now().Format("2006-01-02"),
		},
	}
	newAction.CreateSubscription = &CreateSubscription{
		Terms: CreateSubscriptionTerms{
			InitialTerm: CreateSubscriptionInitialTerm{
				StartDate: time.Now().Format("2006-01-02"),
				TermType:  "EVERGREEN",
			},
		},
	}

	if parent == nil {
		newSub.NewAccount = &account
	} else {
		// this sets the invoice owner, so for family relationships we use the parent
		newSub.ExistingAccountNumber = parent.AccountNumber
		account.ParentId = parent.AccountID
		newAction.CreateSubscription.NewSubscriptionOwnerAccount = &account
	}

	newSub.Subscriptions = []OrderSubscription{OrderSubscription{OrderActions: []OrderAction{newAction}}}

	resp, err := newZuoraReq("POST", ZuoraUrl+OrdersEndpoint, newSub)
	if err != nil {
		return fmt.Errorf("Error sending request: %v\n", err)
	}
	orderResp := OrderResp{}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&orderResp)
	if err != nil {
		return fmt.Errorf("Error parsing response: %v\n", err)
	}
	if !orderResp.Success || orderResp.Status != "Completed" || len(orderResp.SubscriptionNumbers) != 1 {
		// TODO: Add in error reasons when we get access to zuora again
		return fmt.Errorf("Error creating customer")
	}
	info.SubscriptionNumber = orderResp.SubscriptionNumbers[0]
	if parent == nil {
		err = getAccountInfo(orderResp.AccountNumber, info)
		if err != nil {
			return fmt.Errorf("Error setting account info: %v", err)
		}
	} else {
		id, num, err := getSubscriptionOwner(info.SubscriptionNumber)
		if err != nil {
			return fmt.Errorf("Error setting account info: %v", err)
		}
		info.AccountID = id
		info.AccountNumber = num
		info.ParentID = parent.AccountID
		info.ParentNumber = parent.AccountNumber
	}
	// for some reason the api only returns either the account number or id but not both, so get the id manually
	invOwner := info.AccountNumber
	if parent != nil {
		invOwner = info.ParentNumber
	}
	err = AddItem(FlavorUsageProductRatePlanId, info.AccountNumber, invOwner) //TODO: move this when we figure out pricing structure for flavors
	if err != nil {
		return fmt.Errorf("error adding item: %v", err)
	}
	return nil
}

// Create a parent account with no subscription attached
func CreateParentCustomer(name, currency string, billToContact *CustomerBillToContact, info *AccountInfo) error {
	account := NewAccount{
		Name:          name,
		BillToContact: billToContact,
		Currency:      currency,
		PaymentTerm:   "Due Upon Receipt",
		BillCycleDay:  1,
		AutoPay:       false, //required if you dont add a payment method
	}

	resp, err := newZuoraReq("POST", ZuoraUrl+AccountsEndPoint, account)
	if err != nil {
		return fmt.Errorf("Error sending request: %v\n", err)
	}
	accResp := AccountResp{}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&accResp)
	if err != nil {
		return fmt.Errorf("Error parsing response: %v\n", err)
	}
	if !accResp.Success {
		return fmt.Errorf("Error creating customer")
	}
	info.OrgName = name
	info.AccountNumber = accResp.AccountNumber
	info.AccountID = accResp.AccountId
	return nil
}

//Updates the customers billingInfo
func UpdateCustomer(info *AccountInfo, billToContact *CustomerBillToContact) error {
	account := NewAccount{
		BillToContact: billToContact,
		SoldToContact: billToContact, // for now keep them the same TODO: figure out what these actually mean
	}

	resp, err := newZuoraReq("PUT", ZuoraUrl+AccountsEndPoint+"/"+info.AccountNumber, account)
	if err != nil {
		return fmt.Errorf("Error sending request: %v\n", err)
	}
	parsedResp := GenericResp{}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&parsedResp)
	if err != nil {
		return fmt.Errorf("Error parsing response: %v\n", err)
	}
	if !parsedResp.Success {
		return fmt.Errorf("Error updating customer")
	}
	return nil
}

func CancelSubscription(accountInfo *AccountInfo) error {
	newSub := CreateOrder{
		Description:           "canceling subscription for " + accountInfo.OrgName,
		OrderDate:             time.Now().Format("2006-01-02"),
		ExistingAccountNumber: accountInfo.AccountNumber,
	}

	newAction := OrderAction{Type: "CancelSubscription"}
	newAction.TriggerDates = []TriggerDate{
		TriggerDate{
			Name:        "ContractEffective",
			TriggerDate: time.Now().Format("2006-01-02"),
		},
	}
	newAction.CancelSubscription = &CancelSub{
		CancellationEffectiveDate: getNextBillDay(),
		CancellationPolicy:        "SpecificDate",
	}
	newSub.Subscriptions = []OrderSubscription{
		OrderSubscription{
			SubscriptionNumber: accountInfo.SubscriptionNumber,
			OrderActions:       []OrderAction{newAction},
		},
	}

	resp, err := newZuoraReq("POST", ZuoraUrl+OrdersEndpoint, newSub)
	if err != nil {
		return fmt.Errorf("Error sending request: %v\n", err)
	}
	orderResp := OrderResp{}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&orderResp)
	if err != nil {
		return fmt.Errorf("Error parsing response: %v\n", err)
	}
	if !orderResp.Success {
		return fmt.Errorf("Error canceling subscription")
	}
	return nil
}

func getNextBillDay() string {
	//returns the next billing date in formay yyyy-mm-dd
	now := time.Now()
	date := time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC)
	return date.Format("2006-01-02")
}

// Delete a customer
func DeleteCustomer(accountInfo *AccountInfo) error {
	resp, err := newZuoraReq("DELETE", ZuoraUrl+ObjectAccountsEndpoint+accountInfo.AccountID, nil)
	if err != nil {
		return fmt.Errorf("Error sending request: %v\n", err)
	}
	deleteResp := GenericResp{}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&deleteResp)
	if err != nil {
		return fmt.Errorf("Error parsing response: %v\n", err)
	}
	if !deleteResp.Success {
		return fmt.Errorf("Error deleting customer")
	}

	return nil
}

// Creates a subscription for the customer with the product if he doesnt already have one, otherwise just adds the product onto the existing subscription
func AddItem(rateplanId, accountNum, invOwner string) error {
	// Check if they already have an existing subscription
	resp, err := newZuoraReq("GET", ZuoraUrl+GetSubscriptionEndpoint+accountNum, nil)
	if err != nil {
		return fmt.Errorf("Error sending request: %v\n", err)
	}
	subs := CheckSubscriptions{}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&subs)
	if err != nil {
		return fmt.Errorf("Error parsing response: %v\n", err)
	}
	if !subs.Success {
		return fmt.Errorf("Error retrieving Subscription")
	}
	// should have exactly one subscription per account
	if len(subs.Subscriptions) != 1 {
		return fmt.Errorf("Invalid account, contains zero or more than one subscription")
	}
	// check if we actually already have it
	for _, ratePlan := range subs.Subscriptions[0].RatePlans {
		if ratePlan.ProductRatePlanID == rateplanId {
			return nil // return nothing if it already existed
		}
	}
	// Create an order to add the product to the subscription
	subNum := subs.Subscriptions[0].SubscriptionNumber
	newOrder := CreateOrder{
		Description:           fmt.Sprintf("Adding product %s to subscription for account: %s", rateplanId, accountNum),
		ExistingAccountNumber: invOwner,
		OrderDate:             time.Now().Format("2006-01-02"),
	}
	newAction := OrderAction{
		Type: "AddProduct",
		AddProduct: &AddProduct{
			ProductRatePlanId: rateplanId,
		},
	}
	newAction.TriggerDates = []TriggerDate{
		TriggerDate{
			Name:        "ServiceActivation",
			TriggerDate: time.Now().Format("2006-01-02"),
		},
	}
	newOrder.Subscriptions = []OrderSubscription{
		OrderSubscription{
			OrderActions:       []OrderAction{newAction},
			SubscriptionNumber: subNum,
		},
	}

	resp, err = newZuoraReq("POST", ZuoraUrl+OrdersEndpoint, newOrder)
	if err != nil {
		return fmt.Errorf("Error sending request: %v\n", err)
	}
	orderResp := OrderResp{}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&orderResp)
	if err != nil {
		return fmt.Errorf("Error parsing response: %v\n", err)
	}
	if !orderResp.Success || orderResp.Status != "Completed" || len(orderResp.SubscriptionNumbers) != 1 {
		return fmt.Errorf("Error adding product to subscription")
	}
	return nil
}

func getSubscription(accountNum string) (*CheckSubscriptions, error) {
	resp, err := newZuoraReq("GET", ZuoraUrl+GetSubscriptionEndpoint+accountNum, nil)
	if err != nil {
		return nil, fmt.Errorf("Error sending request: %v\n", err)
	}

	subInfo := CheckSubscriptions{}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&subInfo)
	if err != nil {
		return nil, fmt.Errorf("Error parsing response: %v\n", err)
	}
	// for now only allow 1 subscription per account
	if !subInfo.Success || len(subInfo.Subscriptions) != 1 {
		return nil, fmt.Errorf("Unable to get subscription info")
	}

	return &subInfo, nil
}

// takes either the account id or account number and gives the other number, along with the parent(if there is one)
func getAccountInfo(accountIdOrNum string, info *AccountInfo) error {
	resp, err := newZuoraReq("GET", ZuoraUrl+AccountsEndPoint+"/"+accountIdOrNum, nil)
	if err != nil {
		return fmt.Errorf("Error sending request: %v\n", err)
	}

	accInfo := GetAccount{}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&accInfo)
	if err != nil {
		return fmt.Errorf("Error parsing response: %v\n", err)
	}
	if !accInfo.Success {
		return fmt.Errorf("Unable to get account info")
	}
	info.AccountNumber = accInfo.BasicInfo.AccountNumber
	info.AccountID = accInfo.BasicInfo.Id
	return nil
}

func getSubscriptionOwner(subNum string) (string, string, error) {
	resp, err := newZuoraReq("GET", ZuoraUrl+"/v1/subscriptions/"+subNum, nil)
	if err != nil {
		return "", "", fmt.Errorf("Error sending request: %v\n", err)
	}

	info := GetSubscriptionByKey{}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&info)
	if err != nil {
		return "", "", fmt.Errorf("Error parsing response: %v\n", err)
	}
	if !info.Success {
		return "", "", fmt.Errorf("Unable to get account info")
	}
	return info.AccountId, info.AccountNumber, nil
}
