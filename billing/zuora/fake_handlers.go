package zuora

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

func fakeAuth(w http.ResponseWriter, req *http.Request) {
	if req.Method == "POST" {
		if err := req.ParseForm(); err != nil {
			http.Error(w, "Error parsing input", http.StatusInternalServerError)
			return
		}
		id := req.FormValue("client_id")
		secret := req.FormValue("client_secret")
		if id != fakeClientID || secret != fakeClientSecret {
			http.Error(w, fmt.Sprintf("invalid fake credentials, id: %s, secret: %s", id, secret), http.StatusInternalServerError)
			return
		}
		token := OAuthToken{
			AccessToken: "faketoken",
			TokenType:   "Bearer",
			ExpiresIn:   600000, //10,000 minutes, so this will only have to be called once per test run
		}
		resp, err := json.Marshal(token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(resp)
	}
}

func fakeOrder(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.Error(w, fmt.Sprintf("Unsupported method for order request %s", req.Method), http.StatusBadRequest)
		return
	}
	var order CreateOrder
	err := json.NewDecoder(req.Body).Decode(&order)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// right now all of our zuora order calls only have one order per call
	if len(order.Subscriptions) != 1 || len(order.Subscriptions[0].OrderActions) != 1 {
		http.Error(w, "too many order actions in a single request", http.StatusBadRequest)
		return
	}
	action := order.Subscriptions[0].OrderActions[0]
	resp := OrderResp{}
	switch action.Type {
	case "CreateSubscription":
		if action.CreateSubscription == nil {
			http.Error(w, "create subscription fields empty", http.StatusBadRequest)
			return
		}
		account := action.CreateSubscription.NewSubscriptionOwnerAccount
		if account == nil {
			account = order.NewAccount // there is a parent account
			if account == nil {
				http.Error(w, "No Account specified", http.StatusBadRequest)
				return
			}
		}
		accountMux.Lock()
		subMux.Lock()
		accountId := strconv.Itoa(accountIdCounter)
		subId := strconv.Itoa(subIdCounter)
		subOwners[accountId] = subId
		accountIdCounter = accountIdCounter + 1
		subIdCounter = subIdCounter + 1
		subMux.Unlock()
		accountMux.Unlock()
		if account.ParentId != "" {
			// add it to the family
			familyMux.Lock()
			families[account.ParentId] = append(families[account.ParentId], accountId)
			familyMux.Unlock()
		}
		resp.Success = true
		resp.Status = "Completed"
		resp.AccountNumber = accountId
		resp.SubscriptionNumbers = []string{subId}
	case "CancelSubscription":
		if action.CancelSubscription == nil {
			http.Error(w, "cancel subscription fields empty", http.StatusBadRequest)
			return
		}
		resp.Success = true
	case "AddProduct":
		if action.AddProduct == nil {
			http.Error(w, "add product fields empty", http.StatusBadRequest)
			return
		}
		resp.Success = true
		resp.Status = "Completed"
		resp.SubscriptionNumbers = []string{"placeholderSubNumber"}
	default:
		http.Error(w, "unknown order type "+action.Type, http.StatusBadRequest)
		return
	}
	payload, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(payload)
}

func fakeAccounts(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case "POST": // create a new customer(Parent)
		var order NewAccount
		err := json.NewDecoder(req.Body).Decode(&order)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := AccountResp{}
		resp.Success = true
		accountMux.Lock()
		resp.AccountId = strconv.Itoa(accountIdCounter)
		resp.AccountNumber = resp.AccountId
		accountIdCounter = accountIdCounter + 1
		accountMux.Unlock()
		// only parent orgs are created here so setup an entry for them in the family map
		familyMux.Lock()
		families[resp.AccountNumber] = make([]string, 0)
		familyMux.Unlock()
		payload, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(payload)
	case "PUT": //update, verify the account exists then do nothing
		pathSplit := strings.Split(req.URL.Path, "/")
		// path should be of the form: /v1/accounts/<accountID>
		if len(pathSplit) < 3 {
			http.Error(w, "Unable to find accountNumber", http.StatusBadRequest)
			return
		}
		accountStr := pathSplit[len(pathSplit)-1]
		accountNum, err := strconv.Atoi(accountStr)
		if err != nil {
			http.Error(w, "error parsing accountNumber: "+accountStr, http.StatusBadRequest)
			return
		}
		if accountNum < accountIdCounter {
			deleteMux.Lock()
			for _, deleted := range deletedAccounts {
				if deleted == accountStr {
					http.Error(w, "cannot update a deleted account", http.StatusBadRequest)
					deleteMux.Unlock()
					return
				}
			}
			deleteMux.Unlock()
		} else {
			http.Error(w, fmt.Sprintf("account %d does not exist", accountNum), http.StatusBadRequest)
			return
		}

		resp := GenericResp{Success: true}
		payload, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(payload)
	case "GET":
		pathSplit := strings.Split(req.URL.Path, "/")
		// path should be of the form: /v1/accounts/<accountID>
		if len(pathSplit) < 3 {
			http.Error(w, "Unable to find accountNumber", http.StatusBadRequest)
			return
		}
		accountStr := pathSplit[len(pathSplit)-1]
		accountNum, err := strconv.Atoi(accountStr)
		if err != nil {
			http.Error(w, "error parsing accountNumber: "+accountStr, http.StatusBadRequest)
			return
		}
		resp := GetAccount{
			Success: true,
			BasicInfo: BasicInfo{
				Id:            strconv.Itoa(accountNum),
				AccountNumber: strconv.Itoa(accountNum),
			},
		}
		payload, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(payload)
	default:
		http.Error(w, "unsupported http method: "+req.Method, http.StatusBadRequest)
		return
	}
}

func fakeDeleteAccounts(w http.ResponseWriter, req *http.Request) {
	if req.Method != "DELETE" {
		http.Error(w, "unsupported http method: "+req.Method, http.StatusBadRequest)
		return
	}
	pathSplit := strings.Split(req.URL.Path, "/")
	// path should be of the form: /v1/object/account/<accountID>
	if len(pathSplit) < 4 {
		http.Error(w, "Unable to find accountNumber", http.StatusBadRequest)
		return
	}
	accountStr := pathSplit[len(pathSplit)-1]
	deleteMux.Lock()
	deletedAccounts = append(deletedAccounts, accountStr)
	deleteMux.Unlock()
}

func fakeGetSubs(w http.ResponseWriter, req *http.Request) {
	resp := CheckSubscriptions{
		Success: true,
		Subscriptions: []Subs{Subs{
			RatePlans: []SubRatePlans{
				SubRatePlans{
					RatePlanCharges: []SubRatePlanCharges{
						// include the two rate plan numbers getRatePlanChargeId currently returns
						SubRatePlanCharges{
							ProductRatePlanChargeID: "2c92c0f8712986160171369e86d94ce9",
							Number:                  "Rate1",
						},
						SubRatePlanCharges{
							ProductRatePlanChargeID: "2c92c0f9712998b30171369c87bd3c44",
							Number:                  "Rate2",
						},
					},
				},
			},
		},
		},
	}
	payload, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(payload)
}

func fakeCheckSubOwner(w http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" {
		http.Error(w, "Unsupported http method: "+req.Method, http.StatusBadRequest)
		return
	}
	pathSplit := strings.Split(req.URL.Path, "/")
	// path should be of the form: /v1/subscriptions/<subID>
	if len(pathSplit) < 3 {
		http.Error(w, "Unable to find SubscriptionNumber", http.StatusBadRequest)
		return
	}
	subStr := pathSplit[len(pathSplit)-1]
	accountNum := subOwners[subStr]
	resp := GetSubscriptionByKey{
		Success:       true,
		AccountId:     accountNum,
		AccountNumber: accountNum,
	}
	payload, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(payload)
}

func fakeUsageRecord(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.Error(w, "Unsupported http method: "+req.Method, http.StatusBadRequest)
		return
	}
	// just ensure the account number is valid and they put in valid runtimes
	var record CreateUsage
	err := json.NewDecoder(req.Body).Decode(&record)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	acc, err := strconv.Atoi(record.AccountNumber)
	if err != nil || acc < accountIdCounter {
		http.Error(w, "Invalid accountNumber: "+record.AccountNumber, http.StatusBadRequest)
		return
	}
	sub, err := strconv.Atoi(record.SubscriptionNumber)
	if err != nil || sub < subIdCounter {
		http.Error(w, "Invalid SubscriptionNumber: "+record.SubscriptionNumber, http.StatusBadRequest)
		return
	}
	if record.Quantity < 0 {
		http.Error(w, fmt.Sprintf("Invalid Quantity specified: %f", record.Quantity), http.StatusBadRequest)
		return
	}
	resp := GenericResp{
		Success: true,
	}
	payload, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(payload)
}
