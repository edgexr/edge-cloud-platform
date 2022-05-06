// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package chargify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/edgexr/edge-cloud-infra/billing"
	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
)

var showProfilesEndpoint = "/payment_profiles.json"
var deleteProfilesFmt = "/subscriptions/%s/payment_profiles/%d.json"

func (bs *BillingService) ShowPaymentProfiles(ctx context.Context, account *ormapi.AccountInfo) ([]billing.PaymentProfile, error) {
	endpoint, err := url.Parse(showProfilesEndpoint)
	if err != nil {
		return nil, err
	}
	params := url.Values{}
	params.Add("customer_id", account.AccountId)
	endpoint.RawQuery = params.Encode()
	resp, err := newChargifyReq("GET", endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("Error sending request: %v\n", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, infracommon.GetReqErr(resp.Body)
	}
	var profiles []PaymentProfileWrapper
	err = json.NewDecoder(resp.Body).Decode(&profiles)
	if err != nil {
		return nil, fmt.Errorf("Error parsing response: %v\n", err)
	}
	billingProfiles := []billing.PaymentProfile{}
	for _, profile := range profiles {
		newProfile := billing.PaymentProfile{
			ProfileId:  profile.PaymentProfile.Id,
			CardNumber: profile.PaymentProfile.MaskedCardNumber,
			CardType:   profile.PaymentProfile.CardType,
		}
		billingProfiles = append(billingProfiles, newProfile)
	}
	return billingProfiles, nil
}

func (bs *BillingService) DeletePaymentProfile(ctx context.Context, account *ormapi.AccountInfo, profile *billing.PaymentProfile) error {
	endpoint := fmt.Sprintf(deleteProfilesFmt, account.SubscriptionId, profile.ProfileId)
	resp, err := newChargifyReq("DELETE", endpoint, nil)
	if err != nil {
		return fmt.Errorf("Error sending request: %v\n", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return infracommon.GetReqErr(resp.Body)
	}
	return nil
}
