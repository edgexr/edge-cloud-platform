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

package fakebilling

import (
	"context"
	"fmt"
	"strconv"
	"sync"

	"github.com/edgexr/edge-cloud-infra/billing"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud/vault"
)

type BillingService struct{}

var subCounter = 1
var accountCounter = 1
var subMux sync.Mutex
var accMux sync.Mutex

func (bs *BillingService) Init(ctx context.Context, vaultConfig *vault.Config) error {
	return nil
}

func (bs *BillingService) GetType() string {
	return "fakebilling"
}

func (bs *BillingService) CreateCustomer(ctx context.Context, customer *billing.CustomerDetails, account *ormapi.AccountInfo) error {
	accMux.Lock()
	account.AccountId = strconv.Itoa(accountCounter)
	accountCounter = accountCounter + 1
	accMux.Unlock()

	subMux.Lock()
	account.SubscriptionId = strconv.Itoa(subCounter)
	subCounter = subCounter + 1
	subMux.Unlock()

	switch customer.Type {
	case billing.CUSTOMER_TYPE_PARENT:
		fallthrough
	case billing.CUSTOMER_TYPE_SELF:
		fallthrough
	case billing.CUSTOMER_TYPE_CHILD:
		account.Type = customer.Type
	default:
		return fmt.Errorf("Unrecognized account type: %s", customer.Type)
	}
	return nil
}

func (bs *BillingService) DeleteCustomer(ctx context.Context, account *ormapi.AccountInfo) error {
	return nil
}

func (bs *BillingService) UpdateCustomer(ctx context.Context, account *ormapi.AccountInfo, customerDetails *billing.CustomerDetails) error {
	return nil
}

func (bs *BillingService) AddChild(ctx context.Context, parentAccount, childAccount *ormapi.AccountInfo, childDetails *billing.CustomerDetails) error {
	bs.CreateCustomer(ctx, childDetails, childAccount)
	childAccount.ParentId = parentAccount.AccountId
	return nil
}

func (bs *BillingService) RemoveChild(ctx context.Context, parent, child *ormapi.AccountInfo) error {
	return nil
}

func (bs *BillingService) RecordUsage(ctx context.Context, region string, account *ormapi.AccountInfo, usageRecords []billing.UsageRecord) error {
	return nil
}

func (bs *BillingService) GetInvoice(ctx context.Context, account *ormapi.AccountInfo, startDate, endDate string) ([]billing.InvoiceData, error) {
	return nil, nil
}

func (bs *BillingService) ShowPaymentProfiles(ctx context.Context, account *ormapi.AccountInfo) ([]billing.PaymentProfile, error) {
	return nil, nil
}

func (bs *BillingService) DeletePaymentProfile(ctx context.Context, account *ormapi.AccountInfo, profile *billing.PaymentProfile) error {
	return nil
}
