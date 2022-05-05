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

package billing

import (
	"context"
	"time"

	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/vault"
)

const CUSTOMER_TYPE_PARENT = "parent"
const CUSTOMER_TYPE_CHILD = "child"
const CUSTOMER_TYPE_SELF = "self"
const PAYMENT_TYPE_CC = "credit_card"
const BillingTypeFake = "fake"

type CustomerDetails struct {
	OrgName   string
	FirstName string
	LastName  string
	Email     string
	CcEmails  string // comma separated list of additional emails
	Address1  string
	Address2  string
	City      string
	State     string
	Zip       string
	Country   string
	Phone     string
	Type      string // parent or child
	ParentId  string
}

type UsageRecord struct {
	FlavorName  string
	NodeCount   int
	ClusterInst *edgeproto.ClusterInstKey
	AppInst     *edgeproto.AppInstKey
	StartTime   time.Time
	EndTime     time.Time
	IpAccess    string
	Region      string
}

type InvoiceData struct {
	Number              string `json:"number,omitempty"`
	IssueDate           string `json:"issue_date,omitempty"`
	DueDate             string `json:"due_date,omitempty"`
	PaidDate            string `json:"paid_date,omitempty"`
	Status              string `json:"status,omitempty"`
	CollectionMethod    string `json:"collection_method,omitempty"`
	PaymentInstructions string `json:"payment_instructions,omitempty"`
	Currency            string `json:"currency,omitempty"`
	ConsolidationLevel  string `json:"consolidation_level,omitempty"`
	ProductName         string `json:"product_name,omitempty"`
	Seller              struct {
		Name    string  `json:"name,omitempty"`
		Address Address `json:"address,omitempty"`
		Phone   string  `json:"phone,omitempty"`
	} `json:"seller,omitempty"`
	Customer struct {
		FirstName    string `json:"first_name,omitempty"`
		LastName     string `json:"last_name,omitempty"`
		Organization string `json:"organization,omitempty"`
		Email        string `json:"email,omitempty"`
	} `json:"customer,omitempty"`
	Memo                string          `json:"memo,omitempty"`
	BillingAddress      Address         `json:"billing_address,omitempty"`
	ShippingAddress     Address         `json:"shipping_address,omitempty"`
	SubtotalAmount      string          `json:"subtotal_amount,omitempty"`
	DiscountAmount      string          `json:"discount_amount,omitempty"`
	TaxAmount           string          `json:"tax_amount,omitempty"`
	CreditAmount        string          `json:"credit_amount,omitempty"`
	RefundAmount        string          `json:"refund_amount,omitempty"`
	PaidAmount          string          `json:"paid_amount,omitempty"`
	DueAmount           string          `json:"due_amount,omitempty"`
	TotalAmount         string          `json:"total_amount,omitempty"`
	LineItems           []LineItems     `json:"line_items,omitempty"`
	Discounts           []Discounts     `json:"discounts,omitempty"`
	Taxes               []Taxes         `json:"taxes,omitempty"`
	Credits             []Credits       `json:"credits,omitempty"`
	Refunds             []Refunds       `json:"refunds,omitempty"`
	Payments            []Payments      `json:"payments,omitempty"`
	PreviousBalanceData PrevBalanceData `json:"previous_balance_data,omitempty"`
}

type Address struct {
	Street  string `json:"street,omitempty"`
	Line2   string `json:"line2,omitempty"`
	City    string `json:"city,omitempty"`
	State   string `json:"state,omitempty"`
	Zip     string `json:"zip,omitempty"`
	Country string `json:"country,omitempty"`
}

type LineItems struct {
	Uid                 string `json:"uid,omitempty"`
	Title               string `json:"title,omitempty"`
	Description         string `json:"description,omitempty"`
	Quantity            string `json:"quantity,omitempty"`
	UnitPrice           string `json:"unit_price,omitempty"`
	SubtotalAmount      string `json:"subtotal_amount,omitempty"`
	DiscountAmount      string `json:"discount_amount,omitempty"`
	TaxAmount           string `json:"tax_amount,omitempty"`
	TotalAmount         string `json:"total_amount,omitempty"`
	TieredUnitPrice     bool   `json:"tiered_unit_price,omitempty"`
	PeriodRangeStart    string `json:"period_range_start,omitempty"`
	PeriodRangeEnd      string `json:"period_range_end,omitempty"`
	ProductId           int    `json:"product_id,omitempty"`
	ProductVersion      int    `json:"product_version,omitempty"`
	ComponentId         int    `json:"component_id,omitempty"`
	PricePointId        int    `json:"price_point_id,omitempty"`
	ProductPricePointId int    `json:"product_price_point_id,omitempty"`
}

type Discounts struct {
	Uid                string               `json:"uid,omitempty"`
	Title              string               `json:"title,omitempty"`
	Code               string               `json:"code,omitempty"`
	SourceType         string               `json:"source_type,omitempty"`
	SourceId           int                  `json:"source_id,omitempty"`
	DiscountType       string               `json:"discount_type,omitempty"`
	Percentage         string               `json:"percentage,omitempty"`
	EligibleAmount     string               `json:"eligible_amount,omitempty"`
	DiscountAmount     string               `json:"discount_amount,omitempty"`
	LineItemsBreakouts []LineItemsBreakouts `json:"line_items_breakouts,omitempty"`
}

type LineItemsBreakouts struct {
	Uid            string `json:"uid,omitempty"`
	EligibleAmount string `json:"eligible_amount,omitempty"`
	DiscountAmount string `json:"discount_amount,omitempty"`
}

type Taxes struct {
	Uid                string               `json:"uid,omitempty"`
	Title              string               `json:"title,omitempty"`
	SourceType         string               `json:"source_type,omitempty"`
	SourceId           int                  `json:"source_id,omitempty"`
	Percentage         string               `json:"percentage,omitempty"`
	TaxableAmount      string               `json:"taxable_amount,omitempty"`
	TaxAmount          string               `json:"tax_amount,omitempty"`
	LineItemsBreakouts []LineItemsBreakouts `json:"line_items_breakouts,omitempty"`
}

type Credits struct {
	Uid              string `json:"uid,omitempty"`
	CreditNoteNumber string `json:"credit_note_number,omitempty"`
	CreditNoteUid    string `json:"credit_note_uid,omitempty"`
	TransactionTime  string `json:"transaction_time,omitempty"`
	Memo             string `json:"memo,omitempty"`
	OriginalAmount   string `json:"original_amount,omitempty"`
	AppliedAmount    string `json:"applied_amount,omitempty"`
}

type Refunds struct {
	TransactionId        int    `json:"transaction_id,omitempty"`
	PaymentId            int    `json:"payment_id,omitempty"`
	Memo                 string `json:"memo,omitempty"`
	OriginalAmount       string `json:"original_amount,omitempty"`
	AppliedAmount        string `json:"applied_amount,omitempty"`
	GatewayTransactionId string `json:"gateway_transaction_id,omitempty"`
}

type Payments struct {
	TransactionTime string `json:"transaction_time,omitempty"`
	Memo            string `json:"memo,omitempty"`
	OriginalAmount  string `json:"original_amount,omitempty"`
	AppliedAmount   string `json:"applied_amount,omitempty"`
	PaymentMethod   []struct {
		Details          string `json:"details,omitempty"`
		Kind             string `json:"kind,omitempty"`
		Memo             string `json:"memo,omitempty"`
		Type             string `json:"type,omitempty"`
		CardBrand        string `json:"card_brand,omitempty"`
		CardExpiration   string `json:"card_expiration,omitempty"`
		LastFour         string `json:"last_four,omitempty"`
		MaskedCardNumber string `json:"masked_card_number,omitempty"`
	} `json:"payment_method,omitempty"`
	TransactionId        int    `json:"transaction_id,omitempty"`
	Prepayment           bool   `json:"prepayment,omitempty"`
	GatewayTransactionId string `json:"gateway_transaction_id,omitempty"`
}

type PrevBalanceData struct {
	CaptureDate string `json:"capture_date,omitempty"`
	Invoices    []struct {
		Uid               string `json:"uid,omitempty"`
		Number            string `json:"number,omitempty"`
		OutstandingAmount string `json:"outstanding_amount,omitempty"`
	} `json:"invoices,omitempty"`
}

type PaymentProfile struct {
	ProfileId  int    `json:"profile_id,omitempty"`
	CardNumber string `json:"card_number,omitempty"`
	CardType   string `json:"card_type,omitempty"`
}

type BillingService interface {
	// Init is called once during startup
	Init(ctx context.Context, vaultConfig *vault.Config) error
	// The Billing service's type ie. "chargify" or "zuora"
	GetType() string
	// Create Customer, and fills out the accountInfo for that customer
	CreateCustomer(ctx context.Context, customer *CustomerDetails, account *ormapi.AccountInfo) error
	// Delete Customer
	DeleteCustomer(ctx context.Context, account *ormapi.AccountInfo) error
	// Update Customer
	UpdateCustomer(ctx context.Context, account *ormapi.AccountInfo, customerDetails *CustomerDetails) error
	// Add a child to a parent
	AddChild(ctx context.Context, parentAccount, childAccount *ormapi.AccountInfo, childDetails *CustomerDetails) error
	// Remove a child from a parent
	RemoveChild(ctx context.Context, parent, child *ormapi.AccountInfo) error
	// Records usage
	RecordUsage(ctx context.Context, region string, account *ormapi.AccountInfo, usageRecords []UsageRecord) error
	// Grab invoice data
	GetInvoice(ctx context.Context, account *ormapi.AccountInfo, startDate, endDate string) ([]InvoiceData, error)
	// Show payment profiles
	ShowPaymentProfiles(ctx context.Context, account *ormapi.AccountInfo) ([]PaymentProfile, error)
	// Delete payment profile
	DeletePaymentProfile(ctx context.Context, account *ormapi.AccountInfo, profile *PaymentProfile) error
}
