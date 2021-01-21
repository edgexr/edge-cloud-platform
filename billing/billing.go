package billing

import (
	"context"
	"time"

	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/vault"
)

const CUSTOMER_TYPE_PARENT = "parent"
const CUSTOMER_TYPE_CHILD = "child"
const CUSTOMER_TYPE_SELF = "self"
const PAYMENT_TYPE_CC = "credit_card"

const BillingTypeFake = "fake"

type AccountInfo struct {
	OrgName               string `gorm:"primary_key;type:citext"`
	AccountId             string
	SubscriptionId        string
	ParentId              string
	Type                  string
	DefaultPaymentProfile int
}

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

type PaymentMethod struct {
	PaymentType    string
	PaymentProfile int
	CreditCard     CreditCard
}

type CreditCard struct {
	FirstName       string
	LastName        string
	CardNumber      string
	CardType        string
	ExpirationMonth int
	ExpirationYear  int
	Cvv             int
	BillingAddress  string
	BillingAddress2 string
	City            string
	State           string
	Zip             string
	Country         string
}

type UsageRecord struct {
	FlavorName  string
	NodeCount   int
	ClusterInst *edgeproto.ClusterInstKey
	AppInst     *edgeproto.AppInstKey
	StartTime   time.Time
	EndTime     time.Time
}

type BillingService interface {
	// Init is called once during startup
	Init(ctx context.Context, vaultConfig *vault.Config) error
	// The Billing service's type ie. "chargify" or "zuora"
	GetType() string
	// Create Customer, and fills out the accountInfo for that customer
	CreateCustomer(ctx context.Context, customer *CustomerDetails, account *AccountInfo, payment *PaymentMethod) error
	// Delete Customer
	DeleteCustomer(ctx context.Context, account *AccountInfo) error
	// Update Customer
	UpdateCustomer(ctx context.Context, account *AccountInfo, customerDetails *CustomerDetails) error
	// Add a child to a parent
	AddChild(ctx context.Context, parentAccount, childAccount *AccountInfo, childDetails *CustomerDetails) error
	// Remove a child from a parent
	RemoveChild(ctx context.Context, parent, child *AccountInfo) error
	// Records usage
	RecordUsage(ctx context.Context, account *AccountInfo, usageRecords []UsageRecord) error
}
