package chargify

var apiKey string
var siteName string
var apiPassword = "x" // password to go with apiKey in basic auth for http. This is always x, the apiKey is what changes
var vaultPath = "secret/data/accounts/chargify"
var publicEdgeProductHandle = "publicedge"

var paymentTypeCC = "credit_card"
var paymentTypeBank = "bank_account"
var paymentTypePP = "paypal_account"

type CustomerWrapper struct {
	Customer *Customer `json:"customer"`
}

type Customer struct {
	Id                         int    `json:"id,omitempty"`
	FirstName                  string `json:"first_name,omitempty"`
	LastName                   string `json:"last_name,omitempty"`
	Organization               string `json:"organization,omitempty"`
	Email                      string `json:"email,omitempty"`
	CcEmails                   string `json:"cc_emails,omitempty"`
	Reference                  string `json:"reference,omitempty"`
	Address                    string `json:"address,omitempty"`
	Address2                   string `json:"address_2,omitempty"`
	City                       string `json:"city,omitempty"`
	State                      string `json:"state,omitempty"`
	Zip                        string `json:"zip,omitempty"`
	Country                    string `json:"country,omitempty"`
	Phone                      string `json:"phone,omitempty"`
	Verified                   bool   `json:"verified,omitempty"`
	TaxExempt                  bool   `json:"tax_exempt,omitempty"`
	CreatedAt                  string `json:"created_at,omitempty"`
	UpdatedAt                  string `json:"updated_at,omitempty"`
	PortalInviteLastSentAt     string `json:"portal_invite_last_sent_at,omitempty"`
	PortalInviteLastAcceptedAt string `json:"portal_invite_last_accepted_at,omitempty"`
	PortalCustomerCreatedAt    string `json:"portal_customer_created_at,omitempty"`
	ParentId                   int    `json:"parent_id,omitempty"`
}

type CreditCard struct {
	Id                 int    `json:"id,omitempty"`
	FirstName          string `json:"first_name,omitempty"`
	LastName           string `json:"last_name,omitempty"`
	MaskedCardNumber   string `json:"masked_card_number,omitempty"`
	FullCardNumber     string `json:"full_number,omitempty"`
	CardType           string `json:"card_type,omitempty"`
	ExpirationMonth    int    `json:"expiration_month,omitempty"`
	ExpirationYear     int    `json:"expiration_year,omitempty"`
	BillingAddress     string `json:"billing_address,omitempty"`
	BillingAddress2    string `json:"billing_address_2,omitempty"`
	BillingCity        string `json:"billing_city,omitempty"`
	BillingState       string `json:"billing_state,omitempty"`
	BillingZip         string `json:"billing_zip,omitempty"`
	BillingCountry     string `json:"billing_country,omitempty"`
	CurrentVault       string `json:"current_vault,omitempty"`
	VaultToken         string `json:"vault_token,omitempty"`
	CustomerVaultToken string `json:"customer_vault_token,omitempty"`
	CustomerId         int    `json:"customer_id,omitempty"`
	PaypalEmail        string `json:"paypal_email,omitempty"`
	PaymentMethodNonce string `json:"payment_method_nonce,omitempty"`
}

type SubscriptionWrapper struct {
	Subscription *Subscription `json:"subscription"`
}

type Subscription struct {
	Id                          int                `json:"id,omitempty"`
	State                       string             `json:"state,omitempty"`
	TrialStartedAt              string             `json:"trial_started_at,omitempty"`
	CustomerId                  string             `json:"customer_id,omitempty"`
	Customer                    *Customer          `json:"customer,omitempty"`
	CustomerAttributes          *Customer          `json:"customer_attributes,omitempty"`
	Product                     *Product           `json:"product,omitempty"`
	ProductHandle               string             `json:"product_handle,omitempty"`
	CreditCard                  *CreditCard        `json:"credit_card,omitempty"`
	BalanceInCents              int                `json:"balance_in_cents,omitempty"`
	NextProductId               int                `json:"next_product_id,omitempty"`
	CancelAtEndOfPeriod         bool               `json:"cancel_at_end_of_period,omitempty"`
	PaymentCollectionMethod     string             `json:"payment_collection_method,omitempty"`
	SnapDay                     string             `json:"snap_day,omitempty"`
	CancellationMethod          string             `json:"cancellation_method,omitempty"`
	PreviousState               string             `json:"previous_state,omitempty"`
	SignupPaymentId             int                `json:"signup_payment_id,omitempty"`
	SignupRevenue               float32            `json:"signup_revenue,omitempty,string"`
	DelayedCancelAt             string             `json:"delayed_cancel_at,omitempty"`
	CouponCode                  string             `json:"coupon_code,omitempty"`
	TotalRevenueInCents         int                `json:"total_revenue_in_cents,omitempty"`
	ProductPriceInCents         int                `json:"product_price_in_cents,omitempty"`
	ProductVersionNumber        int                `json:"product_version_number,omitempty"`
	PaymentType                 string             `json:"payment_type,omitempty"`
	PaymentProfileId            string             `json:"payment_profile_id,omitempty"`
	ReferralCode                string             `json:"referral_code,omitempty"`
	CouponUseCount              int                `json:"coupon_use_count,omitempty"`
	CouponUsesAllowed           int                `json:"coupon_uses_allowed,omitempty"`
	CurrentBillingAmountInCents int                `json:"current_billing_amount_in_cents,omitempty"`
	NextBillingAt               string             `json:"next_billing_at,omitempty"`
	TrialEndedAt                string             `json:"trial_ended_at,omitempty"`
	ActivatedAt                 string             `json:"activated_at,omitempty"`
	CreatedAt                   string             `json:"created_at,omitempty"`
	UpdatedAt                   string             `json:"updated_at,omitempty"`
	ExpiresAt                   string             `json:"expires_at,omitempty"`
	PreviousExpiresAt           string             `json:"previous_expires_at,omitempty"`
	CurrentPeriodStartedAt      string             `json:"current_period_started_at,omitempty"`
	CurrentPeriodEndsAt         string             `json:"current_period_ends_at,omitempty"`
	NextAssessmentAt            string             `json:"next_assessment_at,omitempty"`
	CanceledAt                  string             `json:"canceled_at,omitempty"`
	CancellationMessage         string             `json:"cancellation_message,omitempty"`
	Group                       *SubscriptionGroup `json:"group,omitempty"`
}

type SubscriptionGroup struct {
	Uid                   string `json:"uid,omitempty"`
	Scheme                int    `json:"scheme,omitempty"`
	PrimarySubscriptionId int    `json:"primary_subscription_id,omitempty"`
	Primary               bool   `json:"primary,omitempty"`
	CustomerId            int    `json:"customer_id,omitempty"`
}

type SubscriptionGroupCancel struct {
	ChargeUnbilledUsage bool `json:"charge_unbilled_usage,omitempty"`
}

type Product struct {
	Id                      int                 `json:"id,omitempty"`
	Name                    string              `json:"name,omitempty"`
	Handle                  string              `json:"handle,omitempty"`
	Description             string              `json:"description,omitempty"`
	AccountingCode          string              `json:"accounting_code,omitempty"`
	RequestCreditCard       bool                `json:"request_credit_card,omitempty"`
	ExpirationInterval      int                 `json:"expiration_interval,omitempty"`
	ExpirationIntervalUnit  string              `json:"expiration_interval_unit,omitempty"`
	PriceInCents            int                 `json:"price_in_cents,omitempty"`
	Interval                int                 `json:"interval,omitempty"`
	IntervalUnit            string              `json:"interval_unit,omitempty"`
	InitialChargeInCents    int                 `json:"initial_charge_in_cents,omitempty"`
	TrialPriceInCents       int                 `json:"trial_price_in_cents,omitempty"`
	TrialInterval           int                 `json:"trial_interval,omitempty"`
	TrialIntervalUnit       string              `json:"trial_interval_unit,omitempty"`
	RequireCreditCard       bool                `json:"require_credit_card,omitempty"`
	ReturnParams            string              `json:"return_params,omitempty"`
	Taxable                 bool                `json:"taxable,omitempty"`
	UpdateReturnUrl         string              `json:"update_return_url,omitempty"`
	InitialChargeAfterTrial bool                `json:"initial_charge_after_trial,omitempty"`
	VersionNumber           int                 `json:"version_number,omitempty"`
	UpdateReturnParams      string              `json:"update_return_params,omitempty"`
	CreatedAt               string              `json:"created_at,omitempty"`
	UpdatedAt               string              `json:"updated_at,omitempty"`
	ArchivedAt              string              `json:"archived_at,omitempty"`
	ProductFamily           *ProductFamily      `json:"product_family,omitempty"`
	PublicSignupPages       []*PublicSignupPage `json:"public_signup_pages,omitempty"`
}

type ProductFamily struct {
	Id             int    `json:"id,omitempty"`
	Name           string `json:"name,omitempty"`
	Handle         string `json:"handle,omitempty"`
	Description    string `json:"description,omitempty"`
	AccountingCode string `json:"accounting_code,omitempty"`
}

type PublicSignupPage struct {
	Id  int    `json:"id,omitempty"`
	Url string `json:"url,omitempty"`
}

type UsageWrapper struct {
	Usage *Usage `json:"usage,omitempty"`
}

type Usage struct {
	Quantity int    `json:"quantity,omitempty"`
	Memo     string `json:"memo,omitempty"`
}

type PaymentProfileWrapper struct {
	PaymentProfile *PaymentProfile `json:"payment_profile,omitempty"`
}

type PaymentProfile struct {
	PaymentType     string `json:"payment_type,omitempty"`
	CustomerId      int    `json:"customer_id,omitempty"`
	FirstName       string `json:"first_name,omitempty"`
	LastName        string `json:"last_name,omitempty"`
	FullNumber      string `json:"full_number,omitempty"`
	ExpirationMonth int    `json:"expiration_month,omitempty"`
	ExpirationYear  int    `json:"expiration_year,omitempty"`
	Cvv             int    `json:"cvv,omitempty"`
	BillingAddress  string `json:"billing_address,omitempty"`
	BillingAddress2 string `json:"billing_address2,omitempty"`
	BillingCity     string `json:"billing_city,omitempty"`
	BillingState    string `json:"billing_state,omitempty"`
	BillingZip      string `json:"billing_zip,omitempty"`
	BillingCountry  string `json:"billing_country,omitempty"`
	CardType        string `json:"card_type,omitempty"`
	Id              int    `json:"id,omitempty"`
}

// This is essentially billing.InvoiceData uncensored
/* Commented out for now as billing.InvoiceData is currently the same as this and is used in chargify.GetInvoice. However if we decide
to change our public facing invoice data setup in the future then we'll need to use these definitions and manually convert them over.
type Invoice struct {
	Uid                        string          `json:"uid,omitempty"`
	SiteId                     int             `json:"site_id,omitempty"`
	CustomerId                 int             `json:"customer_id,omitempty"`
	SubscriptionId             int             `json:"subscription_id,omitempty"`
	Number                     string          `json:"number,omitempty"`
	SequenceNumber             int             `json:"sequence_number,omitempty"`
	IssueDate                  string          `json:"issue_date,omitempty"`
	DueDate                    string          `json:"due_date,omitempty"`
	PaidDate                   string          `json:"paid_date,omitempty"`
	Status                     string          `json:"status_omitempty"`
	CollectionMethod           string          `json:"collection_method,omitempty"`
	PaymentInstructions        string          `json:"payment_instructions,omitempty"`
	Currency                   string          `json:"currency,omitempty"`
	ConsolidationLevel         string          `json:"consolidation_level,omitempty"`
	ParentInvoiceUid           string          `json:"parent_invoice_uid,omitempty"`
	ParentInvoiceNumber        int             `json:"parent_invoice_number,omitempty"`
	GroupPrimarySubscriptionId int             `json:"group_primary_subscription_id,omitempty"`
	ProductName                string          `json:"product_name,omitempty"`
	ProductFamilyName          string          `json:"product_family_name,omitempty"`
	Seller                     Seller          `json:"seller,omitempty"`
	Customer                   Customer        `json:"Customer,omitempty"`
	Memo                       string          `json:"memo,omitempty"`
	BillingAddress             Address         `json:"billing_address,omitempty"`
	ShippingAddress            Address         `json:"shipping_address,omitempty"`
	SubtotalAmount             string          `json:"subtotal_amount,omitempty"`
	DiscountAmount             string          `json:"discount_amount,omitempty"`
	TaxAmount                  string          `json:"tax_amount,omitempty"`
	CreditAmount               string          `json:"credit_amount,omitempty"`
	RefundAmount               string          `json:"refund_amount,omitempty"`
	PaidAmount                 string          `json:"paid_amount,omitempty"`
	DueAmount                  string          `json:"due_amount,omitempty"`
	LineItems                  []LineItems     `json:"line_items,omitempty"`
	Discounts                  []Discounts     `json:"discounts,omitempty"`
	Taxes                      []Taxes         `json:"taxes,omitempty"`
	Credits                    []Credits       `json:"credits,omitempty"`
	Refunds                    []Refunds       `json:"refunds,omitempty"`
	Payments                   []Payments      `json:"payments,omitempty"`
	CustomFields               []CustomFields  `json:"custom_fields,omitempty"`
	PublicUrl                  string          `json:"public_url,omitempty"`
	PreviousBalanceData        PrevBalanceData `json:"previous_balance_data,omitempty"`
}

type Address struct {
	Street  string `json:"street,omitempty"`
	Line2   string `json:"line2,omitempty"`
	City    string `json:"city,omitempty"`
	State   string `json:"state,omitempty"`
	Zip     string `json:"zip,omitempty"`
	Country string `json:"country,omitempty"`
}

type Seller struct {
	Name    string  `json:"name,omitempty"`
	Address Address `json:"address,omitempty"`
	Phone   string  `json:"phone,omitempty"`
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

type CustomFields struct {
	Name      string `json:"name,omitempty"`
	Value     string `json:"value,omitempty"`
	OwnerId   int    `json:"owner_id,omitempty"`
	OwnerType string `json:"owner_type,omitempty"`
}

type PrevBalanceData struct {
	CaptureDate string `json:"capture_date,omitempty"`
	Invoices    []struct {
		Uid               string `json:"uid,omitempty"`
		Number            string `json:"number,omitempty"`
		OutstandingAmount string `json:"outstanding_amount,omitempty"`
	} `json:"invoices,omitempty"`
}
*/
