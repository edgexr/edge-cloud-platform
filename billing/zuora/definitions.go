package zuora

import "time"

// for oauth
var clientId string
var clientSecret string
var ZuoraUrl string
var vaultPath = "secret/data/accounts/zuora/"

// Endpoints
var OAuthEndpoint = "/oauth/token"
var AccountsEndPoint = "/v1/accounts"
var ObjectAccountsEndpoint = "/v1/object/account/"
var ProductEndpoint = "/v1/object/product"
var ProductRatePlanEndpoint = "/v1/object/product-rate-plan"
var ProductRatePlanChargeEndpoint = "/v1/object/product-rate-plan-charge"
var GetSubscriptionEndpoint = "/v1/subscriptions/accounts/"
var OrdersEndpoint = "/v1/orders"
var UsageEndpoint = "/v1/object/usage"
var BillRunEndpoint = "/v1/object/bill-run"

// dates
var StartDate = "2020-01-01"
var EndDate = "2050-01-01"

var FlavorProductId = "2c92c0f870d4538b0170e46c11a06e6c"
var FlavorUsageProductRatePlanId = "2c92c0f9712998a401712de88cc44c9f"
var FlavorUsageProductRatePlanChargeId = "2c92c0f9712998b30171369c87bd3c44"
var usageFlavorRatePlanId = "2c92c0f9712998a401712de88cc44c9f"

type OAuthToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	Jti         string `json:"jti"`
	ExpireTime  time.Time
}

// -------------------------CUSTOMER STUFF----------------------------

type AccountInfo struct {
	OrgName            string `gorm:"primary_key;type:citext"`
	AccountNumber      string
	AccountID          string
	SubscriptionNumber string
	ParentID           string
	ParentNumber       string
}

type NewAccount struct {
	AdditionalEmailAddresses []string               `json:"additionalEmailAddresses,omitempty"`
	AutoPay                  bool                   `json:"autoPay"`
	BillCycleDay             int                    `json:"billCycleDay,omitempty"`
	BillToContact            *CustomerBillToContact `json:"billToContact,omitempty"`
	SoldToContact            *CustomerBillToContact `json:"soldToContact,omitempty"`
	Currency                 string                 `json:"currency,omitempty"`
	Name                     string                 `json:"name,omitempty"`
	Notes                    string                 `json:"notes,omitempty"`
	PaymentTerm              string                 `json:"paymentTerm,omitempty"`
	PaymentMethod            *PaymentMethod         `json:"paymentMethod,omitempty"`
	ParentId                 string                 `json:"parentId,omitempty"`
}

type AccountResp struct {
	Success       bool   `json:"success"`
	AccountId     string `json:"accountId"`
	AccountNumber string `json:"accountNumber"`
}

type CustomerBillToContact struct {
	FirstName  string `json:"firstName,omitempty"`
	LastName   string `json:"lastName,omitempty"`
	WorkEmail  string `json:"workEmail,omitempty"`
	Address1   string `json:"address1,omitempty"`
	Address2   string `json:"address2,omitempty"`
	City       string `json:"city,omitempty"`
	Country    string `json:"country,omitempty"`
	State      string `json:"state,omitempty"`
	PostalCode string `json:"postalCode,omitempty"`
}

type PaymentMethod struct {
	Type         string `json:"type,omitempty"`
	AddressLine1 string `json:"addressLine1,omitempty"`
	AddressLine2 string `json:"addressLine2,omitempty"`
	//For ACH payment methods
	BankABACode       string `json:"bankABACode,omitempty"`
	BankAccountName   string `json:"bankAccountName,omitempty"`
	BankAccountNumber string `json:"bankAccountNumber,omitempty"`
	BankAccountType   string `json:"bankAccountType,omitempty"` //must be either "BusinessChecking", "Checking", or "Saving"
	BankName          string `json:"bankName,omitempty"`
	City              string `json:"city,omitempty"`
	Country           string `json:"country,omitempty"`
	Phone             string `json:"phone,omitempty"`
	State             string `json:"state,omitempty"`
	ZipCode           string `json:"zipCode,omitempty"`
	//CardHolderInfo??? I think we should just be leaving this always blank and using the BillToContact
	CardNumber      string `json:"cardNumber,omitempty"`
	CardType        string `json:"cardType,omitempty"`
	ExpirationMonth string `json:"expirationMonth,omitempty"` //two digit format (01-12)
	ExpirationYear  string `json:"expirationYear,omitempty"`  //four digit, full year
	SecurityCode    string `json:"securityCode,omitempty"`
}

type GetAccount struct {
	Success   bool      `json:"success"`
	BasicInfo BasicInfo `json:"basicInfo"`
}

type BasicInfo struct {
	Id            string `json:"id"`
	AccountNumber string `json:"accountNumber"`
	Status        string `json:"status"`
	Currency      string `json:"currency"`
	ParentId      string `json:"parentId"`
}

// ---------------------ORDERS AND SUBSCRIPTIONS-------------------------------

type CreateOrder struct {
	Description           string              `json:"description,omitempty"`
	ExistingAccountNumber string              `json:"existingAccountNumber,omitempty"`
	NewAccount            *NewAccount         `json:"newAccount,omitempty"`
	OrderDate             string              `json:"orderDate"`
	Subscriptions         []OrderSubscription `json:"subscriptions"`
}

type OrderSubscription struct {
	OrderActions       []OrderAction `json:"orderActions"`
	SubscriptionNumber string        `json:"subscriptionNumber,omitempty"`
}

type OrderAction struct {
	AddProduct         *AddProduct         `json:"addProduct,omitempty"`
	CreateSubscription *CreateSubscription `json:"createSubscription,omitempty"`
	CancelSubscription *CancelSub          `json:"cancelSubscription,omitempty"`
	TriggerDates       []TriggerDate       `json:"triggerDates"`
	Type               string              `json:"type"`
}

type TriggerDate struct {
	Name        string `json:"name"`
	TriggerDate string `json:"triggerDate"`
}

type CancelSub struct {
	CancellationEffectiveDate string `json:"cancellationEffectiveDate,omitempty"`
	CancellationPolicy        string `json:"cancellationPolicy,omitempty"` //SpecificDate
}

type CreateSubscription struct {
	Terms                       CreateSubscriptionTerms `json:"terms,omitempty"`
	NewSubscriptionOwnerAccount *NewAccount             `json:"newSubscriptionOwnerAccount,omitempty"`
}

type CreateSubscriptionTerms struct {
	InitialTerm    CreateSubscriptionInitialTerm `json:"initialTerm,omitempty"`
	RenewalSetting string                        `json:"renewalSetting,omitempty"`
	RenewalTerms   []RenewalTerms                `json:"renewalTerms,omitempty"`
}

type CreateSubscriptionInitialTerm struct {
	Period     int    `json:"period,omitempty"`
	PeriodType string `json:"periodType,omitempty"`
	StartDate  string `json:"startDate,omitempty"` //yyyy-mm-dd
	TermType   string `json:"termType,omitempty"`  //TERMED or EVERGREEN
}

type RenewalTerms struct {
	Period     int    `json:"period,omitempty"`
	PeriodType string `json:"periodType,omitempty"`
}

type AddProduct struct {
	ProductRatePlanId string `json:"productRatePlanId,omitempty"`
}

type OrderResp struct {
	Success             bool     `json:"success"`
	OrderNumber         string   `json:"orderNumber"`
	AccountNumber       string   `json:"accountNumber"`
	Status              string   `json:"status"`
	SubscriptionNumbers []string `json:"subscriptionNumbers"`
}

type CheckSubscriptions struct {
	Success       bool   `json:"success"`
	Subscriptions []Subs `json:"subscriptions"`
}

type Subs struct {
	ID                 string         `json:"id"`
	SubscriptionNumber string         `json:"subscriptionNumber"`
	RatePlans          []SubRatePlans `json:"ratePlans"`
}

type SubRatePlans struct {
	ID                string               `json:"id"`
	ProductID         string               `json:"productId"`
	ProductName       string               `json:"productName"`
	ProductSku        string               `json:"productSku"`
	ProductRatePlanID string               `json:"productRatePlanId"`
	RatePlanName      string               `json:"ratePlanName"`
	RatePlanCharges   []SubRatePlanCharges `json:"ratePlanCharges"`
}

type SubRatePlanCharges struct {
	ID                      string `json:"id"`
	OriginalChargeID        string `json:"originalChargeId"`
	ProductRatePlanChargeID string `json:"productRatePlanChargeId"`
	Number                  string `json:"number"`
	Name                    string `json:"name"`
	Description             string `json:"description"`
}

type GetSubscriptionByKey struct {
	Success       bool   `json:"success"`
	AccountId     string `json:"accountId"`
	AccountNumber string `json:"accountNumber"`
}

// -------------------------PRODUCT STUFF-----------------------------

// dates must be of the form yyyy-mm-dd
type CreateProductReq struct {
	Description        string `json:"Description"`
	EffectiveEndDate   string `json:"EffectiveEndDate"`
	EffectiveStartDate string `json:"EffectiveStartDate"`
	Name               string `json:"Name"`
	SKU                string `json:"SKU"`
}

type GenericResp struct {
	Success bool   `json:"Success"`
	ID      string `json:"id"`
}

type CreateProductRatePlanReq struct {
	Description string `json:"Description"`
	Name        string `json:"Name"`
	ProductID   string `json:"ProductId"`
}

type ProductRatePlan struct {
	ID                     string                   `json:"id"`
	Status                 string                   `json:"status"`
	Name                   string                   `json:"name"`
	Description            string                   `json:"description"`
	EffectiveStartDate     string                   `json:"effectiveStartDate"`
	EffectiveEndDate       string                   `json:"effectiveEndDate"`
	ProductRatePlanCharges []ProductRatePlanCharges `json:"productRatePlanCharges"`
}

type ProductRatePlanCharges struct {
	ID                                string                        `json:"id"`
	Name                              string                        `json:"name"`
	Type                              string                        `json:"type"`
	Model                             string                        `json:"model"`
	Uom                               string                        `json:"uom"`
	PricingSummary                    []string                      `json:"pricingSummary"`
	Pricing                           []Pricing                     `json:"pricing"`
	DefaultQuantity                   float64                       `json:"defaultQuantity"`
	ApplyDiscountTo                   string                        `json:"applyDiscountTo"`
	DiscountLevel                     string                        `json:"discountLevel"`
	DiscountClass                     string                        `json:"discountClass"`
	ProductDiscountApplyDetails       []ProductDiscountApplyDetails `json:"productDiscountApplyDetails"`
	EndDateCondition                  string                        `json:"endDateCondition"`
	UpToPeriods                       int                           `json:"upToPeriods"`
	UpToPeriodsType                   string                        `json:"upToPeriodsType"`
	BillingDay                        string                        `json:"billingDay"`
	ListPriceBase                     string                        `json:"listPriceBase"`
	BillingTiming                     string                        `json:"billingTiming"`
	BillingPeriod                     string                        `json:"billingPeriod"`
	BillingPeriodAlignment            string                        `json:"billingPeriodAlignment"`
	SpecificBillingPeriod             int                           `json:"specificBillingPeriod"`
	SmoothingModel                    string                        `json:"smoothingModel"`
	NumberOfPeriods                   int                           `json:"numberOfPeriods"`
	OverageCalculationOption          string                        `json:"overageCalculationOption"`
	OverageUnusedUnitsCreditOption    string                        `json:"overageUnusedUnitsCreditOption"`
	UnusedIncludedUnitPrice           []UnusedIncludedUnitPrice     `json:"unusedIncludedUnitPrice"`
	UsageRecordRatingOption           string                        `json:"usageRecordRatingOption"`
	PriceChangeOption                 string                        `json:"priceChangeOption"`
	PriceIncreasePercentage           int                           `json:"priceIncreasePercentage"`
	UseTenantDefaultForPriceChange    bool                          `json:"useTenantDefaultForPriceChange"`
	Taxable                           bool                          `json:"taxable"`
	TaxCode                           string                        `json:"taxCode"`
	TaxMode                           string                        `json:"taxMode"`
	TriggerEvent                      string                        `json:"triggerEvent"`
	Description                       string                        `json:"description"`
	RevenueRecognitionRuleName        string                        `json:"revenueRecognitionRuleName"`
	RevRecTriggerCondition            string                        `json:"revRecTriggerCondition"`
	RevRecCode                        string                        `json:"revRecCode"`
	UseDiscountSpecificAccountingCode bool                          `json:"useDiscountSpecificAccountingCode"`
	FinanceInformation                FinanceInformation            `json:"financeInformation"`
}

type Pricing struct {
	Currency           string  `json:"currency"`
	Price              int     `json:"price"`
	Tiers              []Tier  `json:"tiers"`
	IncludedUnits      float64 `json:"includedUnits"`
	OveragePrice       float64 `json:"overagePrice"`
	DiscountPercentage float64 `json:"discountPercentage"`
	DiscountAmount     float64 `json:"discountAmount"`
}

type Tier struct {
	Tier         int     `json:"tier"`
	StartingUnit float64 `json:"startingUnit"`
	EndingUnit   float64 `json:"endingUnit"`
	Price        float64 `json:"price"`
	PriceFormat  string  `json:"priceFormat"`
}

type ProductDiscountApplyDetails struct {
	AppliedProductRatePlanChargeId string `json:"appliedProductRatePlanChargeId"`
	AppliedProductRatePlanId       string `json:"appliedProductRatePlanId"`
}

type UnusedIncludedUnitPrice struct {
	Currency              string  `json:"currency"`
	UnusedUnitsCreditRate float64 `json:"unusedUnitsCreditRate"`
}

type FinanceInformation struct {
	RecognizedRevenueAccountingCode     string `json:"recognizedRevenueAccountingCode"`
	RecognizedRevenueAccountingCodeType string `json:"recognizedRevenueAccountingCodeType"`
	DeferredRevenueAccountingCode       string `json:"deferredRevenueAccountingCode"`
	DeferredRevenueAccountingCodeType   string `json:"deferredRevenueAccountingCodeType"`
}

type CreateProductRatePlanChargeReq struct {
	ProductRatePlanID             string      `json:"ProductRatePlanId"`
	Name                          string      `json:"Name"`
	Description                   string      `json:"Description,omitempty"`
	Model                         ChargeModel `json:"ChargeModel"`
	Type                          ChargeType  `json:"ChargeType"`
	ListPrice                     float64     `json:"ListPrice"`
	Uom                           UOM         `json:"UOM,omitempty"`
	BillingPeriod                 string      `json:"BillingPeriod"`
	TriggerEvent                  string      `json:"TriggerEvent"`
	EndDateCondition              string      `json:"EndDateCondtion"`
	BillingPeriodAlignment        string      `json:"BillingPeriodAlignment"`
	BillCycleType                 string      `json:"BillCycleType"`
	RatingGroup                   string      `json:"RatingGroup,omitempty"`
	ProductRatePlanChargeTierData struct {
		ProductRatePlanChargeTier []interface{} `json:"ProductRatePlanChargeTier"`
	} `json:"ProductRatePlanChargeTierData"`
}

type ChargeModel string

const (
	DISCOUNT_FIXED_AMOUNT       ChargeModel = "Discount-Fixed Amount"
	DISCOUNT_PERCENTAGE         ChargeModel = "Discount-Percentage"
	FLAT_FEE_PRICING            ChargeModel = "Flat Fee Pricing"
	PER_UNIT_PRICING            ChargeModel = "Per Unit Pricing"
	OVERAGE_PRICING             ChargeModel = "Overage Pricing"
	TIERED_PRICING              ChargeModel = "Tiered Pricing"
	TIERED_WITH_OVERAGE_PRICING ChargeModel = "Tiered with Overage Pricing"
	VOLUME_PRICING              ChargeModel = "Volume Pricing"
)

type ChargeType string

const (
	ONETIME   ChargeType = "OneTime"
	RECURRING ChargeType = "Recurring"
	USAGE     ChargeType = "Usage"
)

// unites of measurement for per unit and tiered models
type UOM string

const (
	MINUTE UOM = "Minute"
	GB     UOM = "GB"
	API    UOM = "API Call"
)

// ----------------------USAGE------------------------
type CreateUsage struct {
	AccountNumber      string  `json:"AccountNumber"`
	SubscriptionNumber string  `json:"SubscriptionNumber"`
	ChargeNumber       string  `json:"ChargeNumber"`
	Quantity           float64 `json:"Quantity"`
	StartDateTime      string  `json:"StartDateTime"`
	EndDateTime        string  `json:"EndDateTime,omitempty"`
	UOM                string  `json:"UOM"`
	Description        string  `json:"Description"`
}
