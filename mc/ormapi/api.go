package ormapi

import (
	"strings"
	"time"

	"github.com/mobiledgex/edge-cloud/edgeproto"
)

// Data saved to persistent sql db, also used for API calls

type User struct {
	// User name. Can only contain letters, digits, underscore, period, hyphen. It cannot have leading or trailing spaces or period. It cannot start with hyphen
	// required: true
	Name string `gorm:"primary_key;type:citext"`
	// User email
	Email string `gorm:"unique;not null"`
	// Email address has been verified
	// read only: true
	EmailVerified bool
	// read only: true
	Passhash string `gorm:"not null"`
	// read only: true
	Salt string `gorm:"not null"`
	// read only: true
	Iter int `gorm:"not null"`
	// Family Name
	FamilyName string
	// Given Name
	GivenName string
	// read only: true
	Picture string
	// Nick Name
	Nickname string
	// read only: true
	CreatedAt time.Time `json:",omitempty"`
	// read only: true
	UpdatedAt time.Time `json:",omitempty"`
	// Account is locked
	// read only: true
	Locked bool
	// read only: true
	PassCrackTimeSec float64
	// Enable or disable temporary one-time passwords for the account
	EnableTOTP bool
	// read only: true
	TOTPSharedKey string
	// Metadata
	Metadata string
	// Last successful login time
	// read only: true
	LastLogin time.Time `json:",omitempty"`
	// Last failed login time
	// read only: true
	LastFailedLogin time.Time `json:",omitempty"`
	// Number of failed login attempts since last successful login
	FailedLogins int
}

type CreateUserApiKey struct {
	UserApiKey `json:",inline"`
	// API key
	ApiKey string
	// List of API key permissions
	Permissions []RolePerm `json:"permissions"`
}

type UserApiKey struct {
	// API key ID used as an identifier for API keys
	// read only: true
	Id string `gorm:"primary_key;type:citext"`
	// Description of the purpose of this API key
	// required: true
	Description string
	// Org to which API key has permissions to access its objects
	// required: true
	Org string
	// read only: true
	Username string
	// read only: true
	ApiKeyHash string `gorm:"not null"`
	// read only: true
	Salt string `gorm:"not null"`
	// read only: true
	Iter int `gorm:"not null"`
	// read only: true
	CreatedAt time.Time `json:",omitempty"`
	// read only: true
	UpdatedAt time.Time `json:",omitempty"`
}

type UserResponse struct {
	Message       string
	TOTPSharedKey string
	TOTPQRImage   []byte
}

type Organization struct {
	// Organization name. Can only contain letters, digits, underscore, period, hyphen. It cannot have leading or trailing spaces or period. It cannot start with hyphen
	// required: true
	Name string `gorm:"primary_key;type:citext"`
	// Organization type: "developer" or "operator"
	Type string `gorm:"not null"`
	// Organization address
	Address string `json:",omitempty"`
	// Organization phone number
	Phone string `json:",omitempty"`
	// read only: true
	CreatedAt time.Time `json:",omitempty"`
	// read only: true
	UpdatedAt time.Time `json:",omitempty"`
	// Images are made available to other organization
	// read only: true
	PublicImages bool `json:",omitempty"`
	// Delete of this organization is in progress
	// read only: true
	DeleteInProgress bool `json:",omitempty"`
	// read only: true
	Parent string `json:",omitempty"`
	// Edgebox only operator organization
	// read only: true
	EdgeboxOnly bool `json:",omitempty"`
}

type InvoiceRequest struct {
	// Billing Organization name to retrieve invoices for
	Name string `json:",omitempty"`
	// Date filter for invoice selection, YYYY-MM-DD format
	StartDate string `json:",omitempty"`
	// Date filter for invoice selection, YYYY-MM-DD format
	EndDate string `json:",omitempty"`
}

type BillingOrganization struct {
	// BillingOrganization name. Can only contain letters, digits, underscore, period, hyphen. It cannot have leading or trailing spaces or period. It cannot start with hyphen
	// required: true
	Name string `gorm:"primary_key;type:citext"`
	// Organization type: "parent" or "self"
	Type string `gorm:"not null"`
	// Billing info first name
	FirstName string `json:",omitempty"`
	// Billing info last name
	LastName string `json:",omitempty"`
	// Organization email
	Email string `json:",omitempty"`
	// Organization address
	Address string `json:",omitempty"`
	// Organization address2
	Address2 string `json:",omitempty"`
	// Organization city
	City string `json:",omitempty"`
	// Organization country
	Country string `json:",omitempty"`
	// Organization state
	State string `json:",omitempty"`
	// Organization postal code
	PostalCode string `json:",omitempty"`
	// Organization phone number
	Phone string `json:",omitempty"`
	// Children belonging to this BillingOrganization
	Children string `json:",omitempty"`
	// read only: true
	CreatedAt time.Time `json:",omitempty"`
	// read only: true
	UpdatedAt time.Time `json:",omitempty"`
	// read only: true
	DeleteInProgress bool `json:",omitempty"`
}

type AccountInfo struct {
	// Billing Organization name to commit
	OrgName string `gorm:"primary_key;type:citext"`
	// Account ID given by the billing platform
	AccountId string `json:",omitempty"`
	// Subscription ID given by the billing platform
	SubscriptionId string `json:",omitempty"`
	ParentId       string `json:",omitempty"`
	Type           string `json:",omitempty"`
}

type PaymentProfileDeletion struct {
	// Billing Organization Name associated with the payment profile
	Org string `json:",omitempty"`
	// Payment Profile Id
	Id int `json:",omitempty"`
}

type Controller struct {
	// Controller region name
	Region string `gorm:"primary_key"`
	// Controller API address or URL
	Address string `gorm:"unique;not null"`
	// Controller notify address or URL
	NotifyAddr string `gorm:"type:text"`
	// InfluxDB address
	InfluxDB  string    `gorm:"type:text"`
	CreatedAt time.Time `json:",omitempty"`
	UpdatedAt time.Time `json:",omitempty"`
}

type Config struct {
	// read only: true
	ID int `gorm:"primary_key;auto_increment:false"`
	// Lock new accounts (must be unlocked by admin)
	LockNewAccounts bool
	// Email to notify when locked account is created
	NotifyEmailAddress string
	// Skip email verification for new accounts (testing only)
	SkipVerifyEmail bool
	// User accounts min password crack time seconds (a measure of strength)
	PasswordMinCrackTimeSec float64
	// Admin accounts min password crack time seconds (a measure of strength)
	AdminPasswordMinCrackTimeSec float64
	// InfluxDB max number of data points returned
	MaxMetricsDataPoints int
	// Max number of API keys a user can create
	UserApiKeyCreateLimit int
	// Toggle for enabling billing (primarily for testing purposes)
	BillingEnable bool
	// Toggle to enable and disable MC API rate limiting
	DisableRateLimit bool
	// Maximum number of IPs tracked per API group for rate limiting at MC
	RateLimitMaxTrackedIps int
	// Maximum number of users tracked per API group for rate limiting at MC
	RateLimitMaxTrackedUsers int
	// Failed login lockout threshold 1, after this count, lockout time 1 is enabled (default 3)
	FailedLoginLockoutThreshold1 int
	// Number of seconds to lock account from logging in after threshold 1 is hit (default 60)
	FailedLoginLockoutTimeSec1 int
	// Failed login lockout threshold 2, after this count, lockout time 2 is enabled (default 10)
	FailedLoginLockoutThreshold2 int
	// Number of seconds to lock account from logging in after threshold 2 is hit (default 300)
	FailedLoginLockoutTimeSec2 int
}

type McRateLimitFlowSettings struct {
	// Unique name for FlowSettings
	// required: true
	FlowSettingsName string `gorm:"primary_key;type:citext"`
	// Name of API Path (eg. /api/v1/usercreate)
	ApiName string
	// RateLimitTarget (AllRequests, PerIp, or PerUser)
	RateLimitTarget edgeproto.RateLimitTarget
	// Flow Algorithm (TokenBucketAlgorithm or LeakyBucketAlgorithm)
	FlowAlgorithm edgeproto.FlowRateLimitAlgorithm
	// Number of requests per second
	ReqsPerSecond float64
	// Number of requests allowed at once
	BurstSize int64
}

type McRateLimitMaxReqsSettings struct {
	// Unique name for MaxReqsSettings
	// required: true
	MaxReqsSettingsName string `gorm:"primary_key;type:citext"`
	// Name of API Path (eg. /api/v1/usercreate)
	ApiName string
	// RateLimitTarget (AllRequests, PerIp, or PerUser)
	RateLimitTarget edgeproto.RateLimitTarget
	// MaxReqs Algorithm (FixedWindowAlgorithm)
	MaxReqsAlgorithm edgeproto.MaxReqsRateLimitAlgorithm
	// Maximum number of requests for the specified interval
	MaxRequests int64
	// Time interval
	Interval edgeproto.Duration
}

type McRateLimitSettings struct {
	// Name of API Path (eg. /api/v1/usercreate)
	ApiName string
	// RateLimitTarget (AllRequests, PerIp, or PerUser)
	RateLimitTarget edgeproto.RateLimitTarget
	// Map of Flow Settings name to FlowSettings
	FlowSettings map[string]edgeproto.FlowSettings
	// Map of MaxReqs Settings name to MaxReqsSettings
	MaxReqsSettings map[string]edgeproto.MaxReqsSettings
}

type OrgCloudletPool struct {
	// Developer Organization
	Org string `gorm:"type:citext REFERENCES organizations(name)"`
	// Region
	Region string `gorm:"type:text REFERENCES controllers(region)"`
	// Operator's CloudletPool name
	CloudletPool string `gorm:"not null"`
	// Operator's Organization
	CloudletPoolOrg string `gorm:"type:citext REFERENCES organizations(name)"`
	// Type is an internal-only field which is either invitation or response
	Type string `json:",omitempty"`
	// Decision is to either accept or reject an invitation
	Decision string `json:",omitempty"`
}

const (
	CloudletPoolAccessInvitation = "invitation"
	CloudletPoolAccessResponse   = "response"
)

const (
	CloudletPoolAccessDecisionAccept = "accept"
	CloudletPoolAccessDecisionReject = "reject"
)

// Structs used for API calls

type RolePerm struct {
	// Role defines a collection of permissions, which are resource-action pairs
	Role string `json:"role"`
	// Resource defines a resource to act upon
	Resource string `json:"resource"`
	// Action defines what type of action can be performed on a resource
	Action string `json:"action"`
}

type Role struct {
	// Organization name
	Org string `form:"org" json:"org"`
	// User name
	Username string `form:"username" json:"username"`
	// Role which defines the set of permissions
	Role string `form:"role" json:"role"`
}

type OrgCloudlet struct {
	Region string `json:"region,omitempty"`
	Org    string `form:"org" json:"org"`
}

type ShowUser struct {
	User `json:",inline"`
	// Organization name
	Org string `form:"org" json:"org"`
	// Role name
	Role string `form:"role" json:"role"`
}

type UserLogin struct {
	// User's name or email address
	// required: true
	Username string `form:"username" json:"username"`
	// User's password
	// required: true
	Password string `form:"password" json:"password"`
	// read only: true
	TOTP string `form:"totp" json:"totp"`
	// read only: true
	ApiKeyId string `form:"apikeyid" json:"apikeyid"`
	// read only: true
	ApiKey string `form:"apikey" json:"apikey"`
}

type NewPassword struct {
	Password string `form:"password" json:"password"`
}

type CreateUser struct {
	User   `json:",inline"`
	Verify EmailRequest `json:"verify"` // for verifying email
}

type AuditQuery struct {
	Username            string `json:"username"`
	Org                 string `form:"org" json:"org"`
	Limit               int    `json:"limit"`
	edgeproto.TimeRange `json:",inline"`
	Operation           string            `json:"operation"`
	Tags                map[string]string `json:"tags"`
}

type AuditResponse struct {
	OperationName string               `json:"operationname"`
	Username      string               `json:"username"`
	Org           string               `json:"org"`
	ClientIP      string               `json:"clientip"`
	Status        int                  `json:"status"`
	StartTime     TimeMicroseconds     `json:"starttime"`
	Duration      DurationMicroseconds `json:"duration"`
	Request       string               `json:"request"`
	Response      string               `json:"response"`
	Error         string               `json:"error"`
	TraceID       string               `json:"traceid"`
	Tags          map[string]string    `json:"tags"`
}

// Email request is used for password reset and to resend welcome
// verification email. It contains the information need to send
// some kind of email to the user.
type EmailRequest struct {
	// read only: true
	Email string `form:"email" json:"email"`
	// read only: true
	OperatingSystem string `form:"operatingsystem" json:"operatingsystem"`
	// read only: true
	Browser string `form:"browser" json:"browser"`
	// Callback URL to verify user email
	CallbackURL string `form:"callbackurl" json:"callbackurl"`
	// read only: true
	ClientIP string `form:"clientip" json:"clientip"`
}

type PasswordReset struct {
	// Authentication token
	// required: true
	Token string `form:"token" json:"token"`
	// User's new password
	// required: true
	Password string `form:"password" json:"password"`
}

type Token struct {
	// Authentication token
	Token string `form:"token" json:"token"`
}

// Structs used in replies

type Result struct {
	Message string `json:"message,omitempty"`
	Code    int    `json:"code,omitempty"`
}

type Version struct {
	BuildMaster string `json:"buildmaster,omitempty"`
	BuildHead   string `json:"buildhead,omitempty"`
	BuildAuthor string `json:"buildauthor,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
}

// Data struct sent back for streaming (chunked) commands.
// Contains a data payload for incremental data, and a result
// payload for an error result. Only one of the two will be used
// in each chunk.

type StreamPayload struct {
	Data   interface{} `json:"data,omitempty"`
	Result *Result     `json:"result,omitempty"`
}

type WSStreamPayload struct {
	Code int         `json:"code"`
	Data interface{} `json:"data"`
}

// RegionObj interface is for all protobuf-defined objects that
// are wrapped with a region string.
type RegionObjWithFields interface {
	GetRegion() string
	GetObj() interface{}
	GetObjName() string
	GetObjFields() []string
	SetObjFields([]string)
}

// all data is for full create/delete

type AllData struct {
	Controllers                   []Controller           `json:"controllers,omitempty"`
	BillingOrgs                   []BillingOrganization  `json:"billingorgs,omitempty"`
	AlertReceivers                []AlertReceiver        `json:"alertreceivers,omitempty"`
	Orgs                          []Organization         `json:"orgs,omitempty"`
	Roles                         []Role                 `json:"roles,omitempty"`
	CloudletPoolAccessInvitations []OrgCloudletPool      `json:"cloudletpoolaccessinvitations,omitempty"`
	CloudletPoolAccessResponses   []OrgCloudletPool      `json:"cloudletpoolaccessresponses,omitempty"`
	RegionData                    []RegionData           `json:"regiondata,omitempty"`
	Federators                    []Federator            `json:"federators,omitempty"`
	FederatorZones                []FederatorZone        `json:"federatorzones,omitempty"`
	Federations                   []Federation           `json:"federations,omitempty"`
	FederatedSelfZones            []FederatedSelfZone    `json:"federatedselfzones,omitempty"`
	FederatedPartnerZones         []FederatedPartnerZone `json:"federatedpartnerzones,omitempty"`
}

type RegionData struct {
	Region  string            `json:"region,omitempty"`
	AppData edgeproto.AllData `json:"appdata,omitempty"`
}

type MetricsCommon struct {
	edgeproto.TimeRange `json:",inline"`
	NumSamples          int `json:",omitempty"`
	Limit               int `json:",omitempty"`
}

// Metrics data
type AllMetrics struct {
	Data []MetricData `json:"data"`
}

type MetricData struct {
	Series []MetricSeries `json:"Series"`
}

type MetricSeries struct {
	Columns []string          `json:"columns"`
	Name    string            `json:"name"`
	Tags    map[string]string `json:"tags"`
	Values  [][]interface{}   `json:"values"`
}

type RegionAppInstMetrics struct {
	Region        string
	Selector      string
	AppInst       edgeproto.AppInstKey   `json:",omitempty"`
	AppInsts      []edgeproto.AppInstKey `json:",omitempty"`
	MetricsCommon `json:",inline"`
}

type RegionClusterInstMetrics struct {
	Region        string
	ClusterInst   edgeproto.ClusterInstKey   `json:",omitempty"`
	ClusterInsts  []edgeproto.ClusterInstKey `json:",omitempty"`
	Selector      string
	MetricsCommon `json:",inline"`
}

type RegionCloudletMetrics struct {
	Region        string
	Cloudlet      edgeproto.CloudletKey   `json:",omitempty"`
	Cloudlets     []edgeproto.CloudletKey `json:",omitempty"`
	Selector      string
	PlatformType  string
	MetricsCommon `json:",inline"`
}

type RegionClientApiUsageMetrics struct {
	Region         string
	AppInst        edgeproto.AppInstKey
	Method         string `json:",omitempty"`
	DmeCloudlet    string `json:",omitempty"`
	DmeCloudletOrg string `json:",omitempty"`
	Selector       string
	MetricsCommon  `json:",inline"`
}

type RegionClientAppUsageMetrics struct {
	Region          string
	AppInst         edgeproto.AppInstKey
	Selector        string
	DeviceCarrier   string `json:",omitempty"`
	DataNetworkType string `json:",omitempty"`
	DeviceModel     string `json:",omitempty"`
	DeviceOs        string `json:",omitempty"`
	SignalStrength  string `json:",omitempty"`
	LocationTile    string `json:",omitempty"`
	MetricsCommon   `json:",inline"`
}

type RegionClientCloudletUsageMetrics struct {
	Region          string
	Cloudlet        edgeproto.CloudletKey
	Selector        string
	DeviceCarrier   string `json:",omitempty"`
	DataNetworkType string `json:",omitempty"`
	DeviceModel     string `json:",omitempty"`
	DeviceOs        string `json:",omitempty"`
	SignalStrength  string `json:",omitempty"`
	LocationTile    string `json:",omitempty"`
	MetricsCommon   `json:",inline"`
}

type RegionAppInstEvents struct {
	Region        string
	AppInst       edgeproto.AppInstKey
	MetricsCommon `json:",inline"`
}

type RegionClusterInstEvents struct {
	Region        string
	ClusterInst   edgeproto.ClusterInstKey
	MetricsCommon `json:",inline"`
}

type RegionCloudletEvents struct {
	Region        string
	Cloudlet      edgeproto.CloudletKey
	MetricsCommon `json:",inline"`
}

type RegionAppInstUsage struct {
	Region    string
	AppInst   edgeproto.AppInstKey
	StartTime time.Time `json:",omitempty"`
	EndTime   time.Time `json:",omitempty"`
	VmOnly    bool      `json:",omitempty"`
}

type RegionClusterInstUsage struct {
	Region      string
	ClusterInst edgeproto.ClusterInstKey
	StartTime   time.Time `json:",omitempty"`
	EndTime     time.Time `json:",omitempty"`
}

type RegionCloudletPoolUsage struct {
	Region         string
	CloudletPool   edgeproto.CloudletPoolKey
	StartTime      time.Time `json:",omitempty"`
	EndTime        time.Time `json:",omitempty"`
	ShowVmAppsOnly bool      `json:",omitempty"`
}

type RegionCloudletPoolUsageRegister struct {
	Region          string
	CloudletPool    edgeproto.CloudletPoolKey
	UpdateFrequency time.Duration
	PushEndpoint    string
	StartTime       time.Time
}

// Configurable part of AlertManager Receiver
type AlertReceiver struct {
	// Receiver Name
	Name string
	// Receiver type. Eg. email, slack, pagerduty
	Type string
	// Alert severity filter
	Severity string
	// Region for the alert receiver
	Region string `json:",omitempty"`
	// User that created this receiver
	User string `json:",omitempty"`
	// Custom receiving email
	Email string `json:",omitempty"`
	// Custom slack channel
	SlackChannel string `json:",omitempty"`
	// Custom slack webhook
	SlackWebhook string `json:",omitempty"`
	// PagerDuty integration key
	PagerDutyIntegrationKey string `json:",omitempty"`
	// PagerDuty API version
	PagerDutyApiVersion string `json:",omitempty"`
	// Cloudlet spec for alerts
	Cloudlet edgeproto.CloudletKey `json:",omitempty"`
	// AppInst spec for alerts
	AppInst edgeproto.AppInstKey `json:",omitempty"`
}

// Reporter to generate period reports
type Reporter struct {
	// Reporter name. Can only contain letters, digits, period, hyphen. It cannot have leading or trailing spaces or period. It cannot start with hyphen
	// required: true
	Name string `gorm:"primary_key;type:citext"`
	// Organization name
	// required: true
	Org string `gorm:"primary_key;type:citext REFERENCES organizations(name)"`
	// Email to send generated reports
	Email string `json:",omitempty"`
	// Indicates how often a report should be generated, one of EveryWeek, Every15Days, EveryMonth
	Schedule edgeproto.ReportSchedule `json:",omitempty"`
	// Start date (in RFC3339 format with intended timezone) when the report is scheduled to be generated (Default: today)
	StartScheduleDate string `json:",omitempty"`
	// Date when the next report is scheduled to be generated (for internal use only)
	// read only: true
	NextScheduleDate string `json:",omitempty"`
	// User name (for internal use only)
	// read only: true
	Username string
	// Timezone in which to show the reports, defaults to UTC
	Timezone string
	// Last report status
	// read only: true
	Status string
}

type DownloadReport struct {
	// Organization name
	// required: true
	Org string
	// Reporter name
	Reporter string
	// Name of the report file to be downloaded
	Filename string
}

type GenerateReport struct {
	// Organization name
	// required: true
	Org string
	// Absolute time (in RFC3339 format with intended timezone) to start report capture
	// required: true
	StartTime time.Time `json:",omitempty"`
	// Absolute time (in RFC3339 format with intended timezone) to end report capture
	// required: true
	EndTime time.Time `json:",omitempty"`
	// Region name (for internal use only)
	// read only: true
	Region string
	// Timezone in which to show the reports, defaults to UTC
	Timezone string
}

func GetReporterFileName(reporterName string, report *GenerateReport) string {
	startDate := report.StartTime.Format(TimeFormatDateName) // YYYYMMDD
	endDate := report.EndTime.Format(TimeFormatDateName)
	return report.Org + "/" + reporterName + "/" + startDate + "_" + endDate + ".pdf"
}

func GetReportFileName(report *GenerateReport) string {
	startDate := report.StartTime.Format(TimeFormatDateName) // YYYYMMDD
	endDate := report.EndTime.Format(TimeFormatDateName)
	return report.Org + "_" + startDate + "_" + endDate + ".pdf"
}

func GetInfoFromReportFileName(fileName string) (string, string) {
	parts := strings.Split(fileName, "/")
	if len(parts) > 1 {
		return parts[0], parts[1]
	}
	return "", ""
}
