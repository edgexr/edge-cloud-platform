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

package ormapi

import (
	"sort"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud/edgeproto"
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
	// Delete of this BillingOrganization is in progress
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
	Address string `gorm:"unique;not null" json:",omitempty"`
	// Controller notify address or URL
	NotifyAddr string `gorm:"type:text" json:",omitempty"`
	// InfluxDB address
	InfluxDB string `gorm:"type:text" json:",omitempty"`
	// Thanos Query URL
	ThanosMetrics string `gorm:"type:text" json:",omitempty"`
	// Unique DNS label for the region
	// read only: true
	DnsRegion string `gorm:"unique;not null" json:",omitempty"`
	// read only: true
	CreatedAt time.Time `json:",omitempty"`
	// read only: true
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
	// User login token valid duration (in format 2h30m10s, default 24h)
	UserLoginTokenValidDuration edgeproto.Duration
	// API key login token valid duration (in format 2h30m10s, default 4h)
	ApiKeyLoginTokenValidDuration edgeproto.Duration
	// Websocket auth token valid duration (in format 2h30m10s, default 2m)
	WebsocketTokenValidDuration edgeproto.Duration
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
	// Region name
	Region string `json:"region,omitempty"`
	// Org that has permissions for cloudlets
	Org string `form:"org" json:"org"`
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
	// Temporary one-time password if 2-factor authentication is enabled
	TOTP string `form:"totp" json:"totp"`
	// API key ID if logging in using API key
	ApiKeyId string `form:"apikeyid" json:"apikeyid"`
	// API key if logging in using API key
	ApiKey string `form:"apikey" json:"apikey"`
}

type NewPassword struct {
	// User's current password
	// required: true
	CurrentPassword string `form:"password" json:"currentpassword"`
	// User's new password
	// required: true
	Password string `form:"password" json:"password"`
}

type CreateUser struct {
	User `json:",inline"`
	// Client information to include in verification email request, used mainly by Web UI client
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
// verification email.
type EmailRequest struct {
	// User's email address
	// read only: true
	Email string `form:"email" json:"email"`
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
	// Region name
	Region  string            `json:"region,omitempty"`
	AppData edgeproto.AllData `json:"appdata,omitempty"`
}

type MetricsCommon struct {
	edgeproto.TimeRange `json:",inline"`
	// Display X samples spaced out evenly over start and end times
	NumSamples int `json:",omitempty"`
	// Display the last X metrics
	Limit int `json:",omitempty"`
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
	// Region name
	Region string
	// Comma separated list of metrics to view. Available metrics: utilization, network, ipusage
	Selector string
	// Application instance to filter for metrics
	AppInst edgeproto.AppInstKey `json:",omitempty"`
	// Application instances to filter for metrics
	AppInsts      []edgeproto.AppInstKey `json:",omitempty"`
	MetricsCommon `json:",inline"`
}

type RegionCustomAppMetrics struct {
	Region        string
	Measurement   string
	AppInst       edgeproto.AppInstKey `json:",omitempty"`
	Port          string               `json:",omitempty"`
	AggrFunction  string               `json:",omitempty"`
	MetricsCommon `json:",inline"`
}

type RegionClusterInstMetrics struct {
	// Region name
	Region string
	// Cluster instance key for metrics
	ClusterInst edgeproto.ClusterInstKey `json:",omitempty"`
	// Cluster instance keys for metrics
	ClusterInsts []edgeproto.ClusterInstKey `json:",omitempty"`
	// Comma separated list of metrics to view. Available metrics: utilization, network, ipusage
	Selector      string
	MetricsCommon `json:",inline"`
}

type RegionCloudletMetrics struct {
	// Region name
	Region string
	// Cloudlet key for metrics
	Cloudlet edgeproto.CloudletKey `json:",omitempty"`
	// Cloudlet keys for metrics
	Cloudlets []edgeproto.CloudletKey `json:",omitempty"`
	// Comma separated list of metrics to view. Available metrics: utilization, network, ipusage
	Selector      string
	PlatformType  string
	MetricsCommon `json:",inline"`
}

type RegionClientApiUsageMetrics struct {
	// Region name
	Region string
	// Application instance key for usage
	AppInst edgeproto.AppInstKey
	// API call method, one of: FindCloudlet, PlatformFindCloudlet, RegisterClient, VerifyLocation
	Method string `json:",omitempty"`
	// Cloudlet name where DME is running
	DmeCloudlet string `json:",omitempty"`
	// Operator organization where DME is running
	DmeCloudletOrg string `json:",omitempty"`
	// Comma separated list of metrics to view. Available metrics: utilization, network, ipusage
	Selector      string
	MetricsCommon `json:",inline"`
}

type RegionClientAppUsageMetrics struct {
	// Region name
	Region string
	// Application instance key for usage
	AppInst edgeproto.AppInstKey
	// Comma separated list of metrics to view. Available metrics: utilization, network, ipusage
	Selector string
	// Device carrier. Can be used for selectors: latency, deviceinfo
	DeviceCarrier string `json:",omitempty"`
	// Data network type used by client device. Can be used for selectors: latency
	DataNetworkType string `json:",omitempty"`
	// Device model. Can be used for selectors: deviceinfo
	DeviceModel string `json:",omitempty"`
	// Device operating system. Can be used for selectors: deviceinfo
	DeviceOs       string `json:",omitempty"`
	SignalStrength string `json:",omitempty"`
	// Provides the range of GPS coordinates for the location tile/square.
	// Format is: 'LocationUnderLongitude,LocationUnderLatitude_LocationOverLongitude,LocationOverLatitude_LocationTileLength'.
	// LocationUnder are the GPS coordinates of the corner closest to (0,0) of the location tile.
	// LocationOver are the GPS coordinates of the corner farthest from (0,0) of the location tile.
	// LocationTileLength is the length (in kilometers) of one side of the location tile square
	LocationTile  string `json:",omitempty"`
	MetricsCommon `json:",inline"`
}

type RegionClientCloudletUsageMetrics struct {
	// Region name
	Region string
	// Cloudlet key for metrics
	Cloudlet edgeproto.CloudletKey
	// Comma separated list of metrics to view. Available metrics: utilization, network, ipusage
	Selector string
	// Device carrier. Can be used for selectors: latency, deviceinfo
	DeviceCarrier string `json:",omitempty"`
	// Data network type used by client device. Can be used for selectors: latency
	DataNetworkType string `json:",omitempty"`
	// Device model. Can be used for selectors: deviceinfo
	DeviceModel string `json:",omitempty"`
	// Device operating system. Can be used for selectors: deviceinfo
	DeviceOs       string `json:",omitempty"`
	SignalStrength string `json:",omitempty"`
	// Provides the range of GPS coordinates for the location tile/square.
	// Format is: 'LocationUnderLongitude,LocationUnderLatitude_LocationOverLongitude,LocationOverLatitude_LocationTileLength'.
	// LocationUnder are the GPS coordinates of the corner closest to (0,0) of the location tile.
	// LocationOver are the GPS coordinates of the corner farthest from (0,0) of the location tile.
	// LocationTileLength is the length (in kilometers) of one side of the location tile square
	LocationTile  string `json:",omitempty"`
	MetricsCommon `json:",inline"`
}

type RegionAppInstEvents struct {
	// Region name
	Region string
	// Application instance key for events
	AppInst       edgeproto.AppInstKey
	MetricsCommon `json:",inline"`
}

type RegionClusterInstEvents struct {
	// Region name
	Region string
	// Cluster instance key for events
	ClusterInst   edgeproto.ClusterInstKey
	MetricsCommon `json:",inline"`
}

type RegionCloudletEvents struct {
	// Region name
	Region string
	// Cloudlet key for events
	Cloudlet      edgeproto.CloudletKey
	MetricsCommon `json:",inline"`
}

type RegionAppInstUsage struct {
	// Region name
	Region string
	// Application instance key for usage
	AppInst edgeproto.AppInstKey
	// Time to start displaying stats from
	StartTime time.Time `json:",omitempty"`
	// Time up to which to display stats
	EndTime time.Time `json:",omitempty"`
	// Show only VM-based apps
	VmOnly bool `json:",omitempty"`
}

type RegionClusterInstUsage struct {
	// Region name
	Region string
	// Cluster instances key for usage
	ClusterInst edgeproto.ClusterInstKey
	// Time to start displaying stats from
	StartTime time.Time `json:",omitempty"`
	// Time up to which to display stats
	EndTime time.Time `json:",omitempty"`
}

type RegionCloudletPoolUsage struct {
	// Region name
	Region string
	// Cloudlet pool key for usage
	CloudletPool edgeproto.CloudletPoolKey
	// Time to start displaying stats from
	StartTime time.Time `json:",omitempty"`
	// Time up to which to display stats
	EndTime time.Time `json:",omitempty"`
	// Show only VM-based apps
	ShowVmAppsOnly bool `json:",omitempty"`
}

type RegionCloudletPoolUsageRegister struct {
	// Region name
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

func (s *AlertReceiver) GetKeyString() string {
	return s.Region + "," + s.Type + "," + s.Name
}

func (s *Role) GetKeyString() string {
	return s.Username + "," + s.Org + "," + s.Role
}

func (s *OrgCloudletPool) GetKeyString() string {
	return s.Region + "," + s.Org + "," + s.CloudletPoolOrg + "," + s.CloudletPool + "," + s.Type
}

func (s *AllData) Sort() {
	sort.Slice(s.Controllers, func(i, j int) bool {
		return s.Controllers[i].Region < s.Controllers[j].Region
	})
	sort.Slice(s.BillingOrgs, func(i, j int) bool {
		return s.BillingOrgs[i].Name < s.BillingOrgs[j].Name
	})
	sort.Slice(s.AlertReceivers, func(i, j int) bool {
		return s.AlertReceivers[i].GetKeyString() < s.AlertReceivers[j].GetKeyString()
	})
	sort.Slice(s.Orgs, func(i, j int) bool {
		return s.Orgs[i].Name < s.Orgs[j].Name
	})
	sort.Slice(s.Roles, func(i, j int) bool {
		return s.Roles[i].GetKeyString() < s.Roles[j].GetKeyString()
	})
	sort.Slice(s.CloudletPoolAccessInvitations, func(i, j int) bool {
		return s.CloudletPoolAccessInvitations[i].GetKeyString() < s.CloudletPoolAccessInvitations[j].GetKeyString()
	})
	sort.Slice(s.CloudletPoolAccessResponses, func(i, j int) bool {
		return s.CloudletPoolAccessResponses[i].GetKeyString() < s.CloudletPoolAccessResponses[j].GetKeyString()
	})
	sort.Slice(s.RegionData, func(i, j int) bool {
		return s.RegionData[i].Region < s.RegionData[j].Region
	})
	for ii := range s.RegionData {
		s.RegionData[ii].AppData.Sort()
	}
	sort.Slice(s.Federators, func(i, j int) bool {
		return s.Federators[i].FederationId < s.Federators[j].FederationId
	})
	sort.Slice(s.FederatorZones, func(i, j int) bool {
		return s.FederatorZones[i].ZoneId < s.FederatorZones[j].ZoneId
	})
	sort.Slice(s.Federations, func(i, j int) bool {
		return s.Federations[i].Name < s.Federations[j].Name
	})
	sort.Slice(s.FederatedSelfZones, func(i, j int) bool {
		return s.FederatedSelfZones[i].ZoneId < s.FederatedSelfZones[j].ZoneId
	})
	sort.Slice(s.FederatedPartnerZones, func(i, j int) bool {
		return s.FederatedPartnerZones[i].FederatorZone.ZoneId < s.FederatedPartnerZones[j].FederatorZone.ZoneId
	})
}
