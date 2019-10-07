package ormapi

import (
	"time"

	"github.com/mobiledgex/edge-cloud/edgeproto"
)

// Data saved to persistent sql db, also used for API calls

type User struct {
	Name          string `gorm:"primary_key;type:citext"`
	Email         string `gorm:"unique;not null"`
	EmailVerified bool
	Passhash      string `gorm:"not null"`
	Salt          string `gorm:"not null"`
	Iter          int    `gorm:"not null"`
	FamilyName    string
	GivenName     string
	Picture       string
	Nickname      string
	CreatedAt     time.Time `json:",omitempty"`
	UpdatedAt     time.Time `json:",omitempty"`
	Locked        bool
}

type Organization struct {
	Name      string `gorm:"primary_key;type:citext"`
	Type      string `gorm:"not null"`
	Address   string
	Phone     string
	CreatedAt time.Time `json:",omitempty"`
	UpdatedAt time.Time `json:",omitempty"`
}

type Controller struct {
	Region    string    `gorm:"primary_key"`
	Address   string    `gorm:"unique;not null"`
	InfluxDB  string    `gorm:"type:text"`
	CreatedAt time.Time `json:",omitempty"`
	UpdatedAt time.Time `json:",omitempty"`
}

type Config struct {
	ID                 int `gorm:"primary_key;auto_increment:false"`
	LockNewAccounts    bool
	NotifyEmailAddress string
}

type OrgCloudletPool struct {
	Org          string `gorm:"type:citext REFERENCES organizations(name)"`
	Region       string `gorm:"type:text REFERENCES controllers(region)"`
	CloudletPool string `gorm:"not null"`
}

// Structs used for API calls

type RolePerm struct {
	Role     string `json:"role"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

type Role struct {
	Org      string `form:"org" json:"org"`
	Username string `form:"username" json:"username"`
	Role     string `form:"role" json:"role"`
}

type OrgCloudlet struct {
	Region string `json:"region,omitempty"`
	Org    string `form:"org" json:"org"`
}

type UserLogin struct {
	Username string `form:"username" json:"username"`
	Password string `form:"password" json:"password"`
}

type NewPassword struct {
	Password string `form:"password" json:"password"`
}

type CreateUser struct {
	User   `json:",inline"`
	Verify EmailRequest `json:"verify"` // for verifying email
}

type AuditQuery struct {
	Username string `json:"username"`
	Org      string `form:"org" json:"org"`
	Limit    int    `json:"limit"`
}

type AuditResponse struct {
	OperationName string               `json:"operationname"`
	Username      string               `json:"username"`
	ClientIP      string               `json:"clientip"`
	Status        int                  `json:"status"`
	StartTime     TimeMicroseconds     `json:"starttime"`
	Duration      DurationMicroseconds `json:"duration"`
	Request       string               `json:"request"`
	Response      string               `json:"response"`
	Error         string               `json:"error"`
	TraceID       string               `json:"traceid"`
}

// Email request is used for password reset and to resend welcome
// verification email. It contains the information need to send
// some kind of email to the user.
type EmailRequest struct {
	Email           string `form:"email" json:"email"`
	OperatingSystem string `form:"operatingsystem" json:"operatingsystem"`
	Browser         string `form:"browser" json:"browser"`
	CallbackURL     string `form:"callbackurl" json:"callbackurl"`
	ClientIP        string `form:"clientip" json:"clientip"`
}

type PasswordReset struct {
	Token    string `form:"token" json:"token"`
	Password string `form:"password" json:"password"`
}

type Token struct {
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

// all data is for full create/delete

type AllData struct {
	Controllers      []Controller      `json:"controllers,omitempty"`
	Orgs             []Organization    `json:"orgs,omitempty"`
	Roles            []Role            `json:"roles,omitempty"`
	OrgCloudletPools []OrgCloudletPool `json:"orgcloudletpools,omitempty"`
	RegionData       []RegionData      `json:"regiondata,omitempty"`
}

type RegionData struct {
	Region  string                    `json:"region,omitempty"`
	AppData edgeproto.ApplicationData `json:"appdata,omitempty"`
}

// Metrics data
type RegionAppInstMetrics struct {
	Region    string
	AppInst   edgeproto.AppInstKey
	Selector  string
	StartTime time.Time `json:",omitempty"`
	EndTime   time.Time `json:",omitempty"`
	Last      int       `json:",omitempty"`
}

type RegionClusterInstMetrics struct {
	Region      string
	ClusterInst edgeproto.ClusterInstKey
	Selector    string
	StartTime   time.Time `json:",omitempty"`
	EndTime     time.Time `json:",omitempty"`
	Last        int       `json:",omitempty"`
}

type RegionCloudletMetrics struct {
	Region    string
	Cloudlet  edgeproto.CloudletKey
	Selector  string
	StartTime time.Time `json:",omitempty"`
	EndTime   time.Time `json:",omitempty"`
	Last      int       `json:",omitempty"`
}
