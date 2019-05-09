package ormapi

import (
	"time"

	"github.com/mobiledgex/edge-cloud/edgeproto"
)

// Data saved to persistent sql db, also used for API calls

type User struct {
	Name          string `gorm:"primary_key"`
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
	Name          string `gorm:"primary_key"`
	Type          string `gorm:"not null"`
	Address       string
	Phone         string
	AdminUsername string    `gorm:"type:text REFERENCES users(name)"`
	CreatedAt     time.Time `json:",omitempty"`
	UpdatedAt     time.Time `json:",omitempty"`
}

type Controller struct {
	Region    string    `gorm:"primary_key"`
	Address   string    `gorm:"unique;not null"`
	CreatedAt time.Time `json:",omitempty"`
	UpdatedAt time.Time `json:",omitempty"`
}

type Config struct {
	ID                 int `gorm:"primary_key;auto_increment:false"`
	LockNewAccounts    bool
	NotifyEmailAddress string
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

type UserLogin struct {
	Username string `form:"username" json:"username"`
	Password string `form:"password" json:"password"`
}

type NewPassword struct {
	Password string `form:"password" json:"password"`
}

// PasswordResetRequest should contain the user's email,
// the operating system and browser type of the client,
// and the UI's URI to complete the password reset request.
type PasswordResetRequest struct {
	Email           string `form:"email" json:"email"`
	OperatingSystem string `form:"operatingsystem" json:"operatingsystem"`
	Browser         string `form:"browser" json:"browser"`
	ResetPageURL    string `form:"resetpageurl" json:"resetpageurl"`
}

type PasswordReset struct {
	Token    string `form:"token" json:"token"`
	Password string `form:"password" json:"password"`
}

// Structs used in replies

type Result struct {
	Message string `json:"message,omitempty"`
	Code    int    `json:"code,omitempty"`
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
	Controllers []Controller   `json:"controllers,omitempty"`
	Orgs        []Organization `json:"orgs,omitempty"`
	Roles       []Role         `json:"roles,omitempty"`
	// not supported yet
	RegionData []RegionData `json:"regiondata,omitempty"`
}

type RegionData struct {
	Region  string                    `json:"region,omitempty"`
	AppData edgeproto.ApplicationData `json:"appdata,omitempty"`
}
