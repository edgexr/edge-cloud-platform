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

package orm

import (
	"context"
	fmt "fmt"
	"net/http"
	"time"

	"github.com/labstack/echo"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud-infra/mc/ormutil"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
)

// Password crack times are estimates of how long it would take to brute
// force crack the password offline.
var defaultConfig = ormapi.Config{
	ID:                            1,
	NotifyEmailAddress:            "support@mobiledgex.com",
	PasswordMinCrackTimeSec:       30 * 86400,      // 30 days
	AdminPasswordMinCrackTimeSec:  2 * 365 * 86400, // 2 years
	MaxMetricsDataPoints:          10000,
	UserApiKeyCreateLimit:         10,
	BillingEnable:                 false, // TODO: eventually set the default to true?
	DisableRateLimit:              false,
	RateLimitMaxTrackedIps:        10000,
	RateLimitMaxTrackedUsers:      10000,
	FailedLoginLockoutThreshold1:  3,
	FailedLoginLockoutTimeSec1:    60,
	FailedLoginLockoutThreshold2:  10,
	FailedLoginLockoutTimeSec2:    300,
	UserLoginTokenValidDuration:   edgeproto.Duration(24 * time.Hour),
	ApiKeyLoginTokenValidDuration: edgeproto.Duration(4 * time.Hour),
	WebsocketTokenValidDuration:   edgeproto.Duration(2 * time.Minute),
}

func InitConfig(ctx context.Context) error {
	log.SpanLog(ctx, log.DebugLevelApi, "init config")

	// create config if it doesn't exist
	config := defaultConfig
	db := loggedDB(ctx)
	err := db.FirstOrCreate(&config, &ormapi.Config{ID: config.ID}).Error
	if err != nil {
		return err
	}

	config = ormapi.Config{ID: config.ID}
	err = db.First(&config).Error
	if err != nil {
		return err
	}
	save := false
	// set password min times if not set
	if config.PasswordMinCrackTimeSec == 0 && config.AdminPasswordMinCrackTimeSec == 0 {
		config.PasswordMinCrackTimeSec = defaultConfig.PasswordMinCrackTimeSec
		config.AdminPasswordMinCrackTimeSec = defaultConfig.AdminPasswordMinCrackTimeSec
		save = true
	}
	// set influxDB data points max number if not set
	if config.MaxMetricsDataPoints == 0 {
		config.MaxMetricsDataPoints = defaultConfig.MaxMetricsDataPoints
		save = true
	}
	// set userapikeykeycreatelimit if not set
	if config.UserApiKeyCreateLimit == 0 {
		config.UserApiKeyCreateLimit = defaultConfig.UserApiKeyCreateLimit
		save = true
	}
	// set ratelimitmaxtrackedips if not set
	if config.RateLimitMaxTrackedIps == 0 {
		config.RateLimitMaxTrackedIps = defaultConfig.RateLimitMaxTrackedIps
		save = true
	}
	// set ratelimitmaxtrackedusers if not set
	if config.RateLimitMaxTrackedUsers == 0 {
		config.RateLimitMaxTrackedUsers = defaultConfig.RateLimitMaxTrackedUsers
		save = true
	}
	if config.FailedLoginLockoutThreshold1 == 0 {
		config.FailedLoginLockoutThreshold1 = defaultConfig.FailedLoginLockoutThreshold1
		save = true
	}
	if config.FailedLoginLockoutTimeSec1 == 0 {
		config.FailedLoginLockoutTimeSec1 = defaultConfig.FailedLoginLockoutTimeSec1
		save = true
	}
	if config.FailedLoginLockoutThreshold2 == 0 {
		config.FailedLoginLockoutThreshold2 = defaultConfig.FailedLoginLockoutThreshold2
		save = true
	}
	if config.FailedLoginLockoutTimeSec2 == 0 {
		config.FailedLoginLockoutTimeSec2 = defaultConfig.FailedLoginLockoutTimeSec2
		save = true
	}
	if config.UserLoginTokenValidDuration == 0 {
		config.UserLoginTokenValidDuration = defaultConfig.UserLoginTokenValidDuration
		save = true
	}
	if config.ApiKeyLoginTokenValidDuration == 0 {
		config.ApiKeyLoginTokenValidDuration = defaultConfig.ApiKeyLoginTokenValidDuration
		save = true
	}
	if config.WebsocketTokenValidDuration == 0 {
		config.WebsocketTokenValidDuration = defaultConfig.WebsocketTokenValidDuration
		save = true
	}
	if config.NotifyEmailAddress == "" {
		config.NotifyEmailAddress = defaultConfig.NotifyEmailAddress
		save = true
	}

	if save {
		err = db.Save(&config).Error
		if err != nil {
			return err
		}
	}

	log.SpanLog(ctx, log.DebugLevelApi, "using config", "config", config)
	return nil
}

func UpdateConfig(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	if err := authorized(ctx, claims.Username, "", ResourceConfig, ActionManage); err != nil {
		return err
	}
	config, err := getConfig(ctx)
	if err != nil {
		return err
	}
	oldConfig := *config
	// calling bind after doing lookup will overwrite only the
	// fields specified in the request body, keeping existing fields intact.
	if err := c.Bind(&config); err != nil {
		return ormutil.BindErr(err)
	}
	config.ID = defaultConfig.ID

	if config.AdminPasswordMinCrackTimeSec < config.PasswordMinCrackTimeSec {
		return fmt.Errorf("admin password min crack time must be greater than password min crack time")
	}
	if config.AdminPasswordMinCrackTimeSec != oldConfig.AdminPasswordMinCrackTimeSec || config.PasswordMinCrackTimeSec != oldConfig.PasswordMinCrackTimeSec {
		err = resetUserPasswordCrackTimes(ctx)
		if err != nil {
			return err
		}
	}
	if config.FailedLoginLockoutThreshold1 <= 0 {
		return fmt.Errorf("Failed login lockout threshold 1 cannot be less than or equal to 0")
	}
	if config.FailedLoginLockoutThreshold2 <= 0 {
		return fmt.Errorf("Failed login lockout threshold 2 cannot be less than or equal to 0")
	}
	if config.FailedLoginLockoutThreshold2 <= config.FailedLoginLockoutThreshold1 {
		return fmt.Errorf("Failed login lockout threshold 2 of %d must be greater than threshold 1 of %d", config.FailedLoginLockoutThreshold2, config.FailedLoginLockoutThreshold1)
	}
	lockoutTime1 := time.Duration(config.FailedLoginLockoutTimeSec1) * time.Second
	if lockoutTime1 < 0 {
		// check for duration overflow
		return fmt.Errorf("Failed login lockout time sec 1 of %s cannot be negative", lockoutTime1.String())
	}
	if lockoutTime1 < BadAuthDelay {
		return fmt.Errorf("Failed login lockout time sec 1 of %s must be greater than or equal to default lockout time of %s", lockoutTime1.String(), BadAuthDelay.String())
	}
	lockoutTime2 := time.Duration(config.FailedLoginLockoutTimeSec2) * time.Second
	if lockoutTime2 < 0 {
		// check for duration overflow
		return fmt.Errorf("Failed login lockout time sec 2 of %s cannot be negative", lockoutTime2.String())
	}
	if lockoutTime2 < lockoutTime1 {
		return fmt.Errorf("Failed login lockout time sec 2 of %s must be greater than or equal to lockout time 1 of %s", lockoutTime2.String(), lockoutTime1.String())
	}
	if config.UserLoginTokenValidDuration.TimeDuration() < 3*time.Minute {
		// avoid setting duration so low that we can't log in and change it back
		return fmt.Errorf("User login token valid duration cannot be less than 3 minutes")
	}

	// Update RateLimitMgr settings
	if config.DisableRateLimit != oldConfig.DisableRateLimit {
		rateLimitMgr.UpdateDisableRateLimit(config.DisableRateLimit)
	}
	if config.RateLimitMaxTrackedIps != oldConfig.RateLimitMaxTrackedIps {
		rateLimitMgr.UpdateMaxTrackedIps(config.RateLimitMaxTrackedIps)
	}
	if config.RateLimitMaxTrackedUsers != oldConfig.RateLimitMaxTrackedUsers {
		rateLimitMgr.UpdateMaxTrackedUsers(config.RateLimitMaxTrackedUsers)
	}

	db := loggedDB(ctx)
	err = db.Save(&config).Error
	if err != nil {
		return err
	}
	return nil
}

func ResetConfig(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	if err := authorized(ctx, claims.Username, "", ResourceConfig, ActionManage); err != nil {
		return err
	}
	config := defaultConfig
	db := loggedDB(ctx)
	err = db.Save(&config).Error
	if err != nil {
		return err
	}
	err = resetUserPasswordCrackTimes(ctx)
	if err != nil {
		return err
	}

	// Update RateLimitMgr settings
	rateLimitMgr.UpdateDisableRateLimit(defaultConfig.DisableRateLimit)
	rateLimitMgr.UpdateMaxTrackedIps(defaultConfig.RateLimitMaxTrackedIps)
	rateLimitMgr.UpdateMaxTrackedUsers(defaultConfig.RateLimitMaxTrackedUsers)

	return nil
}

func ShowConfig(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	if err := authorized(ctx, claims.Username, "", ResourceConfig, ActionManage); err != nil {
		return err
	}
	config, err := getConfig(ctx)
	if err != nil {
		return err
	}
	// zero out ID so it is not shown to user
	config.ID = 0
	return c.JSON(http.StatusOK, config)
}

func getConfig(ctx context.Context) (*ormapi.Config, error) {
	config := ormapi.Config{}
	config.ID = defaultConfig.ID
	db := loggedDB(ctx)
	err := db.First(&config).Error
	// note: should always exist
	return &config, err
}

// this should be called if the password crack time configuration changed
func resetUserPasswordCrackTimes(ctx context.Context) error {
	log.SpanLog(ctx, log.DebugLevelInfo, "reset user password crack times")
	// this resets PassCrackTimeSec values to 0 for all users
	db := loggedDB(ctx)
	res := db.Model(&ormapi.User{}).Where("pass_crack_time_sec > ?", 0).Update("pass_crack_time_sec", 0)
	return res.Error
}

// PubliConfig gets configuration that the UI needs to make the behavior of the
// UI consistent with the behavior of the back-end. This is an un-authenticated
// API so only that which is needed should be revealed.
func PublicConfig(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	config, err := getConfig(ctx)
	if err != nil {
		return err
	}
	publicConfig := &ormapi.Config{}
	publicConfig.PasswordMinCrackTimeSec = config.PasswordMinCrackTimeSec
	return c.JSON(http.StatusOK, publicConfig)
}
