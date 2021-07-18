package orm

import (
	"context"
	fmt "fmt"
	"net/http"

	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/log"
)

// Password crack times are estimates of how long it would take to brute
// force crack the password offline.
var defaultConfig = ormapi.Config{
	ID:                           1,
	NotifyEmailAddress:           "support@mobiledgex.com",
	PasswordMinCrackTimeSec:      30 * 86400,      // 30 days
	AdminPasswordMinCrackTimeSec: 2 * 365 * 86400, // 2 years
	MaxMetricsDataPoints:         10000,
	UserApiKeyCreateLimit:        10,
	BillingEnable:                false, // TODO: eventually set the default to true?
	DisableRateLimit:             false,
	MaxNumPerIpRateLimiters:      10000,
	MaxNumPerUserRateLimiters:    10000,
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
	// set maxnumperipratelimiters if not set
	if config.MaxNumPerIpRateLimiters == 0 {
		config.MaxNumPerIpRateLimiters = defaultConfig.MaxNumPerIpRateLimiters
		save = true
	}
	// set maxnumperuserratelimiters if not set
	if config.MaxNumPerUserRateLimiters == 0 {
		config.MaxNumPerUserRateLimiters = defaultConfig.MaxNumPerUserRateLimiters
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
	ctx := GetContext(c)
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
		return bindErr(err)
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

	// Update RateLimitMgr settings
	if config.DisableRateLimit != oldConfig.DisableRateLimit {
		rateLimitMgr.UpdateDisableRateLimit(config.DisableRateLimit)
	}
	if config.MaxNumPerIpRateLimiters != oldConfig.MaxNumPerIpRateLimiters {
		rateLimitMgr.UpdateMaxNumPerIpRateLimiters(config.MaxNumPerIpRateLimiters)
	}
	if config.MaxNumPerUserRateLimiters != oldConfig.MaxNumPerUserRateLimiters {
		rateLimitMgr.UpdateMaxNumPerUserRateLimiters(config.MaxNumPerUserRateLimiters)
	}

	db := loggedDB(ctx)
	err = db.Save(&config).Error
	if err != nil {
		return err
	}
	return nil
}

func ResetConfig(c echo.Context) error {
	ctx := GetContext(c)
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
	rateLimitMgr.UpdateMaxNumPerIpRateLimiters(defaultConfig.MaxNumPerIpRateLimiters)
	rateLimitMgr.UpdateMaxNumPerUserRateLimiters(defaultConfig.MaxNumPerUserRateLimiters)

	return nil
}

func ShowConfig(c echo.Context) error {
	ctx := GetContext(c)
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
	ctx := GetContext(c)
	config, err := getConfig(ctx)
	if err != nil {
		return err
	}
	publicConfig := &ormapi.Config{}
	publicConfig.PasswordMinCrackTimeSec = config.PasswordMinCrackTimeSec
	return c.JSON(http.StatusOK, publicConfig)
}
