package orm

import (
	"context"
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
	// set password min times if not set
	if config.PasswordMinCrackTimeSec == 0 && config.AdminPasswordMinCrackTimeSec == 0 {
		config.PasswordMinCrackTimeSec = defaultConfig.PasswordMinCrackTimeSec
		config.AdminPasswordMinCrackTimeSec = defaultConfig.AdminPasswordMinCrackTimeSec
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
	// calling bind after doing lookup will overwrite only the
	// fields specified in the request body, keeping existing fields intact.
	if err := c.Bind(&config); err != nil {
		return bindErr(c, err)
	}
	config.ID = defaultConfig.ID

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
