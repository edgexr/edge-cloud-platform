package orm

import (
	"context"
	"net/http"

	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/log"
)

const configID = 1

func InitConfig(ctx context.Context) error {
	log.SpanLog(ctx, log.DebugLevelApi, "init config")

	// create config if it doesn't exist
	config := ormapi.Config{}
	config.ID = configID
	config.NotifyEmailAddress = "support@mobiledgex.com"
	db := loggedDB(ctx)
	err := db.FirstOrCreate(&config, &ormapi.Config{ID: configID}).Error
	if err != nil {
		return err
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
	return c.JSON(http.StatusOK, config)
}

func getConfig(ctx context.Context) (*ormapi.Config, error) {
	config := ormapi.Config{}
	config.ID = configID
	db := loggedDB(ctx)
	err := db.First(&config).Error
	// note: should always exist
	return &config, err
}
