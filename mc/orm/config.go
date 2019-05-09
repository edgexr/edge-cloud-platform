package orm

import (
	"net/http"

	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/log"
)

const configID = 1

func InitConfig() error {
	log.DebugLog(log.DebugLevelApi, "init config")

	// create config if it doesn't exist
	config := ormapi.Config{}
	config.ID = configID
	config.NotifyEmailAddress = "support@mobiledgex.com"
	err := db.FirstOrCreate(&config, &config).Error
	if err != nil {
		return err
	}
	log.DebugLog(log.DebugLevelApi, "using config", "config", config)
	return nil
}

func UpdateConfig(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	if !enforcer.Enforce(claims.Username, "", ResourceConfig, ActionManage) {
		return echo.ErrForbidden
	}
	config, err := getConfig()
	if err != nil {
		return err
	}
	// calling bind after doing lookup will overwrite only the
	// fields specified in the request body, keeping existing fields intact.
	if err := c.Bind(&config); err != nil {
		return bindErr(c, err)
	}
	err = db.Save(&config).Error
	if err != nil {
		return err
	}
	return nil
}

func ShowConfig(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	if !enforcer.Enforce(claims.Username, "", ResourceConfig, ActionManage) {
		return echo.ErrForbidden
	}
	config, err := getConfig()
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, config)
}

func getConfig() (*ormapi.Config, error) {
	config := ormapi.Config{}
	config.ID = configID
	err := db.First(&config).Error
	// note: should always exist
	return &config, err
}
