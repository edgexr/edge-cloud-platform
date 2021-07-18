package orm

import (
	"encoding/json"
	fmt "fmt"
	"io/ioutil"
	"net/http"

	"github.com/jinzhu/gorm"
	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

// Create MC RateLimit MaxReqs settings
func CreateMaxReqsRateLimitSettingsMc(c echo.Context) error {
	ctx := GetContext(c)

	// Check if rate limiting is disabled
	if getDisableRateLimit(ctx) {
		return fmt.Errorf("DisableRateLimit must be false to create ratelimitsettingsmc")
	}

	// Validate rbac
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	if err := authorized(ctx, claims.Username, "", ResourceConfig, ActionManage); err != nil {
		return err
	}

	// Get McRateLimitMaxReqsSettings from request
	in := ormapi.McRateLimitMaxReqsSettings{}
	if err := c.Bind(&in); err != nil {
		return bindErr(err)
	}

	// Create McRateLimitMaxReqsSettings entry
	db := loggedDB(ctx)
	if err := db.Create(&in).Error; err != nil {
		return fmt.Errorf("Unable to create MaxReqsRateLimitSettings %v - error: %s", in, err.Error())
	}

	// Update RateLimitMgr with new MaxReqsRateLimitSettings
	rateLimitMgr.UpdateMaxReqsRateLimitSettings(convertToMaxReqsRateLimitSettings(&in))
	return nil
}

// Update MC RateLimit maxreqs settings
func UpdateMaxReqsRateLimitSettingsMc(c echo.Context) error {
	ctx := GetContext(c)
	// Check if rate limiting is disabled
	if getDisableRateLimit(ctx) {
		return fmt.Errorf("DisableRateLimit must be false to delete ratelimitsettingsmc")
	}

	// Validate rbac
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	if err := authorized(ctx, claims.Username, "", ResourceConfig, ActionManage); err != nil {
		return err
	}

	body, err := ioutil.ReadAll(c.Request().Body)
	in := ormapi.McRateLimitMaxReqsSettings{}
	err = json.Unmarshal(body, &in)
	if err != nil {
		return bindErr(err)
	}

	// Update McRateLimitMaxReqsSettings entry
	db := loggedDB(ctx)
	searchMaxReqs := &ormapi.McRateLimitMaxReqsSettings{
		MaxReqsSettingsName: in.MaxReqsSettingsName,
	}
	maxreqs := ormapi.McRateLimitMaxReqsSettings{}
	res := db.Where(searchMaxReqs).First(&maxreqs)
	if res.RecordNotFound() {
		return fmt.Errorf("MaxReqsSettingsName not found")
	}
	if res.Error != nil {
		return newHTTPError(http.StatusInternalServerError, dbErr(res.Error).Error())
	}

	err = json.Unmarshal(body, &maxreqs)
	if err != nil {
		return bindErr(err)
	}

	err = db.Save(&maxreqs).Error
	if err != nil {
		return newHTTPError(http.StatusInternalServerError, dbErr(err).Error())
	}

	// Update RateLimitMgr with new MaxReqsRateLimitSettings
	rateLimitMgr.UpdateMaxReqsRateLimitSettings(convertToMaxReqsRateLimitSettings(&maxreqs))
	return nil
}

// Delete MC RateLimit maxreqs settings
func DeleteMaxReqsRateLimitSettingsMc(c echo.Context) error {
	ctx := GetContext(c)
	// Check if rate limiting is disabled
	if getDisableRateLimit(ctx) {
		return fmt.Errorf("DisableRateLimit must be false to delete ratelimitsettingsmc")
	}

	// Validate rbac
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	if err := authorized(ctx, claims.Username, "", ResourceConfig, ActionManage); err != nil {
		return err
	}

	// Get McRateLimitMaxReqsSettings from request
	in := ormapi.McRateLimitMaxReqsSettings{}
	if err := c.Bind(&in); err != nil {
		return bindErr(err)
	}

	// Remove McRateLimitMaxReqsSettings entry
	db := loggedDB(ctx)
	err = db.Delete(&in).Error
	if err == gorm.ErrRecordNotFound {
		return fmt.Errorf("Unable to find McRateLimitMaxReqsSettings for specified name: %s", in.MaxReqsSettingsName)
	}
	if err != nil {
		return err
	}

	// Remove MaxReqsRateLimitSettings from RateLimitMgr
	rateLimitMgr.RemoveMaxReqsRateLimitSettings(convertToMaxReqsRateLimitSettings(&in).Key)
	return nil
}

// Show MC RateLimit maxreqs settings
func ShowMaxReqsRateLimitSettingsMc(c echo.Context) error {
	ctx := GetContext(c)
	// Check if rate limiting is disabled
	if getDisableRateLimit(ctx) {
		return fmt.Errorf("DisableRateLimit must be false to show ratelimitsettingsmc")
	}

	// Validate rbac
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	if err := authorized(ctx, claims.Username, "", ResourceConfig, ActionManage); err != nil {
		return err
	}

	// Get McRateLimitMaxReqsSettings from request
	in := ormapi.McRateLimitMaxReqsSettings{}
	if err := c.Bind(&in); err != nil {
		return bindErr(err)
	}

	search := &ormapi.McRateLimitMaxReqsSettings{
		MaxReqsSettingsName: in.MaxReqsSettingsName,
		ApiName:             in.ApiName,
		RateLimitTarget:     in.RateLimitTarget,
	}

	// Search for all entries with specified primary keys (if fields are not specified, fields are left out of search)
	db := loggedDB(ctx)
	r := db.Where(search)
	if r.RecordNotFound() {
		return fmt.Errorf("Specified Key not found")
	}
	if r.Error != nil {
		return dbErr(r.Error)
	}

	mcmaxreqsrecords := make([]*ormapi.McRateLimitMaxReqsSettings, 0)
	if err = r.Find(&mcmaxreqsrecords).Error; err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "Unable to find records for maxreqs", "error", err.Error())
	}

	return setReply(c, &mcmaxreqsrecords)
}

func convertToMaxReqsRateLimitSettings(m *ormapi.McRateLimitMaxReqsSettings) *edgeproto.MaxReqsRateLimitSettings {
	return &edgeproto.MaxReqsRateLimitSettings{
		Key: edgeproto.MaxReqsRateLimitSettingsKey{
			MaxReqsSettingsName: m.MaxReqsSettingsName,
			RateLimitKey: edgeproto.RateLimitSettingsKey{
				ApiName:         m.ApiName,
				RateLimitTarget: m.RateLimitTarget,
			},
		},
		Settings: &edgeproto.MaxReqsSettings{
			MaxReqsAlgorithm: m.MaxReqsAlgorithm,
			MaxRequests:      m.MaxRequests,
			Interval:         m.Interval,
		},
	}
}
