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
	fmt "fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/jinzhu/gorm"
	"github.com/labstack/echo"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud-infra/mc/ormutil"
	edgeproto "github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
)

// Create MC RateLimit MaxReqs settings
func CreateMaxReqsRateLimitSettingsMc(c echo.Context) error {
	ctx := ormutil.GetContext(c)

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
		return ormutil.BindErr(err)
	}

	// Create McRateLimitMaxReqsSettings entry
	db := loggedDB(ctx)

	if err := db.Create(&in).Error; err != nil {
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint \"mc_rate_limit_max_reqs_settings_pkey") {
			return fmt.Errorf("MaxReqsRateLimitSettings with MaxReqsSettingsName %s already exists", in.MaxReqsSettingsName)
		}
		return fmt.Errorf("Unable to create MaxReqsRateLimitSettings %v - error: %s", in, err.Error())
	}

	// Update RateLimitMgr with new MaxReqsRateLimitSettings
	rateLimitMgr.UpdateMaxReqsRateLimitSettings(convertToMaxReqsRateLimitSettings(&in))
	return nil
}

// Update MC RateLimit maxreqs settings
func UpdateMaxReqsRateLimitSettingsMc(c echo.Context) error {
	ctx := ormutil.GetContext(c)
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
	err = BindJson(body, &in)
	if err != nil {
		return ormutil.BindErr(err)
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
		return ormutil.NewHTTPError(http.StatusInternalServerError, ormutil.DbErr(res.Error).Error())
	}

	err = BindJson(body, &maxreqs)
	if err != nil {
		return ormutil.BindErr(err)
	}

	err = db.Save(&maxreqs).Error
	if err != nil {
		return ormutil.NewHTTPError(http.StatusInternalServerError, ormutil.DbErr(err).Error())
	}

	// Update RateLimitMgr with new MaxReqsRateLimitSettings
	rateLimitMgr.UpdateMaxReqsRateLimitSettings(convertToMaxReqsRateLimitSettings(&maxreqs))
	return nil
}

// Delete MC RateLimit maxreqs settings
func DeleteMaxReqsRateLimitSettingsMc(c echo.Context) error {
	ctx := ormutil.GetContext(c)
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
		return ormutil.BindErr(err)
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
	ctx := ormutil.GetContext(c)
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
		return ormutil.BindErr(err)
	}

	// Search for all entries with specified primary keys (if fields are not specified, fields are left out of search)
	db := loggedDB(ctx)
	r := db.Where(&in)
	if r.RecordNotFound() {
		return fmt.Errorf("Specified Key not found")
	}
	if r.Error != nil {
		return ormutil.DbErr(r.Error)
	}

	mcmaxreqsrecords := make([]*ormapi.McRateLimitMaxReqsSettings, 0)
	if err = r.Find(&mcmaxreqsrecords).Error; err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "Unable to find records for maxreqs", "error", err.Error())
	}

	return ormutil.SetReply(c, &mcmaxreqsrecords)
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
		Settings: edgeproto.MaxReqsSettings{
			MaxReqsAlgorithm: m.MaxReqsAlgorithm,
			MaxRequests:      m.MaxRequests,
			Interval:         m.Interval,
		},
	}
}
