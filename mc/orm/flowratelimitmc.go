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

// Create MC RateLimit Flow settings
func CreateFlowRateLimitSettingsMc(c echo.Context) error {
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

	// Get McRateLimitFlowSettings from request
	in := ormapi.McRateLimitFlowSettings{}
	if err := c.Bind(&in); err != nil {
		return ormutil.BindErr(err)
	}

	// Create McRateLimitFlowSettings entry
	db := loggedDB(ctx)

	if err := db.Create(&in).Error; err != nil {
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint \"mc_rate_limit_flow_settings_pkey") {
			return fmt.Errorf("FlowRateLimitSettings with FlowSettingsName %s already exists", in.FlowSettingsName)
		}
		return fmt.Errorf("Unable to create FlowRateLimitSettings %v - error: %s", in, err.Error())
	}

	// Update RateLimitMgr with new FlowRateLimitSettings
	rateLimitMgr.UpdateFlowRateLimitSettings(convertToFlowRateLimitSettings(&in))
	return nil
}

// Update MC RateLimit flow settings
func UpdateFlowRateLimitSettingsMc(c echo.Context) error {
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
	in := ormapi.McRateLimitFlowSettings{}
	err = BindJson(body, &in)
	if err != nil {
		return ormutil.BindErr(err)
	}

	// Update McRateLimitFlowSettings entry
	db := loggedDB(ctx)
	searchFlow := &ormapi.McRateLimitFlowSettings{
		FlowSettingsName: in.FlowSettingsName,
	}
	flow := ormapi.McRateLimitFlowSettings{}
	res := db.Where(searchFlow).First(&flow)
	if res.RecordNotFound() {
		return fmt.Errorf("FlowSettingsName not found")
	}
	if res.Error != nil {
		return ormutil.NewHTTPError(http.StatusInternalServerError, ormutil.DbErr(res.Error).Error())
	}

	err = BindJson(body, &flow)
	if err != nil {
		return ormutil.BindErr(err)
	}

	err = db.Save(&flow).Error
	if err != nil {
		return ormutil.NewHTTPError(http.StatusInternalServerError, ormutil.DbErr(err).Error())
	}

	// Update RateLimitMgr with new FlowRateLimitSettings
	rateLimitMgr.UpdateFlowRateLimitSettings(convertToFlowRateLimitSettings(&flow))
	return nil
}

// Delete MC RateLimit flow settings
func DeleteFlowRateLimitSettingsMc(c echo.Context) error {
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

	// Get McRateLimitFlowSettings from request
	in := ormapi.McRateLimitFlowSettings{}
	if err := c.Bind(&in); err != nil {
		return ormutil.BindErr(err)
	}

	// Remove McRateLimitFlowSettings entry
	db := loggedDB(ctx)
	err = db.Delete(&in).Error
	if err == gorm.ErrRecordNotFound {
		return fmt.Errorf("Unable to find McRateLimitFlowSettings for specified name: %s", in.FlowSettingsName)
	}
	if err != nil {
		return err
	}

	// Remove FlowRateLimitSettings from RateLimitMgr
	rateLimitMgr.RemoveFlowRateLimitSettings(convertToFlowRateLimitSettings(&in).Key)
	return nil
}

// Show MC RateLimit flow settings
func ShowFlowRateLimitSettingsMc(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	// Check if rate limiting is disabled
	if getDisableRateLimit(ctx) {
		return fmt.Errorf("DisableRateLimit must be false to show flowratelimitsettingsmc")
	}

	// Validate rbac
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	if err := authorized(ctx, claims.Username, "", ResourceConfig, ActionManage); err != nil {
		return err
	}

	// Get McRateLimitFlowSettings from request
	in := ormapi.McRateLimitFlowSettings{}
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

	mcflowrecords := make([]*ormapi.McRateLimitFlowSettings, 0)
	if err = r.Find(&mcflowrecords).Error; err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "Unable to find records for flow", "error", err.Error())
	}

	return ormutil.SetReply(c, &mcflowrecords)
}

func convertToFlowRateLimitSettings(f *ormapi.McRateLimitFlowSettings) *edgeproto.FlowRateLimitSettings {
	return &edgeproto.FlowRateLimitSettings{
		Key: edgeproto.FlowRateLimitSettingsKey{
			FlowSettingsName: f.FlowSettingsName,
			RateLimitKey: edgeproto.RateLimitSettingsKey{
				ApiName:         f.ApiName,
				RateLimitTarget: f.RateLimitTarget,
			},
		},
		Settings: edgeproto.FlowSettings{
			FlowAlgorithm: f.FlowAlgorithm,
			ReqsPerSecond: f.ReqsPerSecond,
			BurstSize:     f.BurstSize,
		},
	}
}
