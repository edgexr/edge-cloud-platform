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
	"bytes"
	"context"
	"encoding/json"
	fmt "fmt"
	"io/ioutil"
	"net/http"

	"github.com/jinzhu/gorm"
	"github.com/labstack/echo"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud-infra/mc/ormutil"
	"github.com/edgexr/edge-cloud/cloudcommon/ratelimit"
	edgeproto "github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
)

// Default McRateLimitSettings structs

var GlobalAllRequestsMcRateLimitSettings = &ormapi.McRateLimitSettings{
	ApiName:         edgeproto.GlobalApiName,
	RateLimitTarget: edgeproto.RateLimitTarget_ALL_REQUESTS,
	FlowSettings: map[string]edgeproto.FlowSettings{
		"mcglobalallreqs1": edgeproto.FlowSettings{
			FlowAlgorithm: edgeproto.FlowRateLimitAlgorithm_TOKEN_BUCKET_ALGORITHM,
			ReqsPerSecond: 10000,
			BurstSize:     500,
		},
	},
}

var GlobalPerIpMcRateLimitSettings = &ormapi.McRateLimitSettings{
	ApiName:         edgeproto.GlobalApiName,
	RateLimitTarget: edgeproto.RateLimitTarget_PER_IP,
	FlowSettings: map[string]edgeproto.FlowSettings{
		"mcglobalperip1": edgeproto.FlowSettings{
			FlowAlgorithm: edgeproto.FlowRateLimitAlgorithm_TOKEN_BUCKET_ALGORITHM,
			ReqsPerSecond: 1000,
			BurstSize:     100,
		},
	},
}

var GlobalPerUserMcRateLimitSettings = &ormapi.McRateLimitSettings{
	ApiName:         edgeproto.GlobalApiName,
	RateLimitTarget: edgeproto.RateLimitTarget_PER_USER,
	FlowSettings: map[string]edgeproto.FlowSettings{
		"mcglobalperuser1": edgeproto.FlowSettings{
			FlowAlgorithm: edgeproto.FlowRateLimitAlgorithm_TOKEN_BUCKET_ALGORITHM,
			ReqsPerSecond: 1000,
			BurstSize:     100,
		},
	},
}

var userCreateApiName = "/api/v1/usercreate"

var UserCreateAllRequestsMcRateLimitSettings = &ormapi.McRateLimitSettings{
	ApiName:         userCreateApiName,
	RateLimitTarget: edgeproto.RateLimitTarget_ALL_REQUESTS,
	FlowSettings: map[string]edgeproto.FlowSettings{
		"usercreateallreqs1": edgeproto.FlowSettings{
			FlowAlgorithm: edgeproto.FlowRateLimitAlgorithm_TOKEN_BUCKET_ALGORITHM,
			ReqsPerSecond: 100,
			BurstSize:     5,
		},
	},
}

var UserCreatePerIpMcRateLimitSettings = &ormapi.McRateLimitSettings{
	ApiName:         userCreateApiName,
	RateLimitTarget: edgeproto.RateLimitTarget_PER_IP,
	FlowSettings: map[string]edgeproto.FlowSettings{
		"usercreateperip1": edgeproto.FlowSettings{
			FlowAlgorithm: edgeproto.FlowRateLimitAlgorithm_TOKEN_BUCKET_ALGORITHM,
			ReqsPerSecond: 2,
			BurstSize:     2,
		},
	},
}

/*
 * Intialize McRateLimitSettings for MC APIs
 * Store default McRateLimitSettings in postgres
 * Add RateLimitSettings to RateLimitMgr
 */
func InitRateLimitMc(ctx context.Context) error {
	log.SpanLog(ctx, log.DebugLevelApi, "init ratelimit")
	db := loggedDB(ctx)

	createFunc := func(settings interface{}) error {
		return db.FirstOrCreate(settings).Error
	}

	// Create Global RateLimitSettings and UserCreate RateLimitSettings entries in postgres
	var err error
	if err = executeDbOperationOnMcRateLimitSettings(GlobalAllRequestsMcRateLimitSettings, createFunc); err != nil {
		return fmt.Errorf("Unable to create Global AllRequests RateLimitSettings - error: %s", err.Error())
	}
	if err = executeDbOperationOnMcRateLimitSettings(GlobalPerIpMcRateLimitSettings, createFunc); err != nil {
		return fmt.Errorf("Unable to create Global PerIP RateLimitSettings - error: %s", err.Error())
	}
	if err = executeDbOperationOnMcRateLimitSettings(GlobalPerUserMcRateLimitSettings, createFunc); err != nil {
		return fmt.Errorf("Unable to create Global PerUser RateLimitSettings - error: %s", err.Error())
	}
	if err = executeDbOperationOnMcRateLimitSettings(UserCreateAllRequestsMcRateLimitSettings, createFunc); err != nil {
		return fmt.Errorf("Unable to create UserCreate AllRequests RateLimitSettings - error: %s", err.Error())
	}
	if err = executeDbOperationOnMcRateLimitSettings(UserCreatePerIpMcRateLimitSettings, createFunc); err != nil {
		return fmt.Errorf("Unable to create UserCreate PerIP RateLimitSettings - error: %s", err.Error())
	}

	// Init RateLimitMgr and add Global RateLimitSettings and UserCreate RateLimitSettings
	rateLimitMgr = ratelimit.NewRateLimitManager(getDisableRateLimit(ctx), getRateLimitMaxTrackedIps(ctx), getRateLimitMaxTrackedUsers(ctx))
	rateLimitMgr.CreateApiEndpointLimiter(edgeproto.GlobalApiName, convertToRateLimitSettings(GlobalAllRequestsMcRateLimitSettings), convertToRateLimitSettings(GlobalPerIpMcRateLimitSettings), convertToRateLimitSettings(GlobalPerUserMcRateLimitSettings))
	rateLimitMgr.CreateApiEndpointLimiter(userCreateApiName, convertToRateLimitSettings(UserCreateAllRequestsMcRateLimitSettings), convertToRateLimitSettings(UserCreatePerIpMcRateLimitSettings), nil)
	return nil
}

// Generates unique id for McRateLimitFlowSettings or McRateLimitMaxReqsSettings based on the index the setting occurs in the slice
func generateId(apiName string, rateLimitTarget edgeproto.RateLimitTarget, idx int) string {
	return fmt.Sprintf("%s%d%d", apiName, rateLimitTarget, idx)
}

/*
 * Pulls out all FlowSettings and MaxReqsSettings from McRateLimitSettings and converts each to McRateLimitFlowSettings and McRateLimitMaxReqsSettings respectively
 * Executes provided db operation on each
 */
func executeDbOperationOnMcRateLimitSettings(settings *ormapi.McRateLimitSettings, operation func(settings interface{}) error) error {
	ApiName := settings.ApiName
	rateLimitTarget := settings.RateLimitTarget

	// Add FlowSettings to postgres
	for name, flowsetting := range settings.FlowSettings {
		mcflowsettings := &ormapi.McRateLimitFlowSettings{
			FlowSettingsName: name,
			ApiName:          ApiName,
			RateLimitTarget:  rateLimitTarget,
			FlowAlgorithm:    flowsetting.FlowAlgorithm,
			ReqsPerSecond:    flowsetting.ReqsPerSecond,
			BurstSize:        flowsetting.BurstSize,
		}
		err := operation(mcflowsettings)
		if err != nil {
			return err
		}
	}

	// Add MaxReqsSettings to postgres
	for name, maxreqssetting := range settings.MaxReqsSettings {
		mcmaxreqssettings := &ormapi.McRateLimitMaxReqsSettings{
			MaxReqsSettingsName: name,
			ApiName:             ApiName,
			RateLimitTarget:     rateLimitTarget,
			MaxReqsAlgorithm:    maxreqssetting.MaxReqsAlgorithm,
			MaxRequests:         maxreqssetting.MaxRequests,
			Interval:            maxreqssetting.Interval,
		}
		err := operation(mcmaxreqssettings)
		if err != nil {
			return err
		}
	}
	return nil
}

// Echo middleware function that handles rate limiting for MC APIs
func RateLimit(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := ormutil.GetContext(c)

		// Check if rate limiting is disabled, if disabled continue
		if getDisableRateLimit(ctx) {
			return next(c)
		}

		// Create callerInfo
		callerInfo := &ratelimit.CallerInfo{
			Api: c.Path(),
		}
		claims, err := getClaims(c)
		if err != nil {
			// use IP if cannot get claims
			callerInfo.Ip = c.RealIP()
		} else {
			// use Username if can get claims
			callerInfo.User = claims.Username
		}

		// Rate limit
		if err = rateLimitMgr.Limit(ctx, callerInfo); err != nil {
			errMsg := fmt.Sprintf("%s is rejected, please retry later.", c.Path())
			if err != nil {
				errMsg += fmt.Sprintf(" Error is: %s.", err.Error())
			}
			return echo.NewHTTPError(http.StatusTooManyRequests, errMsg)

		}
		return next(c)
	}
}

// Echo middleware function that handles rate limiting for federation APIs
func FederationRateLimit(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := ormutil.GetContext(c)

		// Check if rate limiting is disabled, if disabled continue
		if getDisableRateLimit(ctx) {
			return next(c)
		}

		// Get partner's federation ID from request body.
		reqBody := []byte{}
		if c.Request().Body != nil { // Read
			reqBody, _ = ioutil.ReadAll(c.Request().Body)
		}
		c.Request().Body = ioutil.NopCloser(bytes.NewBuffer(reqBody)) // Reset

		// All federation APIs must have `origFederationId` field, use that
		// as username for ratelimitting federation APIs
		type CommonReq struct {
			OrigFederationId string `json:"origFederationId"`
		}
		origFedId := ""
		fedIdObj := CommonReq{}
		err := json.Unmarshal(reqBody, &fedIdObj)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfo, "failed to unmarshal request body to fetch origin federation ID", "req body", string(reqBody), "err", err)
		} else {
			origFedId = fedIdObj.OrigFederationId
		}

		// Create callerInfo
		callerInfo := &ratelimit.CallerInfo{
			Api: c.Path(),
		}
		if origFedId == "" {
			// use IP if cannot get partner's federation ID
			callerInfo.Ip = c.RealIP()
		} else {
			// use partner's federation ID as Username
			callerInfo.User = origFedId
		}

		// Rate limit
		if err = rateLimitMgr.Limit(ctx, callerInfo); err != nil {
			errMsg := fmt.Sprintf("%s is rejected, please retry later.", c.Path())
			if err != nil {
				errMsg += fmt.Sprintf(" Error is: %s.", err.Error())
			}
			return echo.NewHTTPError(http.StatusTooManyRequests, errMsg)

		}
		return next(c)
	}
}

// Helper function that grabs the DisableRateLimit bool from the Config struct
func getDisableRateLimit(ctx context.Context) bool {
	config, err := getConfig(ctx)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "unable to check config for disableRateLimit", "err", err)
		return defaultConfig.DisableRateLimit
	}
	return config.DisableRateLimit
}

// Helper function that grabs the RateLimitMaxTrackedIps int from the Config struct
func getRateLimitMaxTrackedIps(ctx context.Context) int {
	config, err := getConfig(ctx)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "unable to check config for RateLimitMaxTrackedIps", "err", err)
		return defaultConfig.RateLimitMaxTrackedIps
	}
	return config.RateLimitMaxTrackedIps
}

// Helper function that grabs the RateLimitMaxTrackedUsers int from the Config struct
func getRateLimitMaxTrackedUsers(ctx context.Context) int {
	config, err := getConfig(ctx)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "unable to check config for RateLimitMaxTrackedUsers", "err", err)
		return defaultConfig.RateLimitMaxTrackedUsers
	}
	return config.RateLimitMaxTrackedUsers
}

// Show MC RateLimit settings
func ShowRateLimitSettingsMc(c echo.Context) error {
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

	// Get McRateLimitSettings from request
	in := ormapi.McRateLimitSettings{}
	if err := c.Bind(&in); err != nil {
		return ormutil.BindErr(err)
	}

	db := loggedDB(ctx)
	mcflowrecords, mcmaxreqsrecords, err := getAllEntriesForApiAndTarget(ctx, db, in.ApiName, in.RateLimitTarget)
	if err != nil {
		return err
	}

	show := buildMcRateLimitSettings(mcflowrecords, mcmaxreqsrecords)
	return ormutil.SetReply(c, &show)
}

// Search for all entries with specified primary keys (if fields are not specified, fields are left out of search)
func getAllEntriesForApiAndTarget(ctx context.Context, db *gorm.DB, apiName string, rateLimitTarget edgeproto.RateLimitTarget) ([]*ormapi.McRateLimitFlowSettings, []*ormapi.McRateLimitMaxReqsSettings, error) {
	search := &ormapi.McRateLimitFlowSettings{
		ApiName:         apiName,
		RateLimitTarget: rateLimitTarget,
	}

	r := db.Where(search)
	if r.RecordNotFound() {
		return nil, nil, fmt.Errorf("Specified Key not found")
	}
	if r.Error != nil {
		return nil, nil, ormutil.DbErr(r.Error)
	}

	mcflowrecords := make([]*ormapi.McRateLimitFlowSettings, 0)
	mcmaxreqsrecords := make([]*ormapi.McRateLimitMaxReqsSettings, 0)
	if err := r.Find(&mcflowrecords).Error; err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "Unable to find records for flow", "error", err.Error())
	}
	if err := r.Find(&mcmaxreqsrecords).Error; err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "Unable to find records for maxreqs", "error", err.Error())
	}

	return mcflowrecords, mcmaxreqsrecords, nil
}

// Helper function that converts McRateLimitFlowSettings to edgeproto.FlowSettings
func convertToEdgeProtoFlowSettings(flowsettings *ormapi.McRateLimitFlowSettings) edgeproto.FlowSettings {
	return edgeproto.FlowSettings{
		FlowAlgorithm: flowsettings.FlowAlgorithm,
		ReqsPerSecond: flowsettings.ReqsPerSecond,
		BurstSize:     flowsettings.BurstSize,
	}
}

// Helper function that converts McRateLimitMaxReqsSettings to edgeproto.MaxReqsSettings
func convertToEdgeProtoMaxReqsSettings(maxreqssettings *ormapi.McRateLimitMaxReqsSettings) edgeproto.MaxReqsSettings {
	return edgeproto.MaxReqsSettings{
		MaxReqsAlgorithm: maxreqssettings.MaxReqsAlgorithm,
		MaxRequests:      maxreqssettings.MaxRequests,
		Interval:         maxreqssettings.Interval,
	}
}

// Helper function to convert lists of McRateLimitFlowSettings and McRateLimitMaxReqsSettings to McRateLimitSettings to return to api caller
func buildMcRateLimitSettings(flowsettings []*ormapi.McRateLimitFlowSettings, maxreqssettings []*ormapi.McRateLimitMaxReqsSettings) []*ormapi.McRateLimitSettings {
	settingsmap := make(map[edgeproto.RateLimitSettingsKey]*ormapi.McRateLimitSettings)

	for _, flowsetting := range flowsettings {
		key := edgeproto.RateLimitSettingsKey{
			ApiName:         flowsetting.ApiName,
			RateLimitTarget: flowsetting.RateLimitTarget,
		}
		mcratelimitsetting, ok := settingsmap[key]
		if !ok || mcratelimitsetting == nil {
			mcratelimitsetting = &ormapi.McRateLimitSettings{
				ApiName:         flowsetting.ApiName,
				RateLimitTarget: flowsetting.RateLimitTarget,
				FlowSettings:    make(map[string]edgeproto.FlowSettings),
				MaxReqsSettings: make(map[string]edgeproto.MaxReqsSettings),
			}
		}
		mcratelimitsetting.FlowSettings[flowsetting.FlowSettingsName] = convertToEdgeProtoFlowSettings(flowsetting)
		settingsmap[key] = mcratelimitsetting
	}

	for _, maxreqssetting := range maxreqssettings {
		key := edgeproto.RateLimitSettingsKey{
			ApiName:         maxreqssetting.ApiName,
			RateLimitTarget: maxreqssetting.RateLimitTarget,
		}
		mcratelimitsetting, ok := settingsmap[key]
		if !ok || mcratelimitsetting == nil {
			mcratelimitsetting = &ormapi.McRateLimitSettings{
				ApiName:         maxreqssetting.ApiName,
				RateLimitTarget: maxreqssetting.RateLimitTarget,
				FlowSettings:    make(map[string]edgeproto.FlowSettings),
				MaxReqsSettings: make(map[string]edgeproto.MaxReqsSettings),
			}
		}
		mcratelimitsetting.MaxReqsSettings[maxreqssetting.MaxReqsSettingsName] = convertToEdgeProtoMaxReqsSettings(maxreqssetting)
		settingsmap[key] = mcratelimitsetting
	}

	mcratelimitsettings := make([]*ormapi.McRateLimitSettings, 0)
	for _, settings := range settingsmap {
		mcratelimitsettings = append(mcratelimitsettings, settings)
	}
	return mcratelimitsettings
}

// Helper function that converts ormapi.McRateLimitSettings to edgeproto.RateLimitSettings for RateLimitMgr calls
func convertToRateLimitSettings(mcsettings *ormapi.McRateLimitSettings) *edgeproto.RateLimitSettings {
	// Init RateLimitSettings with key
	settings := &edgeproto.RateLimitSettings{
		Key: edgeproto.RateLimitSettingsKey{
			ApiName:         mcsettings.ApiName,
			RateLimitTarget: mcsettings.RateLimitTarget,
		},
	}

	// Add FlowSettings
	if mcsettings.FlowSettings != nil && len(mcsettings.FlowSettings) > 0 {
		flowsettings := make(map[string]*edgeproto.FlowSettings)
		for name, settings := range mcsettings.FlowSettings {
			flowsettings[name] = &settings
		}
		settings.FlowSettings = flowsettings
	}

	// Add MaxReqsSettings
	if mcsettings.MaxReqsSettings != nil && len(mcsettings.MaxReqsSettings) > 0 {
		maxreqssettings := make(map[string]*edgeproto.MaxReqsSettings)
		for name, setting := range mcsettings.MaxReqsSettings {
			maxreqssettings[name] = &setting
		}
		settings.MaxReqsSettings = maxreqssettings
	}
	return settings
}
