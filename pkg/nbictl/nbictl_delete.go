// Copyright 2024 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nbictl

import (
	"context"
	"net/http"

	"github.com/edgexr/edge-cloud-platform/api/nbi"
)

func DeleteAll(ctx context.Context, client *nbi.ClientWithResponses, data *DeleteData) []APIErr {
	errs := []APIErr{}

	// Delete AppInsts
	if len(data.AppInsts) > 0 {
		// look up AppInsts so we can map names to IDs
		instsByKey, apiErr := getAppInstsByKey(ctx, client)
		if apiErr != nil {
			errs = append(errs, *apiErr)
		}
		for _, appinst := range data.AppInsts {
			apiErr = ensureDeleteAppInstID(instsByKey, &appinst)
			if apiErr != nil {
				errs = append(errs, *apiErr)
				continue
			}
			params := &nbi.DeleteAppInstanceParams{}
			resp, err := client.DeleteAppInstanceWithResponse(ctx, appinst.ID, params)
			apiErr := checkForAPIErr("deleteappinst", resp, err, http.StatusAccepted)
			if apiErr != nil {
				errs = append(errs, *apiErr)
			}
		}
	}

	// Delete Apps
	if len(data.Apps) > 0 {
		// get Apps so we can map App name to app ID
		appsByKey, apiErr := getAppsByKey(ctx, client)
		if apiErr != nil {
			errs = append(errs, *apiErr)
		}
		for _, app := range data.Apps {
			apiErr = ensureDeleteAppID(appsByKey, &app)
			if apiErr != nil {
				errs = append(errs, *apiErr)
				continue
			}
			params := &nbi.DeleteAppParams{}
			resp, err := client.DeleteAppWithResponse(ctx, *app.AppId, params)
			apiErr := checkForAPIErr("deleteapp", resp, err, http.StatusAccepted)
			if apiErr != nil {
				errs = append(errs, *apiErr)
			}
		}
	}
	return errs
}

func ensureDeleteAppInstID(instsByKey AppInstsByKey, appInst *DeleteAppInst) *APIErr {
	if appInst.ID == "" {
		id, err := instsByKey.getIDFromName(appInst.Name, appInst.AppProvider)
		if err != nil {
			return wrapAPIErr("ensureDeleteAppInstID", 0, err)
		}
		appInst.ID = id
	}
	return nil
}

func ensureDeleteAppID(appsByKey AppsByKey, app *nbi.AppManifest) *APIErr {
	if app.AppId == nil || *app.AppId == "" {
		id, err := appsByKey.getIDFromName(app.Name, app.AppProvider, app.Version)
		if err != nil {
			return wrapAPIErr("ensureDeleteAppID", 0, err)
		}
		app.AppId = &id
	}
	return nil
}
