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

func ApplyAll(ctx context.Context, client *nbi.ClientWithResponses, data *ApplyData) []APIErr {
	errs := []APIErr{}

	// apply Apps
	for _, app := range data.Apps {
		desc := "submit app " + app.Name
		params := nbi.SubmitAppParams{}
		resp, err := client.SubmitAppWithResponse(ctx, &params, app)
		apiErr := checkForAPIErr(desc, resp, err, http.StatusCreated)
		if apiErr != nil {
			errs = append(errs, *apiErr)
		}
	}
	if len(data.AppInsts) > 0 {
		// get Apps so we can map App names to app IDs for AppInst requests
		appsByKey, apiErr := getAppsByKey(ctx, client)
		if apiErr != nil {
			errs = append(errs, *apiErr)
		}
		zonesByKey, apiErr := getZonesByKey(ctx, client)
		if apiErr != nil {
			errs = append(errs, *apiErr)
		}
		clustersByKey, apiErr := getClustersByKey(ctx, client)
		if apiErr != nil {
			errs = append(errs, *apiErr)
		}
		// apply AppInsts
		for _, appinst := range data.AppInsts {
			apiErr = ensureCreateAppInstIDs(appsByKey, zonesByKey, clustersByKey, &appinst)
			if apiErr != nil {
				errs = append(errs, *apiErr)
				continue
			}
			desc := "create app instance " + appinst.Name
			params := &nbi.CreateAppInstanceParams{}
			req := nbi.CreateAppInstanceJSONRequestBody(appinst.CreateAppInstanceJSONBody)
			resp, err := client.CreateAppInstanceWithResponse(ctx, params, req)
			apiErr := checkForAPIErr(desc, resp, err, http.StatusAccepted)
			if apiErr != nil {
				errs = append(errs, *apiErr)
			}
		}
	}
	return errs
}

func ensureCreateAppInstIDs(appsByKey AppsByKey, zonesByKey ZonesByKey, clustersByKey ClustersByKey, appInst *CreateAppInst) *APIErr {
	desc := "ensureCreateAppInstIDs"
	if appInst.AppId == "" {
		id, err := appsByKey.getIDFromName(appInst.AppName, appInst.AppProvider, appInst.AppVersion)
		if err != nil {
			return wrapAPIErr(desc, 0, err)
		}
		appInst.AppId = id
	}
	if appInst.EdgeCloudZoneId == "" {
		id, err := zonesByKey.getIDFromName(appInst.EdgeCloudZoneName, appInst.EdgeCloudProvider)
		if err != nil {
			return wrapAPIErr(desc, 0, err)
		}
		appInst.EdgeCloudZoneId = id
	}
	if appInst.ClusterName != "" && appInst.ClusterProvider != "" {
		id, err := clustersByKey.getIDFromName(appInst.ClusterName, appInst.ClusterProvider)
		if err != nil {
			return wrapAPIErr(desc, 0, err)
		}
		appInst.KubernetesClusterRef = &id
	}
	return nil
}
