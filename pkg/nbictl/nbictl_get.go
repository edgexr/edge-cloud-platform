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

func GetAll(ctx context.Context, client *nbi.ClientWithResponses) (*GetData, []APIErr) {
	data := &GetData{}
	apiErrors := []APIErr{}

	// get apps
	apps, apierr := GetApps(ctx, client)
	if apierr != nil {
		apiErrors = append(apiErrors, *apierr)
	} else {
		data.Apps = apps
	}

	// get app instances
	appinsts, apierr := GetAppInsts(ctx, client)
	if apierr != nil {
		apiErrors = append(apiErrors, *apierr)
	} else {
		data.AppInsts = appinsts
	}

	// get zones
	zones, apierr := GetZones(ctx, client)
	if apierr != nil {
		apiErrors = append(apiErrors, *apierr)
	} else {
		data.Zones = zones
	}

	return data, apiErrors
}

func GetApps(ctx context.Context, client *nbi.ClientWithResponses) ([]nbi.AppManifest, *APIErr) {
	resp, err := client.GetAppsWithResponse(ctx, &nbi.GetAppsParams{})
	status := resp.StatusCode()
	if err != nil || status != http.StatusOK {
		return nil, &APIErr{
			Desc:   "getapps",
			Status: status,
			Err:    err,
		}
	}
	return *resp.JSON200, nil
}

func GetAppInsts(ctx context.Context, client *nbi.ClientWithResponses) ([]nbi.AppInstanceInfo, *APIErr) {
	resp, err := client.GetAppInstanceWithResponse(ctx, &nbi.GetAppInstanceParams{})
	status := resp.StatusCode()
	if err != nil || status != http.StatusOK {
		return nil, &APIErr{
			Desc:   "getappinstances",
			Status: status,
			Err:    err,
		}
	}
	return *resp.JSON200.AppInstaceInfo, nil
}

func GetZones(ctx context.Context, client *nbi.ClientWithResponses) ([]nbi.EdgeCloudZone, *APIErr) {
	resp, err := client.GetEdgeCloudZonesWithResponse(ctx, &nbi.GetEdgeCloudZonesParams{})
	status := 0
	if resp != nil {
		status = resp.StatusCode()
	}
	if err != nil || status != http.StatusOK {
		return nil, &APIErr{
			Desc:   "getzones",
			Status: status,
			Err:    err,
		}
	}
	return *resp.JSON200, nil
}
