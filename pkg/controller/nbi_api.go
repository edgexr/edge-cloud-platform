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

package controller

import (
	"context"
	"net/http"
	"slices"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/nbi"
	"github.com/edgexr/edge-cloud-platform/pkg/nbiconvert"
	"github.com/labstack/echo/v4"
)

// NBIAPI implements nbi.ServerInterface
type NBIAPI struct {
	allApis *AllApis
}

func NewNBIAPI(allApis *AllApis) *NBIAPI {
	return &NBIAPI{
		allApis: allApis,
	}
}

func (s *NBIAPI) GetApps(ctx context.Context, request nbi.GetAppsRequestObject) (nbi.GetAppsResponseObject, error) {
	return nil, echo.NewHTTPError(http.StatusNotImplemented, "Not implemented yet")
}

func (s *NBIAPI) SubmitApp(ctx context.Context, request nbi.SubmitAppRequestObject) (nbi.SubmitAppResponseObject, error) {
	return nil, echo.NewHTTPError(http.StatusNotImplemented, "Not implemented yet")
}

func (s *NBIAPI) DeleteApp(ctx context.Context, request nbi.DeleteAppRequestObject) (nbi.DeleteAppResponseObject, error) {
	return nil, echo.NewHTTPError(http.StatusNotImplemented, "Not implemented yet")
}

func (s *NBIAPI) GetApp(ctx context.Context, request nbi.GetAppRequestObject) (nbi.GetAppResponseObject, error) {
	return nil, echo.NewHTTPError(http.StatusNotImplemented, "Not implemented yet")
}

func (s *NBIAPI) GetAppInstance(ctx context.Context, request nbi.GetAppInstanceRequestObject) (nbi.GetAppInstanceResponseObject, error) {
	return nil, echo.NewHTTPError(http.StatusNotImplemented, "Not implemented yet")
}

func (s *NBIAPI) CreateAppInstance(ctx context.Context, request nbi.CreateAppInstanceRequestObject) (nbi.CreateAppInstanceResponseObject, error) {
	return nil, echo.NewHTTPError(http.StatusNotImplemented, "Not implemented yet")
}

func (s *NBIAPI) DeleteAppInstance(ctx context.Context, request nbi.DeleteAppInstanceRequestObject) (nbi.DeleteAppInstanceResponseObject, error) {
	return nil, echo.NewHTTPError(http.StatusNotImplemented, "Not implemented yet")
}

func (s *NBIAPI) GetEdgeCloudZones(ctx context.Context, request nbi.GetEdgeCloudZonesRequestObject) (nbi.GetEdgeCloudZonesResponseObject, error) {
	filter := &edgeproto.Zone{}
	resp := nbi.GetEdgeCloudZones200JSONResponse{}
	err := s.allApis.zoneApi.cache.Show(filter, func(obj *edgeproto.Zone) error {
		resp.Body = append(resp.Body, *nbiconvert.NBIZone(obj, *region))
		return nil
	})
	if err != nil {
		return nil, echoShowErr("zone", err)
	}
	slices.SortStableFunc(resp.Body, nbiconvert.ZoneSort)
	return nbi.GetEdgeCloudZonesResponseObject(&resp), nil
}

func echoShowErr(objType string, err error) error {
	return &echo.HTTPError{
		Code:     http.StatusInternalServerError,
		Message:  "failed to get " + objType + " information",
		Internal: err,
	}
}
