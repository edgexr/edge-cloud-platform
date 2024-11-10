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
	"encoding/json"
	"net/http"

	"github.com/edgexr/edge-cloud-platform/api/nbi"
	"github.com/edgexr/edge-cloud-platform/pkg/echoutil"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/labstack/echo/v4"
)

const XCorrelatorKey = "x-correlator"

func NBIErrorHandler(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// All error handling is done here. We do not rely on
		// echo's default error handler, which just calls c.JSON().
		// This traps errors and converts them to http responses.
		// This also injects the x-correlator id into the response.
		// All NBI error responses use the ErrorInfo object in the
		// body of the response.
		xcor := c.Request().Header.Get(XCorrelatorKey)
		err := next(c)
		if err == nil {
			if xcor != "" {
				c.Response().Header().Set(XCorrelatorKey, xcor)
			}
			return nil
		}
		errorInfo, ok := err.(*nbi.ErrorInfo)
		if !ok {
			errorInfo = &nbi.ErrorInfo{
				Status:  http.StatusBadRequest,
				Code:    http.StatusText(http.StatusBadRequest),
				Message: err.Error(),
			}
		}
		resp := c.Response()
		if xcor != "" {
			resp.Header().Set(XCorrelatorKey, xcor)
		}
		resp.Header().Set("Content-Type", "application/json")
		resp.WriteHeader(errorInfo.Status)
		writeErr := json.NewEncoder(resp).Encode(errorInfo)
		if writeErr != nil {
			ctx := echoutil.GetContext(c)
			log.SpanLog(ctx, log.DebugLevelApi, "NBI echo error handler failed to write error response", "err", err, "writeErr", writeErr)
		}
		return nil
	}
}
