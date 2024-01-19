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
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	edgeproto "github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/echoutil"
	"github.com/edgexr/edge-cloud-platform/pkg/fedewapi"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/federation"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormutil"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	"github.com/labstack/echo/v4"
	"google.golang.org/grpc/status"
)

var AuditId uint64

var redactor *util.JSONRedactor
var ReqUrlEncodedClearer = util.NewFormUrlEncodedClearer("client_id", "client_secret")

func init() {
	// Note that keys are treated case-insensitively, so case
	// does not matter here.
	redactor = util.NewJSONRedactor("***")
	redactor.AddKey("token")
	redactor.AddKey("access_token")
	redactor.AddKey("clientSecret")
	redactor.AddKey("password")
	redactor.AddKey("passhash")
	redactor.AddKey("totp")
	redactor.AddKey("apikey")
	// from edgeproto.Cloudlet
	redactor.AddKey("access_vars")
	redactor.AddKey("license_config")
	redactor.AddKey("driver_path_creds")
	// federation related
	redactor.AddKey("ClientKey")
	redactor.AddKey("PartnerNotifyClientKey")
	redactor.AddKey("ProviderClientKey")
}

type AuditNameLookupKey struct {
	method string
	path   string
}

type AuditLogger struct {
	lookup       map[AuditNameLookupKey]string
	errorHandler echo.MiddlewareFunc
}

func NewAuditLogger(errorHandler echo.MiddlewareFunc) *AuditLogger {
	return &AuditLogger{
		lookup:       make(map[AuditNameLookupKey]string),
		errorHandler: errorHandler,
	}
}

// These are show commands that the UI calls without the user's
// knowledge, and are likely not what is needed to see for debugging.
var excludeLogShowApis = map[string]struct{}{
	"/" + ApiRoot + "/":                          {},
	"/" + ApiRoot + "/auth/ctrl/ShowAlert":       {},
	"/" + ApiRoot + "/auth/events/terms":         {},
	"/" + ApiRoot + "/auth/events/show":          {},
	"/" + ApiRoot + "/auth/config/show":          {},
	"/" + ApiRoot + "/auth/user/current":         {},
	"/" + ApiRoot + "/auth/org/show":             {},
	"/" + ApiRoot + "/auth/role/showuser":        {},
	"/" + ApiRoot + "/publicconfig":              {},
	"/" + ApiRoot + "/auth/role/assignment/show": {},
	"/" + ApiRoot + "/auth/controller/show":      {},
	"/" + ApiRoot + "/login":                     {},
}

func includeLogShowAPI(uri string) bool {
	if _, found := excludeLogShowApis[uri]; found {
		return false
	}
	return true
}

func (s *AuditLogger) echoHandler(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		eventStart := time.Now()
		logaudit := true
		req := c.Request()
		res := c.Response()

		lvl := log.DebugLevelApi

		path := strings.Split(req.RequestURI, "/")
		method := path[len(path)-1]
		contentType := req.Header.Get("Content-Type")
		isShow := false
		debugEvents := log.GetDebugLevel()&log.DebugLevelEvents != 0
		if strings.Contains(req.RequestURI, "/auth/events/") && debugEvents {
			// log events
		} else if strings.Contains(req.RequestURI, "show") ||
			edgeproto.IsShow(method) ||
			(strings.Contains(req.RequestURI, "operatorplatform") && req.Method == http.MethodGet) ||
			strings.Contains(req.RequestURI, "/auth/user/current") ||
			strings.Contains(req.RequestURI, "/auth/metrics/") ||
			strings.Contains(req.RequestURI, "/oauth2/token") ||
			strings.Contains(req.RequestURI, "/ctrl/Stream") ||
			strings.Contains(req.RequestURI, "/auth/audit/") ||
			strings.Contains(req.RequestURI, "/auth/events/") ||
			strings.Contains(req.RequestURI, "/auth/report/generate") ||
			strings.Contains(req.RequestURI, "/auth/report/download") ||
			strings.Contains(req.RequestURI, "/api/v1/httpauth") {
			config := getCachedConfig()
			if config.LogAllShowApis || (len(config.LogShowUrl) > 0 && strings.Contains(req.RequestURI, config.LogShowUrl)) {
				// for debugging, log show api
			} else if config.LogShowApis && includeLogShowAPI(req.RequestURI) {
				// for debugging, log show api
			} else {
				// don't log (fills up Audit logs)
				lvl = log.SuppressLvl
				logaudit = false
				isShow = true
			}
		}

		// All Tags on this span will be exposed to the end-user in
		// the form of an "audit" log. Anything that should be kept
		// internal for debugging should be put on log.SpanLog() call.
		span := log.StartSpan(lvl, req.RequestURI)
		span.SetTag("remote-ip", c.RealIP())
		span.SetTag("level", "audit")
		defer span.Finish()
		ctx := log.ContextWithSpan(req.Context(), span)
		// postgres saves time in microseconds, while ElasticSearch
		// saves them in nanoseconds. In order to compare them for
		// event filtering by org createdat time, truncate timestamp
		// to microseconds.
		eventStart = eventStart.Truncate(time.Microsecond)
		ec := echoutil.NewEchoContext(c, ctx, eventStart)

		// The error handler injects the error into the response.
		// This audit log needs the error to log it, but does not
		// pass the error up, since it's already been written to
		// the response, so echo doesn't need to see it.
		// Error handler must come before body dump, so that body
		// dump captures the changes to the response.
		next = s.errorHandler(next)

		reqBody := []byte{}
		resBody := []byte{}
		reqHeaders := util.GetHeadersString(req.Header)
		if strings.HasPrefix(req.RequestURI, "/ws/") {
			// can't use bodydump on websocket-upgraded connection,
			// as it tries to write the response back in the body
			// to preserve it, which triggers a write to a hijacked
			// connection error because websocket hijacks the http
			// connection.
			// req/reply is captured later below
		} else {
			// use body dump to capture req/res.
			bd := BodyDump(func(c echo.Context, reqB, resB []byte) {
				reqBody = reqB
				resBody = resB
			})
			next = bd(next)
		}
		span.SetTag("method", req.Method)

		nexterr := next(ec)

		span.SetTag("status", res.Status)

		if lvl == log.SuppressLvl && (nexterr != nil || res.Status != http.StatusOK) && (!isShow || res.Status != http.StatusForbidden) {
			// log if there was a failure for shows.
			// note logs will not show up in stdout
			// except for final "finish" log,
			// but full logs will show up in jaeger.
			log.Unsuppress(span)
			logaudit = true
		}

		response := ""
		resHeaders := util.GetHeadersString(res.Header())
		if ws := echoutil.GetWs(ec); ws != nil {
			wsRequest, wsResponse := echoutil.GetWsLogData(ec)
			if len(wsRequest) > 0 {
				reqBody = wsRequest
			}
			if len(wsResponse) > 0 {
				response = strings.Join(wsResponse, "\n")
			}
		}

		// remove passwords from requests so they aren't logged
		if strings.Contains(contentType, "application/json") {
			newReqBody, err := redactor.Redact(reqBody)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelApi, "failed to redact json request", "jsonData", reqBody, "err", err)
			} else {
				reqBody = newReqBody
			}
		} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
			reqBody = ReqUrlEncodedClearer.Clear(reqBody)
		}

		span.SetTag("request", string(reqBody))
		eventErr := nexterr
		if nexterr != nil {
			span.SetTag("error", nexterr)
			he, ok := nexterr.(*ormutil.HTTPError)
			if ok && he.Internal != nil {
				log.SpanLog(ctx, log.DebugLevelInfo, "internal-err", "err", he.Internal)
				eventErr = he.Internal
			}
		}
		if strings.Contains(req.RequestURI, "/auth/ctrl/RunDebug") {
			// omit response as it can be quite large when dumping data,
			// and may also contain sensitive data.
			response = ""
		} else if len(resBody) > 0 {
			if strings.Contains(req.RequestURI, "/metrics/") || strings.Contains(req.RequestURI, "/events/") || strings.Contains(req.RequestURI, "/spans") {
				// assume no secrets to filter, avoid parsing large data
			} else {
				newResBody, err := redactor.Redact(resBody)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelApi, "failed to redact json response", "jsonData", resBody, "err", err)
				} else {
					resBody = newResBody
				}
			}
			response = string(resBody)
		}
		span.SetTag("response", response)
		if logaudit {
			// Create audit event from Span data.
			eventTags := make(map[string]string)
			code := res.Status
			if nexterr != nil && code == http.StatusOK {
				// override 200(OK) status if streaming error
				eventTags["respstatus"] = fmt.Sprintf("%d", code)
				code, _ = getErrorResult(nexterr)
			}
			eventTags["status"] = fmt.Sprintf("%d", code)
			eventOrg := ""
			eventTags["localuri"] = req.RequestURI
			eventTags["reqheaders"] = reqHeaders
			eventTags["respheaders"] = resHeaders
			for k, v := range log.GetTags(span) {
				if k == "level" || k == "error" || log.IgnoreSpanTag(k) {
					continue
				}
				// handle only string values
				// (they should mostly all be string values)
				str, ok := v.(string)
				if !ok {
					continue
				}
				if k == "org" {
					eventOrg = str
				}
				eventTags[k] = str
			}
			auditName := s.getAuditName(c)
			nodeMgr.TimedEvent(ctx, auditName, eventOrg, node.AuditType, eventTags, eventErr, eventStart, time.Now())
		}
		// do not pass error up, as it's already been handled by the handler
		return nil
	}
}

// Convert the error to a result to put in response.
func getErrorResult(err error) (int, *ormapi.Result) {
	// convert a GRPC error message to something more human readable
	if st, ok := status.FromError(err); ok {
		err = fmt.Errorf("%s", st.Message())
	}
	// convert err to result which can be inserted into http response
	code := http.StatusBadRequest
	msg := ""
	if e, ok := err.(*ormutil.HTTPError); ok {
		code = e.Code
		msg = e.Message
	} else if e, ok := err.(*echo.HTTPError); ok {
		code = e.Code
		msg = fmt.Sprintf("%v", e.Message)
	} else if e, ok := err.(*federation.FedError); ok {
		code = e.Code
		msg = e.Message
	} else {
		msg = err.Error()
	}
	if len(msg) > 0 {
		msg = util.CapitalizeMessage(msg)
	}
	return code, &ormapi.Result{
		Message: msg,
	}
}

func resultErrorHandler(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// All error handling is done here. We do not rely on
		// echo's default error handler, which basically just calls
		// c.JSON(). We still pass the error up, but that's just
		// so it can go into the audit log.
		err := next(c)
		if err == nil {
			return nil
		}
		code, res := getErrorResult(err)

		// write error to response/stream
		var writeErr error
		if ws := echoutil.GetWs(c); ws != nil {
			// websocket errors must be handled in
			// websocketUpgrade before the ws is closed.
		} else if c.Get(StreamAPITag) != nil && c.Response().Committed {
			// JSON streaming response that has already written
			// the header, so inject the error into the stream.
			res.Code = code
			payload := ormapi.StreamPayload{
				Result: res,
			}
			writeErr = json.NewEncoder(c.Response()).Encode(payload)
		} else {
			// write to response header
			writeErr = c.JSON(code, res)
		}
		if writeErr != nil {
			ctx := echoutil.GetContext(c)
			log.SpanLog(ctx, log.DebugLevelApi, "Failed to write error to response", "err", err, "writeError", writeErr)
		}
		return err
	}
}

func fedErrorHandler(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		err := next(c)
		if err == nil {
			return nil
		}
		code, res := getErrorResult(err)
		resp := fedewapi.ProblemDetails{
			Detail: &res.Message,
		}
		writeErr := c.JSON(code, &resp)
		if writeErr != nil {
			ctx := echoutil.GetContext(c)
			log.SpanLog(ctx, log.DebugLevelApi, "Failed to write error to response", "err", err, "writeError", writeErr)
		}
		return err
	}
}

type AuditNameLookup struct {
	lookup map[AuditNameLookupKey]string
}

func (s *AuditLogger) initAuditNames(e *echo.Echo) {
	// Map should only be written to during init
	// for thread safety.
	for _, r := range e.Routes() {
		path := r.Path
		if path[0] != '/' {
			path = "/" + path
		}
		key := AuditNameLookupKey{
			method: r.Method,
			path:   path,
		}
		// get last part of fully qualified path to function name
		names := strings.Split(r.Name, ".")
		name := names[len(names)-1]
		// Federation functions have -fm suffix
		s.lookup[key] = strings.TrimSuffix(name, "-fm")
	}
}

func (s *AuditLogger) getAuditName(c echo.Context) string {
	key := AuditNameLookupKey{
		method: c.Request().Method,
		path:   c.Path(),
	}
	name, found := s.lookup[key]
	if found {
		return name
	}
	return c.Path()
}
