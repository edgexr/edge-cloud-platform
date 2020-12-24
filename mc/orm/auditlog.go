package orm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	jaeger_json "github.com/jaegertracing/jaeger/model/json"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/cloudcommon/node"
	edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

var AuditId uint64

func logger(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) (nexterr error) {
		eventStart := time.Now()
		logaudit := true
		req := c.Request()
		res := c.Response()

		lvl := log.DebugLevelApi

		path := strings.Split(req.RequestURI, "/")
		method := path[len(path)-1]
		debugEvents := log.GetDebugLevel()&log.DebugLevelEvents != 0
		if strings.Contains(req.RequestURI, "/auth/events/") && debugEvents {
			// log events
		} else if strings.Contains(req.RequestURI, "show") ||
			edgeproto.IsShow(method) ||
			strings.Contains(req.RequestURI, "/auth/user/current") ||
			strings.Contains(req.RequestURI, "/auth/metrics/") ||
			strings.Contains(req.RequestURI, "/ctrl/Stream") ||
			strings.Contains(req.RequestURI, "/auth/audit/") ||
			strings.Contains(req.RequestURI, "/auth/events/") {
			// don't log (fills up Audit logs)
			lvl = log.SuppressLvl
			logaudit = false
		}

		// All Tags on this span will be exposed to the end-user in
		// the form of an "audit" log. Anything that should be kept
		// internal for debugging should be put on log.SpanLog() call.
		span := log.StartSpan(lvl, req.RequestURI)
		span.SetTag("remote-ip", c.RealIP())
		span.SetTag("level", "audit")
		defer span.Finish()
		ctx := log.ContextWithSpan(context.Background(), span)
		ec := NewEchoContext(c, ctx)

		reqBody := []byte{}
		resBody := []byte{}
		if strings.HasPrefix(req.RequestURI, "/ws/") {
			// can't use bodydump on websocket-upgraded connection,
			// as it tries to write the response back in the body
			// to preserve it, which triggers a write to a hijacked
			// connection error because websocket hijacks the http
			// connection.
			// req/reply is captured later below
		} else {
			// use body dump to capture req/res.
			bd := middleware.BodyDump(func(c echo.Context, reqB, resB []byte) {
				reqBody = reqB
				resBody = resB
			})
			next = bd(next)
		}
		span.SetTag("method", req.Method)

		nexterr = next(ec)

		span.SetTag("status", res.Status)

		if lvl == log.SuppressLvl && (nexterr != nil || res.Status != http.StatusOK) {
			// log if there was a failure for shows.
			// note logs will not show up in stdout
			// except for final "finish" log,
			// but full logs will show up in jaeger.
			log.Unsuppress(span)
			logaudit = true
		}

		response := ""
		if ws := GetWs(ec); ws != nil {
			wsRequest, wsResponse := GetWsLogData(ec)
			if len(wsRequest) > 0 {
				reqBody = wsRequest
			}
			if len(wsResponse) > 0 {
				response = strings.Join(wsResponse, "\n")
			}
		}

		// remove passwords from requests so they aren't logged
		if strings.Contains(req.RequestURI, "login") {
			login := ormapi.UserLogin{}
			err := json.Unmarshal(reqBody, &login)
			if err == nil {
				login.Password = ""
				login.TOTP = ""
				login.ApiKey = ""
				reqBody, err = json.Marshal(login)
			}
			if err != nil {
				reqBody = []byte{}
			}
		} else if strings.Contains(req.RequestURI, "usercreate") {
			user := ormapi.CreateUser{}
			err := json.Unmarshal(reqBody, &user)
			if err == nil {
				user.Passhash = ""
				reqBody, err = json.Marshal(user)
			}
			if err != nil {
				reqBody = []byte{}
			}
		} else if strings.Contains(req.RequestURI, "passwordreset") {
			reset := ormapi.PasswordReset{}
			err := json.Unmarshal(reqBody, &reset)
			if err == nil {
				reset.Password = ""
				reqBody, err = json.Marshal(reset)
			}
			if err != nil {
				reqBody = []byte{}
			}
		} else if strings.Contains(req.RequestURI, "user/newpass") {
			newpass := ormapi.NewPassword{}
			err := json.Unmarshal(reqBody, &newpass)
			if err == nil {
				newpass.Password = ""
				reqBody, err = json.Marshal(newpass)
			}
			if err != nil {
				reqBody = []byte{}
			}
		} else if strings.Contains(req.RequestURI, "/auth/ctrl/CreateCloudlet") ||
			strings.Contains(req.RequestURI, "/auth/ctrl/UpdateCloudlet") {
			regionCloudlet := ormapi.RegionCloudlet{}
			err := json.Unmarshal(reqBody, &regionCloudlet)
			if err == nil {
				regionCloudlet.Cloudlet.AccessVars = nil
				reqBody, err = json.Marshal(regionCloudlet)
			}
			if err != nil {
				reqBody = []byte{}
			}
		}
		span.SetTag("request", string(reqBody))
		eventErr := nexterr
		if nexterr != nil {
			span.SetTag("error", nexterr)
			he, ok := nexterr.(*echo.HTTPError)
			if ok && he.Internal != nil {
				log.SpanLog(ctx, log.DebugLevelInfo, "internal-err", "err", he.Internal)
				eventErr = he.Internal
			}
		}
		if len(resBody) > 0 {
			// for all responses, if it has a jwt token
			// remove it before logging
			if strings.Contains(string(resBody), "token") {
				ms := cloudcommon.QuotedStringRegex.FindAllStringSubmatch(string(resBody), -1)
				if ms != nil {
					ss := make([]string, len(ms))
					for i, m := range ms {
						ss[i] = m[1]
					}
					if ss[1] != "" {
						result := strings.Replace(string(resBody), ss[1], "", len(ss[1]))
						response = result
					}
				}
			} else if strings.Contains(string(resBody), "TOTP") {
				resp := ormapi.UserResponse{}
				err := json.Unmarshal(resBody, &resp)
				if err == nil {
					resp.TOTPSharedKey = ""
					resp.TOTPQRImage = nil
					updatedResp, err := json.Marshal(&resp)
					if err == nil {
						response = string(updatedResp)
					} else {
						response = string(resBody)
					}
				} else {
					response = string(resBody)
				}
			} else if strings.Contains(string(resBody), "ApiKey") {
				resp := ormapi.CreateUserApiKey{}
				err := json.Unmarshal(resBody, &resp)
				if err == nil {
					resp.ApiKey = ""
					updatedResp, err := json.Marshal(&resp)
					if err == nil {
						response = string(updatedResp)
					} else {
						response = string(resBody)
					}
				} else {
					response = string(resBody)
				}

			} else {
				response = string(resBody)
			}
		}
		span.SetTag("response", response)
		if logaudit {
			// Create audit event from Span data.
			eventTags := make(map[string]string)
			eventTags["status"] = fmt.Sprintf("%d", res.Status)
			eventOrg := ""
			if eventErr == nil && res.Status != http.StatusOK {
				// setReply and echo put the error into
				// the response body and set the status when
				// using c.JSON(), whose err return value
				// is only for writing to the response.
				contextErr := c.Get(echoContextError)
				if contextErr != nil {
					if cerr, ok := contextErr.(error); ok {
						eventErr = cerr
					}
				}
				if eventErr == nil {
					eventErr = fmt.Errorf("%s", response)
				}
			}
			for k, v := range log.GetTags(span) {
				if k == "level" || k == "error" || k == "sampler.type" {
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
			nodeMgr.TimedEvent(ctx, req.RequestURI, eventOrg, node.AuditType, eventTags, eventErr, eventStart, time.Now())
		}
		return nexterr
	}
}

func ShowAuditSelf(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := GetContext(c)

	query := ormapi.AuditQuery{}
	if err := c.Bind(&query); err != nil {
		return bindErr(c, err)
	}

	params := make(map[string]string)
	if err := addAuditParams(&query, params); err != nil {
		return c.JSON(http.StatusBadRequest, MsgErr(err))
	}

	tags := make(map[string]string)
	tags["level"] = "audit"
	tags["email"] = claims.Email
	if err := addAuditTags(&query, tags); err != nil {
		return c.JSON(http.StatusBadRequest, MsgErr(err))
	}

	resps, err := sendJaegerAuditQuery(ctx, serverConfig.JaegerAddr, params, tags, nil)
	if err != nil {
		return c.JSON(http.StatusBadRequest, MsgErr(err))
	}
	return c.JSON(http.StatusOK, resps)
}

func ShowAuditOrg(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := GetContext(c)

	query := ormapi.AuditQuery{}
	if err := c.Bind(&query); err != nil {
		return bindErr(c, err)
	}

	filter := &AuditOrgsFilter{}
	// get all orgs user can view
	filter.allowedOrgs, err = enforcer.GetAuthorizedOrgs(ctx, claims.Username, ResourceUsers, ActionView)
	if err != nil {
		return err
	}
	if _, found := filter.allowedOrgs[""]; found {
		// admin
		filter.admin = true
		delete(filter.allowedOrgs, "")
	}
	if query.Org != "" && !filter.admin {
		// make sure user has access to org
		if _, found := filter.allowedOrgs[query.Org]; !found {
			return echo.ErrForbidden
		}
	}
	if !filter.admin && len(filter.allowedOrgs) == 0 {
		// no access to any org, don't bother querying Jaeger
		return echo.ErrForbidden
	}

	params := make(map[string]string)
	if err := addAuditParams(&query, params); err != nil {
		return c.JSON(http.StatusBadRequest, MsgErr(err))
	}

	tags := make(map[string]string)
	tags["level"] = "audit"
	if err := addAuditTags(&query, tags); err != nil {
		return c.JSON(http.StatusBadRequest, MsgErr(err))
	}

	resps, err := sendJaegerAuditQuery(ctx, serverConfig.JaegerAddr, params, tags, filter)
	if err != nil {
		return c.JSON(http.StatusBadRequest, MsgErr(err))
	}
	return c.JSON(http.StatusOK, resps)
}

func addAuditParams(query *ormapi.AuditQuery, params map[string]string) error {
	// set limit
	if query.Limit == 0 {
		// reasonable default
		query.Limit = 100
	}
	params["limit"] = strconv.Itoa(query.Limit)

	// set service
	params["service"] = log.SpanServiceName

	// set operation
	if query.Operation != "" {
		params["operation"] = query.Operation
	}

	// resolve time args
	err := query.TimeRange.Resolve(node.DefaultTimeDuration)
	if err != nil {
		return err
	}
	var startusec, endusec ormapi.TimeMicroseconds
	startusec.FromTime(query.StartTime)
	endusec.FromTime(query.EndTime)
	params["start"] = strconv.FormatUint(uint64(startusec), 10)
	params["end"] = strconv.FormatUint(uint64(endusec), 10)
	params["lookback"] = "custom"
	return nil
}

func addAuditTags(query *ormapi.AuditQuery, tags map[string]string) error {
	if query.Org != "" {
		tags["org"] = query.Org
	}
	if query.Username != "" {
		tags["username"] = query.Username
	}
	for k, v := range query.Tags {
		tags[k] = v
	}
	return nil
}

type AuditOrgsFilter struct {
	admin       bool
	allowedOrgs map[string]struct{}
}

// see https://github.com/jaegertracing/jaeger/blob/master/cmd/query/app/http_handler.go
type jaegerQueryResponse struct {
	Data   []*jaeger_json.Trace
	Errors []*jaegerQueryError
}

type jaegerQueryError struct {
	Code    int
	Msg     string
	TraceID jaeger_json.TraceID
}

func sendJaegerAuditQuery(ctx context.Context, addr string, params, tags map[string]string, filter *AuditOrgsFilter) ([]*ormapi.AuditResponse, error) {
	resp, err := sendJaegerQuery(ctx, addr, "/api/traces", params, tags)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Bad status from log server, %s", http.StatusText(resp.StatusCode))
	}

	respData := jaegerQueryResponse{}
	err = json.NewDecoder(resp.Body).Decode(&respData)
	if err != nil {
		return nil, fmt.Errorf("Cannot parse log server response, %v", err)
	}
	return getAuditResponses(&respData, filter), nil
}

func sendJaegerQuery(ctx context.Context, addr, path string, params, tags map[string]string) (*http.Response, error) {
	tlsConfig, err := nodeMgr.GetPublicClientTlsConfig(ctx)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(addr, "http") {
		if tlsConfig == nil {
			addr = "http://" + addr
		} else {
			addr = "https://" + addr
		}
	}
	req, err := http.NewRequest("GET", addr+path, nil)
	if err != nil {
		return nil, err
	}
	q := req.URL.Query()
	for k, v := range params {
		q.Add(k, v)
	}
	for k, v := range tags {
		q.Add("tag", fmt.Sprintf("%s:%s", k, v))
	}

	req.URL.RawQuery = q.Encode()

	tr := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Could not reach log server, %v", err)
	}
	return resp, nil
}

func getAuditResponses(resp *jaegerQueryResponse, filter *AuditOrgsFilter) []*ormapi.AuditResponse {
	resps := make([]*ormapi.AuditResponse, 0)
	for _, trace := range resp.Data {
		resp := &ormapi.AuditResponse{}
		isAudit := false
		var orgs []string
		for _, span := range trace.Spans {
			if span.References == nil || len(span.References) == 0 {
				// starting span
				// could also tell by spanID == traceID
				isAudit, orgs = fillAuditResponse(resp, &span)
				break
			}
		}
		if !isAudit {
			continue
		}
		if filter != nil && !filter.admin {
			// The "data" apis allow multiple organizations
			// to be modified via one API call.
			// If so, multiple org tags will exist on the
			// span, and any one of those could match.
			// Make sure the caller actually has permission
			// to see all the affected orgs. If not,
			// for security, blank out the request data.
			matchedOrgs := 0
			for _, orgname := range orgs {
				if _, ok := filter.allowedOrgs[orgname]; ok {
					matchedOrgs++
				}
			}
			if matchedOrgs == 0 {
				// no perms at all
				continue
			}
			if matchedOrgs < len(orgs) {
				// only partial perms, clear request for security
				resp.Request = "insufficient permissions"
			}
		}
		resp.TraceID = string(trace.TraceID)
		resps = append(resps, resp)
	}
	sort.Slice(resps, func(i, j int) bool {
		return resps[i].StartTime > resps[j].StartTime
	})
	return resps
}

func fillAuditResponse(resp *ormapi.AuditResponse, span *jaeger_json.Span) (bool, []string) {
	isAudit := false
	orgs := []string{}
	for _, kv := range span.Tags {
		val, ok := kv.Value.(string)
		if !ok {
			if ival, ok := kv.Value.(float64); ok && kv.Key == "status" {
				resp.Status = int(ival)
			}
			continue
		}
		switch kv.Key {
		case "level":
			if val != "audit" {
				return false, orgs
			}
			isAudit = true
		case "request":
			resp.Request = val
		case "response":
			resp.Response = val
		case "username":
			resp.Username = val
		case "remote-ip":
			resp.ClientIP = val
		case "error":
			resp.Error = val
		case "org":
			orgs = append(orgs, val)
		default:
			if _, found := edgeproto.AllKeyTagsMap[kv.Key]; found {
				if resp.Tags == nil {
					resp.Tags = make(map[string]string)
				}
				resp.Tags[kv.Key] = val
			}
		}
	}
	resp.OperationName = span.OperationName
	resp.Org = strings.Join(orgs, ", ")
	resp.StartTime = ormapi.TimeMicroseconds(span.StartTime)
	resp.Duration = ormapi.DurationMicroseconds(span.Duration)
	return isAudit, orgs
}

type jaegerOperationsResponse struct {
	Data   []string
	Total  int
	Limit  int
	Offset int
	Errors []*jaegerQueryError
}

func GetAuditOperations(c echo.Context) error {
	_, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := GetContext(c)

	path := "/api/services/" + log.SpanServiceName + "/operations"
	emptyMap := make(map[string]string)
	resp, err := sendJaegerQuery(ctx, serverConfig.JaegerAddr, path, emptyMap, emptyMap)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		str := fmt.Sprintf("Bad status from log server, %s", http.StatusText(resp.StatusCode))
		return c.JSON(http.StatusInternalServerError, Msg(str))
	}

	respData := jaegerOperationsResponse{}
	err = json.NewDecoder(resp.Body).Decode(&respData)
	if err != nil {
		str := fmt.Sprintf("Cannot parse log server response, %v", err)
		return c.JSON(http.StatusInternalServerError, Msg(str))
	}
	// ignore any operations that are not user api calls, like
	// "main" or "appstore sync".
	operations := []string{}
	for _, op := range respData.Data {
		if !strings.HasPrefix(op, "/api/v1") {
			continue
		}
		operations = append(operations, op)
	}
	sort.Strings(operations)
	return c.JSON(http.StatusOK, operations)
}
