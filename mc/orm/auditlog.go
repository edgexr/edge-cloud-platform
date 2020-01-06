package orm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	jaeger_json "github.com/jaegertracing/jaeger/model/json"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/tls"
)

var AuditId uint64

func logger(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) (nexterr error) {
		req := c.Request()
		res := c.Response()

		lvl := log.DebugLevelApi

		if strings.Contains(req.RequestURI, "show") ||
			strings.Contains(req.RequestURI, "Show") ||
			strings.Contains(req.RequestURI, "/auth/user/current") ||
			strings.Contains(req.RequestURI, "/metrics/") ||
			strings.Contains(req.RequestURI, "/ctrl/Stream") ||
			strings.Contains(req.RequestURI, "/auth/audit/") {
			// don't log (fills up Audit logs)
			lvl = log.SuppressLvl
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
		// use body dump to capture req/res.
		bd := middleware.BodyDump(func(c echo.Context, reqB, resB []byte) {
			reqBody = reqB
			resBody = resB
		})
		span.SetTag("method", req.Method)

		handler := bd(next)
		nexterr = handler(ec)

		span.SetTag("status", res.Status)

		if lvl == log.SuppressLvl && (nexterr != nil || res.Status != http.StatusOK) {
			// log if there was a failure for shows.
			// note logs will not show up in stdout
			// except for final "finish" log,
			// but full logs will show up in jaeger.
			log.Unsuppress(span)
		}

		// remove passwords from requests so they aren't logged
		if strings.Contains(req.RequestURI, "login") {
			login := ormapi.UserLogin{}
			err := json.Unmarshal(reqBody, &login)
			if err == nil {
				login.Password = ""
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
		if nexterr != nil {
			span.SetTag("error", nexterr)
			he, ok := nexterr.(*echo.HTTPError)
			if ok && he.Internal != nil {
				log.SpanLog(ctx, log.DebugLevelInfo, "internal-err", "err", he.Internal)
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
						span.SetTag("response", result)
					}
				}

			} else {
				span.SetTag("response", string(resBody))
			}
		}
		return nexterr
	}
}

func ShowAuditSelf(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}

	query := ormapi.AuditQuery{}
	if err := c.Bind(&query); err != nil {
		return c.JSON(http.StatusBadRequest, Msg("Invalid POST data"))
	}

	tags := make(map[string]string)
	tags["level"] = "audit"
	tags["email"] = claims.Email
	if query.Org != "" {
		tags["org"] = query.Org
	}

	resps, err := sendJaegerQuery(serverConfig.JaegerAddr, tags, query.Limit, nil)
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
		return c.JSON(http.StatusBadRequest, Msg("Invalid POST data"))
	}

	if !authorized(ctx, claims.Username, query.Org, ResourceUsers, ActionView) {
		if query.Org == "" {
			return fmt.Errorf("Organization not specified or no permissions")
		}
		return echo.ErrForbidden
	}
	admin, orgnames, err := getUserOrgnames(claims.Username)
	if err != nil {
		// leave orgnames blank so it will be filtered, continue anyway
		log.SpanLog(ctx, log.DebugLevelApi, "get user orgnames failed", "err", err)
	}
	filter := &AllDataFilter{
		admin:    admin,
		orgnames: orgnames,
	}

	tags := make(map[string]string)
	tags["level"] = "audit"
	if query.Org != "" {
		tags["org"] = query.Org
	}
	if query.Username != "" {
		tags["username"] = query.Username
	}

	resps, err := sendJaegerQuery(serverConfig.JaegerAddr, tags, query.Limit, filter)
	if err != nil {
		return c.JSON(http.StatusBadRequest, MsgErr(err))
	}
	return c.JSON(http.StatusOK, resps)
}

type AllDataFilter struct {
	admin    bool
	orgnames map[string]struct{}
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

func sendJaegerQuery(addr string, tags map[string]string, limit int, filter *AllDataFilter) ([]*ormapi.AuditResponse, error) {
	req, err := jaegerQueryRequest(addr, tags, limit)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := tls.GetTLSClientConfig(addr, serverConfig.TlsCertFile, "", false)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Could not reach log server, %v", err)
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

func jaegerQueryRequest(addr string, tags map[string]string, limit int) (*http.Request, error) {
	if !strings.HasPrefix(addr, "http://") {
		if serverConfig.TlsCertFile == "" {
			addr = "http://" + addr
		} else {
			addr = "https://" + addr
		}
	}
	addr = addr + "/api/traces"
	req, err := http.NewRequest("GET", addr, nil)
	if err != nil {
		return nil, err
	}
	q := req.URL.Query()
	q.Add("service", log.SpanServiceName)
	for k, v := range tags {
		q.Add("tag", fmt.Sprintf("%s:%s", k, v))
	}
	if limit == 0 {
		// reasonable default
		limit = 100
	}
	q.Add("limit", fmt.Sprintf("%d", limit))

	req.URL.RawQuery = q.Encode()
	return req, nil
}

func getAuditResponses(resp *jaegerQueryResponse, filter *AllDataFilter) []*ormapi.AuditResponse {
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
		if isAudit {
			if filter != nil && !filter.admin && strings.Contains(resp.OperationName, "/auth/data/") {
				// The "data" apis allow multiple organizations
				// to be modified via one API call.
				// If so, multiple org tags will exist on the
				// span, and any one of those could match.
				// Make sure the caller actually has permission
				// to see all the affected orgs. If not,
				// for security, blank out the request data.
				allowed := true
				for _, orgname := range orgs {
					if _, ok := filter.orgnames[orgname]; !ok {
						allowed = false
						break
					}
				}
				if !allowed {
					resp.Request = "insufficient permissions"
				}
			}
			resp.TraceID = string(trace.TraceID)
			resps = append(resps, resp)
		}
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
		}
	}
	resp.OperationName = span.OperationName
	resp.StartTime = ormapi.TimeMicroseconds(span.StartTime)
	resp.Duration = ormapi.DurationMicroseconds(span.Duration)
	return isAudit, orgs
}
