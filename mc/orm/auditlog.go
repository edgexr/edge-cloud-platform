package orm

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/log"
)

var AuditId uint64
var jwtRegex = regexp.MustCompile(`"(.*?)"`) // scrub jwt tokens from responses before logging, find all quoted strings.

func logger(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) (nexterr error) {
		req := c.Request()
		res := c.Response()

		// All Tags on this span will be exposed to the end-user in
		// the form of an "audit" log. Anything that should be kept
		// internal for debugging should be put on log.SpanLog() call.
		span := log.StartSpan(log.DebugLevelApi, req.RequestURI)
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
		}
		span.SetTag("request", string(reqBody))
		if nexterr != nil {
			span.SetTag("error", nexterr)
			he, ok := nexterr.(*echo.HTTPError)
			if ok && he.Internal != nil {
				log.SpanLog(ctx, log.DebugLevelInfo, "internal-err", he.Internal)
			}
		}
		if len(resBody) > 0 {
			// for all responses, if it has a jwt token
			// remove it before logging
			if strings.Contains(string(resBody), "token") {
				ms := jwtRegex.FindAllStringSubmatch(string(resBody), -1)
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
