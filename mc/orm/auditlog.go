package orm

import (
	"encoding/json"
	"strings"
	"sync/atomic"
	"time"
	"regexp"

	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/log"
)

var AuditId uint64
var jwtRegex = regexp.MustCompile(`"(.*?)"`) // scrub jwt tokens from responses before logging, find all quoted strings.

func logger(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		req := c.Request()
		res := c.Response()
		if strings.HasSuffix(req.RequestURI, "show") || strings.HasSuffix(req.RequestURI, "showall") {
			// don't log show commands
			return next(c)
		}
		id := atomic.AddUint64(&AuditId, 1)
		start := time.Now()

		reqBody := []byte{}
		resBody := []byte{}
		var nexterr error
		// use body dump to capture req/res.
		bd := middleware.BodyDump(func(c echo.Context, reqB, resB []byte) {
			reqBody = reqB
			resBody = resB
		})
		kvs := []interface{}{}
		kvs = append(kvs, "id")
		kvs = append(kvs, id)
		kvs = append(kvs, "method")
		kvs = append(kvs, req.Method)
		kvs = append(kvs, "uri")
		kvs = append(kvs, req.RequestURI)
		kvs = append(kvs, "remote-ip")
		kvs = append(kvs, c.RealIP())
		log.InfoLog("Audit start", kvs...)

		handler := bd(next)
		nexterr = handler(c)
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

		kvs = []interface{}{}
		kvs = append(kvs, "id")
		kvs = append(kvs, id)
		if claims, err := getClaims(c); err == nil {
			kvs = append(kvs, "user")
			kvs = append(kvs, claims.Username)
		}
		kvs = append(kvs, "status")
		kvs = append(kvs, res.Status)
		if nexterr != nil {
			kvs = append(kvs, "err")
			kvs = append(kvs, nexterr)
			he, ok := nexterr.(*echo.HTTPError)
			if ok && he.Internal != nil {
				kvs = append(kvs, "ierr", he.Internal)
			}
		}
		if len(reqBody) > 0 {
			kvs = append(kvs, "req")
			kvs = append(kvs, string(reqBody))
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
						kvs = append(kvs, "resp")
						kvs = append(kvs, result)
					}
				}

			} else {
				kvs = append(kvs, "resp")
				kvs = append(kvs, string(resBody))
			}
		}
		kvs = append(kvs, "took")
		kvs = append(kvs, time.Since(start))

		log.InfoLog("Audit end", kvs...)
		return nexterr
	}
}
