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
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/federationmgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormutil"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/websocket"
	"github.com/labstack/echo/v4"
)

var PasswordMinLength = 8
var PasswordMaxLength = 4096

var BruteForceGuessesPerSecond = 1000000

var Jwks vault.JWKS
var NoUserClaims *ormutil.UserClaims = nil
var TokenHttpCookieName = "token"

type TokenAuth struct {
	Token string
}

func InitVault(config *vault.Config, serverDone chan struct{}, updateDone chan struct{}) {
	Jwks.Init(config, "", "mcorm")
	Jwks.GoUpdate(serverDone, updateDone)
}

func ValidPassword(pw string) error {
	if utf8.RuneCountInString(pw) < PasswordMinLength {
		return fmt.Errorf("password must be at least %d characters",
			PasswordMinLength)
	}
	if utf8.RuneCountInString(pw) >= PasswordMaxLength {
		return fmt.Errorf("password must be less than %d characters",
			PasswordMaxLength)
	}
	// Todo: dictionary check; related strings (email, etc) check.
	return nil
}

func NewHTTPAuthCookie(token string, expires int64, domain string) *http.Cookie {
	return &http.Cookie{
		Name:    TokenHttpCookieName,
		Value:   token,
		Expires: time.Unix(expires, 0),
		// only send this cookie over HTTPS
		Secure: true,
		// set an explicit path, otherwise browser may fill in /api/v1, which prevents this cookie from being used to httpauth other subdomains like jaeger-ui.<this-domain>
		Path: "/",
		// true means no scripts will be able to access this cookie, http requests only
		HttpOnly: true,
		// limit cookie access to this domain only. Note that this may be a subdomain, i.e. abc.xyz.com, which is more strict than "site", which is only the last two labels, xyz.com.
		Domain: domain,
		// Site is only xyz.com, unless xyz.com is on the list of "public sites" (which it won't be for this platform). Subdomains like console.xyz.com and jaeger.xyz.com are considered the same "site".
		SameSite: http.SameSiteStrictMode,
	}
}

type CookieOptions struct {
	ObjectRestriction string
	ValidDuration     time.Duration
}

type GenCookieOp func(opts *CookieOptions)

func WithObjectRestriction(restriction string) GenCookieOp {
	return func(opts *CookieOptions) { opts.ObjectRestriction = restriction }
}

func WithValidDuration(dur time.Duration) GenCookieOp {
	return func(opts *CookieOptions) { opts.ValidDuration = dur }
}

func GenerateCookie(user *ormapi.User, apiKeyId, domain string, config *ormapi.Config, ops ...GenCookieOp) (*http.Cookie, error) {
	options := &CookieOptions{}
	for _, op := range ops {
		op(options)
	}
	duration := options.ValidDuration
	if duration == 0 {
		duration = config.UserLoginTokenValidDuration.TimeDuration()
	}
	claims := ormutil.UserClaims{
		StandardClaims: jwt.StandardClaims{
			IssuedAt: time.Now().Unix(),
			// 1 day expiration for now
			ExpiresAt: time.Now().Add(duration).Unix(),
		},
		Username: user.Name,
		Email:    user.Email,
		// This is used to keep track of when the first auth token was issued,
		// using this info we allow refreshing of auth token if the token is valid
		FirstIssuedAt:     time.Now().Unix(),
		ObjectRestriction: options.ObjectRestriction,
	}
	if apiKeyId != "" {
		// Set ApiKeyId as username to ensure that we always enforce RBAC on ApikeyId,
		// rather than on user name
		claims.Username = apiKeyId
		// shorter expiration time if apiKeyId is specified
		claims.ExpiresAt = time.Now().Add(config.ApiKeyLoginTokenValidDuration.TimeDuration()).Unix()
		claims.AuthType = ormutil.ApiKeyAuth
		claims.ApiKeyUsername = user.Name
	} else {
		claims.AuthType = ormutil.PasswordAuth
	}
	cookie, err := Jwks.GenerateCookie(&claims)
	return NewHTTPAuthCookie(cookie, claims.ExpiresAt, domain), err
}

func getClaims(c echo.Context) (*ormutil.UserClaims, error) {
	return ormutil.GetClaims(c)
}

func AuthCookie(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		api := c.Path()
		if (strings.Contains(api, "/auth/") || strings.Contains(api, federationmgmt.ApiRoot) || strings.Contains(api, federationmgmt.CallbackRoot)) && !strings.Contains(api, "/ws/") {
			err := registerAuthClaims(c)
			if err != nil {
				return err
			}
		}
		return next(c)
	}
}

func registerAuthClaims(c echo.Context) error {
	auth := c.Request().Header.Get(echo.HeaderAuthorization)
	scheme := "Bearer"
	l := len(scheme)
	cookie := ""
	if len(auth) > len(scheme) && strings.HasPrefix(auth, scheme) {
		cookie = auth[l+1:]
	} else {
		// if no token provided as part of request headers,
		// then check if it is part of http cookie
		for _, httpCookie := range c.Request().Cookies() {
			if httpCookie.Name == TokenHttpCookieName {
				cookie = httpCookie.Value
				break
			}
		}
	}

	if cookie == "" {
		//if no token found, return a 401 err for nginx auth proxy
		return &echo.HTTPError{
			Code:     http.StatusUnauthorized,
			Message:  "no bearer token found",
			Internal: fmt.Errorf("no token found for Authorization Bearer"),
		}
	}

	claims := ormutil.UserClaims{}
	token, err := Jwks.VerifyCookie(cookie, &claims)
	if err == nil && token.Valid {
		c.Set("user", token)
		return nil
	}
	// display error regarding token valid time/expired
	if err != nil && strings.Contains(err.Error(), "expired") {
		return &echo.HTTPError{
			Code:     http.StatusUnauthorized,
			Message:  err.Error(),
			Internal: err,
		}
	}
	return &echo.HTTPError{
		Code:     http.StatusUnauthorized,
		Message:  "invalid or expired jwt",
		Internal: err,
	}
}

func AuthWSCookie(c echo.Context, ws *websocket.Conn) (bool, error) {
	tokAuth := TokenAuth{}
	err := ws.ReadJSON(&tokAuth)
	if err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return false, fmt.Errorf("no bearer token found")
		}
		return false, err
	}

	claims := ormutil.UserClaims{}
	cookie := tokAuth.Token
	token, err := Jwks.VerifyCookie(cookie, &claims)
	if err == nil && token.Valid {
		c.Set("user", token)
		return true, nil
	}
	return false, fmt.Errorf("invalid or expired jwt")
}

func authorized(ctx context.Context, sub, org, obj, act string, ops ...authOp) error {
	opts := authOptions{}
	for _, op := range ops {
		op(&opts)
	}

	allow, admin, err := enforcer.Enforce(ctx, sub, org, obj, act)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "enforcer failed", "err", err)
		return echo.ErrForbidden
	}
	if !allow {
		return echo.ErrForbidden
	}
	if !opts.showAudit {
		if opts.requiresOrg != "" {
			if err := checkRequiresOrg(ctx, opts.requiresOrg, obj, admin, opts.edgeboxCheckFunc); err != nil {
				return err
			}
		}
		for _, refOrg := range opts.refOrgs {
			if refOrg.org == "" {
				continue
			}
			if _, err := checkReferenceOrg(ctx, refOrg.org, refOrg.orgDesc, refOrg.orgType); err != nil {
				return err
			}
		}
	}
	return nil
}

// Returns error if required org is not found or invalid.
// If not present, hides not found error with Forbidden to prevent
// fishing for org names.
func checkRequiresOrg(ctx context.Context, org, resource string, admin bool, edgeboxCheckFunc EdgeboxCheckFunc) error {
	orgType := OrgTypeAny
	if _, ok := DeveloperResourcesMap[resource]; ok {
		orgType = OrgTypeDeveloper
	} else if _, ok := OperatorResourcesMap[resource]; ok {
		orgType = OrgTypeOperator
	}
	lookup, err := checkReferenceOrg(ctx, org, "", orgType)
	if err != nil {
		if _, ok := err.(OrgLookupError); ok && !admin {
			// prevent bad actors from fishing for org names
			return echo.ErrForbidden
		}
		return err
	}
	// make sure only edgebox cloudlets are created for edgebox org
	if edgeboxCheckFunc != nil {
		err := edgeboxCheckFunc(lookup)
		if err != nil {
			return err
		}
	}
	return nil
}

type OrgLookupError struct {
	Err error
}

func (e OrgLookupError) Error() string {
	return e.Err.Error()
}

// Returns error if referenced org is not found or invalid.
func checkReferenceOrg(ctx context.Context, org, orgDesc, orgType string) (*ormapi.Organization, error) {
	// make sure org actually exists, and is not in the
	// process of being deleted.
	lookup, err := orgExists(ctx, org)
	if orgDesc != "" {
		orgDesc += " "
	}
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "org exists check failed", "err", err)
		if !strings.Contains(err.Error(), "not found") {
			err = fmt.Errorf("%sorg %s lookup failed: %v", orgDesc, org, err)
		} else {
			err = fmt.Errorf("%sorg %s not found", orgDesc, org)
		}
		lookupErr := OrgLookupError{
			Err: err,
		}
		return nil, lookupErr
	}
	if lookup.DeleteInProgress {
		return lookup, fmt.Errorf("Operation not allowed for %sorg %s with delete in progress", orgDesc, org)
	}
	// see if resource is only for a specific type of org
	if orgType != OrgTypeAny && lookup.Type != orgType {
		return lookup, fmt.Errorf("Operation for %sorg %s only allowed for orgs of type %s", orgDesc, org, orgType)
	}
	return lookup, nil
}

type authOptions struct {
	showAudit          bool
	requiresOrg        string
	edgeboxCheckFunc   EdgeboxCheckFunc
	requiresBillingOrg string
	targetCloudlet     *edgeproto.Cloudlet
	refOrgs            []refOrg
}

type refOrg struct {
	org     string
	orgType string
	orgDesc string
}

type EdgeboxCheckFunc func(org *ormapi.Organization) error

type authOp func(opts *authOptions)

func withShowAudit() authOp {
	return func(opts *authOptions) { opts.showAudit = true }
}

func withRequiresOrg(org string) authOp {
	return func(opts *authOptions) { opts.requiresOrg = org }
}

func withReferenceOrg(org, orgDesc, orgType string) authOp {
	return func(opts *authOptions) {
		ro := refOrg{
			org:     org,
			orgType: orgType,
			orgDesc: orgDesc,
		}
		opts.refOrgs = append(opts.refOrgs, ro)
	}
}

func withCheckEdgeboxOnly(checkFunc EdgeboxCheckFunc) authOp {
	return func(opts *authOptions) { opts.edgeboxCheckFunc = checkFunc }
}

func withRequiresBillingOrg(org string, targetCloudlet *edgeproto.Cloudlet) authOp {
	return func(opts *authOptions) {
		opts.requiresBillingOrg = org
		opts.targetCloudlet = targetCloudlet
	}
}
