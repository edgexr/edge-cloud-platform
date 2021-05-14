package orm

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/websocket"
	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
	"golang.org/x/crypto/pbkdf2"
)

var PasswordMinLength = 8
var PasswordMaxLength = 4096

// As computing power grows, we should increase iter and salt bytes
var PasshashIter = 10000
var PasshashKeyBytes = 32
var PasshashSaltBytes = 8
var BruteForceGuessesPerSecond = 1000000

var JWTShortDuration = 4 * time.Hour

var Jwks vault.JWKS

const (
	ApiKeyAuth   string = "apikeyauth"
	PasswordAuth string = "passwordauth"
)

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

func Passhash(pw, salt []byte, iter int) []byte {
	return pbkdf2.Key(pw, salt, iter, PasshashKeyBytes, sha256.New)
}

func NewPasshash(password string) (passhash, salt string, iter int) {
	saltb := make([]byte, PasshashSaltBytes)
	rand.Read(saltb)
	pass := Passhash([]byte(password), saltb, PasshashIter)
	return base64.StdEncoding.EncodeToString(pass),
		base64.StdEncoding.EncodeToString(saltb), PasshashIter
}

func PasswordMatches(password, passhash, salt string, iter int) (bool, error) {
	sa, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return false, err
	}
	ph := Passhash([]byte(password), sa, iter)
	phenc := base64.StdEncoding.EncodeToString(ph)
	return phenc == passhash, nil
}

type UserClaims struct {
	jwt.StandardClaims
	Username       string `json:"username"`
	Email          string `json:"email"`
	Kid            int    `json:"kid"`
	FirstIssuedAt  int64  `json:"firstiat,omitempty"`
	AuthType       string `json:"authtype"`
	ApiKeyUsername string `json:"apikeyusername"`
}

func (u *UserClaims) GetKid() (int, error) {
	return u.Kid, nil
}

func (u *UserClaims) SetKid(kid int) {
	u.Kid = kid
}

func GenerateCookie(user *ormapi.User, apiKeyId, domain string) (*http.Cookie, error) {
	claims := UserClaims{
		StandardClaims: jwt.StandardClaims{
			IssuedAt: time.Now().Unix(),
			// 1 day expiration for now
			ExpiresAt: time.Now().AddDate(0, 0, 1).Unix(),
		},
		Username: user.Name,
		Email:    user.Email,
		// This is used to keep track of when the first auth token was issued,
		// using this info we allow refreshing of auth token if the token is valid
		FirstIssuedAt: time.Now().Unix(),
	}
	if apiKeyId != "" {
		// Set ApiKeyId as username to ensure that we always enforce RBAC on ApikeyId,
		// rather than on user name
		claims.Username = apiKeyId
		// shorter expiration time if apiKeyId is specified
		claims.ExpiresAt = time.Now().Add(JWTShortDuration).Unix()
		claims.AuthType = ApiKeyAuth
		claims.ApiKeyUsername = user.Name
	} else {
		claims.AuthType = PasswordAuth
	}
	cookie, err := Jwks.GenerateCookie(&claims)
	httpCookie := http.Cookie{
		Name:    "token",
		Value:   cookie,
		Expires: time.Unix(claims.ExpiresAt, 0),
		// only send this cookie over HTTPS
		Secure: true,
		// true means no scripts will be able to access this cookie, http requests only
		HttpOnly: true,
		// limit cookie access to this domain only
		Domain: domain,
		// limits cookie's scope to only requests originating from same site
		SameSite: http.SameSiteStrictMode,
	}
	return &httpCookie, err
}

func getClaims(c echo.Context) (*UserClaims, error) {
	user := c.Get("user")
	ctx := GetContext(c)
	if user == nil {
		log.SpanLog(ctx, log.DebugLevelApi, "get claims: no user")
		return nil, echo.ErrUnauthorized
	}
	token, ok := user.(*jwt.Token)
	if !ok {
		log.SpanLog(ctx, log.DebugLevelApi, "get claims: no token")
		return nil, echo.ErrUnauthorized
	}
	claims, ok := token.Claims.(*UserClaims)
	if !ok {
		log.SpanLog(ctx, log.DebugLevelApi, "get claims: bad claims type")
		return nil, echo.ErrUnauthorized
	}
	if claims.Username == "" {
		log.SpanLog(ctx, log.DebugLevelApi, "get claims: bad claims content")
		return nil, echo.ErrUnauthorized
	}
	span := log.SpanFromContext(ctx)
	if claims.AuthType == ApiKeyAuth {
		span.SetTag("username", claims.ApiKeyUsername)
		span.SetTag("apikeyid", claims.Username)
	} else {
		span.SetTag("username", claims.Username)
	}
	span.SetTag("email", claims.Email)
	return claims, nil
}

func AuthCookie(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
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
				if httpCookie.Name == "token" {
					cookie = httpCookie.Value
					break
				}
			}
		}

		if cookie == "" {
			//if no token found, return a 400 err
			return &echo.HTTPError{
				Code:     http.StatusBadRequest,
				Message:  "no bearer token found",
				Internal: fmt.Errorf("no token found for Authorization Bearer"),
			}
		}

		claims := UserClaims{}
		token, err := Jwks.VerifyCookie(cookie, &claims)
		if err == nil && token.Valid {
			c.Set("user", token)
			return next(c)
		}
		// display error regarding token valid time/expired
		if err != nil && strings.Contains(err.Error(), "expired") {
			return &echo.HTTPError{
				Code:     http.StatusBadRequest,
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
}

func AuthWSCookie(c echo.Context, ws *websocket.Conn) (bool, error) {
	tokAuth := TokenAuth{}
	err := ws.ReadJSON(&tokAuth)
	if err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return false, setReply(c, fmt.Errorf("no bearer token found"), nil)
		}
		return false, setReply(c, err, nil)
	}

	claims := UserClaims{}
	cookie := tokAuth.Token
	token, err := Jwks.VerifyCookie(cookie, &claims)
	if err == nil && token.Valid {
		c.Set("user", token)
		return true, nil
	}
	return false, setReply(c, fmt.Errorf("invalid or expired jwt"), nil)
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

	if opts.requiresOrg != "" && !opts.showAudit {
		if err := checkRequiresOrg(ctx, opts.requiresOrg, obj, admin, opts.noEdgeboxOnly); err != nil {
			return err
		}
	}
	return nil
}

func checkRequiresOrg(ctx context.Context, org, resource string, admin, noEdgeboxOnly bool) error {
	// make sure org actually exists, and is not in the
	// process of being deleted.
	lookup, err := orgExists(ctx, org)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "org exists check failed", "err", err)
		if !admin {
			return echo.ErrForbidden
		}
		if strings.Contains(err.Error(), "not found") {
			return echo.NewHTTPError(http.StatusBadRequest, err)
		}
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Org %s lookup failed: %v", org, err))
	}
	if lookup.DeleteInProgress {
		return echo.NewHTTPError(http.StatusBadRequest, "Operation not allowed for org with delete in progress")
	}
	// see if resource is only for a specific type of org
	orgType := ""
	if _, ok := DeveloperResourcesMap[resource]; ok {
		orgType = OrgTypeDeveloper
	} else if _, ok := OperatorResourcesMap[resource]; ok {
		orgType = OrgTypeOperator
	}
	if orgType != "" && lookup.Type != orgType {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Operation only allowed for organizations of type %s", orgType))
	}
	// make sure only edgebox cloudlets are created for edgebox org
	if lookup.EdgeboxOnly && noEdgeboxOnly {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Only allowed to create EDGEBOX cloudlet on org %s", org))
	}
	return nil
}

type authOptions struct {
	showAudit          bool
	requiresOrg        string
	noEdgeboxOnly      bool
	requiresBillingOrg string
	targetCloudlet     *edgeproto.Cloudlet
}

type authOp func(opts *authOptions)

func withShowAudit() authOp {
	return func(opts *authOptions) { opts.showAudit = true }
}

func withRequiresOrg(org string) authOp {
	return func(opts *authOptions) { opts.requiresOrg = org }
}

func withNoEdgeboxOnly() authOp {
	return func(opts *authOptions) { opts.noEdgeboxOnly = true }
}

func withRequiresBillingOrg(org string, targetCloudlet *edgeproto.Cloudlet) authOp {
	return func(opts *authOptions) {
		opts.requiresBillingOrg = org
		opts.targetCloudlet = targetCloudlet
	}
}
