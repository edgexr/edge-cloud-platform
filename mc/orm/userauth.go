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

var Jwks vault.JWKS

type TokenAuth struct {
	Token string
}

func InitVault(config *vault.Config, updateDone chan struct{}) {
	Jwks.Init(config, "", "mcorm")
	Jwks.GoUpdate(updateDone)
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
	Username string `json:"username"`
	Email    string `json:"email"`
	Kid      int    `json:"kid"`
}

func (u *UserClaims) GetKid() (int, error) {
	return u.Kid, nil
}

func (u *UserClaims) SetKid(kid int) {
	u.Kid = kid
}

func GenerateCookie(user *ormapi.User) (string, error) {
	claims := UserClaims{
		StandardClaims: jwt.StandardClaims{
			IssuedAt: time.Now().Unix(),
			// 1 day expiration for now
			ExpiresAt: time.Now().AddDate(0, 0, 1).Unix(),
		},
		Username: user.Name,
		Email:    user.Email,
	}
	cookie, err := Jwks.GenerateCookie(&claims)
	return cookie, err
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
	span.SetTag("username", claims.Username)
	span.SetTag("email", claims.Email)
	return claims, nil
}

func AuthCookie(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		auth := c.Request().Header.Get(echo.HeaderAuthorization)
		scheme := "Bearer"
		l := len(scheme)
		if len(auth) <= len(scheme) || !strings.HasPrefix(auth, scheme) {
			//if no token provided, return a 400 err
			return &echo.HTTPError{
				Code:     http.StatusBadRequest,
				Message:  "no bearer token found",
				Internal: fmt.Errorf("no token found for Authorization Bearer"),
			}
		}

		cookie := auth[l+1:]

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

func authorized(ctx context.Context, sub, org, obj, act string, ops ...authOp) bool {
	opts := authOptions{}
	for _, op := range ops {
		op(&opts)
	}

	allow, admin, err := enforcer.Enforce(ctx, sub, org, obj, act)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "enforcer failed", "err", err)
		return false
	}
	if admin && org != "" && !opts.showAudit {
		// make sure org actually exists
		found, err := orgExists(ctx, org)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "admin authorized, org exists check failed", "err", err)
			return false
		}
		if !found {
			log.SpanLog(ctx, log.DebugLevelApi, "admin authorized, but org not found", "org", org)
			return false
		}
	}
	return allow
}

type authOptions struct {
	showAudit bool
}

type authOp func(opts *authOptions)

func withShowAudit() authOp {
	return func(opts *authOptions) { opts.showAudit = true }
}
