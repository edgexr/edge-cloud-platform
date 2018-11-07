package orm

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"time"
	"unicode/utf8"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud/log"
	"golang.org/x/crypto/pbkdf2"
)

var PasswordMinLength = 8
var PasswordMaxLength = 4096

// As computing power grows, we should increase iter and salt bytes
var PasshashIter = 10000
var PasshashKeyBytes = 32
var PasshashSaltBytes = 8

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
	UserID   int64  `json:"id"`
}

func GenerateCookie(user *User) (string, error) {
	claims := UserClaims{
		StandardClaims: jwt.StandardClaims{
			IssuedAt: time.Now().Unix(),
			// 1 day expiration for now
			ExpiresAt: time.Now().AddDate(0, 0, 1).Unix(),
		},
		Username: user.Name,
		UserID:   user.ID,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, &claims)
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKey))
	if err != nil {
		return "", err
	}
	cookie, err := tok.SignedString(signKey)
	return cookie, err
}

func getClaims(c echo.Context) (*UserClaims, error) {
	user := c.Get("user")
	if user == nil {
		log.DebugLog(log.DebugLevelApi, "get claims: no user")
		return nil, echo.ErrUnauthorized
	}
	token, ok := user.(*jwt.Token)
	if !ok {
		log.DebugLog(log.DebugLevelApi, "get claims: no token")
		return nil, echo.ErrUnauthorized
	}
	claims, ok := token.Claims.(*UserClaims)
	if !ok {
		log.DebugLog(log.DebugLevelApi, "get claims: bad claims type")
		return nil, echo.ErrUnauthorized
	}
	if claims.Username == "" || claims.UserID == 0 {
		log.DebugLog(log.DebugLevelApi, "get claims: bad claims content")
		return nil, echo.ErrUnauthorized
	}
	return claims, nil
}

// RBAC model for Casbin (see https://vicarie.in/posts/generalized-authz.html
// and https://casbin.org/editor/).
// This extends the default RBAC model slightly by allowing Roles (sub)
// to be scoped by Organization (org) on a per-user basis, by prepending the
// Organization name to the user name when assigning a role to a user.
// Users without organizations prepended are super users and their role is
// not restricted to any organization - these users will be admins for
// the master controller.
func createRbacModel(filename string) error {
	data := []byte(`
[request_definition]
r = sub, org, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = (g(r.org + "::" + r.sub, p.sub) || g(r.sub, p.sub)) && r.obj == p.obj && r.act == p.act

[role_definition]
g = _, _
`)
	// A partial example matching config would be:
	//
	// p, DeveloperManager, Users, Manage
	// p, DeveloperContributer, Apps, Manage
	// p, DeveloperViewer, Apps, View
	// p, AdminManager, Users, Manage
	//
	// g, superuser, AdminManager
	// g, orgABC::adam, DeveloperManager
	// g, orgABC::alice, DeveloperContributor
	// g, orgXYZ::jon, DeveloperManager
	// g, orgXYZ::bob, DeveloperContributor
	//
	// Example requests:
	// (adam, orgABC, Users, Manage) -> OK
	// (adam, orgXYZ, Users, Manage) -> Denied
	// (superuser, <anything here>, Users, Manage) -> OK
	//
	// Note that in implemenation, we use IDs instead of names
	// for users and orgs.
	return ioutil.WriteFile(filename, data, 0644)
}

// temporarily hardcode the keys here, later we can get them via config file
// or perhaps from secrets repo like Vault
var privateKey = `***REMOVED***`

var publicKey = `***REMOVED***`
