package dmecommon

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/mobiledgex/edge-cloud/log"
	"google.golang.org/grpc/peer"
)

// temporarily hardcode the keys here, later we can get them via config file
// or perhaps from the controller
var dmePrivateKey = `***REMOVED***`

var dmePublicKey = `***REMOVED***`

// returns Peer IP or Error
func VerifyCookie(cookie string) (string, error) {

	if cookie == "" {
		return "", fmt.Errorf("missing cookie")
	}
	claims := jwt.StandardClaims{}
	pubKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(dmePublicKey))
	if err != nil {
		return "", err
	}
	_, err = jwt.ParseWithClaims(cookie, &claims, func(token *jwt.Token) (verifykey interface{}, err error) {
		return pubKey, nil
	})

	if err != nil {
		log.WarnLog("error in verifycookie", "cookie", cookie, "err", err)
		return "", err
	}

	if claims.ExpiresAt < time.Now().Unix() {
		log.InfoLog("cookie is expired", "cookie", cookie, "expiresAt", claims.ExpiresAt)
		return "", errors.New("Expired cookie")
	}

	log.DebugLog(log.DebugLevelDmereq, "verified cookie", "cookie", cookie, "expires", claims.ExpiresAt)
	return claims.Id, nil
}

func GenerateCookie(appName string, ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", errors.New("unable to get peer IP info")
	}

	ss := strings.Split(p.Addr.String(), ":")
	if len(ss) != 2 {
		return "", errors.New("unable to parse peer address " + p.Addr.String())
	}
	peerIp := ss[0]

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.StandardClaims{
		Subject:   appName,
		Id:        peerIp,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().AddDate(0, 0, 1).Unix(), // 1 day expiration for now
	})
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(dmePrivateKey))
	if err != nil {
		return "", err
	}
	cookie, err := tok.SignedString(signKey)
	log.DebugLog(log.DebugLevelDmereq, "generated cookie", "app", appName, "cookie", cookie, "err", err)
	return cookie, err
}
