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

package dmecommon

import (
	"context"
	"errors"
	"fmt"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	jwt "github.com/golang-jwt/jwt/v4"
)

type EdgeEventsCookieKey struct {
	AppInstName  string  `json:"appinstname,omitempty"`
	ClusterOrg   string  `json:"clusterorg,omitempty"`
	ClusterName  string  `json:"clustername,omitempty"`
	CloudletOrg  string  `json:"cloudletorg,omitempty"`
	CloudletName string  `json:"cloudletname,omitempty"`
	Location     dme.Loc `json:"location,omitempty"`
	Kid          int     `json:"kid,omitempty"`
}

type edgeEventsClaims struct {
	jwt.StandardClaims
	Key *EdgeEventsCookieKey `json:"key,omitempty"`
}

type ctxEdgeEventsCookieKey struct{}

func (e *edgeEventsClaims) GetKid() (int, error) {
	if e.Key == nil {
		return 0, fmt.Errorf("Invalid cookie, no key")
	}
	return e.Key.Kid, nil
}

func (e *edgeEventsClaims) SetKid(kid int) {
	e.Key.Kid = kid
}

func CreateEdgeEventsCookieKey(appInst *DmeAppInst, loc dme.Loc) *EdgeEventsCookieKey {
	key := &EdgeEventsCookieKey{
		AppInstName:  appInst.key.Name,
		ClusterOrg:   appInst.clusterKey.Organization,
		ClusterName:  appInst.clusterKey.Name,
		CloudletOrg:  appInst.cloudletKey.Organization,
		CloudletName: appInst.cloudletKey.Name,
		Location:     loc,
	}
	return key
}

func VerifyEdgeEventsCookie(ctx context.Context, cookie string) (*EdgeEventsCookieKey, error) {
	claims := edgeEventsClaims{}
	token, err := Jwks.VerifyCookie(cookie, &claims)
	if err != nil {
		log.InfoLog("error in verifyedgeeventscookie", "cookie", cookie, "err", err)
		return nil, err
	}
	if claims.Key == nil || !verifyEdgeEventsCookieKey(claims.Key) {
		log.InfoLog("no key parsed", "eecookie", cookie, "err", err)
		return nil, errors.New("No Key data in cookie")
	}
	if !token.Valid {
		log.InfoLog("edgeevents cookie is invalid or expired", "eecookie", cookie, "claims", claims)
		return nil, errors.New("invalid or expired cookie")
	}
	err = ValidateLocation(&claims.Key.Location)
	if err != nil {
		log.InfoLog("edgeevents cookie has invalid location", "eecookie", cookie, "claims", claims)
		return nil, errors.New("invalid location in cookie")
	}
	log.SpanLog(ctx, log.DebugLevelDmereq, "verified edgeevents cookie", "eecookie", cookie, "expires", claims.ExpiresAt)
	return claims.Key, nil
}

func verifyEdgeEventsCookieKey(key *EdgeEventsCookieKey) bool {
	if key.ClusterOrg == "" && key.ClusterName == "" && key.CloudletOrg == "" && key.CloudletName == "" {
		return false
	}
	return true
}

func GenerateEdgeEventsCookie(key *EdgeEventsCookieKey, ctx context.Context, cookieExpiration time.Duration) (string, error) {
	claims := edgeEventsClaims{
		StandardClaims: jwt.StandardClaims{
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(cookieExpiration).Unix(),
		},
		Key: key,
	}

	cookie, err := Jwks.GenerateCookie(&claims)
	log.SpanLog(ctx, log.DebugLevelDmereq, "generated edge events cookie", "key", key, "eecookie", cookie, "err", err)
	return cookie, err
}

func NewEdgeEventsCookieContext(ctx context.Context, eekey *EdgeEventsCookieKey) context.Context {
	if eekey == nil {
		return ctx
	}
	return context.WithValue(ctx, ctxEdgeEventsCookieKey{}, eekey)
}

func EdgeEventsCookieFromContext(ctx context.Context) (eekey *EdgeEventsCookieKey, ok bool) {
	eekey, ok = ctx.Value(ctxEdgeEventsCookieKey{}).(*EdgeEventsCookieKey)
	return
}

func IsTheSameCluster(key1 *EdgeEventsCookieKey, key2 *EdgeEventsCookieKey) bool {
	return key1.CloudletOrg == key2.CloudletOrg && key1.CloudletName == key2.CloudletName && key1.ClusterOrg == key2.ClusterOrg && key1.ClusterName == key2.ClusterName
}
