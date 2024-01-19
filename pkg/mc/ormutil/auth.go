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

package ormutil

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/echoutil"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/passhash"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/jinzhu/gorm"
	"github.com/labstack/echo/v4"
)

const harborVaultAccount = "/secret/data/accounts/harbor"

const (
	ApiKeyAuth   string = "apikeyauth"
	PasswordAuth string = "passwordauth"
)

type UserClaims struct {
	jwt.StandardClaims
	Username          string `json:"username"`
	Email             string `json:"email"`
	Kid               int    `json:"kid"`
	FirstIssuedAt     int64  `json:"firstiat,omitempty"`
	AuthType          string `json:"authtype"`
	ApiKeyUsername    string `json:"apikeyusername"`
	ObjectRestriction string `json:"objectrestriction"`
	OrgRestriction    string `json:"orgrestriction"`
}

func (u *UserClaims) GetKid() (int, error) {
	return u.Kid, nil
}

func (u *UserClaims) SetKid(kid int) {
	u.Kid = kid
}

func GetClaims(c echo.Context) (*UserClaims, error) {
	user := c.Get("user")
	ctx := echoutil.GetContext(c)
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
	if claims.Email != "" {
		span.SetTag("email", claims.Email)
	}
	return claims, nil
}

// Create api key. Returns client id and key.
func CreateApiKey(ctx context.Context, db *gorm.DB, id, org, username, description string, allowUpdate bool) (*ormapi.UserApiKey, string, error) {
	key := uuid.New().String()
	hash, salt, iter := passhash.NewPasshash(key)
	apiKey := ormapi.UserApiKey{
		Id:          id,
		Description: description,
		Org:         org,
		Username:    username,
		ApiKeyHash:  hash,
		Salt:        salt,
		Iter:        iter,
	}
	var err error
	if allowUpdate {
		err = db.Save(&apiKey).Error
	} else {
		err = db.Create(&apiKey).Error
	}
	if err != nil {
		return nil, "", DbErr(err)
	}
	return &apiKey, key, nil
}

func DeleteApiKey(ctx context.Context, db *gorm.DB, id string) error {
	apiKey := ormapi.UserApiKey{
		Id: id,
	}
	err := db.Delete(&apiKey).Error
	if err != nil {
		return DbErr(err)
	}
	return nil
}
