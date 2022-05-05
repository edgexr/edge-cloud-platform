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

	"github.com/labstack/echo"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
)

type AuthzOrgCloudletPool struct {
	allowedOperOrgs map[string]struct{}
	allowedDevOrgs  map[string]struct{}
	allowAll        bool
}

func newAuthzOrgCloudletPool(ctx context.Context, region, username, action string) (*AuthzOrgCloudletPool, error) {
	// This may be called by either a developer or an operator.
	authOperOrgs, err := enforcer.GetAuthorizedOrgs(ctx, username, ResourceCloudletPools, action)
	if err != nil {
		return nil, err
	}
	authDevOrgs, err := enforcer.GetAuthorizedOrgs(ctx, username, ResourceUsers, action)
	if err != nil {
		return nil, err
	}
	if len(authDevOrgs) == 0 && len(authOperOrgs) == 0 {
		return nil, echo.ErrForbidden
	}
	authz := AuthzOrgCloudletPool{
		allowedOperOrgs: authOperOrgs,
		allowedDevOrgs:  authDevOrgs,
	}
	if _, found := authOperOrgs[""]; found {
		// user is an admin
		authz.allowAll = true
	}
	return &authz, nil
}

func (s *AuthzOrgCloudletPool) Ok(in *ormapi.OrgCloudletPool) bool {
	if s.allowAll {
		return true
	}
	if _, found := s.allowedOperOrgs[in.CloudletPoolOrg]; found {
		return true
	}
	if _, found := s.allowedDevOrgs[in.Org]; found {
		return true
	}
	return false
}
