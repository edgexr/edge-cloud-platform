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
	fmt "fmt"

	"github.com/labstack/echo"
	"github.com/edgexr/edge-cloud-infra/mc/ctrlclient"
	"github.com/edgexr/edge-cloud/edgeproto"
)

type AuthzOrgTpe struct {
	allowedOperOrgs map[string]struct{}
	allowedDevOrgs  map[string]struct{}
	allowAll        bool
}

func (s *AuthzOrgTpe) populate(ctx context.Context, region, username, orgfilter, resource, action string, authops ...authOp) error {
	opts := authOptions{}
	for _, op := range authops {
		op(&opts)
	}
	// This may be called by either a developer or an operator.
	authOperOrgs, err := enforcer.GetAuthorizedOrgs(ctx, username, ResourceCloudletPools, action)
	if err != nil {
		return err
	}
	authDevOrgs, err := enforcer.GetAuthorizedOrgs(ctx, username, ResourceApps, action)
	if err != nil {
		return err
	}
	if len(authDevOrgs) == 0 && len(authOperOrgs) == 0 {
		return echo.ErrForbidden
	}

	s.allowedDevOrgs = authDevOrgs
	s.allowedOperOrgs = authOperOrgs

	if _, found := authOperOrgs[""]; found {
		// user is an admin
		s.allowAll = true
	}
	return nil
}

func (s *AuthzOrgTpe) Ok(obj *edgeproto.TrustPolicyException) (bool, bool) {
	filterOutput := false
	if s.allowAll {
		return true, filterOutput
	}
	if _, found := s.allowedOperOrgs[obj.Key.CloudletPoolKey.Organization]; found {
		// operator has access to policies created by their org
		return true, filterOutput
	}
	if _, found := s.allowedDevOrgs[obj.Key.AppKey.Organization]; found {
		return true, filterOutput
	}
	filterOutput = true
	return false, filterOutput
}

func (s *AuthzOrgTpe) Filter(obj *edgeproto.TrustPolicyException) {
}

func newShowTrustPolicyExceptionAuthz(ctx context.Context, region, username, resource, action string) (ctrlclient.ShowTrustPolicyExceptionAuthz, error) {
	authzOrgTpe := AuthzOrgTpe{}
	err := authzOrgTpe.populate(ctx, region, username, "", resource, action)
	if err != nil {
		return nil, err
	}
	return &authzOrgTpe, nil
}

func newAuthzGetOrgsTpe(ctx context.Context, region, username, action string) (*AuthzOrgTpe, error) {
	// This may be called by either a developer or an operator.
	authOperOrgs, err := enforcer.GetAuthorizedOrgs(ctx, username, ResourceCloudletPools, action)
	if err != nil {
		return nil, err
	}
	authDevOrgs, err := enforcer.GetAuthorizedOrgs(ctx, username, ResourceApps, action)
	if err != nil {
		return nil, err
	}
	if len(authDevOrgs) == 0 && len(authOperOrgs) == 0 {
		return nil, echo.ErrForbidden
	}
	authz := AuthzOrgTpe{
		allowedOperOrgs: authOperOrgs,
		allowedDevOrgs:  authDevOrgs,
	}
	if _, found := authOperOrgs[""]; found {
		// user is an admin
		authz.allowAll = true
	}
	return &authz, nil
}

func authzUpdateTrustPolicyException(ctx context.Context, region, username string, tpe *edgeproto.TrustPolicyException, resource, action string) error {

	authz, err := newAuthzGetOrgsTpe(ctx, region, username, action)
	if err != nil {
		return err
	}
	if authz.allowAll {
		return nil
	}
	_, isOper := authz.allowedOperOrgs[tpe.Key.CloudletPoolKey.Organization]
	_, isDev := authz.allowedDevOrgs[tpe.Key.AppKey.Organization]

	if isOper && isDev {
		return nil
	}

	if isOper {
		// Operator can only update state
		for _, field := range tpe.Fields {
			if tpe.IsKeyField(field) {
				continue
			}
			if field != edgeproto.TrustPolicyExceptionFieldState {
				return fmt.Errorf("Operator can update only state field")
			}
		}
		return nil
	}

	if isDev {
		// Developer can not update state
		for _, field := range tpe.Fields {
			if tpe.IsKeyField(field) {
				continue
			}
			if field == edgeproto.TrustPolicyExceptionFieldState {
				return fmt.Errorf("Developer not allowed to update state field")
			}
		}
		return nil
	}

	return echo.ErrForbidden
}
