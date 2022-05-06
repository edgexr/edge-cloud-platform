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
	"github.com/edgexr/edge-cloud/cloudcommon"
	edgeproto "github.com/edgexr/edge-cloud/edgeproto"
)

type AuthzAlert struct {
	orgs     map[string]struct{}
	allowAll bool
}

func newShowAlertAuthz(ctx context.Context, region, username, resource, action string) (*AuthzAlert, error) {
	orgs, err := enforcer.GetAuthorizedOrgs(ctx, username, resource, action)
	if err != nil {
		return nil, err
	}
	if len(orgs) == 0 {
		return nil, echo.ErrForbidden
	}
	authz := AuthzAlert{
		orgs: orgs,
	}
	if _, found := orgs[""]; found {
		// user is an admin.
		authz.allowAll = true
	}
	return &authz, nil
}

func (s *AuthzAlert) Ok(obj *edgeproto.Alert) (bool, bool) {
	filterOutput := true
	if s.allowAll {
		return true, false
	}

	// if not an admin, we filter internal alerts
	_, ok := obj.Labels["alertname"]
	if !ok {
		return false, filterOutput
	}
	if cloudcommon.IsInternalAlert(obj.Labels) {
		return false, filterOutput
	}

	org := obj.Labels["apporg"]
	alertScope := obj.Labels["scope"]
	if alertScope == cloudcommon.AlertScopeCloudlet {
		org = obj.Labels["cloudletorg"]
	}
	_, found := s.orgs[org]
	return found, filterOutput
}

func (s *AuthzAlert) Filter(obj *edgeproto.Alert) {
	for k, _ := range obj.Labels {
		if cloudcommon.IsLabelInternal(k) {
			delete(obj.Labels, k)
		}
	}
}
