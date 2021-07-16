package orm

import (
	"context"

	"github.com/mobiledgex/edge-cloud/cloudcommon"
	edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
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
	filterOutput := false
	if s.allowAll {
		return true, filterOutput
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
}
