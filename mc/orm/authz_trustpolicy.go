package orm

import (
	"context"

	"github.com/mobiledgex/edge-cloud/edgeproto"
)

// AuthzTrustPolicy allows a user to see a trust policy only if
// 1) user is an admin (AuthzCloudlet allowAll)
// 2) user is part of the org for that policy
// 3) there at least one cloudlet using that policy that they can see, based
//    on AuthzCloudlet pool checking
type AuthzTrustPolicy struct {
	authzCloudlet        *AuthzCloudlet
	allowedTrustPolicies map[edgeproto.PolicyKey]struct{}
}

func (s *AuthzTrustPolicy) Ok(obj *edgeproto.TrustPolicy) bool {
	if s.authzCloudlet.allowAll {
		return true
	}
	if _, found := s.authzCloudlet.orgs[obj.Key.Organization]; found {
		// operator has access to policies created by their org
		return true
	}
	if _, found := s.allowedTrustPolicies[obj.Key]; found {
		return true
	}
	return false
}

func (s *AuthzTrustPolicy) populate(ctx context.Context, region, username string) error {
	rc := RegionContext{
		region:    region,
		username:  username,
		skipAuthz: true, // skip since we already have the cloudlet authz
	}
	// allow policies associated with cloudlets that the user can see
	err := ShowCloudletStream(ctx, &rc, &edgeproto.Cloudlet{}, func(cloudlet *edgeproto.Cloudlet) {
		if !s.authzCloudlet.Ok(cloudlet) || cloudlet.TrustPolicy == "" {
			return
		}
		key := edgeproto.PolicyKey{
			Organization: cloudlet.Key.Organization,
			Name:         cloudlet.TrustPolicy,
		}
		s.allowedTrustPolicies[key] = struct{}{}
	})
	if err != nil {
		return err
	}
	return nil
}

func newShowTrustPolicyAuthz(ctx context.Context, region, username, resource, action string) (ShowTrustPolicyAuthz, error) {
	authzCloudlet := AuthzCloudlet{}
	err := authzCloudlet.populate(ctx, region, username, "", resource, action)
	if err != nil {
		return nil, err
	}
	authzTrustPolicy := AuthzTrustPolicy{
		authzCloudlet:        &authzCloudlet,
		allowedTrustPolicies: make(map[edgeproto.PolicyKey]struct{}),
	}
	err = authzTrustPolicy.populate(ctx, region, username)
	if err != nil {
		return nil, err
	}
	return &authzTrustPolicy, nil
}
