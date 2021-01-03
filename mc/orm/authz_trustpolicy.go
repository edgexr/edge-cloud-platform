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
	authzCloudlet *AuthzCloudlet
	cloudlets     []*edgeproto.Cloudlet
}

func (s *AuthzTrustPolicy) Ok(obj *edgeproto.TrustPolicy) bool {
	if s.authzCloudlet.allowAll {
		return true
	}
	if _, found := s.authzCloudlet.orgs[obj.Key.Organization]; found {
		// operator has access to policies created by their org
		return true
	}
	// see if this user is allowed on any cloudlet associated with this policy
	for _, cloudlet := range s.cloudlets {
		if obj.Key.Organization == cloudlet.Key.Organization &&
			obj.Key.Name == cloudlet.TrustPolicy {
			return true
		}
	}
	return false
}

func (s *AuthzTrustPolicy) populate(ctx context.Context, region, username string) error {
	rc := RegionContext{
		region:    region,
		username:  username,
		skipAuthz: false,
	}
	err := ShowCloudletStream(ctx, &rc, &edgeproto.Cloudlet{}, func(cloudlet *edgeproto.Cloudlet) {
		s.cloudlets = append(s.cloudlets, cloudlet)
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
		authzCloudlet: &authzCloudlet,
	}
	err = authzTrustPolicy.populate(ctx, region, username)
	if err != nil {
		return nil, err
	}
	return &authzTrustPolicy, nil
}
