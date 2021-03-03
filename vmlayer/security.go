package vmlayer

import (
	"context"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/crmutil"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

func (v *VMPlatform) ConfigureCloudletSecurityRules(ctx context.Context, action ActionType) error {
	// update security groups based on a configured privacy policy or none
	privPolName := v.VMProperties.CommonPf.PlatformConfig.TrustPolicy
	var privPol *edgeproto.TrustPolicy
	egressRestricted := false
	var err error
	if privPolName != "" {
		privPol, err = crmutil.GetCloudletTrustPolicy(ctx, privPolName, v.VMProperties.CommonPf.PlatformConfig.CloudletKey.Organization, v.Caches.TrustPolicyCache)
		if err != nil {
			return err
		}
		egressRestricted = true
	} else {
		// use an empty policy
		privPol = &edgeproto.TrustPolicy{}
	}
	return v.VMProvider.ConfigureCloudletSecurityRules(ctx, egressRestricted, privPol, action, edgeproto.DummyUpdateCallback)
}
