package vmlayer

import (
	"context"
	"fmt"

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
	rootlbClients, err := v.GetAllRootLBClients(ctx)
	if err != nil {
		return fmt.Errorf("Unable to get rootlb clients - %v", err)
	}
	return v.VMProvider.ConfigureCloudletSecurityRules(ctx, egressRestricted, privPol, rootlbClients, action, edgeproto.DummyUpdateCallback)
}
