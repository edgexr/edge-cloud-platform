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

package vmlayer

import (
	"context"
	"fmt"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/crmutil"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
)

func (v *VMPlatform) ConfigureCloudletSecurityRules(ctx context.Context, action ActionType) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ConfigureCloudletSecurityRules", "action", action)
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
	rootlbClients, err := v.GetRootLBClients(ctx)
	if err != nil {
		return fmt.Errorf("Unable to get rootlb clients - %v", err)
	}
	return v.VMProvider.ConfigureCloudletSecurityRules(ctx, egressRestricted, privPol, rootlbClients, action, edgeproto.DummyUpdateCallback)
}
