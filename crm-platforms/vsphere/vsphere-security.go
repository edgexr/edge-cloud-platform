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

package vsphere

import (
	"context"
	"fmt"

	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

func (v *VSpherePlatform) WhitelistSecurityRules(ctx context.Context, client ssh.Client, wlParams *infracommon.WhiteListParams) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "WhitelistSecurityRules", "wlParams", wlParams)
	// this can be called during LB init so we need to ensure we can reach the server before trying iptables commands
	err := vmlayer.WaitServerReady(ctx, v, client, wlParams.ServerName, vmlayer.MaxRootLBWait)
	if err != nil {
		return err
	}
	return infracommon.AddIngressIptablesRules(ctx, client, wlParams.Label, wlParams.AllowedCIDR, wlParams.DestIP, wlParams.Ports)
}

func (v *VSpherePlatform) RemoveWhitelistSecurityRules(ctx context.Context, client ssh.Client, wlParams *infracommon.WhiteListParams) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "RemoveWhitelistSecurityRules", "wlParams", wlParams)
	return infracommon.RemoveIngressIptablesRules(ctx, client, wlParams.Label, wlParams.AllowedCIDR, wlParams.DestIP, wlParams.Ports)
}

func (v *VSpherePlatform) PrepareRootLB(ctx context.Context, client ssh.Client, rootLBName string, secGrpName string, TrustPolicy *edgeproto.TrustPolicy, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "PrepareRootLB", "rootLBName", rootLBName)
	// configure iptables based security
	// allow our external vsphere network
	sshCidrsAllowed := []string{infracommon.RemoteCidrAll}
	egressRestricted := false

	var rules []edgeproto.SecurityRule
	if TrustPolicy != nil {
		rules = TrustPolicy.OutboundSecurityRules
		egressRestricted = true
	}
	return v.vmProperties.SetupIptablesRulesForRootLB(ctx, client, sshCidrsAllowed, egressRestricted, infracommon.TrustPolicySecGrpNameLabel, rules, false)
}

func (o *VSpherePlatform) ConfigureTrustPolicyExceptionSecurityRules(ctx context.Context, TrustPolicyException *edgeproto.TrustPolicyException, rootLbClients map[string]ssh.Client, action vmlayer.ActionType, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("Platform not supported for TrustPolicyException SecurityRules")
}
