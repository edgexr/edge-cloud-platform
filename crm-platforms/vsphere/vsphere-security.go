package vsphere

import (
	"context"

	"github.com/mobiledgex/edge-cloud/log"

	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	dme "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	ssh "github.com/mobiledgex/golang-ssh"
)

func (v *VSpherePlatform) WhitelistSecurityRules(ctx context.Context, client ssh.Client, secGrpName, serverName, label string, allowedCIDR string, ports []dme.AppPort) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "WhitelistSecurityRules", "secGrpName", secGrpName, "allowedCIDR", allowedCIDR, "ports", ports)
	// this can be called during LB init so we need to ensure we can reach the server before trying iptables commands
	err := vmlayer.WaitServerReady(ctx, v, client, serverName, vmlayer.MaxRootLBWait)
	if err != nil {
		return err
	}
	return vmlayer.AddIngressIptablesRules(ctx, client, label, allowedCIDR, ports)
}

func (v *VSpherePlatform) RemoveWhitelistSecurityRules(ctx context.Context, client ssh.Client, secGrpName, server, label string, allowedCIDR string, ports []dme.AppPort) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "RemoveWhitelistSecurityRules", "secGrpName", secGrpName, "allowedCIDR", allowedCIDR, "ports", ports)
	return vmlayer.RemoveIngressIptablesRules(ctx, client, label, allowedCIDR, ports)
}

func (v *VSpherePlatform) PrepareRootLB(ctx context.Context, client ssh.Client, rootLBName string, secGrpName string, TrustPolicy *edgeproto.TrustPolicy, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "PrepareRootLB", "rootLBName", rootLBName)
	// configure iptables based security
	// allow our external vsphere network
	sshCidrsAllowed := []string{}
	externalNet, err := v.GetExternalIpNetworkCidr(ctx)
	if err != nil {
		return err
	}
	sshCidrsAllowed = append(sshCidrsAllowed, externalNet)
	return v.vmProperties.SetupIptablesRulesForRootLB(ctx, client, sshCidrsAllowed, TrustPolicy)
}
