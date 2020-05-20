package vsphere

import (
	"context"

	dme "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
	"github.com/mobiledgex/edge-cloud/log"
)

func (v *VSpherePlatform) AddSecurityRuleCIDRWithRetry(ctx context.Context, cidr string, proto string, group string, port string, serverName string) error {
	// TODO
	log.SpanLog(ctx, log.DebugLevelInfra, "vsphere AddSecurityRuleCIDRWithRetry not yet implemented")
	return nil
}

func (v *VSpherePlatform) WhitelistSecurityRules(ctx context.Context, secGrpName string, serverName string, allowedCIDR string, ports []dme.AppPort) error {
	// TODO
	log.SpanLog(ctx, log.DebugLevelInfra, "vsphere WhitelistSecurityRules not yet implemented")
	return nil
}
func (v *VSpherePlatform) RemoveWhitelistSecurityRules(ctx context.Context, secGrpName string, allowedCIDR string, ports []dme.AppPort) error {
	// TODO
	log.SpanLog(ctx, log.DebugLevelInfra, "vsphere RemoveWhitelistSecurityRules not yet implemented")
	return nil
}
