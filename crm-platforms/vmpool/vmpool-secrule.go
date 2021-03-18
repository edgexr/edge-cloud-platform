package vmpool

import (
	"context"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/log"

	ssh "github.com/mobiledgex/golang-ssh"
)

func (o *VMPoolPlatform) RemoveWhitelistSecurityRules(ctx context.Context, client ssh.Client, wlParams *infracommon.WhiteListParams) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "RemoveWhitelistSecurityRules not supported")
	return nil
}

func (o *VMPoolPlatform) WhitelistSecurityRules(ctx context.Context, client ssh.Client, wlParams *infracommon.WhiteListParams) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "WhitelistSecurityRules not supported")
	return nil
}
