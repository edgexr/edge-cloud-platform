package vmpool

import (
	"context"
	"fmt"

	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

func (o *VMPoolPlatform) GetRouterDetail(ctx context.Context, routerName string) (*vmlayer.RouterDetail, error) {
	return nil, fmt.Errorf("Router not supported for VM Pool platform")
}

func (o *VMPoolPlatform) GetInternalPortPolicy() vmlayer.InternalPortAttachPolicy {
	return vmlayer.AttachPortNotSupported
}

func (o *VMPoolPlatform) ValidateAdditionalNetworks(ctx context.Context, additionalNets []string) error {
	return fmt.Errorf("Additional networks not supported in VMPool cloudlets")
}

func (v *VMPoolPlatform) ConfigureCloudletSecurityRules(ctx context.Context, egressRestricted bool, TrustPolicy *edgeproto.TrustPolicy, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}
