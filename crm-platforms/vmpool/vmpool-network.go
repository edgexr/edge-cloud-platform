package vmpool

import (
	"context"
	"fmt"

	ssh "github.com/mobiledgex/golang-ssh"

	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

func (o *VMPoolPlatform) GetRouterDetail(ctx context.Context, routerName string) (*vmlayer.RouterDetail, error) {
	return nil, fmt.Errorf("Router not supported for VM Pool platform")
}

func (o *VMPoolPlatform) GetInternalPortPolicy() vmlayer.InternalPortAttachPolicy {
	return vmlayer.AttachPortNotSupported
}

func (o *VMPoolPlatform) ValidateAdditionalNetworks(ctx context.Context, additionalNets map[string]vmlayer.NetworkType) error {
	return fmt.Errorf("Additional networks not supported in VMPool cloudlets")
}

func (v *VMPoolPlatform) ConfigureCloudletSecurityRules(ctx context.Context, egressRestricted bool, TrustPolicy *edgeproto.TrustPolicy, rootlbClients map[string]ssh.Client, action vmlayer.ActionType, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}
