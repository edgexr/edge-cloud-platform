package vmpool

import (
	"context"
	"fmt"

	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
)

func (o *VMPoolPlatform) GetRouterDetail(ctx context.Context, routerName string) (*vmlayer.RouterDetail, error) {
	return nil, fmt.Errorf("Router not supported for VM Pool platform")
}

func (o *VMPoolPlatform) GetInternalPortPolicy() vmlayer.InternalPortAttachPolicy {
	return vmlayer.AttachPortNotSupported
}
