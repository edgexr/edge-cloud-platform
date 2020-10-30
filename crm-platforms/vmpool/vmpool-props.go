package vmpool

import (
	"context"
	"fmt"

	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	pf "github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/vault"
)

var VMPoolProps = map[string]*edgeproto.PropertyInfo{
	"MEX_ROUTER": {
		Name:        "External Router Type",
		Description: vmlayer.GetSupportedRouterTypes(),
		// For VMPool, we don't mess with internal networking
		Value: vmlayer.NoConfigExternalRouter,
	},
}

func (o *VMPoolPlatform) GetProviderSpecificProps(ctx context.Context, pfconfig *pf.PlatformConfig, vaultConfig *vault.Config) (map[string]*edgeproto.PropertyInfo, error) {
	return VMPoolProps, nil
}

func (o *VMPoolPlatform) InitApiAccessProperties(ctx context.Context, key *edgeproto.CloudletKey, region, physicalName string, vaultConfig *vault.Config, vars map[string]string) error {
	return nil
}

func (o *VMPoolPlatform) GetApiAccessFilename() string {
	return ""
}

func (o *VMPoolPlatform) GetExternalGateway(ctx context.Context, extNetName string) (string, error) {
	if val, ok := o.VMProperties.CommonPf.Properties.GetValue("MEX_EXTERNAL_NETWORK_GATEWAY"); ok {
		return val, nil
	}
	return "", fmt.Errorf("Unable to find MEX_EXTERNAL_NETWORK_GATEWAY")
}
