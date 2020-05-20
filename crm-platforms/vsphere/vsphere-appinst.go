package vsphere

import (
	"context"
	"fmt"

	"github.com/mobiledgex/edge-cloud/edgeproto"
)

func (v *VSpherePlatform) GetConsoleUrl(ctx context.Context, serverName string) (string, error) {
	return "", fmt.Errorf("GetConsoleUrl not implemented for vsphere ")

}

func (v *VSpherePlatform) AddAppImageIfNotPresent(ctx context.Context, app *edgeproto.App, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("AddAppImageIfNotPresent not implemented for vsphere ")
}
