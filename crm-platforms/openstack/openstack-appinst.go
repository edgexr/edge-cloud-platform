package openstack

import (
	"context"
)

func (o *OpenstackPlatform) GetConsoleUrl(ctx context.Context, serverName string) (string, error) {
	consoleUrl, err := o.OSGetConsoleUrl(ctx, serverName)
	if err != nil {
		return "", err
	}
	return consoleUrl.Url, nil
}
