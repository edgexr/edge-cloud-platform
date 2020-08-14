package vmpool

import (
	"context"
	"fmt"

	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

func (o *VMPoolPlatform) SaveCloudletAccessVars(ctx context.Context, cloudlet *edgeproto.Cloudlet, accessVarsIn map[string]string, pfConfig *edgeproto.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SaveCloudletAccessVars not supported")
	return nil
}

func (o *VMPoolPlatform) GetApiEndpointAddr(ctx context.Context) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetApiEndpointAddr not supported")
	return "", nil
}

func (o *VMPoolPlatform) GetCloudletManifest(ctx context.Context, name string, VMGroupOrchestrationParams *vmlayer.VMGroupOrchestrationParams) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetCloudletManifest", "name", name)
	if VMGroupOrchestrationParams == nil {
		return "", nil
	}
	if len(VMGroupOrchestrationParams.VMs) != 1 {
		return "", fmt.Errorf("invalid number of VMs")
	}
	chefParams := VMGroupOrchestrationParams.VMs[0].ChefParams
	if chefParams == nil {
		return "", fmt.Errorf("missing chef params for %s", name)
	}
	if chefParams.ClientKey == "" {
		return "", fmt.Errorf("missing chef client key for %s", chefParams.NodeName)
	}

	manifest := fmt.Sprintf(`
#!/bin/bash

cat > /home/ubuntu/client.pem << EOF
%s
EOF

sudo bash /etc/mobiledgex/setup-chef.sh -s "%s" -n "%s"
`, chefParams.ClientKey, chefParams.ServerPath, chefParams.NodeName)

	codeQuotes := "```"

	instructions := `
1) SSH into one of the VMs from the VMPool which has access to controller's notify port
2) Save and execute the following script on the VM
` + codeQuotes + manifest + codeQuotes

	return instructions, nil
}
