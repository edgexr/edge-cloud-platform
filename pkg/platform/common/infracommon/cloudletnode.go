package infracommon

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/confignode"
)

// CreateCloudletNode requests the Controller via the accessApi
// to register a new cloudlet node, and stores the new password
// into ConfigureNodeVars.
func CreateCloudletNode(ctx context.Context, config *confignode.ConfigureNodeVars, accessApi platform.AccessApi) error {
	cloudletNode := &edgeproto.CloudletNode{
		Key:       config.Key,
		NodeType:  config.NodeType.String(),
		NodeRole:  config.NodeRole.String(),
		OwnerTags: config.OwnerKey.GetTags(),
	}
	password, err := accessApi.CreateCloudletNode(ctx, cloudletNode)
	if err != nil {
		return err
	}
	config.Password = password
	return nil
}
