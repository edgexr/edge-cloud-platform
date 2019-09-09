package shepherd_platform

import (
	"context"

	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

// Platform abstracts the underlying cloudlet platform.
type Platform interface {
	// GetType Returns the Cloudlet's stack type, i.e. Openstack, Azure, etc.
	GetType() string
	// Init is called once during shepherd startup.
	Init(ctx context.Context, key *edgeproto.CloudletKey, physicalName, vaultAddr string) error
	// Gets the IP for a cluster
	GetClusterIP(ctx context.Context, clusterInst *edgeproto.ClusterInst) (string, error)
	// Gets a platform client to be able to runn commands against (mainly for curling the prometheuses)
	GetPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst) (pc.PlatformClient, error)
	// Gets cloudlet-level metrics. This is platform-dependent, hence the common interfcae
	GetPlatformStats(ctx context.Context) (shepherd_common.CloudletMetrics, error)
}
