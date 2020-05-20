package shepherd_platform

import (
	"context"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	ssh "github.com/mobiledgex/golang-ssh"
)

// Platform abstracts the underlying cloudlet platform.
type Platform interface {
	// GetType Returns the Cloudlet's stack type, i.e. Openstack, Azure, etc.
	GetType() string
	// Init is called once during shepherd startup.
	Init(ctx context.Context, key *edgeproto.CloudletKey, region, physicalName, vaultAddr, appDNSRoot string, vars map[string]string) error
	// Gets the IP for a cluster
	GetClusterIP(ctx context.Context, clusterInst *edgeproto.ClusterInst) (string, error)
	// Gets a platform client to be able to run commands against (mainly for curling the prometheuses)
	GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst) (ssh.Client, error)
	// Gets cloudlet-level metrics. This is platform-dependent, hence the common interfcae
	GetPlatformStats(ctx context.Context) (shepherd_common.CloudletMetrics, error)
	// Get VM metrics - this is really a set of AppMetrics
	GetVmStats(ctx context.Context, key *edgeproto.AppInstKey) (shepherd_common.AppMetrics, error)
	// Get Platform Specific collection time. If the platform doesn't have periodic collection, it will return 0
	GetMetricsCollectInterval() time.Duration
}
