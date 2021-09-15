package shepherd_platform

import (
	"context"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	ssh "github.com/mobiledgex/golang-ssh"
)

// Platform abstracts the underlying cloudlet platform.
type Platform interface {
	// Init is called once during shepherd startup.
	Init(ctx context.Context, pc *platform.PlatformConfig, caches *platform.Caches) error
	// Set VMPool in cache
	SetVMPool(ctx context.Context, vmPool *edgeproto.VMPool)
	// Gets the IP for a cluster
	GetClusterIP(ctx context.Context, clusterInst *edgeproto.ClusterInst) (string, error)
	// Gets a platform client to be able to run commands against (mainly for curling the prometheuses)
	GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error)
	// Gets a rootLb ssh client for VM apps
	GetVmAppRootLbClient(ctx context.Context, app *edgeproto.AppInstKey) (ssh.Client, error)
	// Gets cloudlet-level metrics. This is platform-dependent, hence the common interfcae
	GetPlatformStats(ctx context.Context) (shepherd_common.CloudletMetrics, error)
	// Get VM metrics - this is really a set of AppMetrics
	GetVmStats(ctx context.Context, key *edgeproto.AppInstKey) (shepherd_common.AppMetrics, error)
	// Get Platform Specific collection time. If the platform doesn't have periodic collection, it will return 0
	GetMetricsCollectInterval() time.Duration
	// Inform the platform that a VM App was added or deleted
	VmAppChangedCallback(ctx context.Context)
	// Check if the platform is running locally
	IsPlatformLocal(ctx context.Context) bool
}
