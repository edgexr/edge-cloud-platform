package k8sbm

import (
	"context"
	"fmt"
	"time"

	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

func (k *K8sBareMetalPlatform) CreateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateClusterInst")
	if clusterInst.Key.ClusterKey.Name == cloudcommon.DefaultMultiTenantCluster && clusterInst.Key.Organization == cloudcommon.OrganizationMobiledgeX {
		// The cluster that represents this Cloudlet's cluster.
		// This is a no-op as the cluster already exists.
		return nil
	}
	return fmt.Errorf("CreateClusterInst not supported on " + platformName())
}

func (k *K8sBareMetalPlatform) UpdateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("UpdateClusterInst not supported on " + platformName())
}

func (k *K8sBareMetalPlatform) DeleteClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("DeleteClusterInst not supported on " + platformName())
}
