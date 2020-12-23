package edgebox

import (
	"context"
	"fmt"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

func (e *EdgeboxPlatform) UpdateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("update not implemented")
}

func (e *EdgeboxPlatform) GetCloudletInfraResources(ctx context.Context) (*edgeproto.InfraResources, error) {
	return e.generic.GetCloudletInfraResources(ctx)
}

func (e *EdgeboxPlatform) GetClusterInfraResources(ctx context.Context, clusterKey *edgeproto.ClusterInstKey) (*edgeproto.InfraResources, error) {
	return e.generic.GetClusterInfraResources(ctx, clusterKey)
}

func (e *EdgeboxPlatform) CreateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) error {
	err := e.generic.CreateClusterInst(ctx, clusterInst, updateCallback, timeout)
	if err != nil {
		return err
	}
	// The rest is k8s specific
	if clusterInst.Deployment == cloudcommon.DeploymentTypeDocker {
		return nil
	}
	client, err := e.generic.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		return err
	}
	clusterName := clusterInst.Key.ClusterKey.Name

	err = infracommon.CreateClusterConfigMap(ctx, client, clusterInst)
	if err != nil {
		return fmt.Errorf("cannot create ConfigMap for: %s, err: %v", clusterName, err)
	}
	return nil
}

func (e *EdgeboxPlatform) DeleteClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return e.generic.DeleteClusterInst(ctx, clusterInst, updateCallback)
}
