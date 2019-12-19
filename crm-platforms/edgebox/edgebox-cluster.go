package edgebox

import (
	"context"
	"fmt"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/mexos"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

func (s *Platform) UpdateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("update not implemented")
}

func (s *Platform) CreateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) error {
	err := s.generic.CreateClusterInst(ctx, clusterInst, updateCallback, timeout)
	if err != nil {
		return err
	}
	// The rest is k8s specific
	if clusterInst.Deployment == cloudcommon.AppDeploymentTypeDocker {
		return nil
	}
	client, err := s.generic.GetPlatformClient(ctx, clusterInst)
	if err != nil {
		return err
	}
	clusterName := clusterInst.Key.ClusterKey.Name

	err = mexos.CreateClusterConfigMap(ctx, client, clusterInst)
	if err != nil {
		return fmt.Errorf("cannot create ConfigMap for: %s, err: %v", clusterName, err)
	}
	return nil
}

func (s *Platform) DeleteClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst) error {
	return s.generic.DeleteClusterInst(ctx, clusterInst)
}
