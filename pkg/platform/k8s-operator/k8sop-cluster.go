package k8sop

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
)

func (s *K8sOperator) CreateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) error {
	return errors.New("create cluster should not be called for k8s operator")
}

func (s *K8sOperator) DeleteClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return errors.New("delete cluster should not be called for k8s operator")
}

func (s *K8sOperator) UpdateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return errors.New("update cluster should not be called for k8s operator")
}

func (s *K8sOperator) GetClusterInfraResources(ctx context.Context, clusterKey *edgeproto.ClusterInstKey) (*edgeproto.InfraResources, error) {
	return nil, fmt.Errorf("GetClusterInfraResources not implemented for k8s operator")
}
