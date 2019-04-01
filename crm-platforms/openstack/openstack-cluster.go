package openstack

import (
	"github.com/mobiledgex/edge-cloud-infra/mexos"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

func (s *Platform) CreateCluster(clusterInst *edgeproto.ClusterInst, flavor *edgeproto.ClusterFlavor) error {
	return mexos.CreateCluster(s.rootLBName, clusterInst, flavor)
}

func (s *Platform) DeleteCluster(clusterInst *edgeproto.ClusterInst) error {
	return mexos.DeleteCluster(clusterInst)
}
