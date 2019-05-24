package openstack

import (
	"github.com/mobiledgex/edge-cloud-infra/mexos"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

func (s *Platform) UpdateClusterInst(clusterInst *edgeproto.ClusterInst) error {
	lbName := s.rootLBName
	if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		lbName = cloudcommon.GetDedicatedLBFQDN(s.cloudletKey, &clusterInst.Key.ClusterKey)
	}
	return mexos.UpdateCluster(lbName, clusterInst)
}

func (s *Platform) CreateClusterInst(clusterInst *edgeproto.ClusterInst) error {
	lbName := s.rootLBName
	if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		lbName = cloudcommon.GetDedicatedLBFQDN(s.cloudletKey, &clusterInst.Key.ClusterKey)
	}
	return mexos.CreateCluster(lbName, clusterInst)
}

func (s *Platform) DeleteClusterInst(clusterInst *edgeproto.ClusterInst) error {
	lbName := s.rootLBName
	if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		lbName = cloudcommon.GetDedicatedLBFQDN(s.cloudletKey, &clusterInst.Key.ClusterKey)
	}
	return mexos.DeleteCluster(lbName, clusterInst)
}
