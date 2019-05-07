package mexdind

import (
	"fmt"

	"github.com/mobiledgex/edge-cloud-infra/mexos"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

func (s *Platform) UpdateClusterInst(clusterInst *edgeproto.ClusterInst) error {
	return fmt.Errorf("update not implemented")
}

func (s *Platform) CreateClusterInst(clusterInst *edgeproto.ClusterInst) error {
	err := s.generic.CreateClusterInst(clusterInst)
	if err != nil {
		return err
	}
	client, err := s.generic.GetPlatformClient(clusterInst)
	if err != nil {
		return err
	}
	clusterName := clusterInst.Key.ClusterKey.Name

	err = mexos.CreateDockerRegistrySecret(client, clusterInst)
	if err != nil {
		return fmt.Errorf("cannot create mexreg secret for: %s, err: %v", clusterName, err)
	}
	err = mexos.CreateClusterConfigMap(client, clusterInst)
	if err != nil {
		return fmt.Errorf("cannot create ConfigMap for: %s, err: %v", clusterName, err)
	}
	return nil
}

func (s *Platform) DeleteClusterInst(clusterInst *edgeproto.ClusterInst) error {
	return s.generic.DeleteClusterInst(clusterInst)
}
