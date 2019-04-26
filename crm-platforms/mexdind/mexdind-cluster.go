package mexdind

import (
	"fmt"

	"github.com/mobiledgex/edge-cloud-infra/mexos"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

func (s *Platform) CreateCluster(clusterInst *edgeproto.ClusterInst, flavor *edgeproto.ClusterFlavor) error {
	err := s.generic.CreateCluster(clusterInst, flavor)
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

func (s *Platform) DeleteCluster(clusterInst *edgeproto.ClusterInst) error {
	return s.generic.DeleteCluster(clusterInst)
}
