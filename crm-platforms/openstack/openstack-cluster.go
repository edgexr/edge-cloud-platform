package openstack

import (
	"context"
	"fmt"

	"github.com/mobiledgex/edge-cloud-infra/vmlayer"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

// GetMasterNameAndIP gets the name and IP address of the cluster's master node.
func (s *OpenstackPlatform) GetClusterMasterNameAndIP(ctx context.Context, clusterInst *edgeproto.ClusterInst) (string, string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "get master IP", "cluster", clusterInst.Key.ClusterKey.Name)
	srvs, err := s.ListServers(ctx)
	if err != nil {
		return "", "", fmt.Errorf("error getting server list: %v", err)

	}
	namePrefix := vmlayer.ClusterTypeKubernetesMasterLabel
	if clusterInst.Deployment == cloudcommon.AppDeploymentTypeDocker {
		namePrefix = vmlayer.ClusterTypeDockerVMLabel
	}

	nodeNameSuffix := k8smgmt.GetK8sNodeNameSuffix(&clusterInst.Key)
	masterName, err := s.FindClusterMaster(ctx, namePrefix, nodeNameSuffix, srvs)
	if err != nil {
		return "", "", fmt.Errorf("%s -- %s, %v", vmlayer.ServerDoesNotExistError, nodeNameSuffix, err)
	}
	masterIP, err := s.FindNodeIP(masterName, srvs)
	return masterName, masterIP, err
}
