package mexos

import (
	"fmt"

	"github.com/mobiledgex/edge-cloud/log"
)

// TODO: All of this needs to be taken from the controller config
//AvailableClusterFlavors lists currently available flavors
var AvailableClusterFlavors = []*ClusterFlavor{
	&ClusterFlavor{
		Name:           "x1.small",
		Kind:           "mex-cluster-flavor",
		PlatformFlavor: "m4.small",
		Status:         "active",
		NumNodes:       2,
		NumMasterNodes: 1,
		Topology:       "type-1",
		NetworkSpec:    "priv-subnet,mex-k8s-net-1," + defaultPrivateNetRange,
		StorageSpec:    "default",
		NodeFlavor:     ClusterNodeFlavor{Name: "m4.small", Type: "k8s-node"},
		MasterFlavor:   ClusterMasterFlavor{Name: "m4.small", Type: "k8s-master"},
	},
	&ClusterFlavor{
		Name:           "x1.medium",
		Kind:           "mex-cluster-flavor",
		PlatformFlavor: "m4.medium",
		Status:         "active",
		NumNodes:       2,
		NumMasterNodes: 1,
		Topology:       "type-1",
		NetworkSpec:    "priv-subnet,mex-k8s-net-1," + defaultPrivateNetRange,
		StorageSpec:    "default",
		NodeFlavor:     ClusterNodeFlavor{Name: "m4.medium", Type: "k8s-node"},
		MasterFlavor:   ClusterMasterFlavor{Name: "m4.medium", Type: "k8s-master"},
	},
	&ClusterFlavor{
		Name:           "x1.large",
		Kind:           "mex-cluster-flavor",
		PlatformFlavor: "m4.large",
		Status:         "active",
		NumNodes:       2,
		NumMasterNodes: 1,
		Topology:       "type-1",
		NetworkSpec:    "priv-subnet,mex-k8s-net-1," + defaultPrivateNetRange,
		StorageSpec:    "default",
		NodeFlavor:     ClusterNodeFlavor{Name: "m4.large", Type: "k8s-node"},
		MasterFlavor:   ClusterMasterFlavor{Name: "m4.large", Type: "k8s-master"},
	},
}

func GetClusterFlavor(flavor string) (*ClusterFlavor, error) {
	log.DebugLog(log.DebugLevelMexos, "get cluster flavor details", "cluster flavor", flavor)
	for _, af := range AvailableClusterFlavors {
		if af.Name == flavor {
			//log.DebugLog(log.DebugLevelMexos, "using cluster flavor", "cluster flavor", af)
			return af, nil
		}
	}
	return nil, fmt.Errorf("unsupported cluster flavor %s", flavor)
}
