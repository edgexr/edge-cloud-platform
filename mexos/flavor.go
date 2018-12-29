package mexos

import (
	"fmt"

	"github.com/mobiledgex/edge-cloud/log"
)

//AvailableClusterFlavors lists currently available flavors
var AvailableClusterFlavors = []*ClusterFlavor{
	&ClusterFlavor{
		Name:           "x1.tiny",
		Kind:           "mex-cluster-flavor",
		PlatformFlavor: "m4.small",
		Status:         "active",
		NumNodes:       2,
		NumMasterNodes: 1,
		Topology:       "type-1",
		NetworkSpec:    "priv-subnet,mex-k8s-net-1," + defaultPrivateNetRange,
		StorageSpec:    "default",
		NodeFlavor:     ClusterNodeFlavor{Name: "k8s-tiny", Type: "k8s-node"},
		MasterFlavor:   ClusterMasterFlavor{Name: "k8s-tiny", Type: "k8s-master"},
	},
	&ClusterFlavor{
		Name:           "x1.small",
		Kind:           "mex-cluster-flavor",
		PlatformFlavor: "m4.medium",
		Status:         "active",
		NumNodes:       2,
		NumMasterNodes: 1,
		Topology:       "type-1",
		NetworkSpec:    "priv-subnet,mex-k8s-net-1," + defaultPrivateNetRange,
		StorageSpec:    "default",
		NodeFlavor:     ClusterNodeFlavor{Name: "k8s-small", Type: "k8s-node"},
		MasterFlavor:   ClusterMasterFlavor{Name: "k8s-small", Type: "k8s-master"},
	},
	&ClusterFlavor{
		Name:           "x1.medium",
		Kind:           "mex-cluster-flavor",
		PlatformFlavor: "m4.large",
		Status:         "active",
		NumNodes:       2,
		NumMasterNodes: 1,
		Topology:       "type-1",
		NetworkSpec:    "priv-subnet,mex-k8s-net-1," + defaultPrivateNetRange,
		StorageSpec:    "default",
		NodeFlavor:     ClusterNodeFlavor{Name: "k8s-medium", Type: "k8s-node"},
		MasterFlavor:   ClusterMasterFlavor{Name: "k8s-medium", Type: "k8s-master"},
	},
	&ClusterFlavor{
		Name:           "x1.large",
		Kind:           "mex-cluster-flavor",
		PlatformFlavor: "m4.xlarge",
		Status:         "active",
		NumNodes:       2,
		NumMasterNodes: 1,
		Topology:       "type-1",
		NetworkSpec:    "priv-subnet,mex-k8s-net-1," + defaultPrivateNetRange,
		StorageSpec:    "default",
		NodeFlavor:     ClusterNodeFlavor{Name: "k8s-large", Type: "k8s-node"},
		MasterFlavor:   ClusterMasterFlavor{Name: "k8s-large", Type: "k8s-master"},
	},
}

func AddFlavorManifest(mf *Manifest) error {
	_, err := GetClusterFlavor(mf.Spec.Flavor)
	if err != nil {
		return err
	}
	// Adding flavors in platforms cannot be done dynamically. For example, x1.xlarge cannot be
	// implemented in currently DT cloudlets. Controller can learn what flavors available. Not create new ones.
	return nil
}

func GetClusterFlavor(flavor string) (*ClusterFlavor, error) {
	log.DebugLog(log.DebugLevelMexos, "get cluster flavor details", "cluster flavor", flavor)
	for _, af := range AvailableClusterFlavors {
		if af.Name == flavor {
			log.DebugLog(log.DebugLevelMexos, "using cluster flavor", "cluster flavor", af)
			return af, nil
		}
	}
	return nil, fmt.Errorf("unsupported cluster flavor %s", flavor)
}
