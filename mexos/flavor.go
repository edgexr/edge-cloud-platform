package mexos

import (
	"fmt"

	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/log"
)

// TODO: All of this needs to be taken from the controller config
//AvailableClusterFlavors lists currently available flavors
var OpenstackClusterFlavors = []*ClusterFlavor{
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
var AzureClusterFlavors = []*ClusterFlavor{
	&ClusterFlavor{
		Name:           "x1.small",
		Kind:           "mex-cluster-flavor",
		PlatformFlavor: "Standard_DS1_v2", // 1-vCPU, 3.5G-Mem
		Status:         "active",
		NumNodes:       2,
		NumMasterNodes: 1,
		NodeFlavor:     ClusterNodeFlavor{Name: "Standard_DS1_v2", Type: "k8s-node"},
	},
	&ClusterFlavor{
		Name:           "x1.medium",
		Kind:           "mex-cluster-flavor",
		PlatformFlavor: "Standard_DS2_v2", // 2-vCPU, 7G-Mem
		Status:         "active",
		NumNodes:       2,
		NumMasterNodes: 1,
		NodeFlavor:     ClusterNodeFlavor{Name: "Standard_DS2_v2", Type: "k8s-node"},
	},
	&ClusterFlavor{
		Name:           "x1.large",
		Kind:           "mex-cluster-flavor",
		PlatformFlavor: "Standard_DS3_v2", // 4-vCPU, 14G-Mem
		Status:         "active",
		NumNodes:       2,
		NumMasterNodes: 1,
		NodeFlavor:     ClusterNodeFlavor{Name: "Standard_DS3_v2", Type: "k8s-node"},
	},
}

func GetClusterFlavor(flavor string) (*ClusterFlavor, error) {
	log.DebugLog(log.DebugLevelMexos, "get cluster flavor details", "cluster flavor", flavor)

	var AvailableClusterFlavors []*ClusterFlavor
	switch GetCloudletKind() {
	case cloudcommon.CloudletKindAzure:
		AvailableClusterFlavors = AzureClusterFlavors
	default:
		AvailableClusterFlavors = OpenstackClusterFlavors
	}

	for _, af := range AvailableClusterFlavors {
		if af.Name == flavor {
			//log.DebugLog(log.DebugLevelMexos, "using cluster flavor", "cluster flavor", af)
			return af, nil
		}
	}
	return nil, fmt.Errorf("unsupported cluster flavor %s", flavor)
}
