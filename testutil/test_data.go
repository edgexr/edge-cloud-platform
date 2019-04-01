package testutil

import (
	dme "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/util"
)

var FlavorData = []edgeproto.Flavor{
	edgeproto.Flavor{
		Key: edgeproto.FlavorKey{
			Name: "x1.tiny",
		},
		Ram:   1024,
		Vcpus: 1,
		Disk:  1,
	},
	edgeproto.Flavor{
		Key: edgeproto.FlavorKey{
			Name: "x1.small",
		},
		Ram:   2048,
		Vcpus: 2,
		Disk:  2,
	},
	edgeproto.Flavor{
		Key: edgeproto.FlavorKey{
			Name: "x1.medium",
		},
		Ram:   4096,
		Vcpus: 4,
		Disk:  4,
	},
	edgeproto.Flavor{
		Key: edgeproto.FlavorKey{
			Name: "x1.large",
		},
		Ram:   8192,
		Vcpus: 10,
		Disk:  40,
	},
}
var ClusterFlavorData = []edgeproto.ClusterFlavor{
	edgeproto.ClusterFlavor{
		Key: edgeproto.ClusterFlavorKey{
			Name: "c1.tiny",
		},
		NodeFlavor:   FlavorData[0].Key,
		MasterFlavor: FlavorData[0].Key,
		NumNodes:     2,
		MaxNodes:     2,
		NumMasters:   1,
	},
	edgeproto.ClusterFlavor{
		Key: edgeproto.ClusterFlavorKey{
			Name: "c1.small",
		},
		NodeFlavor:   FlavorData[1].Key,
		MasterFlavor: FlavorData[1].Key,
		NumNodes:     3,
		MaxNodes:     3,
		NumMasters:   1,
	},
	edgeproto.ClusterFlavor{
		Key: edgeproto.ClusterFlavorKey{
			Name: "c1.medium",
		},
		NodeFlavor:   FlavorData[2].Key,
		MasterFlavor: FlavorData[2].Key,
		NumNodes:     3,
		MaxNodes:     4,
		NumMasters:   1,
	},
	edgeproto.ClusterFlavor{
		Key: edgeproto.ClusterFlavorKey{
			Name: "c1.large",
		},
		NodeFlavor:   FlavorData[3].Key,
		MasterFlavor: FlavorData[3].Key,
		NumNodes:     10,
		MaxNodes:     15,
		NumMasters:   1,
	},
}
var DevData = []edgeproto.Developer{
	edgeproto.Developer{
		Key: edgeproto.DeveloperKey{
			Name: "Atlantic, Inc.",
		},
		Address: "1230 Midas Way #200, Sunnyvale, CA 94085",
		Email:   "edge.atlantic.com",
	},
	edgeproto.Developer{
		Key: edgeproto.DeveloperKey{
			Name: "Eaiever",
		},
		Address: "1 Letterman Drive Building C, San Francisco, CA 94129",
		Email:   "edge.everai.com",
	},
	edgeproto.Developer{
		Key: edgeproto.DeveloperKey{
			Name: "1000 realities",
		},
		Address: "Kamienna 43, 31-403 Kraken, Poland",
		Email:   "edge.Untomt.com",
	},
	edgeproto.Developer{
		Key: edgeproto.DeveloperKey{
			Name: "Sierraware LLC",
		},
		Address: "1250 Oakmead Parkway Suite 210, Sunnyvalue, CA 94085",
		Email:   "support@sierraware.com",
	},
}
var ClusterData = []edgeproto.Cluster{
	edgeproto.Cluster{
		Key: edgeproto.ClusterKey{
			Name: "Pillimos",
		},
		DefaultFlavor: ClusterFlavorData[0].Key,
	},
	edgeproto.Cluster{
		Key: edgeproto.ClusterKey{
			Name: "Ever.Ai",
		},
		DefaultFlavor: ClusterFlavorData[1].Key,
	},
	edgeproto.Cluster{
		Key: edgeproto.ClusterKey{
			Name: "Untomt",
		},
		DefaultFlavor: ClusterFlavorData[2].Key,
	},
	edgeproto.Cluster{
		Key: edgeproto.ClusterKey{
			Name: "Big-Pillimos",
		},
		DefaultFlavor: ClusterFlavorData[2].Key,
	},
}

var AppData = []edgeproto.App{
	edgeproto.App{
		Key: edgeproto.AppKey{
			DeveloperKey: DevData[0].Key,
			Name:         "Pillimo Go!",
			Version:      "1.0.0",
		},
		ImageType:     edgeproto.ImageType_ImageTypeDocker,
		AccessPorts:   "http:443,tcp:10002,udp:10002",
		DefaultFlavor: FlavorData[0].Key,
		Cluster:       ClusterData[0].Key,
	},
	edgeproto.App{
		Key: edgeproto.AppKey{
			DeveloperKey: DevData[0].Key,
			Name:         "Pillimo Go!",
			Version:      "1.0.1",
		},
		ImageType:     edgeproto.ImageType_ImageTypeDocker,
		AccessPorts:   "tcp:80,http:443",
		DefaultFlavor: FlavorData[0].Key,
	},
	edgeproto.App{
		Key: edgeproto.AppKey{
			DeveloperKey: DevData[0].Key,
			Name:         "Hunna Stoll Go! Go!",
			Version:      "0.0.1",
		},
		ImageType:     edgeproto.ImageType_ImageTypeDocker,
		AccessPorts:   "tcp:443,udp:11111",
		DefaultFlavor: FlavorData[1].Key,
	},
	edgeproto.App{
		Key: edgeproto.AppKey{
			DeveloperKey: DevData[1].Key,
			Name:         "AI",
			Version:      "1.2.0",
		},
		ImageType:     edgeproto.ImageType_ImageTypeQCOW,
		AccessPorts:   "http:8080",
		DefaultFlavor: FlavorData[1].Key,
	},
	edgeproto.App{
		Key: edgeproto.AppKey{
			DeveloperKey: DevData[2].Key,
			Name:         "my reality",
			Version:      "0.0.1",
		},
		ImageType:     edgeproto.ImageType_ImageTypeQCOW,
		AccessPorts:   "udp:1024",
		DefaultFlavor: FlavorData[2].Key,
		Cluster:       ClusterData[2].Key,
	},
	edgeproto.App{
		Key: edgeproto.AppKey{
			DeveloperKey: DevData[3].Key,
			Name:         "helmApp",
			Version:      "0.0.1",
		},
		Deployment:    "helm",
		AccessPorts:   "udp:2024",
		DefaultFlavor: FlavorData[2].Key,
		Cluster:       ClusterData[2].Key,
	},
}
var OperatorData = []edgeproto.Operator{
	edgeproto.Operator{
		Key: edgeproto.OperatorKey{
			Name: "UFGT Inc.",
		},
	},
	edgeproto.Operator{
		Key: edgeproto.OperatorKey{
			Name: "xmobx",
		},
	},
	edgeproto.Operator{
		Key: edgeproto.OperatorKey{
			Name: "Zerilu",
		},
	},
	edgeproto.Operator{
		Key: edgeproto.OperatorKey{
			Name: "Denton telecom",
		},
	},
}
var CloudletData = []edgeproto.Cloudlet{
	edgeproto.Cloudlet{
		Key: edgeproto.CloudletKey{
			OperatorKey: OperatorData[0].Key,
			Name:        "San Jose Site",
		},
		AccessUri:     "10.100.0.1",
		IpSupport:     edgeproto.IpSupport_IpSupportDynamic,
		NumDynamicIps: 100,
		Location: dme.Loc{
			Latitude:  37.338207,
			Longitude: -121.886330,
		},
	},
	edgeproto.Cloudlet{
		Key: edgeproto.CloudletKey{
			OperatorKey: OperatorData[0].Key,
			Name:        "New York Site",
		},
		AccessUri:     "ff.f8::1",
		IpSupport:     edgeproto.IpSupport_IpSupportDynamic,
		NumDynamicIps: 100,
		Location: dme.Loc{
			Latitude:  40.712776,
			Longitude: -74.005974,
		},
	},
	edgeproto.Cloudlet{
		Key: edgeproto.CloudletKey{
			OperatorKey: OperatorData[1].Key,
			Name:        "San Francisco Site",
		},
		AccessUri:     "172.24.0.1",
		IpSupport:     edgeproto.IpSupport_IpSupportDynamic,
		NumDynamicIps: 100,
		Location: dme.Loc{
			Latitude:  37.774929,
			Longitude: -122.419418,
		},
	},
	edgeproto.Cloudlet{
		Key: edgeproto.CloudletKey{
			OperatorKey: OperatorData[2].Key,
			Name:        "Hawaii Site",
		},
		AccessUri:     "***REMOVED***",
		IpSupport:     edgeproto.IpSupport_IpSupportDynamic,
		NumDynamicIps: 10,
		Location: dme.Loc{
			Latitude:  21.306944,
			Longitude: -157.858337,
		},
	},
}
var ClusterInstData = []edgeproto.ClusterInst{
	edgeproto.ClusterInst{
		Key: edgeproto.ClusterInstKey{
			ClusterKey:  ClusterData[0].Key,
			CloudletKey: CloudletData[0].Key,
		},
		Flavor:       ClusterData[0].DefaultFlavor,
		IpAccess:     edgeproto.IpAccess_IpAccessDedicated,
		NodeFlavor:   CloudletInfoData[0].Flavors[1].Name,
		MasterFlavor: CloudletInfoData[0].Flavors[1].Name,
	},
	edgeproto.ClusterInst{
		Key: edgeproto.ClusterInstKey{
			ClusterKey:  ClusterData[0].Key,
			CloudletKey: CloudletData[1].Key,
		},
		Flavor:       ClusterData[0].DefaultFlavor,
		IpAccess:     edgeproto.IpAccess_IpAccessShared,
		NodeFlavor:   CloudletInfoData[1].Flavors[1].Name,
		MasterFlavor: CloudletInfoData[1].Flavors[1].Name,
	},
	edgeproto.ClusterInst{
		Key: edgeproto.ClusterInstKey{
			ClusterKey:  ClusterData[0].Key,
			CloudletKey: CloudletData[2].Key,
		},
		Flavor:       ClusterData[0].DefaultFlavor,
		IpAccess:     edgeproto.IpAccess_IpAccessDedicatedOrShared,
		NodeFlavor:   CloudletInfoData[2].Flavors[2].Name,
		MasterFlavor: CloudletInfoData[2].Flavors[2].Name,
	},
	edgeproto.ClusterInst{
		Key: edgeproto.ClusterInstKey{
			ClusterKey:  ClusterData[1].Key,
			CloudletKey: CloudletData[0].Key,
		},
		Flavor:       ClusterData[1].DefaultFlavor,
		IpAccess:     edgeproto.IpAccess_IpAccessDedicated,
		NodeFlavor:   CloudletInfoData[0].Flavors[3].Name,
		MasterFlavor: CloudletInfoData[0].Flavors[3].Name,
	},
	edgeproto.ClusterInst{
		Key: edgeproto.ClusterInstKey{
			ClusterKey:  ClusterData[1].Key,
			CloudletKey: CloudletData[1].Key,
		},
		Flavor:       ClusterData[1].DefaultFlavor,
		IpAccess:     edgeproto.IpAccess_IpAccessShared,
		NodeFlavor:   CloudletInfoData[1].Flavors[0].Name,
		MasterFlavor: CloudletInfoData[1].Flavors[0].Name,
	},
	edgeproto.ClusterInst{
		Key: edgeproto.ClusterInstKey{
			ClusterKey:  ClusterData[2].Key,
			CloudletKey: CloudletData[2].Key,
		},
		Flavor:       ClusterData[2].DefaultFlavor,
		IpAccess:     edgeproto.IpAccess_IpAccessDedicated,
		NodeFlavor:   CloudletInfoData[2].Flavors[1].Name,
		MasterFlavor: CloudletInfoData[2].Flavors[1].Name,
	},
	edgeproto.ClusterInst{
		Key: edgeproto.ClusterInstKey{
			ClusterKey:  ClusterData[3].Key,
			CloudletKey: CloudletData[3].Key,
		},
		Flavor:       ClusterData[3].DefaultFlavor,
		NodeFlavor:   CloudletInfoData[3].Flavors[0].Name,
		MasterFlavor: CloudletInfoData[3].Flavors[0].Name,
	},
}

// These are the cluster insts that will be created automatically
// from appinsts that have not specified a cluster.
var ClusterInstAutoData = []edgeproto.ClusterInst{
	// from AppInstData[3] -> AppData[1]
	edgeproto.ClusterInst{
		Key: edgeproto.ClusterInstKey{
			ClusterKey: edgeproto.ClusterKey{
				Name: util.K8SSanitize("AutoCluster" + AppData[1].Key.Name),
			},
			CloudletKey: CloudletData[1].Key,
		},
		Flavor:       ClusterData[0].DefaultFlavor,
		NodeFlavor:   CloudletInfoData[1].Flavors[1].Name,
		MasterFlavor: CloudletInfoData[1].Flavors[1].Name,
		Auto:         true,
	},
	// from AppInstData[4] -> AppData[2]
	edgeproto.ClusterInst{
		Key: edgeproto.ClusterInstKey{
			ClusterKey: edgeproto.ClusterKey{
				Name: util.K8SSanitize("AutoCluster" + AppData[2].Key.Name),
			},
			CloudletKey: CloudletData[2].Key,
		},
		Flavor:       ClusterData[1].DefaultFlavor,
		NodeFlavor:   CloudletInfoData[2].Flavors[2].Name,
		MasterFlavor: CloudletInfoData[2].Flavors[2].Name,
		Auto:         true,
	},
}
var AppInstData = []edgeproto.AppInst{
	edgeproto.AppInst{
		Key: edgeproto.AppInstKey{
			AppKey:      AppData[0].Key,
			CloudletKey: CloudletData[0].Key,
			Id:          1,
		},
		CloudletLoc:    CloudletData[0].Location,
		ClusterInstKey: ClusterInstData[0].Key,
	},
	edgeproto.AppInst{
		Key: edgeproto.AppInstKey{
			AppKey:      AppData[0].Key,
			CloudletKey: CloudletData[0].Key,
			Id:          2,
		},
		CloudletLoc:    CloudletData[0].Location,
		ClusterInstKey: ClusterInstData[0].Key,
	},
	edgeproto.AppInst{
		Key: edgeproto.AppInstKey{
			AppKey:      AppData[0].Key,
			CloudletKey: CloudletData[1].Key,
			Id:          1,
		},
		CloudletLoc:    CloudletData[1].Location,
		ClusterInstKey: ClusterInstData[1].Key,
	},
	edgeproto.AppInst{
		Key: edgeproto.AppInstKey{
			AppKey:      AppData[1].Key,
			CloudletKey: CloudletData[1].Key,
			Id:          1,
		},
		CloudletLoc: CloudletData[1].Location,
		// ClusterInst is ClusterInstAutoData[0]
		ClusterInstKey: edgeproto.ClusterInstKey{
			ClusterKey: edgeproto.ClusterKey{
				Name: "autocluster",
			},
		},
	},
	edgeproto.AppInst{
		Key: edgeproto.AppInstKey{
			AppKey:      AppData[2].Key,
			CloudletKey: CloudletData[2].Key,
			Id:          1,
		},
		CloudletLoc: CloudletData[2].Location,
		// ClusterInst is ClusterInstAutoData[1]
		ClusterInstKey: edgeproto.ClusterInstKey{
			ClusterKey: edgeproto.ClusterKey{
				Name: "autocluster",
			},
		},
	},
	edgeproto.AppInst{
		Key: edgeproto.AppInstKey{
			AppKey:      AppData[5].Key,
			CloudletKey: CloudletData[2].Key,
			Id:          1,
		},
		CloudletLoc:    CloudletData[2].Location,
		ClusterInstKey: ClusterInstData[2].Key,
	},
}
var AppInstInfoData = []edgeproto.AppInstInfo{
	edgeproto.AppInstInfo{
		Key: AppInstData[0].Key,
	},
	edgeproto.AppInstInfo{
		Key: AppInstData[1].Key,
	},
	edgeproto.AppInstInfo{
		Key: AppInstData[2].Key,
	},
	edgeproto.AppInstInfo{
		Key: AppInstData[3].Key,
	},
	edgeproto.AppInstInfo{
		Key: AppInstData[4].Key,
	},
	edgeproto.AppInstInfo{
		Key: AppInstData[5].Key,
	},
}
var CloudletInfoData = []edgeproto.CloudletInfo{
	edgeproto.CloudletInfo{
		Key:         CloudletData[0].Key,
		State:       edgeproto.CloudletState_CloudletStateReady,
		OsMaxRam:    65536,
		OsMaxVcores: 16,
		OsMaxVolGb:  500,
		Flavors: []*edgeproto.FlavorInfo{
			&edgeproto.FlavorInfo{
				Name:  "flavor.tiny1",
				Vcpus: uint64(1),
				Ram:   uint64(512),
				Disk:  uint64(10),
			},
			&edgeproto.FlavorInfo{
				Name:  "flavor.tiny2",
				Vcpus: uint64(1),
				Ram:   uint64(1024),
				Disk:  uint64(10),
			},
			&edgeproto.FlavorInfo{
				Name:  "flavor.small",
				Vcpus: uint64(2),
				Ram:   uint64(1024),
				Disk:  uint64(20),
			},
			&edgeproto.FlavorInfo{
				Name:  "flavor.medium",
				Vcpus: uint64(4),
				Ram:   uint64(4096),
				Disk:  uint64(40),
			},
		},
	},
	edgeproto.CloudletInfo{
		Key:         CloudletData[1].Key,
		State:       edgeproto.CloudletState_CloudletStateReady,
		OsMaxRam:    65536,
		OsMaxVcores: 16,
		OsMaxVolGb:  500,
		Flavors: []*edgeproto.FlavorInfo{
			&edgeproto.FlavorInfo{
				Name:  "flavor.small1",
				Vcpus: uint64(2),
				Ram:   uint64(2048),
				Disk:  uint64(10),
			},
			&edgeproto.FlavorInfo{
				Name:  "flavor.small2",
				Vcpus: uint64(2),
				Ram:   uint64(1024),
				Disk:  uint64(20),
			},
		},
	},
	edgeproto.CloudletInfo{
		Key:         CloudletData[2].Key,
		State:       edgeproto.CloudletState_CloudletStateReady,
		OsMaxRam:    65536,
		OsMaxVcores: 16,
		OsMaxVolGb:  500,
		Flavors: []*edgeproto.FlavorInfo{
			&edgeproto.FlavorInfo{
				Name:  "flavor.medium1",
				Vcpus: uint64(4),
				Ram:   uint64(8192),
				Disk:  uint64(80),
			},
			&edgeproto.FlavorInfo{
				Name:  "flavor.medium2",
				Vcpus: uint64(4),
				Ram:   uint64(4096),
				Disk:  uint64(40),
			},
			&edgeproto.FlavorInfo{
				Name:  "flavor.medium3",
				Vcpus: uint64(4),
				Ram:   uint64(2048),
				Disk:  uint64(20),
			},
		},
	},
	edgeproto.CloudletInfo{
		Key:         CloudletData[3].Key,
		State:       edgeproto.CloudletState_CloudletStateReady,
		OsMaxRam:    65536,
		OsMaxVcores: 16,
		OsMaxVolGb:  500,
		Flavors: []*edgeproto.FlavorInfo{
			&edgeproto.FlavorInfo{
				Name:  "flavor.large",
				Vcpus: uint64(8),
				Ram:   uint64(101024),
				Disk:  uint64(100),
			},
			&edgeproto.FlavorInfo{
				Name:  "flavor.medium",
				Vcpus: uint64(4),
				Ram:   uint64(1),
				Disk:  uint64(1),
			},
		},
	},
}

// To figure out what resources are used on each Cloudlet,
// see ClusterInstData to see what clusters are instantiated on what Cloudlet.
var CloudletRefsData = []edgeproto.CloudletRefs{
	// ClusterInstData[0,3]:
	edgeproto.CloudletRefs{
		Key: CloudletData[0].Key,
		Clusters: []edgeproto.ClusterKey{
			ClusterData[0].Key,
			ClusterData[1].Key,
		},
		UsedRam:        GetCloudletUsedRam(0, 1),
		UsedVcores:     GetCloudletUsedVcores(0, 1),
		UsedDisk:       GetCloudletUsedDisk(0, 1),
		UsedDynamicIps: 2,
	},
	// ClusterInstData[1,4]:
	edgeproto.CloudletRefs{
		Key: CloudletData[1].Key,
		Clusters: []edgeproto.ClusterKey{
			ClusterData[0].Key,
			ClusterData[1].Key,
		},
		UsedRam:    GetCloudletUsedRam(0, 1),
		UsedVcores: GetCloudletUsedVcores(0, 1),
		UsedDisk:   GetCloudletUsedDisk(0, 1),
	},
	// ClusterInstData[2,5]:
	edgeproto.CloudletRefs{
		Key: CloudletData[2].Key,
		Clusters: []edgeproto.ClusterKey{
			ClusterData[0].Key,
			ClusterData[2].Key,
		},
		UsedRam:        GetCloudletUsedRam(0, 2),
		UsedVcores:     GetCloudletUsedVcores(0, 2),
		UsedDisk:       GetCloudletUsedDisk(0, 2),
		UsedDynamicIps: 1,
	},
	// ClusterInstData[2,6]:
	edgeproto.CloudletRefs{
		Key: CloudletData[3].Key,
		Clusters: []edgeproto.ClusterKey{
			ClusterData[3].Key,
		},
		UsedRam:    GetCloudletUsedRam(2),
		UsedVcores: GetCloudletUsedVcores(2),
		UsedDisk:   GetCloudletUsedDisk(2),
	},
}

// These Refs are after creating both cluster insts and app insts.
// Some of the app insts trigger creating auto-clusterinsts,
// and ports are reserved with the creation of app insts.
var CloudletRefsWithAppInstsData = []edgeproto.CloudletRefs{
	// ClusterInstData[0,3]: (dedicated,dedicated)
	// AppInstData[0,1] -> ports[http:443;http:443]:
	edgeproto.CloudletRefs{
		Key: CloudletData[0].Key,
		Clusters: []edgeproto.ClusterKey{
			ClusterData[0].Key,
			ClusterData[1].Key,
		},
		UsedRam:        GetCloudletUsedRam(0, 1),
		UsedVcores:     GetCloudletUsedVcores(0, 1),
		UsedDisk:       GetCloudletUsedDisk(0, 1),
		UsedDynamicIps: 2,
	},
	// ClusterInstData[1,4], ClusterInstAutoData[0]: (shared,shared,shared)
	// AppInstData[2,3] -> ports[http:443;tcp:80,http:443]
	edgeproto.CloudletRefs{
		Key: CloudletData[1].Key,
		Clusters: []edgeproto.ClusterKey{
			ClusterData[0].Key,
			ClusterData[1].Key,
			ClusterInstAutoData[0].Key.ClusterKey,
		},
		UsedRam:     GetCloudletUsedRam(0, 1, 0),
		UsedVcores:  GetCloudletUsedVcores(0, 1, 0),
		UsedDisk:    GetCloudletUsedDisk(0, 1, 0),
		RootLbPorts: map[int32]int32{80: 1, 443: 1, 10000: 1, 10001: 1, 10002: 1},
	},
	// ClusterInstData[2,5], ClusterInstAutoData[1]: (shared,dedicated,shared)
	// AppInstData[4,5] -> ports[tcp:443,udp:11111;udp:2024]
	edgeproto.CloudletRefs{
		Key: CloudletData[2].Key,
		Clusters: []edgeproto.ClusterKey{
			ClusterData[0].Key,
			ClusterData[2].Key,
			ClusterInstAutoData[1].Key.ClusterKey,
		},
		UsedRam:        GetCloudletUsedRam(0, 2, 1),
		UsedVcores:     GetCloudletUsedVcores(0, 2, 1),
		UsedDisk:       GetCloudletUsedDisk(0, 2, 1),
		UsedDynamicIps: 1,
		RootLbPorts:    map[int32]int32{443: 1, 11111: 1, 2024: 1},
	},
	// ClusterInstData[6]: (no app insts on this clusterinst) (shared)
	edgeproto.CloudletRefs{
		Key: CloudletData[3].Key,
		Clusters: []edgeproto.ClusterKey{
			ClusterData[3].Key,
		},
		UsedRam:    GetCloudletUsedRam(2),
		UsedVcores: GetCloudletUsedVcores(2),
		UsedDisk:   GetCloudletUsedDisk(2),
	},
}

func FindFlavorData(key *edgeproto.FlavorKey) *edgeproto.Flavor {
	for ii, _ := range FlavorData {
		if FlavorData[ii].Key.Matches(key) {
			return &FlavorData[ii]
		}
	}
	return nil
}

func GetCloudletUsedRam(indices ...int) uint64 {
	var ram uint64
	for _, idx := range indices {
		clflavor := ClusterFlavorData[idx]
		flavor := FindFlavorData(&clflavor.NodeFlavor)
		ram += flavor.Ram * uint64(clflavor.MaxNodes)
	}
	return ram
}

func GetCloudletUsedVcores(indices ...int) uint64 {
	var vcores uint64
	for _, idx := range indices {
		clflavor := ClusterFlavorData[idx]
		flavor := FindFlavorData(&clflavor.NodeFlavor)
		vcores += flavor.Vcpus * uint64(clflavor.MaxNodes)
	}
	return vcores
}

func GetCloudletUsedDisk(indices ...int) uint64 {
	var disk uint64
	for _, idx := range indices {
		clflavor := ClusterFlavorData[idx]
		flavor := FindFlavorData(&clflavor.NodeFlavor)
		disk += flavor.Disk * uint64(clflavor.MaxNodes)
	}
	return disk
}
