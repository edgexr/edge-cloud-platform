package shepherd_test

import (
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	dme "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

var (
	// Test App/Cluster state data
	TestCloudletKey = edgeproto.CloudletKey{
		Organization: "testoperator",
		Name:         "testcloudlet",
	}
	TestClusterKey     = edgeproto.ClusterKey{Name: "testcluster"}
	TestClusterInstKey = edgeproto.ClusterInstKey{
		ClusterKey:   TestClusterKey,
		CloudletKey:  TestCloudletKey,
		Organization: "",
	}
	TestClusterInst = edgeproto.ClusterInst{
		Key:        TestClusterInstKey,
		Deployment: cloudcommon.AppDeploymentTypeDocker,
	}
	TestAppKey = edgeproto.AppKey{
		Name: "App",
	}
	TestApp = edgeproto.App{
		Key:         TestAppKey,
		AccessPorts: "tcp:1234",
		AccessType:  edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER,
	}
	TestAppInstKey = edgeproto.AppInstKey{
		AppKey:         TestAppKey,
		ClusterInstKey: TestClusterInstKey,
	}
	TestAppInst = edgeproto.AppInst{
		Key:         TestAppInstKey,
		State:       edgeproto.TrackedState_READY,
		HealthCheck: edgeproto.HealthCheck_HEALTH_CHECK_OK,
		MappedPorts: []dme.AppPort{
			dme.AppPort{
				Proto:      dme.LProto_L_PROTO_TCP,
				PublicPort: 1234,
			},
		},
	}
)
