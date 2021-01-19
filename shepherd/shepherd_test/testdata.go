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
	TestCloudlet = edgeproto.Cloudlet{
		Key: TestCloudletKey,
	}
	TestClusterKey     = edgeproto.ClusterKey{Name: "testcluster"}
	TestClusterInstKey = edgeproto.ClusterInstKey{
		ClusterKey:   TestClusterKey,
		CloudletKey:  TestCloudletKey,
		Organization: "",
	}
	TestClusterInst = edgeproto.ClusterInst{
		Key:        TestClusterInstKey,
		Deployment: cloudcommon.DeploymentTypeDocker,
	}
	TestAutoProvPolicyKey = edgeproto.PolicyKey{
		Name: "autoprov",
	}
	TestAutoProvPolicy = edgeproto.AutoProvPolicy{
		Key:                   TestAutoProvPolicyKey,
		UndeployClientCount:   3,
		UndeployIntervalCount: 3,
		Cloudlets: []*edgeproto.AutoProvCloudlet{
			&edgeproto.AutoProvCloudlet{
				Key: TestCloudletKey,
			},
		},
	}
	TestAppKey = edgeproto.AppKey{
		Name: "App",
	}
	TestApp = edgeproto.App{
		Key:         TestAppKey,
		AccessPorts: "tcp:1234",
		AccessType:  edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER,
		AutoProvPolicies: []string{
			TestAutoProvPolicyKey.Name,
		},
	}
	TestAppInstKey = edgeproto.AppInstKey{
		AppKey:         TestAppKey,
		ClusterInstKey: TestClusterInstKey,
	}
	TestAppInst = edgeproto.AppInst{
		Key:         TestAppInstKey,
		State:       edgeproto.TrackedState_READY,
		HealthCheck: dme.HealthCheck_HEALTH_CHECK_OK,
		Liveness:    edgeproto.Liveness_LIVENESS_AUTOPROV,
		MappedPorts: []dme.AppPort{
			dme.AppPort{
				Proto:      dme.LProto_L_PROTO_TCP,
				PublicPort: 1234,
			},
		},
	}
)
