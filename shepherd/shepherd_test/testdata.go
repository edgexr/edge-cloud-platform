// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package shepherd_test

import (
	"github.com/edgexr/edge-cloud/cloudcommon"
	dme "github.com/edgexr/edge-cloud/d-match-engine/dme-proto"
	"github.com/edgexr/edge-cloud/edgeproto"
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
		ClusterInstKey: *TestClusterInstKey.Virtual(""),
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
