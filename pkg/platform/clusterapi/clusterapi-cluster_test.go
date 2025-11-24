// Copyright 2025 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package clusterapi

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/accessapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	"github.com/stretchr/testify/require"
)

const CAPI_KUBECONFIG = "CAPI_KUBECONFIG"

// These tests require a Cluster API management cluster
// for clusterctl to interact with, plus some number of
// bare metal or virtual nodes available for provisioning.
// CAPI_KUBECONFIG points to the Cluster API management cluster.
// Then, set the ClusterAPI platform's env vars, for example:
// export ManagementNamespace=dc1
// export InfrastructureProvider=metal3
// export FloatingVIPs=192.168.222.201
// export FloatingVIPsSubnet=24
// export ImageURL="http://192.168.50.143/UBUNTU_24.04_NODE_IMAGE_K8S_v1.34.1.qcow2"
// export ImageFormat=qcow2
// export ImageChecksum=8bf730abc51e08ec87eb530c2595d25ff2ba2b51e08e60f6688c50b8bcf099d9
// export ImageChecksumType=sha256
// export DebugUserPassword=changeme
// export CAPI_KUBECONFIG=/home/user/go/src/github.com/edgexr/cluster-api-local/k3s.yaml

func createTestPlatform(t *testing.T) *ClusterAPI {
	kubeconfig := os.Getenv(CAPI_KUBECONFIG)
	if kubeconfig == "" {
		t.Skip(CAPI_KUBECONFIG + " not set")
	}

	kubeconfigData, err := os.ReadFile(kubeconfig)
	require.Nil(t, err)
	accessVars := map[string]string{
		cloudcommon.Kubeconfig: string(kubeconfigData),
	}
	properties := &infracommon.InfraProperties{}
	properties.Init()
	properties.SetProperties(Props)
	// for debug
	properties.Properties[DebugUserPassword] = &edgeproto.PropertyInfo{
		Value: os.Getenv(DebugUserPassword),
	}
	// get property values from env vars
	for key := range Props {
		if val, ok := os.LookupEnv(key); ok {
			fmt.Printf("setting property %s to %s\n", key, val)
			properties.SetValue(key, val)
		}
	}
	commonPf := &infracommon.CommonPlatform{
		PlatformConfig: &platform.PlatformConfig{
			CloudletKey: &edgeproto.CloudletKey{
				Name:         "testcloudlet",
				Organization: "oporg",
			},
			PlatformInitConfig: platform.PlatformInitConfig{
				AccessApi: &accessapi.TestHandler{
					AccessVars: accessVars,
					SkipVault:  true,
				},
			},
		},
	}
	capi := ClusterAPI{}
	err = capi.Init(accessVars, properties, commonPf, nil)
	require.Nil(t, err)
	return &capi
}

func getTestVip(t *testing.T, capi *ClusterAPI) string {
	vipsStr, ok := capi.properties.GetValue(cloudcommon.FloatingControlVIPs)
	if !ok {
		vipsStr, ok = capi.properties.GetValue(cloudcommon.FloatingVIPs)
	}
	require.True(t, ok)
	for ip := range util.IPRangesIter(vipsStr) {
		return ip
	}
	require.False(t, true, "no vips found")
	return ""
}

func createTestCluster(t *testing.T, capi *ClusterAPI) (*edgeproto.ClusterInst, string) {
	ci := &edgeproto.ClusterInst{
		Key: edgeproto.ClusterKey{
			Name:         "testcapi",
			Organization: "testorg",
		},
		CloudletKey: capi.cloudletKey,
		NodePools: []*edgeproto.NodePool{{
			Name:         "controlpool",
			NumNodes:     1,
			ControlPlane: true,
		}, {
			Name:     "workerpool",
			NumNodes: 2,
		}},
		KubernetesVersion: "v1.34.0",
		Annotations: map[string]string{
			cloudcommon.AnnotationControlVIP: getTestVip(t, capi),
		},
	}
	clusterName := capi.NameSanitize(k8smgmt.GetCloudletClusterName(ci))
	return ci, clusterName
}

func TestGenerateClusterManifest(t *testing.T) {
	// This test requires a Cluster API management cluster
	// for clusterctl to interact with.
	capi := createTestPlatform(t)

	log.SetDebugLevel(log.DebugLevelInfra | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	ci, clusterName := createTestCluster(t, capi)

	kubeconfig := os.Getenv(CAPI_KUBECONFIG)
	names := k8smgmt.KconfNames{
		KconfName: kubeconfig,
		KconfArg:  "--kubeconfig=" + kubeconfig,
	}

	manifest, err := capi.generateClusterManifest(ctx, &names, clusterName, ci, "caCertData")
	require.Nil(t, err)
	fmt.Println(manifest)
}

func TestCreateCluster(t *testing.T) {
	// This test requires a Cluster API management cluster
	// for clusterctl to interact with, plus 2 nodes
	// available for provisioning.
	capi := createTestPlatform(t)

	log.SetDebugLevel(log.DebugLevelInfra | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	ci, clusterName := createTestCluster(t, capi)

	_, err := capi.RunClusterCreateCommand(ctx, clusterName, ci, edgeproto.GetUnitTestUpdateCallback(ctx))
	require.Nil(t, err)
}

func TestUpdateCluster(t *testing.T) {
	// This test requires a Cluster API management cluster
	// for clusterctl to interact with, plus 3 nodes
	// available for provisioning.
	capi := createTestPlatform(t)

	log.SetDebugLevel(log.DebugLevelInfra | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	ci, clusterName := createTestCluster(t, capi)
	// add worker node
	ci.NodePools[1].NumNodes += 1

	_, err := capi.RunClusterUpdateCommand(ctx, clusterName, ci, edgeproto.GetUnitTestUpdateCallback(ctx))
	require.Nil(t, err)
}

func TestDeleteCluster(t *testing.T) {
	// This test requires a Cluster API management cluster
	// for clusterctl to interact with.
	capi := createTestPlatform(t)

	log.SetDebugLevel(log.DebugLevelInfra | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	ci, clusterName := createTestCluster(t, capi)

	err := capi.RunClusterDeleteCommand(ctx, clusterName, ci, edgeproto.GetUnitTestUpdateCallback(ctx))
	require.Nil(t, err)
}
