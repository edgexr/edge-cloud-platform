// Copyright 2024 EdgeXR, Inc
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

package osmclient

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/test-go/testify/require"
)

func createTestClient(t *testing.T) *OSMClient {
	accessVars, props := FromEnv()
	if accessVars[OSM_USERNAME] == "" {
		t.Skip("no creds")
	}

	s := OSMClient{}
	s.Init(accessVars, props)
	return &s
}

var testClusterName = "unitTestCluster"
var getTestClusterInst = func() *edgeproto.ClusterInst {
	return &edgeproto.ClusterInst{
		Key: edgeproto.ClusterKey{
			Name:         testClusterName,
			Organization: "dev",
		},
		NodePools: []*edgeproto.NodePool{{
			NumNodes: 1,
			NodeResources: &edgeproto.NodeResources{
				InfraNodeFlavor: "Standard_A2_v2", // Azure flavor
			},
		}},
		InfraAnnotations:     map[string]string{},
		CompatibilityVersion: cloudcommon.GetClusterInstCompatibilityVersion(),
	}
}

func TestCreateCluster(t *testing.T) {
	s := createTestClient(t)

	log.SetDebugLevel(log.DebugLevelInfra | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	ci := getTestClusterInst()

	start := time.Now()
	_, err := s.CreateCluster(ctx, testClusterName, ci)
	require.Nil(t, err)
	dur := time.Since(start)
	fmt.Printf("Cluster create command took %s\n", dur.String())

	nn, err := k8smgmt.GetKubeNames(ci, &edgeproto.App{}, &edgeproto.AppInst{})
	require.Nil(t, err)
	names := nn.GetKConfNames()

	// write credentials to file
	creds, err := s.GetCredentials(ctx, testClusterName, ci)
	require.Nil(t, err)
	err = os.WriteFile(names.KconfName, creds, 0644)
	require.Nil(t, err)
	fmt.Println("wrote kubeconfig to " + names.KconfName)
}

func TestGetCredentials(t *testing.T) {
	s := createTestClient(t)

	log.SetDebugLevel(log.DebugLevelInfra | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	ci := getTestClusterInst()
	testClusterName := "test-cluster-jkg"
	creds, err := s.GetCredentials(ctx, testClusterName, ci)
	require.Nil(t, err)
	nn, err := k8smgmt.GetKubeNames(ci, &edgeproto.App{}, &edgeproto.AppInst{})
	require.Nil(t, err)
	names := nn.GetKConfNames()
	err = os.WriteFile(names.KconfName, creds, 0644)
	require.Nil(t, err)
	fmt.Println("wrote kubeconfig to " + names.KconfName)
}

func TestScaleCluster(t *testing.T) {
	// assumes TestCreateCluster was run and cluster is present
	s := createTestClient(t)

	log.SetDebugLevel(log.DebugLevelInfra | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	ci := getTestClusterInst()
	ci.NodePools[0].NumNodes = 2
	ci.Fields = []string{
		edgeproto.ClusterInstFieldNodePoolsNumNodes,
	}
	err := s.ScaleCluster(ctx, testClusterName, ci)
	require.Nil(t, err)
}

func TestDeleteCluster(t *testing.T) {
	s := createTestClient(t)

	log.SetDebugLevel(log.DebugLevelInfra | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	ci := getTestClusterInst()
	err := s.DeleteCluster(ctx, testClusterName, ci)
	require.Nil(t, err)
}

func TestRegisterCluster(t *testing.T) {
	// this requires a cluster already existing.
	// Use the Azure unit-test to create a cluster.
	s := createTestClient(t)

	log.SetDebugLevel(log.DebugLevelInfra | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	clusterName := "unit-test-cluster-" + os.Getenv("USER")
	kcFile := "/tmp/" + clusterName + ".kubeconfig"
	kc, err := os.ReadFile(kcFile)
	require.Nil(t, err)

	id, err := s.RegisterCluster(ctx, clusterName, string(kc))
	require.Nil(t, err)
	fmt.Printf("registered cluster %s\n", id)
}
