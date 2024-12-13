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

package osmk8s

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	"github.com/test-go/testify/require"
)

func createTestPlatform() *Platform {
	s := Platform{}
	s.accessVars = make(map[string]string)
	s.properties = &infracommon.InfraProperties{
		Properties: make(map[string]*edgeproto.PropertyInfo),
	}
	s.properties.SetProperties(Props)
	s.properties.SetValue(OSM_REGION, os.Getenv(OSM_REGION))
	s.properties.SetValue(OSM_VIM_ACCOUNT, os.Getenv(OSM_VIM_ACCOUNT))
	s.properties.SetValue(OSM_RESOURCE_GROUP, os.Getenv(OSM_RESOURCE_GROUP))
	s.properties.SetValue(OSM_SKIPVERIFY, os.Getenv(OSM_SKIPVERIFY))
	s.accessVars[OSM_USERNAME] = os.Getenv(OSM_USERNAME)
	s.accessVars[OSM_PASSWORD] = os.Getenv(OSM_PASSWORD)
	s.accessVars[OSM_URL] = os.Getenv(OSM_URL)
	return &s
}

var testClusterName = "unitTestCluster"
var getTestClusterInst = func() *edgeproto.ClusterInst {
	return &edgeproto.ClusterInst{
		NodePools: []*edgeproto.NodePool{{
			NumNodes: 1,
			NodeResources: &edgeproto.NodeResources{
				InfraNodeFlavor: "Standard_A2_v2", // Azure flavor
			},
		}},
		InfraAnnotations: map[string]string{},
	}
}

func TestCreateCluster(t *testing.T) {
	s := createTestPlatform()
	if s.accessVars[OSM_USERNAME] == "" {
		t.Skip("no creds")
	}
	log.SetDebugLevel(log.DebugLevelInfra | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	ci := getTestClusterInst()

	_, err := s.RunClusterCreateCommand(ctx, testClusterName, ci)
	require.Nil(t, err)

	// write credentials to file
	creds, err := s.GetCredentials(ctx, testClusterName, ci)
	require.Nil(t, err)
	err = os.WriteFile(testClusterName+".kconf", creds, 0644)
	require.Nil(t, err)
	fmt.Println("wrote kubeconfig to " + testClusterName + ".kconf")
}

func TestGetCredentials(t *testing.T) {
	s := createTestPlatform()
	if s.accessVars[OSM_USERNAME] == "" {
		t.Skip("no creds")
	}
	log.SetDebugLevel(log.DebugLevelInfra | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	ci := getTestClusterInst()
	creds, err := s.GetCredentials(ctx, testClusterName, ci)
	require.Nil(t, err)
	err = os.WriteFile(testClusterName+".kconf", creds, 0644)
	require.Nil(t, err)
	fmt.Println("wrote kubeconfig to " + testClusterName + ".kconf")
}

func TestScaleCluster(t *testing.T) {
	// assumes TestCreateCluster was run and cluster is present
	s := createTestPlatform()
	if s.accessVars[OSM_USERNAME] == "" {
		t.Skip("no creds")
	}
	log.SetDebugLevel(log.DebugLevelInfra | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	ci := getTestClusterInst()
	ci.NodePools[0].NumNodes = 2
	ci.Fields = []string{
		edgeproto.ClusterInstFieldNodePoolsNumNodes,
	}
	_, err := s.RunClusterUpdateCommand(ctx, testClusterName, ci)
	require.Nil(t, err)
}

func TestDeleteCluster(t *testing.T) {
	s := createTestPlatform()
	if s.accessVars[OSM_USERNAME] == "" {
		t.Skip("no creds")
	}
	log.SetDebugLevel(log.DebugLevelInfra | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	_, err := s.getClient(ctx)
	require.Nil(t, err)

	ci := getTestClusterInst()
	err = s.RunClusterDeleteCommand(ctx, testClusterName, ci)
	require.Nil(t, err)
}

func TestGatherCloudletInfo(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelInfra | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	s := Platform{}
	s.properties = &infracommon.InfraProperties{
		Properties: make(map[string]*edgeproto.PropertyInfo),
	}
	s.properties.SetProperties(Props)
	s.properties.SetValue(OSM_FLAVORS, `[{"name":"Standard_D2s_v3","vcpus":2,"ram":8192,"disk":16}]`)

	flavors := []*edgeproto.FlavorInfo{{
		Name:  "Standard_D2s_v3",
		Vcpus: 2,
		Ram:   8192,
		Disk:  16,
	}}
	info := &edgeproto.CloudletInfo{}
	err := s.GatherCloudletInfo(ctx, info)
	require.Nil(t, err)
	require.Equal(t, flavors, info.Flavors)
}
