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

package azure

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	"github.com/test-go/testify/require"
)

func TestFlavors(t *testing.T) {
	a := createTestPlatform()
	if a.accessVars[AZURE_CLIENT_ID] == "" {
		t.Skip("no creds")
	}
	log.SetDebugLevel(log.DebugLevelInfra | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	err := a.Login(ctx)
	require.Nil(t, err)

	err = a.GatherCloudletInfo(ctx, &edgeproto.CloudletInfo{})
	require.Nil(t, err)
}

func getTestClusterName() string {
	return "unit-test-cluster-" + os.Getenv("USER")
}

func getTestClusterInst() edgeproto.ClusterInst {
	return edgeproto.ClusterInst{
		NodePools: []*edgeproto.NodePool{{
			NumNodes: 1,
			NodeResources: &edgeproto.NodeResources{
				InfraNodeFlavor: "Standard_A2_v2",
			},
		}},
	}
}

func TestClusterCreate(t *testing.T) {
	a := createTestPlatform()
	if a.accessVars[AZURE_CLIENT_ID] == "" {
		t.Skip("no creds")
	}
	log.SetDebugLevel(log.DebugLevelInfra | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	err := a.Login(ctx)
	require.Nil(t, err)

	start := time.Now()
	clusterName := getTestClusterName()
	ci := getTestClusterInst()
	_, err = a.RunClusterCreateCommand(ctx, clusterName, &ci)
	require.Nil(t, err)
	fmt.Printf("Cluster create took %s\n", time.Since(start).String())

	creds, err := a.GetCredentials(ctx, clusterName, &ci)
	require.Nil(t, err)
	kubeconfig := "/tmp/" + clusterName + ".kubeconfig"
	err = os.WriteFile(kubeconfig, creds, 0644)
	require.Nil(t, err)
	cmd := exec.Command("kubectl", "get", "pods")
	cmd.Env = append(cmd.Env, "KUBECONFIG="+kubeconfig)
	out, err := cmd.CombinedOutput()
	require.Nil(t, err, string(out))
}

func TestClusterDelete(t *testing.T) {
	a := createTestPlatform()
	if a.accessVars[AZURE_CLIENT_ID] == "" {
		t.Skip("no creds")
	}
	log.SetDebugLevel(log.DebugLevelInfra | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	err := a.Login(ctx)
	require.Nil(t, err)

	clusterName := getTestClusterName()
	ci := getTestClusterInst()
	err = a.RunClusterDeleteCommand(ctx, clusterName, &ci)
	require.Nil(t, err)
}

func createTestPlatform() *AzurePlatform {
	a := AzurePlatform{}
	a.accessVars = make(map[string]string)
	a.properties = &infracommon.InfraProperties{
		Properties: make(map[string]*edgeproto.PropertyInfo),
	}
	a.properties.SetProperties(azureProps)
	a.properties.SetValue(AZURE_LOCATION, os.Getenv(AZURE_LOCATION))
	a.accessVars[AZURE_SUBSCRIPTION_ID] = os.Getenv(AZURE_SUBSCRIPTION_ID)
	a.accessVars[AZURE_TENANT_ID] = os.Getenv(AZURE_TENANT_ID)
	a.accessVars[AZURE_CLIENT_ID] = os.Getenv(AZURE_CLIENT_ID)
	a.accessVars[AZURE_CLIENT_SECRET] = os.Getenv(AZURE_CLIENT_SECRET)
	a.accessVars[AZURE_RESOURCE_GROUP] = os.Getenv(AZURE_RESOURCE_GROUP)
	return &a
}
