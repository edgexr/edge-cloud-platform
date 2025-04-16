// Copyright 2025 EdgeXR, Inc
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
	"encoding/json"
	"fmt"
	"testing"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/test-go/testify/require"
)

func getTestAppInst(t *testing.T, app *edgeproto.App, clusterName string) *edgeproto.AppInst {
	ai := edgeproto.AppInst{}
	ai.Key.Organization = app.Key.Organization
	ai.Key.Name = "test-appinst"
	ai.AppKey = app.Key
	ai.ClusterKey.Name = clusterName
	ai.ClusterKey.Organization = app.Key.Organization
	ai.KubernetesResources = app.KubernetesResources
	ai.CompatibilityVersion = cloudcommon.GetAppInstCompatibilityVersion()
	return &ai
}

func TestCreateAppInst(t *testing.T) {
	s := createTestClient(t)

	log.SetDebugLevel(log.DebugLevelInfra | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	// assumes a test cluster must exist
	clusterName := testClusterName

	app := getTestApp(t)
	appInst := getTestAppInst(t, app, clusterName)
	names, err := k8smgmt.GetKubeNames(&edgeproto.ClusterInst{}, app, appInst)
	require.Nil(t, err)

	_, err = s.CreateAppInst(ctx, names, clusterName, app, appInst)
	require.Nil(t, err)
}

func TestDeleteAppInst(t *testing.T) {
	s := createTestClient(t)

	log.SetDebugLevel(log.DebugLevelInfra | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	clusterName := "azure-jontest-acmeappco"
	//clusterName := testClusterName

	app := getTestApp(t)
	appInst := getTestAppInst(t, app, clusterName)
	err := s.DeleteAppInst(ctx, appInst)
	require.Nil(t, err)
}

func TestListAppInst(t *testing.T) {
	s := createTestClient(t)

	log.SetDebugLevel(log.DebugLevelInfra | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	ksus, err := s.ListKSU(ctx)
	require.Nil(t, err)
	for _, ksu := range ksus {
		out, err := json.MarshalIndent(ksu, "", "  ")
		require.Nil(t, err)
		fmt.Println(string(out))
	}
}
