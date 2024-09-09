// Copyright 2024 EdgeXR, Inc
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

package controller

import (
	"context"
	fmt "fmt"
	"testing"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/ccrmdummy"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
	"github.com/stretchr/testify/require"
)

// TestAppInstGetPotentialClusters tests the algorithm to choose
// the best cluster from pre-existing clusters when the AppInst
// does not specify a specific one.
func TestAppInstGetPotentialClusters(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())
	testSvcs := testinit(ctx, t)
	defer testfinish(testSvcs)
	var err error

	dummy := regiondata.InMemoryStore{}
	dummy.Start()
	defer dummy.Stop()

	sync := regiondata.InitSync(&dummy)
	apis := NewAllApis(sync)
	sync.Start()
	defer sync.Done()
	responder := DefaultDummyInfoResponder(apis)
	responder.InitDummyInfoResponder()
	ccrm := ccrmdummy.StartDummyCCRM(ctx, testSvcs.DummyVault.Config, &dummy)
	registerDummyCCRMConn(t, ccrm)
	defer ccrm.Stop()

	reduceInfoTimeouts(t, ctx, apis)

	// group all cloudlets into a single zone.
	zone := testutil.ZoneData()[0]
	cloudletData := testutil.CloudletData()
	for ii := range cloudletData {
		cloudletData[ii].Key.Organization = zone.Key.Organization
		cloudletData[ii].Zone = zone.Key.Name
	}
	cloudletData[0].EnableDefaultServerlessCluster = true
	// match cloudletInfos
	cloudletInfoData := testutil.CloudletInfoData()
	for ii := range cloudletInfoData {
		cloudletInfoData[ii].Key.Organization = zone.Key.Organization
	}

	// create supporting data
	addTestPlatformFeatures(t, ctx, apis, testutil.PlatformFeaturesData())
	testutil.InternalFlavorCreate(t, apis.flavorApi, testutil.FlavorData())
	testutil.InternalGPUDriverCreate(t, apis.gpuDriverApi, testutil.GPUDriverData())
	testutil.InternalResTagTableCreate(t, apis.resTagTableApi, testutil.ResTagTableData())
	testutil.InternalZoneCreate(t, apis.zoneApi, testutil.ZoneData())
	testutil.InternalCloudletCreate(t, apis.cloudletApi, cloudletData)
	insertCloudletInfo(ctx, apis, cloudletInfoData)

	// create reservable ClusterInsts
	flavorData := testutil.FlavorData()
	reservD := edgeproto.ClusterInst{
		Key: edgeproto.ClusterKey{
			Name:         cloudcommon.BuildReservableClusterName(0, &cloudletData[2].Key),
			Organization: edgeproto.OrganizationEdgeCloud,
		},
		ZoneKey:     zone.Key,
		CloudletKey: cloudletData[2].Key,
		Flavor:      flavorData[0].Key,
		IpAccess:    edgeproto.IpAccess_IP_ACCESS_SHARED,
		Deployment:  cloudcommon.DeploymentTypeDocker,
		Reservable:  true,
	}
	reservK := edgeproto.ClusterInst{
		Key: edgeproto.ClusterKey{
			Name:         cloudcommon.BuildReservableClusterName(0, &cloudletData[3].Key),
			Organization: edgeproto.OrganizationEdgeCloud,
		},
		ZoneKey:     zone.Key,
		CloudletKey: cloudletData[3].Key,
		Flavor:      flavorData[0].Key,
		IpAccess:    edgeproto.IpAccess_IP_ACCESS_SHARED,
		Deployment:  cloudcommon.DeploymentTypeKubernetes,
		Reservable:  true,
	}
	_, err = apis.clusterInstApi.store.Put(ctx, &reservD, sync.SyncWait)
	require.Nil(t, err)
	_, err = apis.clusterInstApi.store.Put(ctx, &reservK, sync.SyncWait)
	require.Nil(t, err)
	// cloudlet 0 should have default MT cluster
	defaultMT0Key := cloudcommon.GetDefaultMTClustKey(cloudletData[0].Key)
	var defaultMT0 edgeproto.ClusterInst
	found := apis.clusterInstApi.store.Get(ctx, defaultMT0Key, &defaultMT0)
	require.True(t, found)
	// cloudlet 4 is a single k8s cluster platform
	singleMT4Key := cloudcommon.GetDefaultClustKey(cloudletData[4].Key, cloudletData[4].SingleKubernetesClusterOwner)
	var singleMT4 edgeproto.ClusterInst
	found = apis.clusterInstApi.store.Get(ctx, singleMT4Key, &singleMT4)
	require.True(t, found)

	appKey := edgeproto.AppKey{
		Organization: "devorg",
		Name:         "testapp",
		Version:      "1.0",
	}
	getApp := func() *edgeproto.App {
		return &edgeproto.App{
			Key:             appKey,
			ImageType:       edgeproto.ImageType_IMAGE_TYPE_DOCKER,
			AccessPorts:     "tcp:443",
			AccessType:      edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER,
			DefaultFlavor:   flavorData[0].Key,
			AllowServerless: false,
			ServerlessConfig: &edgeproto.ServerlessConfig{
				Vcpus: *edgeproto.NewUdec64(0, 500*edgeproto.DecMillis),
				Ram:   20,
			},
		}
	}
	getAppInst := func() *edgeproto.AppInst {
		return &edgeproto.AppInst{
			Key: edgeproto.AppInstKey{
				Name:         "testinst",
				Organization: "devorg",
			},
			AppKey:  appKey,
			ZoneKey: zone.Key,
			Flavor:  flavorData[0].Key,
		}
	}
	cctx := DefCallContext()

	verifyCloudlets := func(pcs []*potentialInstCloudlet, idxs ...int) {
		require.Equal(t, len(idxs), len(pcs))
		for ii, idx := range idxs {
			key := cloudletData[idx].Key
			require.Equal(t, key, pcs[ii].cloudlet.Key, "verify potentialCloudlet[%d] is cloudletData[%d], %s", ii, idx, key.GetKeyString())
		}
	}

	// Docker app without serverless config
	// should find reservD cluster
	// check potential cloudlets
	app := getApp()
	app.Deployment = cloudcommon.DeploymentTypeDocker
	ai := getAppInst()
	pclos, err := apis.appInstApi.getPotentialCloudlets(ctx, cctx, ai, app)
	require.Nil(t, err)
	verifyCloudlets(pclos, 3, 1, 2, 0)
	pclus, err := apis.appInstApi.getPotentialClusters(ctx, cctx, ai, app, pclos)
	require.Nil(t, err)
	require.Equal(t, 1, len(pclus))
	require.Equal(t, reservD.Key, pclus[0].existingCluster)

	// Kubernetes app without serverless config
	// should find reservK cluster
	app.Deployment = cloudcommon.DeploymentTypeKubernetes
	pclos, err = apis.appInstApi.getPotentialCloudlets(ctx, cctx, ai, app)
	require.Nil(t, err)
	verifyCloudlets(pclos, 3, 1, 2, 0)
	pclus, err = apis.appInstApi.getPotentialClusters(ctx, cctx, ai, app, pclos)
	require.Nil(t, err)
	require.Equal(t, 1, len(pclus))
	require.Equal(t, reservK.Key, pclus[0].existingCluster)

	// Docker app with serverless config
	// should find only reservD cluster
	app.Deployment = cloudcommon.DeploymentTypeDocker
	app.AllowServerless = true
	pclos, err = apis.appInstApi.getPotentialCloudlets(ctx, cctx, ai, app)
	require.Nil(t, err)
	verifyCloudlets(pclos, 3, 1, 2, 0)
	pclus, err = apis.appInstApi.getPotentialClusters(ctx, cctx, ai, app, pclos)
	require.Nil(t, err)
	require.Equal(t, 1, len(pclus))
	require.Equal(t, reservD.Key, pclus[0].existingCluster)

	// Kubernetes app with serverless should find
	// singleMT, defaultMT, and reservK
	app.Deployment = cloudcommon.DeploymentTypeKubernetes
	app.AllowServerless = true
	pclos, err = apis.appInstApi.getPotentialCloudlets(ctx, cctx, ai, app)
	require.Nil(t, err)
	verifyCloudlets(pclos, 3, 1, 4, 2, 0)
	pclus, err = apis.appInstApi.getPotentialClusters(ctx, cctx, ai, app, pclos)
	require.Nil(t, err)
	for _, pc := range pclus {
		fmt.Println(*pc)
	}
	require.Equal(t, 3, len(pclus))
	require.Equal(t, *singleMT4Key, pclus[0].existingCluster)
	require.Equal(t, *defaultMT0Key, pclus[1].existingCluster)
	require.Equal(t, reservK.Key, pclus[2].existingCluster)
}
