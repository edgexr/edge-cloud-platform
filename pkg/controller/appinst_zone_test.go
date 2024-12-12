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
	"sort"
	"testing"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/ccrmdummy"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"github.com/edgexr/edge-cloud-platform/pkg/resspec"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
	"github.com/stretchr/testify/require"
)

func TestAppInstGetPotentialCloudletClusters(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi | log.DebugLevelNotify)
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

	devorg := "devorg"
	other := "other"
	docker := cloudcommon.DeploymentTypeDocker
	kubernetes := cloudcommon.DeploymentTypeKubernetes

	cloudletData := testutil.CloudletData()
	cloudletInfoData := testutil.CloudletInfoData()
	features := testutil.PlatformFeaturesData()

	// supporting data
	addTestPlatformFeatures(t, ctx, apis, features)
	testutil.InternalFlavorCreate(t, apis.flavorApi, testutil.FlavorData())
	testutil.InternalGPUDriverCreate(t, apis.gpuDriverApi, testutil.GPUDriverData())
	testutil.InternalResTagTableCreate(t, apis.resTagTableApi, testutil.ResTagTableData())
	testutil.InternalZoneCreate(t, apis.zoneApi, testutil.ZoneData())
	testutil.InternalCloudletCreate(t, apis.cloudletApi, cloudletData)
	insertCloudletInfo(ctx, apis, cloudletInfoData)

	makePC := func() *potentialInstCloudlet {
		pc := &potentialInstCloudlet{
			cloudlet:     cloudletData[0],
			cloudletInfo: cloudletInfoData[0],
			features:     &features[0],
			flavorLookup: cloudletInfoData[0].GetFlavorLookup(),
		}
		err := pc.initResCalc(ctx, apis, nil)
		require.Nil(t, err)
		return pc
	}
	makeClust := func(name, org string) *edgeproto.ClusterInst {
		return &edgeproto.ClusterInst{
			Key: edgeproto.ClusterKey{
				Name:         name,
				Organization: org,
			},
			IpAccess:   edgeproto.IpAccess_IP_ACCESS_SHARED,
			Deployment: cloudcommon.DeploymentTypeKubernetes,
			NodeResources: &edgeproto.NodeResources{
				Vcpus: 2,
				Ram:   4096,
				Disk:  100,
			},
			NodePools: []*edgeproto.NodePool{{
				Name:     "cpupool",
				NumNodes: 1,
				NodeResources: &edgeproto.NodeResources{
					Vcpus: 2,
					Ram:   4096,
					Disk:  100,
				},
			}},
			KubernetesVersion: "1.29",
			State:             edgeproto.TrackedState_READY,
		}
	}
	makeApp := func(name, deployment string) *edgeproto.App {
		app := &edgeproto.App{
			Key: edgeproto.AppKey{
				Name:         name,
				Version:      "1.0",
				Organization: devorg,
			},
			ImageType:       edgeproto.ImageType_IMAGE_TYPE_DOCKER,
			AccessPorts:     "tcp:443",
			AccessType:      edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER,
			Deployment:      deployment,
			AllowServerless: true,
		}
		if deployment == docker {
			app.NodeResources = &edgeproto.NodeResources{
				Vcpus: 2,
				Ram:   1024,
				Disk:  20,
			}
		} else {
			app.KubernetesResources = &edgeproto.KubernetesResources{
				CpuPool: &edgeproto.NodePoolResources{
					TotalVcpus:  *edgeproto.NewUdec64(2, 0),
					TotalMemory: 20,
				},
			}
		}
		return app
	}
	makeAppInst := func(name string, app *edgeproto.App) *edgeproto.AppInst {
		return &edgeproto.AppInst{
			Key: edgeproto.AppInstKey{
				Name:         name,
				Organization: devorg,
			},
			AppKey:              app.Key,
			KubernetesResources: app.KubernetesResources,
			NodeResources:       app.NodeResources,
		}
	}
	type usedAppInst struct {
		ci  *edgeproto.ClusterInst
		app *edgeproto.App
		ai  *edgeproto.AppInst
	}
	var noused []*usedAppInst

	runTest := func(app *edgeproto.App, ai *edgeproto.AppInst, cis []*edgeproto.ClusterInst, used []*usedAppInst, expNames []string) {
		pc := makePC()
		candidates := []edgeproto.ClusterKey{}
		// create test clusters
		for _, ci := range cis {
			_, err = apis.clusterInstApi.store.Put(ctx, ci, sync.SyncWait)
			require.Nil(t, err)
			candidates = append(candidates, ci.Key)
		}
		// create "used" data
		for _, u := range used {
			_, err = apis.appApi.store.Put(ctx, u.app, sync.SyncWait)
			require.Nil(t, err)
			_, err = apis.appInstApi.store.Put(ctx, u.ai, sync.SyncWait)
			require.Nil(t, err)
			refs := &edgeproto.ClusterRefs{}
			if !apis.clusterRefsApi.store.Get(ctx, &u.ci.Key, refs) {
				refs.Key = u.ci.Key
			}
			refs.Apps = append(refs.Apps, u.ai.Key)
			_, err = apis.clusterRefsApi.store.Put(ctx, refs, sync.SyncWait)
			require.Nil(t, err)
		}
		cctx := DefCallContext()
		// test call
		pclusts := apis.appInstApi.getPotentialCloudletClusters(ctx, cctx, ai, app, pc, candidates)
		names := []string{}
		// verify results
		for _, pclust := range pclusts {
			names = append(names, pclust.existingCluster.Name)
		}
		require.Equal(t, expNames, names)
		// clean up
		for _, u := range used {
			_, err = apis.appApi.store.Delete(ctx, u.app, sync.SyncWait)
			require.Nil(t, err)
			_, err = apis.appInstApi.store.Delete(ctx, u.ai, sync.SyncWait)
			require.Nil(t, err)
			refs := &edgeproto.ClusterRefs{
				Key: u.ci.Key,
			}
			_, err = apis.clusterRefsApi.store.Delete(ctx, refs, sync.SyncWait)
			require.Nil(t, err)
		}
		for _, ci := range cis {
			_, err = apis.clusterInstApi.store.Delete(ctx, ci, sync.SyncWait)
			require.Nil(t, err)
		}
	}

	t.Run("deployment-filter", func(t *testing.T) {
		// test that we filter by deployment type
		cik := makeClust("k", devorg)
		cik.Deployment = kubernetes
		cid := makeClust("d", devorg)
		cid.Deployment = docker
		clusts := []*edgeproto.ClusterInst{cik, cid}

		app := makeApp("app", kubernetes)
		ai := makeAppInst("ai", app)
		runTest(app, ai, clusts, noused, []string{"k"})

		app = makeApp("app", docker)
		ai = makeAppInst("ai", app)
		runTest(app, ai, clusts, noused, []string{"d"})

		app = makeApp("app", cloudcommon.DeploymentTypeHelm)
		ai = makeAppInst("ai", app)
		runTest(app, ai, clusts, noused, []string{"k"})

		app = makeApp("app", cloudcommon.DeploymentTypeVM)
		ai = makeAppInst("ai", app)
		runTest(app, ai, clusts, noused, []string{})
	})
	t.Run("serverless-filter", func(t *testing.T) {
		cik := makeClust("k", devorg)
		cikmt := makeClust("mt", devorg)
		cikmt.MultiTenant = true
		clusts := []*edgeproto.ClusterInst{cik, cikmt}

		app := makeApp("app", kubernetes)
		app.AllowServerless = false
		ai := makeAppInst("ai", app)
		runTest(app, ai, clusts, noused, []string{"k"})

		app.AllowServerless = true
		runTest(app, ai, clusts, noused, []string{"k", "mt"})
	})
	t.Run("k8sversion-filter", func(t *testing.T) {
		ci129 := makeClust("k1.29", devorg)
		ci129.KubernetesVersion = "1.29"
		ci130 := makeClust("k1.30", devorg)
		ci130.KubernetesVersion = "1.30"
		ci131 := makeClust("k1.31", devorg)
		ci131.KubernetesVersion = "1.31"
		clusts := []*edgeproto.ClusterInst{ci129, ci130, ci131}

		app := makeApp("app", kubernetes)
		app.KubernetesResources.MinKubernetesVersion = "1.29"
		ai := makeAppInst("ai", app)
		runTest(app, ai, clusts, noused, []string{"k1.29", "k1.30", "k1.31"})

		app.KubernetesResources.MinKubernetesVersion = "1.30"
		runTest(app, ai, clusts, noused, []string{"k1.30", "k1.31"})

		app.KubernetesResources.MinKubernetesVersion = "1.31"
		runTest(app, ai, clusts, noused, []string{"k1.31"})

		app.KubernetesResources.MinKubernetesVersion = "1.32"
		runTest(app, ai, clusts, noused, []string{})

		app.KubernetesResources.MinKubernetesVersion = ""
		runTest(app, ai, clusts, noused, []string{"k1.29", "k1.30", "k1.31"})
	})
	t.Run("owner-filter", func(t *testing.T) {
		owned := makeClust("owned", devorg)
		ownedOther := makeClust("other", other)
		resOwned := makeClust("resOwned", edgeproto.OrganizationEdgeCloud)
		resOwned.Reservable = true
		resOwned.ReservedBy = devorg
		resOther := makeClust("resOther", edgeproto.OrganizationEdgeCloud)
		resOther.Reservable = true
		resOther.ReservedBy = other
		resFree := makeClust("resFree", edgeproto.OrganizationEdgeCloud)
		resFree.Reservable = true
		resFree.ReservedBy = ""
		mt := makeClust("mt", edgeproto.OrganizationEdgeCloud)
		mt.MultiTenant = true
		clusts := []*edgeproto.ClusterInst{owned, ownedOther, resOwned, resOther, resFree, mt}

		// match devorg
		app := makeApp("app", kubernetes)
		ai := makeAppInst("ai", app)
		runTest(app, ai, clusts, noused, []string{"owned", "resOwned", "resFree", "mt"})

		// match other org
		app = makeApp("app", kubernetes)
		app.Key.Organization = other
		ai = makeAppInst("ai", app)
		ai.Key.Organization = other
		runTest(app, ai, clusts, noused, []string{"other", "resOther", "resFree", "mt"})
	})
	t.Run("resfits-filter", func(t *testing.T) {
		space := makeClust("space", devorg)
		lowspace := makeClust("lowspace", devorg)
		lowspace.NodePools[0].NodeResources.Vcpus = 1
		lowspaceScalable := makeClust("lowspaceScalable", devorg)
		lowspaceScalable.NodePools[0].NodeResources.Vcpus = 1
		lowspaceScalable.NodePools[0].Scalable = true
		// these clusters have an AppInst already deployed that is
		// using up all the resources
		blockerApp := makeApp("bocker", kubernetes)
		used := makeClust("used", devorg)
		usedAi := &usedAppInst{
			ci:  used,
			app: blockerApp,
			ai:  makeAppInst("blocker", blockerApp),
		}
		usedScalable := makeClust("usedScalable", devorg)
		usedScalable.NodePools[0].Scalable = true
		usedScalableAi := &usedAppInst{
			ci:  usedScalable,
			app: blockerApp,
			ai:  makeAppInst("blockerScalable", blockerApp),
		}
		clusts := []*edgeproto.ClusterInst{space, lowspace, lowspaceScalable, used, usedScalable}
		usedAIs := []*usedAppInst{usedAi, usedScalableAi}

		reqRes := &edgeproto.KubernetesResources{
			CpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(2, 0),
				TotalMemory: 20,
			},
		}
		reqResLow := &edgeproto.KubernetesResources{
			CpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(1, 0),
				TotalMemory: 20,
			},
		}
		reqResHigh := &edgeproto.KubernetesResources{
			CpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(5, 0),
				TotalMemory: 20,
			},
		}

		// test default resources
		app := makeApp("app", kubernetes)
		app.KubernetesResources = reqRes
		ai := makeAppInst("ai", app)
		runTest(app, ai, clusts, usedAIs, []string{"space", "lowspaceScalable", "usedScalable"})

		// test low resources
		app = makeApp("app", kubernetes)
		app.KubernetesResources = reqResLow
		ai = makeAppInst("ai", app)
		runTest(app, ai, clusts, usedAIs, []string{"space", "lowspace", "lowspaceScalable", "usedScalable"})

		// test high resources
		app = makeApp("app", kubernetes)
		app.KubernetesResources = reqResHigh
		ai = makeAppInst("ai", app)
		runTest(app, ai, clusts, usedAIs, []string{"lowspaceScalable", "usedScalable"})
	})
}

func TestPotentialAppInstClusterSort(t *testing.T) {
	type spec struct {
		name           string
		clusterType    ClusterType
		hasScaleSpec   bool
		resScore       uint64
		parentResScore uint64
	}
	runTest := func(specs []spec, expOrder []string) {
		pcs := []*potentialAppInstCluster{}
		for _, s := range specs {
			pc := potentialAppInstCluster{}
			pc.existingCluster.Name = s.name
			pc.clusterType = s.clusterType
			pc.resourceScore = s.resScore
			pc.parentPC = &potentialInstCloudlet{}
			pc.parentPC.resourceScore = s.parentResScore
			if s.hasScaleSpec {
				pc.scaleSpec = &resspec.KubeResScaleSpec{}
			}
			pcs = append(pcs, &pc)
		}
		sort.Sort(PotentialAppInstClusterByResource(pcs))
		order := []string{}
		for _, pc := range pcs {
			order = append(order, pc.existingCluster.Name)
		}
		require.Equal(t, expOrder, order)
	}
	t.Run("sort-by-scalespec", func(t *testing.T) {
		specs := []spec{
			{"noscale", ClusterTypeOwned, false, 1, 1},
			{"scale1", ClusterTypeOwned, true, 1, 1},
			{"scale2", ClusterTypeOwned, true, 1, 2},
			{"scale3", ClusterTypeOwned, true, 1, 30304},
		}
		runTest(specs, []string{"noscale", "scale3", "scale2", "scale1"})
	})
	t.Run("sort-by-type", func(t *testing.T) {
		specs := []spec{
			{"unknown", ClusterTypeUnknown, false, 1, 1},
			{"mt", ClusterTypeMultiTenant, false, 1, 1},
			{"owned", ClusterTypeOwned, false, 1, 1},
			{"ownedres", ClusterTypeOwnedReservable, false, 1, 1},
			{"freeres", ClusterTypeFreeReservable, false, 1, 1},
		}
		runTest(specs, []string{"owned", "ownedres", "mt", "freeres", "unknown"})
	})
	t.Run("sort-by-res", func(t *testing.T) {
		specs := []spec{
			{"3", ClusterTypeOwned, false, 3, 0},
			{"1", ClusterTypeOwned, false, 1, 0},
			{"9", ClusterTypeOwned, false, 9, 0},
			{"7", ClusterTypeOwned, false, 7, 0},
			{"0", ClusterTypeOwned, false, 0, 0},
			{"3000", ClusterTypeOwned, false, 3000, 0},
		}
		runTest(specs, []string{"3000", "9", "7", "3", "1", "0"})
	})
}

func TestPotentialAppInstClusterCalcResourceScore(t *testing.T) {
	var tests = []struct {
		desc     string
		free     func() resspec.ResValMap
		expScore uint64
	}{{
		desc:     "free nil",
		expScore: 0,
	}, {
		desc: "free res 1",
		free: func() resspec.ResValMap {
			res := resspec.ResValMap{}
			res.AddVcpus(4, 500*edgeproto.DecMillis)
			return res
		},
		expScore: 4500, // (4.5*1000)/1
	}, {
		desc: "free res 2",
		free: func() resspec.ResValMap {
			res := resspec.ResValMap{}
			res.AddVcpus(4, 500*edgeproto.DecMillis)
			res.AddRam(10000)
			return res
		},
		expScore: 7250, // (4.5*1000 + 10000*1)/2
	}, {
		desc: "free res 3 ignore 1",
		free: func() resspec.ResValMap {
			res := resspec.ResValMap{}
			res.AddVcpus(4, 500*edgeproto.DecMillis)
			res.AddRam(10000)
			res.AddRes("foo", "", 20, 0)
			return res
		},
		expScore: 7250, // (4.5*1000 + 10000*1)/2
	}}
	for _, test := range tests {
		clusterInstApi := &ClusterInstApi{}
		var free resspec.ResValMap
		if test.free != nil {
			free = test.free()
		}
		score := clusterInstApi.calcResourceScore(free)
		require.Equal(t, test.expScore, score, fmt.Sprintf("%s: expected %d but was %d", test.desc, test.expScore, score))
	}
}
