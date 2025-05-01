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

package controller

import (
	"context"
	"strconv"
	"testing"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/ccrmdummy"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
	"github.com/stretchr/testify/require"
)

func TestSiteNodeApi(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	testSvcs := testinit(ctx, t)
	defer testfinish(testSvcs)

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

	addTestPlatformFeatures(t, ctx, apis, testutil.PlatformFeaturesData())
	cloudletData := testutil.CloudletData()
	cloudletInfoData := testutil.CloudletInfoData()
	testutil.InternalFlavorCreate(t, apis.flavorApi, testutil.FlavorData())
	testutil.InternalGPUDriverCreate(t, apis.gpuDriverApi, testutil.GPUDriverData())
	testutil.InternalResTagTableCreate(t, apis.resTagTableApi, testutil.ResTagTableData())
	testutil.InternalZoneCreate(t, apis.zoneApi, testutil.ZoneData())
	testutil.InternalCloudletCreate(t, apis.cloudletApi, cloudletData)
	insertCloudletInfo(ctx, apis, cloudletInfoData)

	// create supporting data
	zone := testutil.ZoneData()[0]
	zone.Key.Name = "sitenodes"
	_, err := apis.zoneApi.CreateZone(ctx, &zone)
	require.Nil(t, err)
	defer func() {
		_, err = apis.zoneApi.DeleteZone(ctx, &zone)
		require.Nil(t, err)
	}()

	features := testutil.PlatformFeaturesData()[0]
	features.PlatformType = platform.PlatformTypeFakeSiteNodes
	features.NodeUsage = edgeproto.NodeUsageUserDefined
	apis.platformFeaturesApi.Update(ctx, &features, 0)
	defer func() {
		apis.platformFeaturesApi.Delete(ctx, &features, 0)
	}()

	cloudlet := cloudletData[0].Clone()
	cloudlet.Key.Name = "sitenodes"
	cloudlet.PlatformType = features.PlatformType
	cloudlet.Zone = zone.Key.Name
	cloudlet2 := cloudletData[1].Clone()
	cloudlet2.Key.Name = "sitenodes2"
	cloudlet2.PlatformType = features.PlatformType
	cloudlet2.Zone = zone.Key.Name
	for _, cl := range []*edgeproto.Cloudlet{cloudlet, cloudlet2} {
		err = apis.cloudletApi.CreateCloudlet(cl, testutil.NewCudStreamoutCloudlet(ctx))
		require.Nil(t, err)
		defer func() {
			err = apis.cloudletApi.DeleteCloudlet(cl, testutil.NewCudStreamoutCloudlet(ctx))
			require.Nil(t, err)
		}()
	}

	cloudletInfo := &edgeproto.CloudletInfo{}
	cloudletInfo.Key = cloudlet.Key
	cloudletInfo2 := &edgeproto.CloudletInfo{}
	cloudletInfo2.Key = cloudlet2.Key
	for _, cinfo := range []*edgeproto.CloudletInfo{cloudletInfo, cloudletInfo2} {
		cinfo.State = dme.CloudletState_CLOUDLET_STATE_READY
		apis.cloudletInfoApi.store.Put(ctx, cinfo, apis.cloudletInfoApi.sync.SyncWait)
		defer func() {
			apis.cloudletInfoApi.store.Delete(ctx, cinfo, apis.cloudletInfoApi.sync.SyncWait)
		}()
	}

	testBadSiteNodes(t, ctx, apis, cloudlet.Key, cloudletData)
	testSiteNodeRefs(t, ctx, apis, cloudlet.Key, cloudlet2.Key, cloudletData)
	testSiteNodeResourceCheck(t, ctx, apis, zone.Key, cloudlet.Key)
}

func testBadSiteNodes(t *testing.T, ctx context.Context, apis *AllApis, cloudletKey edgeproto.CloudletKey, cloudletData []edgeproto.Cloudlet) {
	goodNode := &edgeproto.Node{
		Key: edgeproto.NodeKey{
			Name:         "testNode",
			Organization: cloudletKey.Organization,
		},
		CloudletKey:   cloudletKey,
		PublicAddr:    "10.10.10.10",
		Username:      "testUser",
		SkipNodeCheck: true,
	}
	templateNode := goodNode.Clone()
	templateNode.Key.Name = "templateNode"
	templateNode.PublicAddr = "10.10.10.11"

	// this test should pass
	_, err := apis.nodeApi.CreateNode(ctx, goodNode)
	require.Nil(t, err)
	defer func() {
		_, err = apis.nodeApi.DeleteNode(ctx, goodNode)
		require.Nil(t, err)
	}()

	var tests = []struct {
		desc    string
		modfunc func(*edgeproto.Node)
		expErr  string
	}{{
		desc:    "test passes",
		modfunc: func(node *edgeproto.Node) {},
	}, {
		desc: "cloudlet does not support site nodes",
		modfunc: func(node *edgeproto.Node) {
			node.CloudletKey = cloudletData[0].Key
		},
		expErr: "specified cloudlet does not use nodes",
	}, {
		desc: "missing public address",
		modfunc: func(node *edgeproto.Node) {
			node.PublicAddr = ""
		},
		expErr: "invalid public address, empty hostname or IP",
	}, {
		desc: "missing username",
		modfunc: func(node *edgeproto.Node) {
			node.Username = ""
		},
		expErr: "username cannot be empty",
	}, {
		desc: "bad ssh port",
		modfunc: func(node *edgeproto.Node) {
			node.SshPort = 99999
		},
		expErr: "invalid ssh port 99999",
	}, {
		desc: "public address conflict",
		modfunc: func(node *edgeproto.Node) {
			node.PublicAddr = "10.10.10.10"
		},
		expErr: "public address 10.10.10.10 already registered",
	}, {
		desc: "mgmt address conflict",
		modfunc: func(node *edgeproto.Node) {
			node.MgmtAddr = "10.10.10.10"
		},
		expErr: "management SSH address 10.10.10.11:22 already registered",
	}}
	for _, test := range tests {
		testNode := templateNode.Clone()
		test.modfunc(testNode)
		_, err = apis.nodeApi.CreateNode(ctx, testNode)
		if test.expErr == "" {
			require.Nil(t, err, test.desc)
			_, err = apis.nodeApi.DeleteNode(ctx, testNode)
			require.Nil(t, err, test.desc)
		} else {
			require.NotNil(t, err, test.desc)
			require.Contains(t, err.Error(), test.expErr, test.desc)
		}
	}
}

func testSiteNodeRefs(t *testing.T, ctx context.Context, apis *AllApis, cloudletKey, cloudletKey2 edgeproto.CloudletKey, cloudletData []edgeproto.Cloudlet) {
	refs1 := &edgeproto.CloudletNodeRefs{}
	found := apis.cloudletNodeRefsApi.cache.Get(&cloudletKey, refs1)
	require.False(t, found)

	genNode := func(id int, ckey edgeproto.CloudletKey) *edgeproto.Node {
		node := &edgeproto.Node{
			Key: edgeproto.NodeKey{
				Name:         "node" + strconv.Itoa(id),
				Organization: ckey.Organization,
			},
			CloudletKey:   ckey,
			PublicAddr:    "10.10.10." + strconv.Itoa(id),
			Username:      "testUser",
			SkipNodeCheck: true,
		}
		return node
	}
	node1 := genNode(1, cloudletKey)
	node2 := genNode(2, cloudletKey)
	node3 := genNode(3, cloudletKey2)

	badNode := genNode(4, cloudletData[0].Key) // not a site node cloudlet

	// verify add refs
	for _, node := range []*edgeproto.Node{node1, node2, node3} {
		_, err := apis.nodeApi.CreateNode(ctx, node)
		require.Nil(t, err)
	}
	log.SpanLog(ctx, log.DebugLevelApi, "created site nodes")
	refs1 = &edgeproto.CloudletNodeRefs{}
	found = apis.cloudletNodeRefsApi.cache.Get(&cloudletKey, refs1)
	require.True(t, found)
	require.Equal(t, 2, len(refs1.Nodes), refs1.Nodes)
	require.Equal(t, []edgeproto.NodeKey{node1.Key, node2.Key}, refs1.Nodes)
	refs2 := &edgeproto.CloudletNodeRefs{}
	found = apis.cloudletNodeRefsApi.cache.Get(&cloudletKey2, refs2)
	require.True(t, found)
	require.Equal(t, 1, len(refs2.Nodes))
	require.Equal(t, []edgeproto.NodeKey{node3.Key}, refs2.Nodes)

	// verify change refs
	node2.CloudletKey = cloudletKey2
	node2.SkipNodeCheck = true
	node2.Fields = []string{
		edgeproto.NodeFieldCloudletKey,
		edgeproto.NodeFieldSkipNodeCheck,
	}
	_, err := apis.nodeApi.UpdateNode(ctx, node2)
	require.Nil(t, err)
	log.SpanLog(ctx, log.DebugLevelApi, "updated site node2")
	refs1 = &edgeproto.CloudletNodeRefs{}
	found = apis.cloudletNodeRefsApi.cache.Get(&cloudletKey, refs1)
	require.True(t, found)
	require.Equal(t, 1, len(refs1.Nodes), refs1.Nodes)
	require.Equal(t, []edgeproto.NodeKey{node1.Key}, refs1.Nodes)
	refs2 = &edgeproto.CloudletNodeRefs{}
	found = apis.cloudletNodeRefsApi.cache.Get(&cloudletKey2, refs2)
	require.True(t, found)
	require.Equal(t, 2, len(refs2.Nodes), refs2.Nodes)
	require.Equal(t, []edgeproto.NodeKey{node3.Key, node2.Key}, refs2.Nodes)

	// verify delete refs
	// delete node3, refs reduced
	_, err = apis.nodeApi.DeleteNode(ctx, node3)
	require.Nil(t, err)
	log.SpanLog(ctx, log.DebugLevelApi, "deleted site node3")
	refs2 = &edgeproto.CloudletNodeRefs{}
	found = apis.cloudletNodeRefsApi.cache.Get(&cloudletKey2, refs2)
	require.True(t, found)
	require.Equal(t, 1, len(refs2.Nodes))
	require.Equal(t, []edgeproto.NodeKey{node2.Key}, refs2.Nodes)
	// delete node2, refs deleted
	_, err = apis.nodeApi.DeleteNode(ctx, node2)
	require.Nil(t, err)
	log.SpanLog(ctx, log.DebugLevelApi, "deleted site node2")
	refs2 = &edgeproto.CloudletNodeRefs{}
	found = apis.cloudletNodeRefsApi.cache.Get(&cloudletKey2, refs2)
	require.False(t, found)
	// delete node1, refs deleted
	_, err = apis.nodeApi.DeleteNode(ctx, node1)
	require.Nil(t, err)
	log.SpanLog(ctx, log.DebugLevelApi, "deleted site node1")
	refs1 = &edgeproto.CloudletNodeRefs{}
	found = apis.cloudletNodeRefsApi.cache.Get(&cloudletKey, refs1)
	require.False(t, found)

	// verify bad cloudlet does not create refs
	_, err = apis.nodeApi.CreateNode(ctx, badNode)
	require.NotNil(t, err)
	refsBad := &edgeproto.CloudletNodeRefs{}
	found = apis.cloudletNodeRefsApi.cache.Get(&badNode.CloudletKey, refsBad)
	require.False(t, found)
}

func testSiteNodeResourceCheck(t *testing.T, ctx context.Context, apis *AllApis, zkey edgeproto.ZoneKey, ckey edgeproto.CloudletKey) {
	genNode := func(id int, vcpus, mem uint64) *edgeproto.Node {
		node := &edgeproto.Node{
			Key: edgeproto.NodeKey{
				Name:         "resnode" + strconv.Itoa(id),
				Organization: ckey.Organization,
			},
			CloudletKey:   ckey,
			PublicAddr:    "10.10.11." + strconv.Itoa(id),
			Username:      "testUser",
			SkipNodeCheck: true,
			NodeResources: &edgeproto.NodeResources{
				Vcpus: vcpus,
				Ram:   mem,
			},
			Health: edgeproto.NodeHealthOnline,
		}
		return node
	}

	// create 4 different node sizes
	numSizes := 4
	poolSize := 4
	nodes := []*edgeproto.Node{}
	for i := range numSizes {
		factor := 1 << (i + 1)
		vcpus := uint64(factor)
		ram := uint64(factor * 1024)
		log.SpanLog(ctx, log.DebugLevelApi, "create node size", "vcpus", vcpus, "ram", ram)
		// create 4 of each node size, only 3 usable
		for j := range poolSize {
			node := genNode(numSizes*i+j, vcpus, ram)
			if j == 3 {
				node.Health = edgeproto.NodeHealthOffline
			}
			_, err := apis.nodeApi.CreateNode(ctx, node)
			require.Nil(t, err)
			nodes = append(nodes, node)
		}
	}
	defer func() {
		for _, node := range nodes {
			_, err := apis.nodeApi.DeleteNode(ctx, node)
			require.Nil(t, err)
		}
	}()

	// verify that cloudlet info was populated with node flavors
	info := &edgeproto.CloudletInfo{}
	found := apis.cloudletInfoApi.cache.Get(&ckey, info)
	require.True(t, found)
	require.Equal(t, numSizes, len(info.Flavors), info.Flavors)

	var tests = []struct {
		desc          string
		usedNR        *edgeproto.NodeResources
		usedPools     []*edgeproto.NodePool
		nodeResources *edgeproto.NodeResources
		nodePools     []*edgeproto.NodePool
		expErr        string
		expNodes      [][]string // for kubernetes
		expNodeName   string     // for docker
	}{{
		desc: "k8s small nodes",
		nodePools: []*edgeproto.NodePool{{
			Name:     "small",
			NumNodes: 3,
			NodeResources: &edgeproto.NodeResources{
				Vcpus: 2,
				Ram:   2048,
			},
			ControlPlane: true,
		}},
		expNodes: [][]string{{"resnode0", "resnode1", "resnode2"}},
	}, {
		desc: "k8s small nodes not enough",
		nodePools: []*edgeproto.NodePool{{
			Name:     "small",
			NumNodes: 6,
			NodeResources: &edgeproto.NodeResources{
				Vcpus: 2,
				Ram:   2048,
			},
			ControlPlane: true,
		}},
		expErr: "not enough resources available to create the cluster",
	}, {
		desc: "k8s small nodes not enough online nodes",
		nodePools: []*edgeproto.NodePool{{
			Name:     "small",
			NumNodes: 4,
			NodeResources: &edgeproto.NodeResources{
				Vcpus: 2,
				Ram:   2048,
			},
			ControlPlane: true,
		}},
		expErr: "not enough resources available to create the cluster",
	}, {
		desc: "k8s med nodes",
		nodePools: []*edgeproto.NodePool{{
			Name:     "med",
			NumNodes: 3,
			NodeResources: &edgeproto.NodeResources{
				Vcpus: 4,
				Ram:   4096,
			},
			ControlPlane: true,
		}},
		expNodes: [][]string{{"resnode4", "resnode5", "resnode6"}},
	}, {
		desc: "k8s small and med nodes",
		usedPools: []*edgeproto.NodePool{{
			Name:     "small",
			NumNodes: 3,
			NodeResources: &edgeproto.NodeResources{
				Vcpus: 2,
				Ram:   2048,
			},
			ControlPlane: true,
		}},
		nodePools: []*edgeproto.NodePool{{
			Name:     "med",
			NumNodes: 3,
			NodeResources: &edgeproto.NodeResources{
				Vcpus: 4,
				Ram:   4096,
			},
			ControlPlane: true,
		}},
		expNodes: [][]string{{"resnode4", "resnode5", "resnode6"}},
	}, {
		desc: "k8s small nodes",
		usedPools: []*edgeproto.NodePool{{
			Name:     "small",
			NumNodes: 1,
			NodeResources: &edgeproto.NodeResources{
				Vcpus: 2,
				Ram:   2048,
			},
			ControlPlane: true,
		}},
		nodePools: []*edgeproto.NodePool{{
			Name:     "small",
			NumNodes: 2,
			NodeResources: &edgeproto.NodeResources{
				Vcpus: 2,
				Ram:   2048,
			},
			ControlPlane: true,
		}},
		expNodes: [][]string{{"resnode1", "resnode2"}},
	}, {
		desc: "k8s small nodes not enough unused",
		usedPools: []*edgeproto.NodePool{{
			Name:     "small",
			NumNodes: 2,
			NodeResources: &edgeproto.NodeResources{
				Vcpus: 2,
				Ram:   2048,
			},
			ControlPlane: true,
		}},
		nodePools: []*edgeproto.NodePool{{
			Name:     "small",
			NumNodes: 2,
			NodeResources: &edgeproto.NodeResources{
				Vcpus: 2,
				Ram:   2048,
			},
			ControlPlane: true,
		}},
		expErr: "not enough resources available to create the cluster",
	}, {
		desc: "docker small node",
		nodeResources: &edgeproto.NodeResources{
			Vcpus: 2,
			Ram:   2048,
		},
		expNodes: [][]string{{"resnode0"}},
	}, {
		desc: "docker small node with used",
		usedNR: &edgeproto.NodeResources{
			Vcpus: 2,
			Ram:   2048,
		},
		nodeResources: &edgeproto.NodeResources{
			Vcpus: 2,
			Ram:   2048,
		},
		expNodes: [][]string{{"resnode1"}},
	}}
	for _, test := range tests {
		var usedCi *edgeproto.ClusterInst
		if test.usedNR != nil || test.usedPools != nil {
			usedCi = &edgeproto.ClusterInst{
				Key: edgeproto.ClusterKey{
					Name:         "usedClust",
					Organization: "usedOrg",
				},
				ZoneKey:       zkey,
				NodePools:     test.usedPools,
				NodeResources: test.usedNR,
			}
			if len(usedCi.NodePools) > 0 {
				usedCi.Deployment = cloudcommon.DeploymentTypeKubernetes
			} else if usedCi.NodeResources != nil {
				usedCi.Deployment = cloudcommon.DeploymentTypeDocker
			}
			err := apis.clusterInstApi.CreateClusterInst(usedCi, testutil.NewCudStreamoutClusterInst(ctx))
			require.Nil(t, err)
		}
		cleanupUsed := func() {
			if usedCi != nil {
				err := apis.clusterInstApi.DeleteClusterInst(usedCi, testutil.NewCudStreamoutClusterInst(ctx))
				require.Nil(t, err, test.desc)
			}
		}
		ci := &edgeproto.ClusterInst{
			Key: edgeproto.ClusterKey{
				Name:         "testClust",
				Organization: "testOrg",
			},
			ZoneKey:       zkey,
			NodePools:     test.nodePools,
			NodeResources: test.nodeResources,
		}
		if len(ci.NodePools) > 0 {
			ci.Deployment = cloudcommon.DeploymentTypeKubernetes
		} else if ci.NodeResources != nil {
			ci.Deployment = cloudcommon.DeploymentTypeDocker
		}
		// create test cluster
		log.SpanLog(ctx, log.DebugLevelApi, "create test cluster", "cluster", ci)
		err := apis.clusterInstApi.CreateClusterInst(ci, testutil.NewCudStreamoutClusterInst(ctx))
		if test.expErr != "" {
			require.NotNil(t, err, test.desc)
			require.Contains(t, err.Error(), test.expErr, test.desc)
			cleanupUsed()
			continue
		}
		require.Nil(t, err, test.desc)
		// check cluster was created
		log.SpanLog(ctx, log.DebugLevelApi, "check test cluster", "cluster", ci)
		ciCheck := &edgeproto.ClusterInst{}
		found := apis.clusterInstApi.cache.Get(&ci.Key, ciCheck)
		require.True(t, found, test.desc)
		require.Equal(t, ckey, ciCheck.CloudletKey, test.desc)
		// check site node assignment
		if ci.Deployment == cloudcommon.DeploymentTypeKubernetes {
			require.Equal(t, len(test.expNodes), len(ci.NodePools), test.desc)
			for ii := range test.expNodes {
				pool := ci.NodePools[ii]
				expNames := test.expNodes[ii]
				require.Equal(t, expNames, pool.Nodes, test.desc)
				for _, name := range expNames {
					siteNode := edgeproto.Node{}
					siteNodeKey := edgeproto.NodeKey{
						Name:         name,
						Organization: ci.CloudletKey.Organization,
					}
					found := apis.nodeApi.cache.Get(&siteNodeKey, &siteNode)
					require.True(t, found, test.desc)
					require.NotNil(t, siteNode.Owner, test.desc)
					require.Equal(t, ci.Key, *siteNode.Owner, test.desc)
					require.Equal(t, pool.Name, siteNode.NodePool, test.desc)
					require.Equal(t, edgeproto.NodeAssignmentInUse, siteNode.Assignment, test.desc)
				}
			}
		} else if ci.Deployment == cloudcommon.DeploymentTypeDocker {
			require.NotNil(t, ciCheck.NodeResources, test.desc)
			require.Equal(t, test.expNodes[0][0], ciCheck.NodeResources.NodeName, test.desc)
		}
		err = apis.clusterInstApi.DeleteClusterInst(ci, testutil.NewCudStreamoutClusterInst(ctx))
		require.Nil(t, err, test.desc)
		cleanupUsed()
		// check all nodes are free
		for _, node := range nodes {
			siteNode := edgeproto.Node{}
			found := apis.nodeApi.cache.Get(&node.Key, &siteNode)
			require.True(t, found, test.desc)
			require.Equal(t, edgeproto.NodeAssignmentFree, siteNode.Assignment, test.desc)
		}
	}
}
