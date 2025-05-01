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
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/svcnode"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"github.com/edgexr/edge-cloud-platform/pkg/resspec"
	"github.com/stretchr/testify/require"
)

func TestCalcKubernetesClusterUsedResources(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi | log.DebugLevelNotify)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	dummy := regiondata.InMemoryStore{}
	dummy.Start()

	zplookup := &svcnode.ZonePoolCache{}
	zplookup.Init()
	nodeMgr.ZonePoolLookup = zplookup
	cloudletLookup := &svcnode.CloudletCache{}
	cloudletLookup.Init()
	nodeMgr.CloudletLookup = cloudletLookup

	sync := regiondata.InitSync(&dummy)
	apis := NewAllApis(sync)

	app := edgeproto.App{}
	app.Key.Name = "testApp"
	app.Deployment = cloudcommon.DeploymentTypeKubernetes
	apis.appApi.cache.Update(ctx, &app, 0)

	// create some app insts
	for ii := 1; ii <= 5; ii++ {
		ai := edgeproto.AppInst{}
		ai.Key.Name = fmt.Sprintf("c%d", ii)
		ai.AppKey = app.Key
		ai.KubernetesResources = &edgeproto.KubernetesResources{
			CpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(uint64(ii), 0),
				TotalMemory: 1024 * uint64(ii),
				TotalDisk:   10 * uint64(ii),
			},
		}
		apis.appInstApi.cache.Update(ctx, &ai, 0)

		ai2 := edgeproto.AppInst{}
		ai2.Key.Name = fmt.Sprintf("g%d", ii)
		ai2.AppKey = app.Key
		ai2.KubernetesResources = &edgeproto.KubernetesResources{
			GpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(uint64(ii), 0),
				TotalMemory: 1024 * uint64(ii),
				TotalDisk:   10 * uint64(ii),
				TotalGpus: []*edgeproto.GPUResource{{
					ModelId: "NVIDIA-A16-4Q",
					Count:   uint32(ii),
				}},
			},
		}
		apis.appInstApi.cache.Update(ctx, &ai2, 0)
	}

	var tests = []struct {
		desc      string
		insts     []string
		newinst   string
		expCpuRes func() resspec.ResValMap
		expGpuRes func() resspec.ResValMap
	}{{
		desc:  "cpu test 1",
		insts: []string{"c1"},
		expCpuRes: func() resspec.ResValMap {
			resMap := resspec.ResValMap{}
			resMap.AddVcpus(1, 0)
			resMap.AddRam(1024)
			resMap.AddDisk(10)
			return resMap
		},
	}, {
		desc:  "cpu test 1 + 3",
		insts: []string{"c1", "c3"},
		expCpuRes: func() resspec.ResValMap {
			resMap := resspec.ResValMap{}
			resMap.AddVcpus(4, 0)
			resMap.AddRam(4096)
			resMap.AddDisk(40)
			return resMap
		},
	}, {
		desc:  "cpu test 1 + 2 + 3 + 4 + 5",
		insts: []string{"c1", "c2", "c3", "c4", "c5"},
		expCpuRes: func() resspec.ResValMap {
			resMap := resspec.ResValMap{}
			resMap.AddVcpus(15, 0)
			resMap.AddRam(15360)
			resMap.AddDisk(150)
			return resMap
		},
	}, {
		desc:  "gpu test 4",
		insts: []string{"g4"},
		expGpuRes: func() resspec.ResValMap {
			resMap := resspec.ResValMap{}
			resMap.AddVcpus(4, 0)
			resMap.AddRam(4096)
			resMap.AddDisk(40)
			resMap.AddGPU("NVIDIA-A16-4Q", 4)
			return resMap
		},
	}, {
		desc:  "gpu test 1 + 3 + 5",
		insts: []string{"g1", "g2", "g5"},
		expGpuRes: func() resspec.ResValMap {
			resMap := resspec.ResValMap{}
			resMap.AddVcpus(8, 0)
			resMap.AddRam(8192)
			resMap.AddDisk(80)
			resMap.AddGPU("NVIDIA-A16-4Q", 8)
			return resMap
		},
	}, {
		desc:  "cpu 1 + 4, gpu 2 + 5",
		insts: []string{"c1", "c4", "g2", "g5"},
		expCpuRes: func() resspec.ResValMap {
			resMap := resspec.ResValMap{}
			resMap.AddVcpus(5, 0)
			resMap.AddRam(5120)
			resMap.AddDisk(50)
			return resMap
		},
		expGpuRes: func() resspec.ResValMap {
			resMap := resspec.ResValMap{}
			resMap.AddVcpus(7, 0)
			resMap.AddRam(7168)
			resMap.AddDisk(70)
			resMap.AddGPU("NVIDIA-A16-4Q", 7)
			return resMap
		},
	}}

	for _, test := range tests {
		// build refs object
		refs := edgeproto.ClusterRefs{}
		for _, name := range test.insts {
			aikey := edgeproto.AppInstKey{
				Name: name,
			}
			refs.Apps = append(refs.Apps, aikey)
		}
		var newAppInst *edgeproto.AppInst
		if test.newinst != "" {
			newAppInst = &edgeproto.AppInst{}
			newAppInst.Key.Name = test.newinst
		}
		// calculate used resources
		cpuVals, gpuVals, err := apis.clusterInstApi.calcKubernetesClusterUsedResources(&refs, newAppInst)
		require.Nil(t, err, test.desc)
		// verify results
		if test.expCpuRes == nil {
			require.Equal(t, resspec.ResValMap{}, cpuVals, test.desc)
		} else {
			require.Equal(t, test.expCpuRes(), cpuVals, test.desc)
		}
		if test.expGpuRes == nil {
			require.Equal(t, resspec.ResValMap{}, gpuVals, test.desc)
		} else {
			require.Equal(t, test.expGpuRes(), gpuVals, test.desc)
		}
	}

}

func TestNodePoolFromResources(t *testing.T) {
	name := "cpupool"

	var tests = []struct {
		desc        string
		npr         *edgeproto.NodePoolResources
		expNodePool *edgeproto.NodePool
	}{{
		desc: "min specified single node",
		npr: &edgeproto.NodePoolResources{
			TotalVcpus:  *edgeproto.NewUdec64(2, 0),
			TotalMemory: 2048,
		},
		expNodePool: &edgeproto.NodePool{
			Name:     name,
			NumNodes: 1,
			NodeResources: &edgeproto.NodeResources{
				Vcpus: 2,
				Ram:   2048,
			},
		},
	}, {
		desc: "min specified multi node rounding",
		npr: &edgeproto.NodePoolResources{
			TotalVcpus:  *edgeproto.NewUdec64(10, 0),
			TotalMemory: 20480,
			TotalGpus: []*edgeproto.GPUResource{{
				ModelId: "NVIDIA-A16-4Q",
				Count:   5,
			}},
			Topology: edgeproto.NodePoolTopology{
				MinNumberOfNodes: 3,
			},
		},
		expNodePool: &edgeproto.NodePool{
			Name:     name,
			NumNodes: 3,
			NodeResources: &edgeproto.NodeResources{
				Vcpus: 4,
				Ram:   6827,
				Gpus: []*edgeproto.GPUResource{{
					ModelId: "NVIDIA-A16-4Q",
					Count:   2,
				}},
			},
		},
	}, {
		desc: "all specified multi node exact",
		npr: &edgeproto.NodePoolResources{
			TotalVcpus:  *edgeproto.NewUdec64(10, 0),
			TotalMemory: 20480,
			TotalDisk:   50,
			TotalGpus: []*edgeproto.GPUResource{{
				ModelId: "NVIDIA-A16-4Q",
				Count:   5,
			}},
			TotalOptRes: map[string]string{
				"nas": "scsi:jbod:500",
			},
			Topology: edgeproto.NodePoolTopology{
				MinNumberOfNodes: 5,
			},
		},
		expNodePool: &edgeproto.NodePool{
			Name:     name,
			NumNodes: 5,
			NodeResources: &edgeproto.NodeResources{
				Vcpus: 2,
				Ram:   4096,
				Disk:  10,
				Gpus: []*edgeproto.GPUResource{{
					ModelId: "NVIDIA-A16-4Q",
					Count:   1,
				}},
				OptResMap: map[string]string{
					"nas": "scsi:jbod:100",
				},
			},
		},
	}}

	for _, test := range tests {
		outNodePool := NodePoolFromResources(name, test.npr)
		require.Equal(t, test.expNodePool, outNodePool, test.desc)
	}
}
