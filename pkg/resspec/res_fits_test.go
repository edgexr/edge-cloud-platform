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

package resspec

import (
	"context"
	"testing"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/stretchr/testify/require"
)

func TestKubernetesResourcesFits(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi | log.DebugLevelNotify)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	// pre-defined cpu cluster pools
	cpuPoolSmall := &edgeproto.NodePool{
		Name:     "cpu-pool-small",
		NumNodes: 1,
		NodeResources: &edgeproto.NodeResources{
			Vcpus: 2,
			Ram:   2048,
			Disk:  10,
		},
	}
	cpuPoolMedium := &edgeproto.NodePool{
		Name:     "cpu-pool-medium",
		NumNodes: 3,
		NodeResources: &edgeproto.NodeResources{
			Vcpus: 4,
			Ram:   4096,
			Disk:  40,
		},
	}
	cpuPoolSmallFlavor := &edgeproto.NodePool{
		Name:     "cpu-pool-small-flavor",
		NumNodes: 1,
		NodeResources: &edgeproto.NodeResources{ // these will be overridden by infra flavor which is larger
			Vcpus:           2,
			Ram:             2048,
			Disk:            10,
			InfraNodeFlavor: "infra.medium",
		},
	}
	gpuX1000 := "nvidia-x1000"
	// pre-defined gpu cluster pools
	gpuPoolSmall := cpuPoolSmall.Clone()
	gpuPoolSmall.Name = "gpu-pool-small"
	gpuPoolSmall.NodeResources.Gpus = []*edgeproto.GPUResource{{
		ModelId: gpuX1000,
		Count:   1,
	}}
	gpuPoolMedium := cpuPoolMedium.Clone()
	gpuPoolMedium.Name = "gpu-pool-medium"
	gpuPoolMedium.NodeResources.Gpus = []*edgeproto.GPUResource{{
		ModelId: gpuX1000,
		Count:   2,
	}}

	makeScalable := func(np *edgeproto.NodePool) *edgeproto.NodePool {
		cp := np.Clone()
		cp.Name = np.Name + "-scalable"
		cp.Scalable = true
		return cp
	}
	// scalable versions
	cpuPoolSmallScalable := makeScalable(cpuPoolSmall)
	cpuPoolMediumScalable := makeScalable(cpuPoolMedium)
	gpuPoolSmallScalable := makeScalable(gpuPoolSmall)

	// infra flavors
	flavorLookup := edgeproto.FlavorLookup{
		"infra.medium": &edgeproto.FlavorInfo{
			Vcpus: 4,
			Ram:   4096,
			Disk:  40,
		},
	}

	var tests = []struct {
		desc         string
		nodePools    []*edgeproto.NodePool
		reqs         *edgeproto.KubernetesResources
		cpuUsed      func() ResValMap
		gpuUsed      func() ResValMap
		expErr       string
		expErrIgnore bool // expect error, but don't check contents
		expCpuScale  *PoolScaleSpec
		expGpuScale  *PoolScaleSpec
		expFree      func() ResValMap
	}{{
		desc:      "cpu fit 1 pool small",
		nodePools: []*edgeproto.NodePool{cpuPoolSmall},
		reqs: &edgeproto.KubernetesResources{
			CpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(1, 0),
				TotalMemory: 1024,
			},
		},
		expFree: func() ResValMap {
			free := ResValMap{}
			free.AddVcpus(2, 0)
			free.AddRam(2048)
			free.AddDisk(10)
			return free
		},
	}, {
		desc:      "gpu fit 1 pool small",
		nodePools: []*edgeproto.NodePool{gpuPoolSmall},
		reqs: &edgeproto.KubernetesResources{
			GpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(1, 0),
				TotalMemory: 1024,
				TotalGpus: []*edgeproto.GPUResource{{
					ModelId: gpuX1000,
					Count:   1,
				}},
			},
		},
		expFree: func() ResValMap {
			free := ResValMap{}
			free.AddVcpus(2, 0)
			free.AddRam(2048)
			free.AddDisk(10)
			free.AddGPU(gpuX1000, 1)
			return free
		},
	}, {
		desc:      "cpu/gpu fit 1 small pools",
		nodePools: []*edgeproto.NodePool{cpuPoolSmall, gpuPoolSmall},
		reqs: &edgeproto.KubernetesResources{
			CpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(1, 0),
				TotalMemory: 1024,
			},
			GpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(1, 0),
				TotalMemory: 1024,
				TotalGpus: []*edgeproto.GPUResource{{
					ModelId: gpuX1000,
					Count:   1,
				}},
			},
		},
		expFree: func() ResValMap {
			free := ResValMap{}
			free.AddVcpus(4, 0)
			free.AddRam(4096)
			free.AddDisk(20)
			free.AddGPU(gpuX1000, 1)
			return free
		},
	}, {
		desc:      "cpu fit 1 with used 1 small pool",
		nodePools: []*edgeproto.NodePool{cpuPoolSmall},
		reqs: &edgeproto.KubernetesResources{
			CpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(1, 0),
				TotalMemory: 1024,
			},
		},
		cpuUsed: func() ResValMap {
			resMap := ResValMap{}
			resMap.AddVcpus(1, 0)
			resMap.AddRam(1024)
			return resMap
		},
	}, {
		desc:      "cpu fit 1 pool small infra flavor",
		nodePools: []*edgeproto.NodePool{cpuPoolSmallFlavor},
		reqs: &edgeproto.KubernetesResources{
			CpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(4, 0),
				TotalMemory: 4096,
			},
		},
	}, {
		desc:      "cpu fit 2 with used 1 failed small pool",
		nodePools: []*edgeproto.NodePool{cpuPoolSmall},
		reqs: &edgeproto.KubernetesResources{
			CpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(2, 0),
				TotalMemory: 2048,
			},
		},
		cpuUsed: func() ResValMap {
			resMap := ResValMap{}
			resMap.AddVcpus(1, 0)
			resMap.AddRam(1024)
			return resMap
		},
		expErr: "cpu pool requirements not met, want 2048MB RAM but only 1024MB free, want 2 vCPUs but only 1 free",
	}, {
		desc:      "cpu fit 6 medium pool",
		nodePools: []*edgeproto.NodePool{cpuPoolMedium},
		reqs: &edgeproto.KubernetesResources{
			CpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(6, 0),
				TotalMemory: 1024 * 6,
			},
		},
	}, {
		desc:      "cpu fit 6 medium pool ok min reqs",
		nodePools: []*edgeproto.NodePool{cpuPoolMedium},
		reqs: &edgeproto.KubernetesResources{
			CpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(6, 0),
				TotalMemory: 1024 * 6,
				Topology: edgeproto.NodePoolTopology{
					MinNodeVcpus:  4,
					MinNodeMemory: 4096,
				},
			},
		},
	}, {
		desc:      "cpu fit 6 medium pool failed min reqs",
		nodePools: []*edgeproto.NodePool{cpuPoolMedium},
		reqs: &edgeproto.KubernetesResources{
			CpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(6, 0),
				TotalMemory: 1024 * 6,
				Topology: edgeproto.NodePoolTopology{
					MinNodeVcpus:  6,
					MinNodeMemory: 1024 * 6,
				},
			},
		},
		expErr: "cpu pool requirements not met, want 6144MB RAM but only 0MB free, want 6 vCPUs but only 0 free, skipped pool cpu-pool-medium because node resource RAM 4096MB does not meet min reqs of 6144MB",
	}, {
		desc:      "cpu fit 16 medium pool failed",
		nodePools: []*edgeproto.NodePool{cpuPoolMedium},
		reqs: &edgeproto.KubernetesResources{
			CpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(16, 0),
				TotalMemory: 1024 * 16,
			},
		},
		expErr: "cpu pool requirements not met, want 16384MB RAM but only 12288MB free, want 16 vCPUs but only 12 free",
	}, {
		desc:      "cpu/gpu fit max small/medium pools",
		nodePools: []*edgeproto.NodePool{cpuPoolSmall, gpuPoolMedium},
		reqs: &edgeproto.KubernetesResources{
			CpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(2, 0),
				TotalMemory: 2048,
			},
			GpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(12, 0),
				TotalMemory: 1024 * 12,
				TotalGpus: []*edgeproto.GPUResource{{
					ModelId: gpuX1000,
					Count:   6,
				}},
			},
		},
		expFree: func() ResValMap {
			free := ResValMap{}
			free.AddVcpus(14, 0)
			free.AddRam(14336)
			free.AddDisk(130)
			free.AddGPU(gpuX1000, 6)
			return free
		},
	}, {
		desc:      "cpu/gpu fit small/medium pools used check free",
		nodePools: []*edgeproto.NodePool{cpuPoolSmall, gpuPoolMedium},
		reqs: &edgeproto.KubernetesResources{
			CpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(0, 100*edgeproto.DecMillis),
				TotalMemory: 1024,
			},
			GpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(4, 0),
				TotalMemory: 1024 * 4,
				TotalGpus: []*edgeproto.GPUResource{{
					ModelId: gpuX1000,
					Count:   2,
				}},
			},
		},
		cpuUsed: func() ResValMap {
			resMap := ResValMap{}
			resMap.AddVcpus(1, 500*edgeproto.DecMillis)
			resMap.AddRam(200)
			return resMap
		},
		gpuUsed: func() ResValMap {
			resMap := ResValMap{}
			resMap.AddVcpus(5, 600*edgeproto.DecMillis)
			resMap.AddRam(5500)
			resMap.AddGPU(gpuX1000, 2)
			return resMap
		},
		// free is sum of cpu and gpu pools free space
		expFree: func() ResValMap {
			free := ResValMap{}
			free.AddVcpus(6, 900*edgeproto.DecMillis)
			free.AddRam(8636)
			free.AddDisk(130)
			free.AddGPU(gpuX1000, 4)
			return free
		},
	}, {
		desc:      "cpu/gpu fit small/medium pools used check free gpu pool ignored",
		nodePools: []*edgeproto.NodePool{cpuPoolMedium, gpuPoolMedium},
		reqs: &edgeproto.KubernetesResources{
			CpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(0, 100*edgeproto.DecMillis),
				TotalMemory: 1024,
			},
		},
		cpuUsed: func() ResValMap {
			resMap := ResValMap{}
			resMap.AddVcpus(1, 400*edgeproto.DecMillis)
			resMap.AddRam(200)
			return resMap
		},
		gpuUsed: func() ResValMap {
			resMap := ResValMap{}
			resMap.AddVcpus(5, 600*edgeproto.DecMillis)
			resMap.AddRam(5500)
			resMap.AddGPU(gpuX1000, 2)
			return resMap
		},
		// note, no GPU Pool requirements, so "free" resources
		// only takes into account cpu pools
		expFree: func() ResValMap {
			free := ResValMap{}
			free.AddVcpus(10, 600*edgeproto.DecMillis)
			free.AddRam(12088)
			free.AddDisk(120)
			return free
		},
	}, {
		desc:      "cpu/gpu fit max small/medium pools with used, fail cpu pool",
		nodePools: []*edgeproto.NodePool{cpuPoolSmall, gpuPoolMedium},
		reqs: &edgeproto.KubernetesResources{
			CpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(2, 0),
				TotalMemory: 2048,
			},
			GpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(12, 0),
				TotalMemory: 1024 * 12,
				TotalGpus: []*edgeproto.GPUResource{{
					ModelId: gpuX1000,
					Count:   6,
				}},
			},
		},
		cpuUsed: func() ResValMap {
			resMap := ResValMap{}
			resMap.AddVcpus(1, 0)
			return resMap
		},
		gpuUsed: func() ResValMap {
			resMap := ResValMap{}
			resMap.AddGPU(gpuX1000, 6)
			return resMap
		},
		expErr: "cpu pool requirements not met, want 2 vCPUs but only 1 free, skipped gpu pool gpu-pool-medium because no request for gpu",
	}, {
		desc:      "cpu/gpu fit max small/medium pools with used, fail gpu pool",
		nodePools: []*edgeproto.NodePool{cpuPoolSmall, gpuPoolMedium},
		reqs: &edgeproto.KubernetesResources{
			CpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(1, 0),
				TotalMemory: 2048,
			},
			GpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(12, 0),
				TotalMemory: 1024 * 12,
				TotalGpus: []*edgeproto.GPUResource{{
					ModelId: gpuX1000,
					Count:   6,
				}},
			},
		},
		cpuUsed: func() ResValMap {
			resMap := ResValMap{}
			resMap.AddVcpus(1, 0)
			return resMap
		},
		gpuUsed: func() ResValMap {
			resMap := ResValMap{}
			resMap.AddGPU(gpuX1000, 1)
			return resMap
		},
		expErr: "gpu pool requirements not met, want 6 gpu/nvidia-x1000 but only 5 free",
	}, {
		desc:      "cpu pool scale exact 1",
		nodePools: []*edgeproto.NodePool{cpuPoolSmallScalable, gpuPoolSmallScalable},
		reqs: &edgeproto.KubernetesResources{
			CpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(4, 0),
				TotalMemory: 4096,
			},
		},
		expErrIgnore: true,
		expCpuScale: &PoolScaleSpec{
			PoolName:       cpuPoolSmallScalable.Name,
			NumNodesChange: 1,
		},
	}, {
		desc:      "cpu pool scale exact 3",
		nodePools: []*edgeproto.NodePool{cpuPoolSmallScalable, gpuPoolSmallScalable},
		reqs: &edgeproto.KubernetesResources{
			CpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(8, 0),
				TotalMemory: 8192,
			},
		},
		expErrIgnore: true,
		expCpuScale: &PoolScaleSpec{
			PoolName:       cpuPoolSmallScalable.Name,
			NumNodesChange: 3,
		},
	}, {
		desc:      "cpu pool scale exact 3 used",
		nodePools: []*edgeproto.NodePool{cpuPoolSmallScalable, gpuPoolSmallScalable},
		reqs: &edgeproto.KubernetesResources{
			CpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(4, 0),
				TotalMemory: 4096,
			},
		},
		cpuUsed: func() ResValMap {
			resMap := ResValMap{}
			resMap.AddVcpus(4, 0)
			resMap.AddRam(4096)
			return resMap
		},
		expErrIgnore: true,
		expCpuScale: &PoolScaleSpec{
			PoolName:       cpuPoolSmallScalable.Name,
			NumNodesChange: 3,
		},
	}, {
		desc:      "cpu pool scale non-exact 3",
		nodePools: []*edgeproto.NodePool{cpuPoolSmallScalable, gpuPoolSmallScalable},
		reqs: &edgeproto.KubernetesResources{
			CpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(7, 0),
				TotalMemory: 8000,
			},
		},
		expErrIgnore: true,
		expCpuScale: &PoolScaleSpec{
			PoolName:       cpuPoolSmallScalable.Name,
			NumNodesChange: 3,
		},
	}, {
		desc:      "gpu pool scale non-exact 3",
		nodePools: []*edgeproto.NodePool{cpuPoolSmallScalable, gpuPoolSmallScalable},
		reqs: &edgeproto.KubernetesResources{
			CpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(1, 0),
				TotalMemory: 1024,
			},
			GpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(6, 0),
				TotalMemory: 1024 * 6,
				TotalGpus: []*edgeproto.GPUResource{{
					ModelId: gpuX1000,
					Count:   6,
				}},
			},
		},
		expErrIgnore: true,
		expGpuScale: &PoolScaleSpec{
			PoolName:       gpuPoolSmallScalable.Name,
			NumNodesChange: 5,
		},
	}, {
		desc:      "cpu and gpu pool scale mixed pools",
		nodePools: []*edgeproto.NodePool{cpuPoolSmall, cpuPoolSmallScalable, gpuPoolSmall, gpuPoolSmallScalable},
		reqs: &edgeproto.KubernetesResources{
			CpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(8, 0),
				TotalMemory: 8096,
			},
			GpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(6, 0),
				TotalMemory: 1024 * 6,
				TotalGpus: []*edgeproto.GPUResource{{
					ModelId: gpuX1000,
					Count:   6,
				}},
			},
		},
		expErrIgnore: true,
		expCpuScale: &PoolScaleSpec{
			PoolName:       cpuPoolSmallScalable.Name,
			NumNodesChange: 2,
		},
		expGpuScale: &PoolScaleSpec{
			PoolName:       gpuPoolSmallScalable.Name,
			NumNodesChange: 4,
		},
	}, {
		desc:      "cpu pool scale mixed pools topology reqs",
		nodePools: []*edgeproto.NodePool{cpuPoolSmall, cpuPoolSmallScalable, cpuPoolMediumScalable},
		reqs: &edgeproto.KubernetesResources{
			CpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(22, 0),
				TotalMemory: 8096,
				Topology: edgeproto.NodePoolTopology{
					MinNodeVcpus: 4,
				},
			},
		},
		expErrIgnore: true,
		// small pools are ignored due to topology requirements.
		// want 22 vcpus, medium pool has 12, need 10 more
		expCpuScale: &PoolScaleSpec{
			PoolName:       cpuPoolMediumScalable.Name,
			NumNodesChange: 3,
		},
	}}

	for _, test := range tests {
		cluster := edgeproto.ClusterInst{}
		cluster.NodePools = test.nodePools
		var cpuUsed, gpuUsed ResValMap
		if test.cpuUsed != nil {
			cpuUsed = test.cpuUsed()
		}
		if test.gpuUsed != nil {
			gpuUsed = test.gpuUsed()
		}
		clusterSpecified := false
		ss, free, err := KubernetesResourcesFits(ctx, &cluster, test.reqs, cpuUsed, gpuUsed, flavorLookup, clusterSpecified)
		if test.expErr != "" {
			require.NotNil(t, err, test.desc)
			require.Contains(t, err.Error(), test.expErr, test.desc)
		} else if test.expErrIgnore {
			require.NotNil(t, err, test.desc)
		} else {
			require.Nil(t, err, test.desc)
		}
		if test.expFree != nil {
			require.Equal(t, test.expFree(), free, test.desc)
		}
		if test.expCpuScale != nil {
			require.NotNil(t, ss, test.desc)
			// we're not checking the per node resources
			if ss.CPUPoolScale != nil {
				ss.CPUPoolScale.PerNodeResources = nil
			}
			require.Equal(t, test.expCpuScale, ss.CPUPoolScale, test.desc)
		}
		if test.expGpuScale != nil {
			require.NotNil(t, ss, test.desc)
			if ss.GPUPoolScale != nil {
				ss.GPUPoolScale.PerNodeResources = nil
			}
			require.Equal(t, test.expGpuScale, ss.GPUPoolScale, test.desc)
		}
	}
}

func TestNodeResourcesFits(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi | log.DebugLevelNotify)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	var tests = []struct {
		desc     string
		clustRes edgeproto.NodeResources
		reqs     edgeproto.NodeResources
		used     func() ResValMap
		expErr   string
	}{{
		desc: "fit with leeway",
		clustRes: edgeproto.NodeResources{
			Vcpus: 4,
			Ram:   4096,
			Disk:  40,
		},
		reqs: edgeproto.NodeResources{
			Vcpus: 1,
			Ram:   1024,
			Disk:  10,
		},
	}, {
		desc: "fit exactly",
		clustRes: edgeproto.NodeResources{
			Vcpus: 4,
			Ram:   4096,
			Disk:  40,
		},
		reqs: edgeproto.NodeResources{
			Vcpus: 4,
			Ram:   4096,
			Disk:  40,
		},
	}, {
		desc: "not fit",
		clustRes: edgeproto.NodeResources{
			Vcpus: 4,
			Ram:   4096,
			Disk:  40,
		},
		reqs: edgeproto.NodeResources{
			Vcpus: 5,
			Ram:   4096,
			Disk:  50,
		},
		expErr: "want 50GB Disk but only 40GB free, want 5 vCPUs but only 4 free",
	}, {
		desc: "not fit with used",
		clustRes: edgeproto.NodeResources{
			Vcpus: 4,
			Ram:   4096,
			Disk:  40,
		},
		reqs: edgeproto.NodeResources{
			Vcpus: 4,
			Ram:   4096,
			Disk:  40,
		},
		used: func() ResValMap {
			resVals := ResValMap{}
			resVals.AddVcpus(2, 0)
			resVals.AddRam(2048)
			return resVals
		},
		expErr: "want 4096MB RAM but only 2048MB free, want 4 vCPUs but only 2 free",
	}, {
		desc: "not fit with used and flavor",
		clustRes: edgeproto.NodeResources{
			Vcpus:           10000,
			Ram:             1000000,
			Disk:            10000000,
			InfraNodeFlavor: "infra.medium",
		},
		reqs: edgeproto.NodeResources{
			Vcpus: 4,
			Ram:   4096,
			Disk:  40,
		},
		used: func() ResValMap {
			resVals := ResValMap{}
			resVals.AddVcpus(2, 0)
			resVals.AddRam(2048)
			return resVals
		},
		expErr: "want 4096MB RAM but only 2048MB free, want 4 vCPUs but only 2 free",
	}}

	// infra flavors
	flavorLookup := edgeproto.FlavorLookup{
		"infra.medium": &edgeproto.FlavorInfo{
			Vcpus: 4,
			Ram:   4096,
			Disk:  40,
		},
	}

	for _, test := range tests {
		clust := edgeproto.ClusterInst{}
		clust.NodeResources = &test.clustRes
		var used ResValMap
		if test.used != nil {
			used = test.used()
		}
		err := NodeResourcesFits(ctx, &clust, &test.reqs, used, flavorLookup)
		if test.expErr == "" {
			require.Nil(t, err, test.desc)
		} else {
			require.NotNil(t, err, test.desc)
			require.Contains(t, err.Error(), test.expErr, test.desc)
		}
	}
}
