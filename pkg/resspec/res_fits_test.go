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
	// pre-defined gpu cluster pools
	gpuPoolSmall := cpuPoolSmall.Clone()
	gpuPoolSmall.Name = "gpu-pool-small"
	gpuPoolSmall.NodeResources.OptResMap = map[string]string{
		"gpu": "gpu:1",
	}
	gpuPoolMedium := cpuPoolMedium.Clone()
	gpuPoolMedium.Name = "gpu-pool-medium"
	gpuPoolMedium.NodeResources.OptResMap = map[string]string{
		"gpu": "gpu:2",
	}

	// infra flavors
	flavorLookup := edgeproto.FlavorLookup{
		"infra.medium": &edgeproto.FlavorInfo{
			Vcpus: 4,
			Ram:   4096,
			Disk:  40,
		},
	}

	var tests = []struct {
		desc      string
		nodePools []*edgeproto.NodePool
		reqs      *edgeproto.KubernetesResources
		cpuUsed   func() ResValMap
		gpuUsed   func() ResValMap
		expErr    string
	}{{
		desc:      "cpu fit 1 pool small",
		nodePools: []*edgeproto.NodePool{cpuPoolSmall},
		reqs: &edgeproto.KubernetesResources{
			CpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(1, 0),
				TotalMemory: 1024,
			},
		},
	}, {
		desc:      "gpu fit 1 pool small",
		nodePools: []*edgeproto.NodePool{gpuPoolSmall},
		reqs: &edgeproto.KubernetesResources{
			GpuPool: &edgeproto.NodePoolResources{
				TotalVcpus:  *edgeproto.NewUdec64(1, 0),
				TotalMemory: 1024,
				TotalOptRes: map[string]string{
					"gpu": "gpu:1",
				},
			},
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
				TotalOptRes: map[string]string{
					"gpu": "gpu:1",
				},
			},
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
				TotalOptRes: map[string]string{
					"gpu": "gpu:6",
				},
			},
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
				TotalOptRes: map[string]string{
					"gpu": "gpu:6",
				},
			},
		},
		cpuUsed: func() ResValMap {
			resMap := ResValMap{}
			resMap.AddVcpus(1, 0)
			return resMap
		},
		gpuUsed: func() ResValMap {
			resMap := ResValMap{}
			resMap.AddRes("gpu:gpu", "", 1, 0)
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
				TotalOptRes: map[string]string{
					"gpu": "gpu:6",
				},
			},
		},
		cpuUsed: func() ResValMap {
			resMap := ResValMap{}
			resMap.AddVcpus(1, 0)
			return resMap
		},
		gpuUsed: func() ResValMap {
			resMap := ResValMap{}
			resMap.AddRes("gpu:gpu", "", 1, 0)
			return resMap
		},
		expErr: "gpu pool requirements not met, want 6 gpu:gpu but only 5 free",
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
		err := KubernetesResourcesFits(ctx, &cluster, test.reqs, cpuUsed, gpuUsed, flavorLookup)
		if test.expErr == "" {
			require.Nil(t, err, test.desc)
		} else {
			require.NotNil(t, err, test.desc)
			require.Contains(t, err.Error(), test.expErr, test.desc)
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
