// Copyright 2022 MobiledgeX, Inc
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

package resspec

import (
	"context"
	"testing"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/stretchr/testify/require"
)

var (
	MATCH    = true
	NO_MATCH = false

	flavorInfos = map[string]edgeproto.FlavorInfo{
		"pci-620-1": {
			Name: "pci-flavor",
			PropMap: map[string]string{
				"pci_passthrough": "alias=p620gpu:1",
			},
		},
		"pci-t4-1": {
			Name: "pci-t4-1-flavor",
			PropMap: map[string]string{
				"pci_passthrough": "alias=t4gpu:1",
			},
		},
		"pci-t4-2": {
			Name: "pci-t4-2-flavor",
			PropMap: map[string]string{
				"pci_passthrough": "alias=t4gpu:2",
			},
		},
		"vgpu1-1": {
			Name: "vgpu-type1-flavor",
			PropMap: map[string]string{
				"vmware": "vgpu=1",
			},
		},
		"vgpu1-2": {
			Name: "vgpu-type1-flavor",
			PropMap: map[string]string{
				"vmware": "vgpu=2",
			},
		},
		"vgpu2-1": {
			Name: "vgpu-type2-1-flavor",
			PropMap: map[string]string{
				"resources": "VGPU=1",
			},
		},
		"vgpu2-2": {
			Name: "vgpu-type2-2-flavor",
			PropMap: map[string]string{
				"resources": "VGPU=2",
			},
		},
		"random": {
			Name: "random-flavor",
			PropMap: map[string]string{
				"somekey": "somespec=2",
			},
		},
	}

	resTagTbls = map[string]*edgeproto.ResTagTable{
		"restbl-pci-1": &edgeproto.ResTagTable{
			Tags: map[string]string{
				"pci": "p620gpu:1",
			},
		},
		"restbl-all-1": &edgeproto.ResTagTable{
			Tags: map[string]string{
				"pci":       "t4gpu:1",
				"vmware":    "vgpu=1",
				"resources": "VGPU=1",
			},
		},
		"restbl-all-2": &edgeproto.ResTagTable{
			Tags: map[string]string{
				"pci":       "t4gpu:2",
				"resources": "VGPU=2",
			},
		},
		"restbl-random": &edgeproto.ResTagTable{
			Tags: map[string]string{
				"somekey": "somespec=2",
			},
		},
	}
)

func testResMatch(t *testing.T, ctx context.Context, resname, request string, flavorInfo edgeproto.FlavorInfo, resTagTbl *edgeproto.ResTagTable, check bool) {
	err := match(ctx, resname, request, flavorInfo, resTagTbl)
	if check == MATCH {
		require.Nil(t, err)
	} else {
		require.NotNil(t, err, "resource not matched")
		require.Contains(t, err.Error(), "No match found")
	}
}

func TestFlavorResMapMatch(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi | log.DebugLevelNotify)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	verbose = true

	// Wildcard i.e. any GPU type (vGPU/PCI/etc), success
	testResMatch(t, ctx, "gpu", "gpu:1", flavorInfos["pci-620-1"], resTagTbls["restbl-pci-1"], MATCH)
	testResMatch(t, ctx, "gpu", "gpu:2", flavorInfos["pci-t4-2"], resTagTbls["restbl-all-1"], MATCH)
	// Wildcard match, but count mismatch
	testResMatch(t, ctx, "gpu", "gpu:2", flavorInfos["pci-t4-1"], resTagTbls["restbl-all-2"], NO_MATCH)
	// non-GPU resource, should not be matched as we don't handle such resources
	testResMatch(t, ctx, "nas", "xyz:1", flavorInfos["pci-620-1"], resTagTbls["restbl-pci-1"], NO_MATCH)
	// GPU Type, but no spec specified, success
	testResMatch(t, ctx, "gpu", "pci:1", flavorInfos["pci-620-1"], resTagTbls["restbl-pci-1"], MATCH)
	// GPU Type, but restag value doesn't exist or is different
	testResMatch(t, ctx, "gpu", "pci:1", flavorInfos["pci-620-1"], resTagTbls["restbl-all-1"], NO_MATCH)
	// GPU Type with spec, but different res count
	testResMatch(t, ctx, "gpu", "pci:t4gpu:2", flavorInfos["pci-t4-2"], resTagTbls["restbl-all-1"], NO_MATCH)
	// GPU Type with spec, with same res count
	testResMatch(t, ctx, "gpu", "pci:t4gpu:2", flavorInfos["pci-t4-2"], resTagTbls["restbl-all-2"], MATCH)

	// Special handling for vGPU flavors observed with bunch of Operator infra
	// =======================================================================
	// vGPU Type with same res count
	testResMatch(t, ctx, "gpu", "vmware:vgpu:1", flavorInfos["vgpu1-1"], resTagTbls["restbl-all-1"], MATCH)
	testResMatch(t, ctx, "gpu", "resources:VGPU:1", flavorInfos["vgpu2-1"], resTagTbls["restbl-all-1"], MATCH)
	// vGPU Type with different res count
	testResMatch(t, ctx, "gpu", "vmware:vgpu:2", flavorInfos["vgpu1-2"], resTagTbls["restbl-all-1"], NO_MATCH)
	testResMatch(t, ctx, "gpu", "vmware:vgpu:2", flavorInfos["vgpu2-2"], resTagTbls["restbl-all-1"], NO_MATCH)
	// vGPU Type with different spec
	testResMatch(t, ctx, "gpu", "resources:VGPU:2", flavorInfos["vgpu1-2"], resTagTbls["restbl-all-2"], NO_MATCH)
	testResMatch(t, ctx, "gpu", "resources:VGPU:2", flavorInfos["vgpu2-2"], resTagTbls["restbl-all-2"], MATCH)

	// Match for some random GPU type and spec, this is to ensure that we can handle
	// any type of flavorinfo propmap received from Operator's infra
	testResMatch(t, ctx, "gpu", "somekey:somespec:2", flavorInfos["random"], resTagTbls["restbl-random"], MATCH)
}

func TestSatisfiesGpu(t *testing.T) {
	var tests = []struct {
		desc       string
		reqs       []*edgeproto.GPUResource
		gpus       []*edgeproto.GPUResource
		exp        bool
		expMissing map[string]int
		expExtra   map[string]int
	}{{
		desc: "0 gpu exact match",
		reqs: []*edgeproto.GPUResource{},
		gpus: []*edgeproto.GPUResource{},
		exp:  true,
	}, {
		desc: "gpu extra",
		reqs: []*edgeproto.GPUResource{},
		gpus: []*edgeproto.GPUResource{{
			ModelId: "nvidia-t4",
			Count:   1,
		}},
		exp: false,
		expExtra: map[string]int{
			"nvidia-t4": 1,
		},
	}, {
		desc: "gpu missing",
		reqs: []*edgeproto.GPUResource{{
			ModelId: "nvidia-t4",
			Count:   1,
		}},
		gpus: []*edgeproto.GPUResource{},
		exp:  false,
		expMissing: map[string]int{
			"nvidia-t4": 1,
		},
	}, {
		desc: "1 gpu exact match",
		reqs: []*edgeproto.GPUResource{{
			ModelId: "nvidia-t4",
			Count:   1,
		}},
		gpus: []*edgeproto.GPUResource{{
			ModelId: "nvidia-t4",
			Count:   1,
		}},
		exp: true,
	}, {
		desc: "1 gpu missing count",
		reqs: []*edgeproto.GPUResource{{
			ModelId: "nvidia-t4",
			Count:   2,
		}},
		gpus: []*edgeproto.GPUResource{{
			ModelId: "nvidia-t4",
			Count:   1,
		}},
		exp: false,
		expMissing: map[string]int{
			"nvidia-t4": 1,
		},
	}, {
		desc: "1 gpu extra count",
		reqs: []*edgeproto.GPUResource{{
			ModelId: "nvidia-t4",
			Count:   1,
		}},
		gpus: []*edgeproto.GPUResource{{
			ModelId: "nvidia-t4",
			Count:   2,
		}},
		exp: false,
		expExtra: map[string]int{
			"nvidia-t4": 1,
		},
	}, {
		desc: "2 gpu exact match",
		reqs: []*edgeproto.GPUResource{{
			ModelId: "nvidia-t4",
			Count:   1,
		}, {
			ModelId: "amd-g100",
			Count:   1,
		}},
		gpus: []*edgeproto.GPUResource{{
			ModelId: "nvidia-t4",
			Count:   1,
		}, {
			ModelId: "amd-g100",
			Count:   1,
		}},
		exp: true,
	}, {
		desc: "2 gpu missing count",
		reqs: []*edgeproto.GPUResource{{
			ModelId: "nvidia-t4",
			Count:   2,
		}, {
			ModelId: "amd-g100",
			Count:   1,
		}},
		gpus: []*edgeproto.GPUResource{{
			ModelId: "nvidia-t4",
			Count:   1,
		}, {
			ModelId: "amd-g100",
			Count:   1,
		}},
		exp: false,
		expMissing: map[string]int{
			"nvidia-t4": 1,
		},
	}, {
		desc: "2 gpu extra count",
		reqs: []*edgeproto.GPUResource{{
			ModelId: "nvidia-t4",
			Count:   1,
		}, {
			ModelId: "amd-g100",
			Count:   1,
		}},
		gpus: []*edgeproto.GPUResource{{
			ModelId: "nvidia-t4",
			Count:   1,
		}, {
			ModelId: "amd-g100",
			Count:   2,
		}},
		exp: false,
		expExtra: map[string]int{
			"amd-g100": 1,
		},
	}}
	for _, test := range tests {
		missing := map[string]int{}
		extra := map[string]int{}
		res := satisfiesGPUs(test.reqs, test.gpus, missing, extra)
		require.Equal(t, test.exp, res, test.desc)
		if test.expMissing == nil {
			test.expMissing = map[string]int{}
		}
		if test.expExtra == nil {
			test.expExtra = map[string]int{}
		}
		require.Equal(t, test.expMissing, missing, test.desc)
		require.Equal(t, test.expExtra, extra, test.desc)
	}
}
