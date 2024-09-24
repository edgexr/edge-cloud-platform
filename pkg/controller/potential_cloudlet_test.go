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
	"sort"
	"testing"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/stretchr/testify/require"
)

func getPotentialInstCloudletTestData() []*potentialInstCloudlet {
	pc1 := potentialInstCloudlet{}
	pc1.cloudlet.Key.Name = "c1"
	pc1.cloudletInfo.ResourcesSnapshot.Info = []edgeproto.InfraResource{{
		Name:          "RAM",
		Value:         uint64(1024),
		InfraMaxValue: uint64(102400),
	}, {
		Name:          "vCPUs",
		Value:         uint64(10),
		InfraMaxValue: uint64(109),
	}, {
		Name:          "Disk",
		Value:         uint64(20),
		InfraMaxValue: uint64(5000),
	}, {
		Name:          "GPUs",
		Value:         uint64(6),
		InfraMaxValue: uint64(20),
	}, {
		Name:          "External IPs",
		Value:         uint64(2),
		InfraMaxValue: uint64(10),
	}}

	pc2 := potentialInstCloudlet{}
	pc2.cloudlet.Key.Name = "c2"
	pc2.cloudletInfo.ResourcesSnapshot.Info = []edgeproto.InfraResource{{
		Name:          "RAM",
		Value:         uint64(2048),
		InfraMaxValue: uint64(61440),
	}, {
		Name:          "vCPUs",
		Value:         uint64(10),
		InfraMaxValue: uint64(120),
	}, {
		Name:          "Disk",
		Value:         uint64(20),
		InfraMaxValue: uint64(5000),
	}, {
		Name:          "External IPs",
		Value:         uint64(2),
		InfraMaxValue: uint64(10),
	}}

	pc3 := potentialInstCloudlet{}
	pc3.cloudlet.Key.Name = "c3"
	pc3.cloudletInfo.ResourcesSnapshot.Info = []edgeproto.InfraResource{{
		Name:          "RAM",
		Value:         uint64(4096),
		InfraMaxValue: uint64(61440),
	}, {
		Name:          "vCPUs",
		Value:         uint64(15),
		InfraMaxValue: uint64(150),
	}, {
		Name:          "Disk",
		Value:         uint64(20),
		InfraMaxValue: uint64(5000),
	}, {
		Name:          "External IPs",
		Value:         uint64(2),
		InfraMaxValue: uint64(10),
	}}

	pcs := []*potentialInstCloudlet{
		&pc1, &pc2, &pc3,
	}
	return pcs
}

func TestPotentialInstCloudletResourceScore(t *testing.T) {
	pc := getPotentialInstCloudletTestData()[0]
	expScore := uint64(ResourceWeightRAM*(102400-1024) + ResourceWeightVCPU*(109-10))
	require.Equal(t, expScore, pc.resourceScore())
}

func TestSortPotentialInstCloudletsByResource(t *testing.T) {
	pcs := getPotentialInstCloudletTestData()
	sort.Sort(PotentialInstCloudletsByResource(pcs))
	for ii := 0; ii < len(pcs)-1; ii++ {
		require.GreaterOrEqual(t, pcs[ii].resourceScore(), pcs[ii+1].resourceScore())
	}
}
