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
	fmt "fmt"
	"math"
	"sort"
	"strconv"
	"testing"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/resspec"
	"github.com/stretchr/testify/require"
)

func TestPotentialInstCloudletCalcResourceScore(t *testing.T) {
	var tests = []struct {
		desc     string
		infraRes []edgeproto.InfraResource
		quotas   []edgeproto.ResourceQuota
		used     func() resspec.ResValMap
		expScore uint64
	}{{
		desc: "infra max 1",
		infraRes: []edgeproto.InfraResource{{
			Name:          cloudcommon.ResourceVcpus,
			InfraMaxValue: 20,
		}},
		expScore: 20000, // 20*1000 / 1
	}, {
		desc: "quota max 1",
		quotas: []edgeproto.ResourceQuota{{
			Name:  cloudcommon.ResourceRamMb,
			Value: 1000,
		}},
		expScore: 1000, // 1000*1 / 1
	}, {
		desc: "infra max 2 averaged",
		infraRes: []edgeproto.InfraResource{{
			Name:          cloudcommon.ResourceVcpus,
			InfraMaxValue: 20,
		}, {
			Name:          cloudcommon.ResourceRamMb,
			InfraMaxValue: 1000,
		}},
		expScore: 10500, // (20*1000 + 1000*1)/2
	}, {
		desc: "quota max 2 averaged", // quota and inframax are equivalent
		quotas: []edgeproto.ResourceQuota{{
			Name:  cloudcommon.ResourceVcpus,
			Value: 20,
		}, {
			Name:  cloudcommon.ResourceRamMb,
			Value: 1000,
		}},
		expScore: 10500, // (20*1000 + 1000)/2
	}, {
		desc: "infra max ignore unweighted",
		infraRes: []edgeproto.InfraResource{{
			Name:          cloudcommon.ResourceVcpus,
			InfraMaxValue: 20,
		}, {
			Name:          cloudcommon.ResourceExternalIPs,
			InfraMaxValue: 20,
		}},
		expScore: 20000, // 20*1000/1
	}, {
		desc: "quota max with used",
		quotas: []edgeproto.ResourceQuota{{
			Name:  cloudcommon.ResourceVcpus,
			Value: 20,
		}, {
			Name:  cloudcommon.ResourceRamMb,
			Value: 10000,
		}},
		used: func() resspec.ResValMap {
			res := resspec.ResValMap{}
			res.AddVcpus(4, 500*edgeproto.DecMillis)
			res.AddRam(2000)
			return res
		},
		expScore: 11750, // ((20-4.5)*1000 + (10000-2000)*1)/2
	}, {
		desc:     "no max",
		expScore: math.MaxUint64,
	}, {
		desc: "no max with used",
		used: func() resspec.ResValMap {
			res := resspec.ResValMap{}
			res.AddVcpus(4, 500*edgeproto.DecMillis)
			res.AddRam(2000)
			return res
		},
		expScore: math.MaxUint64,
	}, {
		desc: "negative free resources",
		quotas: []edgeproto.ResourceQuota{{
			Name:  cloudcommon.ResourceVcpus,
			Value: 20,
		}},
		used: func() resspec.ResValMap {
			res := resspec.ResValMap{}
			res.AddVcpus(24, 0)
			return res
		},
		expScore: 0,
	}}
	for _, test := range tests {
		// build pc
		pc := potentialInstCloudlet{}
		pc.cloudlet.ResourceQuotas = test.quotas
		pc.cloudletInfo.ResourcesSnapshot.Info = test.infraRes
		pc.resCalc = NewCloudletResCalc(nil, nil, &pc.cloudlet.Key)
		pc.resCalc.deps.cloudlet = &pc.cloudlet
		pc.resCalc.deps.cloudletInfo = &pc.cloudletInfo
		used := resspec.ResValMap{}
		if test.used != nil {
			used = test.used()
		}
		pc.resourceScore = pc.resCalc.calcResourceScoreFromUsed(used)
		require.Equal(t, test.expScore, pc.resourceScore, fmt.Sprintf("%s: expected %d but was %d", test.desc, test.expScore, pc.resourceScore))
	}
}

func TestSortPotentialInstCloudletsByResource(t *testing.T) {
	// Note that pc's with the same score are assigned names
	// based on their index, and should be then compared by name,
	// so lower index will come first.
	var tests = []struct {
		scores []uint64
		expIDs []int
	}{{
		scores: []uint64{1000},
		expIDs: []int{0},
	}, {
		scores: []uint64{1000, 2000, 2000, 3000},
		expIDs: []int{3, 1, 2, 0},
	}, {
		scores: []uint64{3000, 2000, 2000, 3000},
		expIDs: []int{0, 3, 1, 2},
	}}
	for _, test := range tests {
		pcs := PotentialInstCloudletsByResource{}
		for ii, score := range test.scores {
			pc := &potentialInstCloudlet{}
			pc.cloudlet.Key.Name = strconv.Itoa(ii)
			pc.resourceScore = score
			pcs = append(pcs, pc)
		}
		sort.Sort(pcs)
		outIDs := []int{}
		for _, pc := range pcs {
			id, err := strconv.Atoi(pc.cloudlet.Key.Name)
			require.Nil(t, err)
			outIDs = append(outIDs, id)
		}
		require.Equal(t, test.expIDs, outIDs, fmt.Sprintf("sort scores %v", test.scores))
	}
}
