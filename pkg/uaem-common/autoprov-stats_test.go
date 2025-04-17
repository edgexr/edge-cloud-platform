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

package dmecommon

import (
	"context"
	"testing"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/stretchr/testify/require"
)

func TestAutoProvStats(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelDmereq | log.DebugLevelMetrics)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	org := "org"
	app := edgeproto.App{
		Key: edgeproto.AppKey{
			Organization: org,
			Name:         "someapp",
			Version:      "1.0",
		},
	}
	carrier := "oper"

	// zones for policies
	zoneKeys := []*edgeproto.ZoneKey{{
		Organization: carrier,
		Name:         "zone1",
	}, {
		Organization: carrier,
		Name:         "zone4",
	}, {
		Organization: carrier,
		Name:         "zone8",
	}}

	cloudlets := []*edgeproto.Cloudlet{{
		Key: edgeproto.CloudletKey{
			Organization: carrier,
			Name:         "1,1",
		},
		Location: dme.Loc{
			Latitude:  1,
			Longitude: 1,
		},
		Zone: zoneKeys[0].Name,
	}, {
		Key: edgeproto.CloudletKey{
			Organization: carrier,
			Name:         "4,4",
		},
		Location: dme.Loc{
			Latitude:  4,
			Longitude: 4,
		},
		Zone: zoneKeys[1].Name,
	}, {
		Key: edgeproto.CloudletKey{
			Organization: carrier,
			Name:         "8,8",
		},
		Location: dme.Loc{
			Latitude:  8,
			Longitude: 8,
		},
		Zone: zoneKeys[2].Name,
	}}

	// reservable ClusterInsts
	clusterInsts := []edgeproto.ClusterInst{}
	for ii, zkey := range zoneKeys {
		ci := edgeproto.ClusterInst{
			Key: edgeproto.ClusterKey{
				Name:         "clust",
				Organization: edgeproto.OrganizationEdgeCloud,
			},
			ZoneKey:     *zkey,
			CloudletKey: cloudlets[ii].Key,
			Reservable:  true,
		}
		clusterInsts = append(clusterInsts, ci)
	}

	locs := []dme.Loc{}
	for _, cl := range cloudlets {
		locs = append(locs, cl.Location)
	}

	policies := []edgeproto.AutoProvPolicy{
		edgeproto.AutoProvPolicy{
			Key: edgeproto.PolicyKey{
				Name:         "policy01",
				Organization: org,
			},
			DeployClientCount:   2,
			DeployIntervalCount: 2,
			Zones: []*edgeproto.ZoneKey{
				zoneKeys[0],
				zoneKeys[1],
			},
		},
		edgeproto.AutoProvPolicy{
			Key: edgeproto.PolicyKey{
				Name:         "policy12",
				Organization: org,
			},
			DeployClientCount:   2,
			DeployIntervalCount: 2,
			Zones: []*edgeproto.ZoneKey{
				zoneKeys[1],
				zoneKeys[2],
			},
		},
		edgeproto.AutoProvPolicy{
			Key: edgeproto.PolicyKey{
				Name:         "policy012",
				Organization: org,
			},
			DeployClientCount:   2,
			DeployIntervalCount: 2,
			Zones: []*edgeproto.ZoneKey{
				zoneKeys[0],
				zoneKeys[1],
				zoneKeys[2],
			},
		},
	}
	// immediate policies (interval count is 1)
	immPolicies := []edgeproto.AutoProvPolicy{
		edgeproto.AutoProvPolicy{
			Key: edgeproto.PolicyKey{
				Name:         "immpolicy01",
				Organization: org,
			},
			DeployClientCount:   2,
			DeployIntervalCount: 1,
			Zones: []*edgeproto.ZoneKey{
				zoneKeys[0],
				zoneKeys[1],
			},
		},
		edgeproto.AutoProvPolicy{
			Key: edgeproto.PolicyKey{
				Name:         "immpolicy12",
				Organization: org,
			},
			DeployClientCount:   2,
			DeployIntervalCount: 1,
			Zones: []*edgeproto.ZoneKey{
				zoneKeys[1],
				zoneKeys[2],
			},
		},
		edgeproto.AutoProvPolicy{
			Key: edgeproto.PolicyKey{
				Name:         "immpolicy012",
				Organization: org,
			},
			DeployClientCount:   2,
			DeployIntervalCount: 1,
			Zones: []*edgeproto.ZoneKey{
				zoneKeys[0],
				zoneKeys[1],
				zoneKeys[2],
			},
		},
	}

	emptyTest := apStatsTestData{
		app:                app,
		carrier:            carrier,
		cloudlets:          cloudlets,
		expectedCounts:     make(map[edgeproto.ZoneKey]uint64),
		expectedSendCounts: make(map[edgeproto.ZoneKey]uint64),
	}

	// no policies means no stats
	test := emptyTest
	test.clusterInsts = clusterInsts
	test.locs = locs
	test.run(t, ctx)

	// no reservable cluster insts means reservable cluster inst
	// will be automatically created on closest cloudlet
	test = emptyTest
	test.policies = append(policies, immPolicies...)
	test.locs = locs
	test.expectedCounts = map[edgeproto.ZoneKey]uint64{
		*zoneKeys[0]: 1, // req loc 1,1
		*zoneKeys[1]: 1, // req loc 4,4
		*zoneKeys[2]: 1, // req loc 8,8
	}
	test.run(t, ctx)

	// single policy01
	test = emptyTest
	test.clusterInsts = clusterInsts
	test.policies = policies[0:1]
	test.locs = locs
	test.expectedCounts = map[edgeproto.ZoneKey]uint64{
		*zoneKeys[0]: 1, // req loc 1,1
		*zoneKeys[1]: 2, // req loc 4,4 and 8,8
	}
	test.run(t, ctx)

	// single policy12
	test = emptyTest
	test.clusterInsts = clusterInsts
	test.policies = policies[1:2]
	test.locs = append(locs, locs...) // double requests
	test.expectedCounts = map[edgeproto.ZoneKey]uint64{
		*zoneKeys[1]: 4, // req loc 1,1 and 4,4,
		*zoneKeys[2]: 2, // req loc 8,8
	}
	test.run(t, ctx)

	// single policy012
	test = emptyTest
	test.clusterInsts = clusterInsts
	test.policies = policies[2:3]
	test.locs = locs
	test.expectedCounts = map[edgeproto.ZoneKey]uint64{
		*zoneKeys[0]: 1, // req loc 1,1
		*zoneKeys[1]: 1, // req loc 4,4
		*zoneKeys[2]: 1, // req loc 8,8
	}
	test.run(t, ctx)

	// all policies (except immediate)
	test = emptyTest
	test.clusterInsts = clusterInsts
	test.policies = policies
	test.locs = locs
	test.expectedCounts = map[edgeproto.ZoneKey]uint64{
		*zoneKeys[0]: 1, // req loc 1,1
		*zoneKeys[1]: 1, // req loc 4,4
		*zoneKeys[2]: 1, // req loc 8,8
	}

	// all policies (immediate policies should trigger sends)
	test = emptyTest
	test.clusterInsts = clusterInsts
	test.policies = append(policies, immPolicies...)
	test.locs = append(locs, locs...) // double requests
	test.expectedCounts = map[edgeproto.ZoneKey]uint64{
		*zoneKeys[0]: 2,
		*zoneKeys[1]: 2,
		*zoneKeys[2]: 2,
	}
	test.expectedSendCounts = map[edgeproto.ZoneKey]uint64{
		*zoneKeys[0]: 2,
		*zoneKeys[1]: 2,
		*zoneKeys[2]: 2,
	}
	test.run(t, ctx)
}

type apStatsTestData struct {
	app                edgeproto.App
	carrier            string
	cloudlets          []*edgeproto.Cloudlet
	clusterInsts       []edgeproto.ClusterInst
	policies           []edgeproto.AutoProvPolicy
	locs               []dme.Loc
	expectedCounts     map[edgeproto.ZoneKey]uint64
	expectedSendCounts map[edgeproto.ZoneKey]uint64
}

func (s *apStatsTestData) run(t *testing.T, ctx context.Context) {
	// reset all data
	actualSendCounts := make(map[edgeproto.ZoneKey]uint64)

	eehandler := &EmptyEdgeEventsHandler{}
	SetupMatchEngine(eehandler)
	InitAutoProvStats(500, 0, 1, &edgeproto.SvcNodeKey{}, func(ctx context.Context, counts *edgeproto.AutoProvCounts) bool {
		require.Equal(t, 1, len(counts.Counts))
		apCount := counts.Counts[0]
		actualSendCounts[apCount.ZoneKey] = apCount.Count
		require.True(t, apCount.ProcessNow)
		return true
	})
	apHandler := AutoProvPolicyHandler{}

	// add cloudlets
	for _, cloudlet := range s.cloudlets {
		SetInstStateFromCloudlet(ctx, cloudlet)
	}
	require.Equal(t, len(s.cloudlets), len(DmeAppTbl.CloudletLocsByZone))

	// add policies
	for _, policy := range s.policies {
		apHandler.Update(ctx, &policy, 0)
	}
	// add ClusterInsts
	for _, ci := range s.clusterInsts {
		DmeAppTbl.FreeReservableClusterInsts.Update(ctx, &ci, 0)
	}
	// set policies on App
	app := s.app
	for _, p := range s.policies {
		app.AutoProvPolicies = append(app.AutoProvPolicies, p.Key.Name)
	}
	// add App
	AddApp(ctx, &app)

	// do "find cloudlet" calls
	for _, loc := range s.locs {
		findBestForCarrier(ctx, s.carrier, &app.Key, &loc, 1)
	}

	// get actual stats
	actualCounts := make(map[edgeproto.ZoneKey]uint64)
	for ii, _ := range autoProvStats.shards {
		for key, counts := range autoProvStats.shards[ii].appCloudletCounts {
			actualCounts[key.ZoneKey] = counts.count
		}
	}

	require.Equal(t, s.expectedCounts, actualCounts)
	require.Equal(t, s.expectedSendCounts, actualSendCounts)
}
