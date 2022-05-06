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

package orm

import (
	"testing"
	"time"

	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud/cloudcommon/node"
	"github.com/stretchr/testify/require"
)

func TestFilterEvents(t *testing.T) {
	tStart := time.Now()
	orgName := "AcmeAppCo"
	numEvents := 5
	// create a bunch of events tied to an org
	events := []node.EventData{}
	for ii := 0; ii < numEvents; ii++ {
		event := node.EventData{
			Name:      "AutoProv create AppInst",
			Org:       []string{orgName},
			Type:      "event",
			Region:    "local",
			Timestamp: tStart.Add(time.Duration(ii) * time.Minute),
		}
		events = append(events, event)
	}
	orgs := map[string]*ormapi.Organization{
		orgName: &ormapi.Organization{
			Name:      orgName,
			CreatedAt: tStart,
		},
	}
	filtered := filterEvents(events, orgs)
	require.Equal(t, numEvents, len(filtered))

	orgs = map[string]*ormapi.Organization{
		orgName: &ormapi.Organization{
			Name:      orgName,
			CreatedAt: tStart.Add(2 * time.Minute),
		},
	}
	filtered = filterEvents(events, orgs)
	require.Equal(t, numEvents-2, len(filtered))

	orgs = map[string]*ormapi.Organization{
		orgName: &ormapi.Organization{
			Name:      orgName,
			CreatedAt: tStart.Add(time.Duration(numEvents) * time.Minute),
		},
	}
	filtered = filterEvents(events, orgs)
	require.Equal(t, 0, len(filtered))

	// corner case: no matching org
	orgs = map[string]*ormapi.Organization{}
	filtered = filterEvents(events, orgs)
	require.Equal(t, 0, len(filtered))
}
