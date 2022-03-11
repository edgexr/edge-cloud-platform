package orm

import (
	"testing"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cloudcommon/node"
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
