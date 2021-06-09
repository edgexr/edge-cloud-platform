package edgeevents

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	dmecommon "github.com/mobiledgex/edge-cloud/d-match-engine/dme-common"
	dme "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/stretchr/testify/require"
)

// Initialize bunch of CloudletKeys
var cloudlet0 = edgeproto.CloudletKey{
	Name:         "cloudlet0",
	Organization: "op-org0",
}
var cloudlet1 = edgeproto.CloudletKey{
	Name:         "cloudlet1",
	Organization: "op-org1",
}
var cloudlet2 = edgeproto.CloudletKey{
	Name:         "cloudlet2",
	Organization: "op-org2",
}
var cloudlets = [3]edgeproto.CloudletKey{cloudlet0, cloudlet1, cloudlet2}

// Intialize bunch of AppInstKeys
var appinst0 = edgeproto.AppInstKey{
	AppKey: edgeproto.AppKey{
		Name:         "app0",
		Organization: "org0",
	},
	ClusterInstKey: edgeproto.VirtualClusterInstKey{
		ClusterKey: edgeproto.ClusterKey{
			Name: "cluster0",
		},
		CloudletKey:  cloudlet0,
		Organization: "org0",
	},
}
var appinst1 = edgeproto.AppInstKey{
	AppKey: edgeproto.AppKey{
		Name:         "app1",
		Organization: "org1",
	},
	ClusterInstKey: edgeproto.VirtualClusterInstKey{
		ClusterKey: edgeproto.ClusterKey{
			Name: "cluster1",
		},
		CloudletKey:  cloudlet0,
		Organization: "org1",
	},
}
var appinst2 = edgeproto.AppInstKey{
	AppKey: edgeproto.AppKey{
		Name:         "app2",
		Organization: "org2",
	},
	ClusterInstKey: edgeproto.VirtualClusterInstKey{
		ClusterKey: edgeproto.ClusterKey{
			Name: "cluster0",
		},
		CloudletKey:  cloudlet1,
		Organization: "org2",
	},
}
var appinst3 = edgeproto.AppInstKey{
	AppKey: edgeproto.AppKey{
		Name:         "app3",
		Organization: "org3",
	},
	ClusterInstKey: edgeproto.VirtualClusterInstKey{
		ClusterKey: edgeproto.ClusterKey{
			Name: "cluster1",
		},
		CloudletKey:  cloudlet1,
		Organization: "org3",
	},
}
var appinst4 = edgeproto.AppInstKey{
	AppKey: edgeproto.AppKey{
		Name:         "app4",
		Organization: "org4",
	},
	ClusterInstKey: edgeproto.VirtualClusterInstKey{
		ClusterKey: edgeproto.ClusterKey{
			Name: "cluster0",
		},
		CloudletKey:  cloudlet2,
		Organization: "org4",
	},
}
var appinst5 = edgeproto.AppInstKey{
	AppKey: edgeproto.AppKey{
		Name:         "app5",
		Organization: "org5",
	},
	ClusterInstKey: edgeproto.VirtualClusterInstKey{
		ClusterKey: edgeproto.ClusterKey{
			Name: "cluster1",
		},
		CloudletKey:  cloudlet2,
		Organization: "org5",
	},
}
var appinsts = [6]edgeproto.AppInstKey{appinst0, appinst1, appinst2, appinst3, appinst4, appinst5}

// Intialize bunch of Clients
var client0 = dmecommon.CookieKey{
	UniqueId: "client0",
}
var client1 = dmecommon.CookieKey{
	UniqueId: "client1",
}
var client2 = dmecommon.CookieKey{
	UniqueId: "client2",
}
var client3 = dmecommon.CookieKey{
	UniqueId: "client3",
}
var client4 = dmecommon.CookieKey{
	UniqueId: "client4",
}
var client5 = dmecommon.CookieKey{
	UniqueId: "client5",
}
var clients = [6]dmecommon.CookieKey{client0, client1, client2, client3, client4, client5}

var emptyLoc = dme.Loc{}

func TestEdgeEventsHandlerPlugin(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelInfra)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	testAddRemoveKeysSerial(t, ctx)
	testAddRemoveKeysConcurrent(t, ctx)
}

func testAddRemoveKeysSerial(t *testing.T, ctx context.Context) {
	// Intialize EdgeEventsHandlerPlugin
	e := new(EdgeEventsHandlerPlugin)
	e.EdgeEventsCookieExpiration = 00 * time.Minute
	// Add clients
	e.AddClientKey(ctx, appinst0, client0, emptyLoc, "", nil)
	e.AddClientKey(ctx, appinst1, client1, emptyLoc, "", nil)
	e.AddClientKey(ctx, appinst2, client2, emptyLoc, "", nil)
	e.AddClientKey(ctx, appinst3, client3, emptyLoc, "", nil)
	e.AddClientKey(ctx, appinst4, client4, emptyLoc, "", nil)
	e.AddClientKey(ctx, appinst5, client5, emptyLoc, "", nil)

	e.AddClientKey(ctx, appinst0, client1, emptyLoc, "", nil)
	e.AddClientKey(ctx, appinst1, client2, emptyLoc, "", nil)
	e.AddClientKey(ctx, appinst2, client3, emptyLoc, "", nil)
	e.AddClientKey(ctx, appinst3, client4, emptyLoc, "", nil)
	e.AddClientKey(ctx, appinst4, client5, emptyLoc, "", nil)
	e.AddClientKey(ctx, appinst5, client0, emptyLoc, "", nil)

	e.AddClientKey(ctx, appinst0, client2, emptyLoc, "", nil)
	e.AddClientKey(ctx, appinst1, client3, emptyLoc, "", nil)
	e.AddClientKey(ctx, appinst2, client4, emptyLoc, "", nil)
	e.AddClientKey(ctx, appinst3, client5, emptyLoc, "", nil)
	e.AddClientKey(ctx, appinst4, client0, emptyLoc, "", nil)
	e.AddClientKey(ctx, appinst5, client1, emptyLoc, "", nil)

	// Check that all Cloudlets, AppInsts, and Clients were added to maps
	require.Equal(t, 3, len(e.CloudletsMap))
	for _, appinsts := range e.CloudletsMap {
		require.Equal(t, 2, len(appinsts.AppInstsMap))
		for _, clients := range appinsts.AppInstsMap {
			require.Equal(t, 3, len(clients.ClientsMap))
		}
	}

	// Remove clients
	e.RemoveClientKey(ctx, appinst0, client0)
	e.RemoveClientKey(ctx, appinst1, client1)
	e.RemoveClientKey(ctx, appinst2, client2)
	e.RemoveClientKey(ctx, appinst3, client3)
	e.RemoveClientKey(ctx, appinst4, client4)
	e.RemoveClientKey(ctx, appinst5, client5)

	e.RemoveClientKey(ctx, appinst0, client1)
	e.RemoveClientKey(ctx, appinst1, client2)
	e.RemoveClientKey(ctx, appinst2, client3)
	e.RemoveClientKey(ctx, appinst3, client4)
	e.RemoveClientKey(ctx, appinst4, client5)
	e.RemoveClientKey(ctx, appinst5, client0)

	e.RemoveClientKey(ctx, appinst0, client2)
	e.RemoveClientKey(ctx, appinst1, client3)
	e.RemoveClientKey(ctx, appinst2, client4)
	e.RemoveClientKey(ctx, appinst3, client5)
	e.RemoveClientKey(ctx, appinst4, client0)
	e.RemoveClientKey(ctx, appinst5, client1)

	// All Cloudlets, AppInsts, and Clients should have been removed
	require.Equal(t, 0, len(e.CloudletsMap))
}

func testAddRemoveKeysConcurrent(t *testing.T, ctx context.Context) {
	// Intialize EdgeEventsHandlerPlugin
	e := new(EdgeEventsHandlerPlugin)
	e.EdgeEventsCookieExpiration = 10 * time.Minute

	numClients := len(clients)
	numAppInstsPerClient := 3
	sleepRange := 3
	done := make(chan string, numClients*numAppInstsPerClient)

	for i, c := range clients {
		go func(client dmecommon.CookieKey, idx int) {
			appinst := appinsts[idx]
			// sleep
			time.Sleep(time.Duration(rand.Intn(sleepRange)) * time.Millisecond)
			e.AddClientKey(ctx, appinst, client, emptyLoc, "", nil)
			// sleep
			time.Sleep(time.Duration(rand.Intn(sleepRange)) * time.Millisecond)
			e.RemoveClientKey(ctx, appinst, client)
			done <- fmt.Sprintf("Client %d on Appinst %d", idx, idx)
		}(c, i)
		go func(client dmecommon.CookieKey, idx int) {
			// next appinst
			appinstidx := (idx + 1) % 6
			appinst := appinsts[appinstidx]
			// sleep
			time.Sleep(time.Duration(rand.Intn(sleepRange)) * time.Millisecond)
			e.AddClientKey(ctx, appinst, client, emptyLoc, "", nil)
			// sleep
			time.Sleep(time.Duration(rand.Intn(sleepRange)) * time.Millisecond)
			e.RemoveClientKey(ctx, appinst, client)
			done <- fmt.Sprintf("Client %d on Appinst %d", idx, appinstidx)
		}(c, i)
		go func(client dmecommon.CookieKey, idx int) {
			// next appinst
			appinstidx := (idx + 2) % 6
			appinst := appinsts[appinstidx]
			// sleep
			time.Sleep(time.Duration(rand.Intn(sleepRange)) * time.Millisecond)
			e.AddClientKey(ctx, appinst, client, emptyLoc, "", nil)
			// sleep
			time.Sleep(time.Duration(rand.Intn(sleepRange)) * time.Millisecond)
			e.RemoveClientKey(ctx, appinst, client)
			done <- fmt.Sprintf("Client %d on Appinst %d", idx, appinstidx)
		}(c, i)
	}

	for i := 0; i < cap(done); i++ {
		select {
		case client := <-done:
			fmt.Printf("%s completed add remove cycle\n", client)
		}
	}

	// All Cloudlets, AppInsts, and Clients should have been removed
	require.Equal(t, 0, len(e.CloudletsMap))
}
