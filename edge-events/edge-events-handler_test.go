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

package edgeevents

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	dmecommon "github.com/edgexr/edge-cloud/d-match-engine/dme-common"
	dme "github.com/edgexr/edge-cloud/d-match-engine/dme-proto"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
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
	e.Cloudlets = make(map[edgeproto.CloudletKey]*CloudletInfo)
	e.EdgeEventsCookieExpiration = 10 * time.Minute
	// Add appinsts
	e.SendAvailableAppInst(ctx, nil, appinst0, nil, "")
	e.SendAvailableAppInst(ctx, nil, appinst1, nil, "")
	e.SendAvailableAppInst(ctx, nil, appinst2, nil, "")
	e.SendAvailableAppInst(ctx, nil, appinst3, nil, "")
	e.SendAvailableAppInst(ctx, nil, appinst4, nil, "")
	e.SendAvailableAppInst(ctx, nil, appinst5, nil, "")
	// Add clients
	e.AddClient(ctx, appinst0, client0, emptyLoc, "", nil)
	e.AddClient(ctx, appinst1, client1, emptyLoc, "", nil)
	e.AddClient(ctx, appinst2, client2, emptyLoc, "", nil)
	e.AddClient(ctx, appinst3, client3, emptyLoc, "", nil)
	e.AddClient(ctx, appinst4, client4, emptyLoc, "", nil)
	e.AddClient(ctx, appinst5, client5, emptyLoc, "", nil)

	e.AddClient(ctx, appinst0, client1, emptyLoc, "", nil)
	e.AddClient(ctx, appinst1, client2, emptyLoc, "", nil)
	e.AddClient(ctx, appinst2, client3, emptyLoc, "", nil)
	e.AddClient(ctx, appinst3, client4, emptyLoc, "", nil)
	e.AddClient(ctx, appinst4, client5, emptyLoc, "", nil)
	e.AddClient(ctx, appinst5, client0, emptyLoc, "", nil)

	e.AddClient(ctx, appinst0, client2, emptyLoc, "", nil)
	e.AddClient(ctx, appinst1, client3, emptyLoc, "", nil)
	e.AddClient(ctx, appinst2, client4, emptyLoc, "", nil)
	e.AddClient(ctx, appinst3, client5, emptyLoc, "", nil)
	e.AddClient(ctx, appinst4, client0, emptyLoc, "", nil)
	e.AddClient(ctx, appinst5, client1, emptyLoc, "", nil)

	// Check that all Cloudlets, AppInsts, and Clients were added to maps
	require.Equal(t, 3, len(e.Cloudlets))
	for _, cloudletinfo := range e.Cloudlets {
		require.Equal(t, 2, len(cloudletinfo.AppInsts))
		for _, appinstinfo := range cloudletinfo.AppInsts {
			require.Equal(t, 3, len(appinstinfo.Clients))
		}
	}

	// Remove clients
	e.RemoveClient(ctx, appinst0, client0)
	e.RemoveClient(ctx, appinst1, client1)
	e.RemoveClient(ctx, appinst2, client2)
	e.RemoveClient(ctx, appinst3, client3)
	e.RemoveClient(ctx, appinst4, client4)
	e.RemoveClient(ctx, appinst5, client5)

	e.RemoveClient(ctx, appinst0, client1)
	e.RemoveClient(ctx, appinst1, client2)
	e.RemoveClient(ctx, appinst2, client3)
	e.RemoveClient(ctx, appinst3, client4)
	e.RemoveClient(ctx, appinst4, client5)
	e.RemoveClient(ctx, appinst5, client0)

	e.RemoveClient(ctx, appinst0, client2)
	e.RemoveClient(ctx, appinst1, client3)
	e.RemoveClient(ctx, appinst2, client4)
	e.RemoveClient(ctx, appinst3, client5)
	e.RemoveClient(ctx, appinst4, client0)
	e.RemoveClient(ctx, appinst5, client1)

	// Remove AppInsts
	e.RemoveAppInst(ctx, appinst0)
	e.RemoveAppInst(ctx, appinst1)
	e.RemoveAppInst(ctx, appinst2)
	e.RemoveAppInst(ctx, appinst3)
	e.RemoveAppInst(ctx, appinst4)
	e.RemoveAppInst(ctx, appinst5)

	// All Cloudlets, AppInsts, and Clients should have been removed
	require.Equal(t, 0, len(e.Cloudlets))
}

func testAddRemoveKeysConcurrent(t *testing.T, ctx context.Context) {
	// Intialize EdgeEventsHandlerPlugin
	e := new(EdgeEventsHandlerPlugin)
	e.Cloudlets = make(map[edgeproto.CloudletKey]*CloudletInfo)
	e.EdgeEventsCookieExpiration = 10 * time.Minute
	// Add appinsts
	e.SendAvailableAppInst(ctx, nil, appinst0, nil, "")
	e.SendAvailableAppInst(ctx, nil, appinst1, nil, "")
	e.SendAvailableAppInst(ctx, nil, appinst2, nil, "")
	e.SendAvailableAppInst(ctx, nil, appinst3, nil, "")
	e.SendAvailableAppInst(ctx, nil, appinst4, nil, "")
	e.SendAvailableAppInst(ctx, nil, appinst5, nil, "")

	numClients := len(clients)
	numAppInstsPerClient := 3
	sleepRange := 3
	done := make(chan string, numClients*numAppInstsPerClient)

	for i, c := range clients {
		go func(client dmecommon.CookieKey, idx int) {
			appinst := appinsts[idx]
			// sleep
			time.Sleep(time.Duration(rand.Intn(sleepRange)) * time.Millisecond)
			e.AddClient(ctx, appinst, client, emptyLoc, "", nil)
			// sleep
			time.Sleep(time.Duration(rand.Intn(sleepRange)) * time.Millisecond)
			e.RemoveClient(ctx, appinst, client)
			done <- fmt.Sprintf("Client %d on Appinst %d", idx, idx)
		}(c, i)
		go func(client dmecommon.CookieKey, idx int) {
			// next appinst
			appinstidx := (idx + 1) % 6
			appinst := appinsts[appinstidx]
			// sleep
			time.Sleep(time.Duration(rand.Intn(sleepRange)) * time.Millisecond)
			e.AddClient(ctx, appinst, client, emptyLoc, "", nil)
			// sleep
			time.Sleep(time.Duration(rand.Intn(sleepRange)) * time.Millisecond)
			e.RemoveClient(ctx, appinst, client)
			done <- fmt.Sprintf("Client %d on Appinst %d", idx, appinstidx)
		}(c, i)
		go func(client dmecommon.CookieKey, idx int) {
			// next appinst
			appinstidx := (idx + 2) % 6
			appinst := appinsts[appinstidx]
			// sleep
			time.Sleep(time.Duration(rand.Intn(sleepRange)) * time.Millisecond)
			e.AddClient(ctx, appinst, client, emptyLoc, "", nil)
			// sleep
			time.Sleep(time.Duration(rand.Intn(sleepRange)) * time.Millisecond)
			e.RemoveClient(ctx, appinst, client)
			done <- fmt.Sprintf("Client %d on Appinst %d", idx, appinstidx)
		}(c, i)
	}

	for i := 0; i < cap(done); i++ {
		select {
		case client := <-done:
			fmt.Printf("%s completed add remove cycle\n", client)
		}
	}

	// Remove AppInsts
	e.RemoveAppInst(ctx, appinst0)
	e.RemoveAppInst(ctx, appinst1)
	e.RemoveAppInst(ctx, appinst2)
	e.RemoveAppInst(ctx, appinst3)
	e.RemoveAppInst(ctx, appinst4)
	e.RemoveAppInst(ctx, appinst5)

	// All Cloudlets, AppInsts, and Clients should have been removed
	require.Equal(t, 0, len(e.Cloudlets))
}
