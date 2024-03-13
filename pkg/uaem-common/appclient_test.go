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
	"testing"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	uaemtest "github.com/edgexr/edge-cloud-platform/pkg/uaem-testutil"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
)

func TestAddClients(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelDmereq)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())
	Settings.MaxTrackedDmeClients = 2

	InitAppInstClients(time.Minute)
	defer StopAppInstClients()

	// need to grab lock to avoid concurrent access with cleanup thread
	clientsByApp := func(key edgeproto.AppKey) ([]edgeproto.AppInstClient, bool) {
		clientsMap.RLock()
		defer clientsMap.RUnlock()
		list, found := clientsMap.clientsByApp[key]
		if found {
			cp := make([]edgeproto.AppInstClient, len(list))
			copy(cp, list)
			return cp, found
		}
		return list, found
	}

	UpdateClientsBuffer(ctx, &uaemtest.AppInstClientData[0])
	// check that this client is added correctly
	list, found := clientsByApp(uaemtest.AppInstClientData[0].ClientKey.AppKey)
	require.True(t, found)
	require.Equal(t, 1, len(list))
	require.Equal(t, uaemtest.AppInstClientData[0], list[0])

	UpdateClientsBuffer(ctx, &uaemtest.AppInstClientData[1])
	// check that this client is added correctly
	list, found = clientsByApp(uaemtest.AppInstClientData[1].ClientKey.AppKey)
	require.True(t, found)
	require.Equal(t, 1, len(list))
	require.Equal(t, uaemtest.AppInstClientData[1], list[0])

	UpdateClientsBuffer(ctx, &uaemtest.AppInstClientData[2])
	// check that this client is added correctly and replaced the original one that was there
	list, found = clientsByApp(uaemtest.AppInstClientData[0].ClientKey.AppKey)
	require.True(t, found)
	require.Equal(t, 1, len(list))
	require.Equal(t, uaemtest.AppInstClientData[2], list[0])

	// Add couple other clients to trigger the eviction of the first client
	UpdateClientsBuffer(ctx, &uaemtest.AppInstClientData[3])
	UpdateClientsBuffer(ctx, &uaemtest.AppInstClientData[4])
	// check that this client is added correctly and replaced the original one that was there
	list, found = clientsByApp(uaemtest.AppInstClientData[0].ClientKey.AppKey)
	require.True(t, found)
	require.Equal(t, 2, len(list))
	for _, c := range list {
		require.NotEqual(t, c, uaemtest.AppInstClientData[2])
	}

	require.Equal(t, 2, len(clientsMap.clientsByApp))

	// test deletion of AppInstances
	clientKey := &uaemtest.AppInstClientData[1].ClientKey
	PurgeAppInstClients(ctx, &clientKey.AppInstKey, &clientKey.AppKey)
	list, found = clientsByApp(clientKey.AppKey)
	require.True(t, found)
	require.Equal(t, 0, len(list))

	clientKey = &uaemtest.AppInstClientData[0].ClientKey
	PurgeAppInstClients(ctx, &clientKey.AppInstKey, &clientKey.AppKey)
	list, found = clientsByApp(clientKey.AppKey)
	require.True(t, found)
	require.Equal(t, 0, len(list))

	// test timeout of the appInstances
	tsOld := dme.TimeToTimestamp(time.Now().Add(-1 * time.Minute))
	data := uaemtest.AppInstClientData[3]
	data.Location.Timestamp = &tsOld
	UpdateClientsBuffer(ctx, &data)
	tsFuture := dme.TimeToTimestamp(time.Now().Add(1 * time.Minute))
	data = uaemtest.AppInstClientData[4]
	data.Location.Timestamp = &tsFuture
	UpdateClientsBuffer(ctx, &data)
	list, found = clientsByApp(uaemtest.AppInstClientData[4].ClientKey.AppKey)
	require.True(t, found)
	require.Equal(t, 2, len(list))
	// set quick timeout
	Settings.AppinstClientCleanupInterval = edgeproto.Duration(1 * time.Second)
	clientsMap.UpdateClientTimeout(Settings.AppinstClientCleanupInterval)
	// give the thread a bit of time to run
	time.Sleep(2 * time.Second)
	// Check to see that one of them got deleted
	list, found = clientsByApp(uaemtest.AppInstClientData[4].ClientKey.AppKey)
	require.True(t, found)
	require.Equal(t, 1, len(list))
	require.Equal(t, data, list[0])
}
