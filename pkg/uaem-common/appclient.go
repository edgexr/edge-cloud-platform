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
	"fmt"
	"sync"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/notify"
	"golang.org/x/net/context"
)

type ClientsMap struct {
	sync.RWMutex
	clientsByApp               map[edgeproto.AppKey][]edgeproto.AppInstClient
	cleanupTimeout             time.Duration
	waitGrp                    sync.WaitGroup
	stopCleanupThread          chan struct{}
	updateAppinstClientTimeout chan bool
}

var clientsMap *ClientsMap

var ClientSender *notify.AppInstClientSend
var AppInstClientKeyCache edgeproto.AppInstClientKeyCache

func InitAppInstClients(timeout time.Duration) {
	clientsMap = new(ClientsMap)
	clientsMap.clientsByApp = make(map[edgeproto.AppKey][]edgeproto.AppInstClient)
	clientsMap.stopCleanupThread = make(chan struct{})
	clientsMap.updateAppinstClientTimeout = make(chan bool)
	clientsMap.cleanupTimeout = timeout
	clientsMap.waitGrp.Add(1)
	go clientsMap.timeoutAppInstClients()
}

func StopAppInstClients() {
	clientsMap.stop()
}

func (m *ClientsMap) stop() {
	close(m.stopCleanupThread)
	m.waitGrp.Wait()
}

func (m *ClientsMap) UpdateClientTimeout(new edgeproto.Duration) {
	m.cleanupTimeout = time.Duration(new)
	m.updateAppinstClientTimeout <- true
}

// Periodically timeout appInstClients from clientsMap and
// send notifications to the controller to delete them
func (m *ClientsMap) timeoutAppInstClients() {
	done := false
	for !done {
		select {
		case <-m.updateAppinstClientTimeout:
			// This triggers the update of the timeout, so we need to restart the timer
			continue
		case <-time.After(m.cleanupTimeout):
			span := log.StartSpan(log.DebugLevelSampled, "appinstclient-cleanup")
			log.SetTags(span, MyCloudletKey.GetTags())
			ctx := log.ContextWithSpan(context.Background(), span)
			log.SpanLog(ctx, log.DebugLevelInfo, "Running timeoutAppInstClients", "timeout", Settings.AppinstClientCleanupInterval)
			// Last valid timestamp was now-cleanupTimeout
			lastValidTime := time.Now().Add(-m.cleanupTimeout)
			// Walk the entire map to find all possible matches
			clientsMap.Lock()
			for k, list := range m.clientsByApp {
				jj := 0
				for _, client := range list {
					// Check if this client needs to be timed out -
					//   if last Valid time is later than the client timestamp
					if client.Location.Timestamp == nil ||
						lastValidTime.After(dme.TimestampToTime(*client.Location.Timestamp)) {
						continue
					}
					m.clientsByApp[k][jj] = client
					jj++
				}
				// truncate the list
				m.clientsByApp[k] = m.clientsByApp[k][:jj]
			}
			clientsMap.Unlock()
			span.Finish()
		case <-m.stopCleanupThread:
			done = true
		}
	}
	m.waitGrp.Done()
}

// Add a new client to the list of clients
func UpdateClientsBuffer(ctx context.Context, msg *edgeproto.AppInstClient) {
	clientsMap.Lock()
	defer clientsMap.Unlock()
	mapKey := msg.ClientKey.AppKey
	_, found := clientsMap.clientsByApp[mapKey]
	if !found {
		clientsMap.clientsByApp[mapKey] = []edgeproto.AppInstClient{*msg}
	} else {
		// We need to either update, or add the client to the list
		for ii, c := range clientsMap.clientsByApp[mapKey] {
			// Found the same client from before
			if c.ClientKey.UniqueId == msg.ClientKey.UniqueId &&
				c.ClientKey.UniqueIdType == msg.ClientKey.UniqueIdType {
				clientsMap.clientsByApp[mapKey] = append(clientsMap.clientsByApp[mapKey][:ii],
					clientsMap.clientsByApp[mapKey][ii+1:]...)
				break
			}
		}
		//  We reached the limit of clients - remove the first one
		if len(clientsMap.clientsByApp[mapKey]) == int(Settings.MaxTrackedDmeClients) {
			clientsMap.clientsByApp[mapKey] = clientsMap.clientsByApp[mapKey][1:]
		}
		clientsMap.clientsByApp[mapKey] = append(clientsMap.clientsByApp[mapKey], *msg)
	}
	// If there is an outstanding request for this appInstClientKey - send it out
	AppInstClientKeyCache.Show(&edgeproto.AppInstClientKey{}, func(obj *edgeproto.AppInstClientKey) error {
		if msg.ClientKey.Matches(obj, edgeproto.MatchFilter()) {
			ClientSender.Update(ctx, msg)
			return fmt.Errorf("Found match - just send once")
		}
		return nil
	})
}

// If an AppInst is deleted, clean up all the clients from it
func PurgeAppInstClients(ctx context.Context, appInstKey *edgeproto.AppInstKey, appKey *edgeproto.AppKey) {
	clientsMap.Lock()
	defer clientsMap.Unlock()
	clients, found := clientsMap.clientsByApp[*appKey]
	if found {
		// walk the list and keep only the clients that don't match the filter
		jj := 0
		for _, c := range clients {
			// Remove matching clients
			if appInstKey.Matches(&c.ClientKey.AppInstKey) {
				continue
			}
			clientsMap.clientsByApp[*appKey][jj] = c
			jj++
		}
		// truncate the list
		clientsMap.clientsByApp[*appKey] = clientsMap.clientsByApp[*appKey][:jj]
	}
}

func SendCachedClients(ctx context.Context, old *edgeproto.AppInstClientKey, new *edgeproto.AppInstClientKey) {
	// Check if we have an outstanding streaming request which would be a superset. Only the AppInstKey.Organization is required to be set.
	err := AppInstClientKeyCache.Show(&edgeproto.AppInstClientKey{}, func(obj *edgeproto.AppInstClientKey) error {
		// if we found an exact match - it's this clients
		if new.Matches(obj) {
			return nil
		}
		if new.Matches(obj, edgeproto.MatchFilter()) {
			return fmt.Errorf("Already streaming for this superset")
		}
		return nil
	})
	if err != nil {
		return
	}
	clientsMap.RLock()
	defer clientsMap.RUnlock()
	list, found := clientsMap.clientsByApp[new.AppKey]
	// Possible exact match for the map
	if found {
		for ii := range list {
			// Check if we match the complete filter
			if list[ii].ClientKey.Matches(new, edgeproto.MatchFilter()) {
				ClientSender.Update(ctx, &list[ii])
			}
		}
		return
	}
	// Walk the entire map to find all possible matches
	for _, list := range clientsMap.clientsByApp {
		for ii := range list {
			// Check if we match the complete filter
			if list[ii].ClientKey.Matches(new, edgeproto.MatchFilter()) {
				ClientSender.Update(ctx, &list[ii])
			}
		}
	}
}
