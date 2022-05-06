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
	"time"

	"github.com/edgexr/edge-cloud-infra/version"
	dmecommon "github.com/edgexr/edge-cloud/d-match-engine/dme-common"
	dme "github.com/edgexr/edge-cloud/d-match-engine/dme-proto"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	grpcstats "github.com/edgexr/edge-cloud/metrics/grpc"
	"github.com/edgexr/edge-cloud/util"
)

// Implements dmecommon.EdgeEventsHandler interface
type EdgeEventsHandlerPlugin struct {
	util.Mutex
	// hashmap containing Cloudlets and information about each Cloudlet
	Cloudlets                  map[edgeproto.CloudletKey]*CloudletInfo
	EdgeEventsCookieExpiration time.Duration
}

// Struct that holds information about cloudlet
type CloudletInfo struct {
	// hashmap containing AppInsts on this cloudlet and information about each AppInst
	AppInsts map[edgeproto.AppInstKey]*AppInstInfo
}

// Struct that holds information about appinst
type AppInstInfo struct {
	// unique key
	appInstKey edgeproto.AppInstKey
	// carrier associated with appinst
	carrier string
	// DmeAppInst struct used to pass into SearchAppInsts function
	dmeAppInst *dmecommon.DmeAppInst
	// hashmap containing Clients on this appinst and information about each Client
	Clients map[Client]*ClientInfo
}

// Client uniquely identified by session cookie
type Client struct {
	cookieKey dmecommon.CookieKey
}

// Client info contains the client's specific Send function, last location, and carrier
type ClientInfo struct {
	sendFunc func(event *dme.ServerEdgeEvent)
	lastLoc  dme.Loc
	carrier  string
}

// Add Client connected to specified AppInst to Map
func (e *EdgeEventsHandlerPlugin) AddClient(ctx context.Context, appInstKey edgeproto.AppInstKey, cookieKey dmecommon.CookieKey, lastLoc dme.Loc, carrier string, sendFunc func(event *dme.ServerEdgeEvent)) {
	e.Lock()
	defer e.Unlock()
	// Get cloudletinfo for specified cloudlet
	cloudletKey := appInstKey.ClusterInstKey.CloudletKey
	cloudletinfo, ok := e.Cloudlets[cloudletKey]
	if !ok {
		// this should have been added by SendAvailableAppInst
		log.SpanLog(ctx, log.DebugLevelInfra, "unable to find cloudlet", "cloudlet key", cloudletKey)
		return
	}
	// Get appinstinfo for specified appinst
	appinstinfo, ok := cloudletinfo.AppInsts[appInstKey]
	if !ok {
		// this should have been added by SendAvailableAppInst
		log.SpanLog(ctx, log.DebugLevelInfra, "unable to find appinst", "appinst key", appInstKey)
		return
	}
	// Initialize client info for new client
	client := Client{cookieKey: cookieKey}
	appinstinfo.Clients[client] = &ClientInfo{
		sendFunc: sendFunc,
		lastLoc:  lastLoc,
		carrier:  carrier,
	}
}

// Send new FindCloudletReply with available appinst information to all clients that are closer to this appinst
func (e *EdgeEventsHandlerPlugin) SendAvailableAppInst(ctx context.Context, app *dmecommon.DmeApp, newAppInstKey edgeproto.AppInstKey, newAppInst *dmecommon.DmeAppInst, newAppInstCarrier string) {
	e.Lock()
	defer e.Unlock()
	// Get cloudletinfo for specified cloudlet or create entry if needed
	cloudletKey := newAppInstKey.ClusterInstKey.CloudletKey
	cloudletinfo, ok := e.Cloudlets[cloudletKey]
	if !ok {
		cloudletinfo = new(CloudletInfo)
		cloudletinfo.AppInsts = make(map[edgeproto.AppInstKey]*AppInstInfo)
		e.Cloudlets[cloudletKey] = cloudletinfo
	}
	// Get appinstinfo for specified appinst or create entry if needed
	appinstinfo, ok := cloudletinfo.AppInsts[newAppInstKey]
	if !ok {
		appinstinfo = new(AppInstInfo)
		appinstinfo.Clients = make(map[Client]*ClientInfo)
		appinstinfo.appInstKey = newAppInstKey
		appinstinfo.carrier = newAppInstCarrier
		appinstinfo.dmeAppInst = newAppInst
		cloudletinfo.AppInsts[newAppInstKey] = appinstinfo
	}

	// notify clients on app that there is a new appinst if closer
	// iterate through cloudlets, appinsts, and clients
	for cloudletKey, _ := range e.Cloudlets {
		for appinstkey, appinstinfo := range e.Cloudlets[cloudletKey].AppInsts {
			if appinstkey.AppKey == newAppInstKey.AppKey {
				for _, clientinfo := range appinstinfo.Clients {
					// construct carrierData map with the two appinsts to compare
					carrierData := map[string]*dmecommon.DmeAppInsts{
						newAppInstCarrier: &dmecommon.DmeAppInsts{ // newly available appinst
							Insts: map[edgeproto.VirtualClusterInstKey]*dmecommon.DmeAppInst{
								newAppInstKey.ClusterInstKey: newAppInst,
							},
						}, appinstinfo.carrier: &dmecommon.DmeAppInsts{ // current appinst
							Insts: map[edgeproto.VirtualClusterInstKey]*dmecommon.DmeAppInst{
								appinstinfo.appInstKey.ClusterInstKey: appinstinfo.dmeAppInst,
							},
						},
					}
					// compare new appinst with current appinst to see which is better
					// use client's carrier name to perform the search
					foundList := dmecommon.SearchAppInsts(ctx, clientinfo.carrier, app, &clientinfo.lastLoc, carrierData, 1)
					if foundList == nil || len(foundList) != 1 {
						continue
					}
					// check that search result is the same as newAppInst
					if foundList[0].AppInst.Uri == newAppInst.Uri {
						newCloudletEdgeEvent := new(dme.ServerEdgeEvent)
						newCloudletEdgeEvent.EventType = dme.ServerEdgeEvent_EVENT_CLOUDLET_UPDATE
						// construct FindCloudletReply from DmeAppInst struct
						newCloudlet := new(dme.FindCloudletReply)
						dmecommon.ConstructFindCloudletReplyFromDmeAppInst(ctx, newAppInst, &clientinfo.lastLoc, newCloudlet, e.EdgeEventsCookieExpiration)
						newCloudletEdgeEvent.NewCloudlet = newCloudlet
						clientinfo.sendFunc(newCloudletEdgeEvent)
					}
				}
			}
		}
	}
}

// Update Client's last location
func (e *EdgeEventsHandlerPlugin) UpdateClientLastLocation(ctx context.Context, appInstKey edgeproto.AppInstKey, cookieKey dmecommon.CookieKey, lastLoc dme.Loc) {
	e.Lock()
	defer e.Unlock()
	// Update lastLoc field in cliientinfo for specified client
	clientinfo, err := e.getClientInfo(ctx, appInstKey, cookieKey)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "unable to find client to update", "client", cookieKey, "error", err)
		return
	}
	clientinfo.lastLoc = lastLoc
}

func (e *EdgeEventsHandlerPlugin) UpdateClientCarrier(ctx context.Context, appInstKey edgeproto.AppInstKey, cookieKey dmecommon.CookieKey, carrier string) {
	e.Lock()
	defer e.Unlock()
	// Update carrier field in cliientinfo for specified client
	clientinfo, err := e.getClientInfo(ctx, appInstKey, cookieKey)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "unable to find client to update", "client", cookieKey, "error", err)
		return
	}
	clientinfo.carrier = carrier
}

// Remove Client connected to specified AppInst from Map
func (e *EdgeEventsHandlerPlugin) RemoveClient(ctx context.Context, appInstKey edgeproto.AppInstKey, cookieKey dmecommon.CookieKey) {
	e.Lock()
	defer e.Unlock()
	e.removeClientKey(ctx, appInstKey, cookieKey)
}

// Remove AppInst from Map of AppInsts
func (e *EdgeEventsHandlerPlugin) RemoveAppInst(ctx context.Context, appInstKey edgeproto.AppInstKey) {
	e.Lock()
	defer e.Unlock()
	e.removeAppInstKey(ctx, appInstKey)
}

func (e *EdgeEventsHandlerPlugin) RemoveCloudlet(ctx context.Context, cloudletKey edgeproto.CloudletKey) {
	e.Lock()
	defer e.Unlock()
	e.removeCloudletKey(ctx, cloudletKey)
}

// Handle processing of latency samples and then send back to client
// For now: Avg, Min, Max, StdDev
func (e *EdgeEventsHandlerPlugin) ProcessLatencySamples(ctx context.Context, appInstKey edgeproto.AppInstKey, cookieKey dmecommon.CookieKey, samples []*dme.Sample) (*dme.Statistics, error) {
	e.Lock()
	defer e.Unlock()
	// Check to see if client is on appinst
	clientinfo, err := e.getClientInfo(ctx, appInstKey, cookieKey)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot find client connected to appinst", "appInstKey", appInstKey, "client", cookieKey, "error", err)
		return nil, fmt.Errorf("cannot find client connected to appinst %v - error is %v", appInstKey, err)
	}
	// Create latencyEdgeEvent with processed stats
	latencyEdgeEvent := new(dme.ServerEdgeEvent)
	latencyEdgeEvent.EventType = dme.ServerEdgeEvent_EVENT_LATENCY_PROCESSED
	stats := grpcstats.CalculateStatistics(samples)
	latencyEdgeEvent.Statistics = &stats
	// Send processed stats to client
	clientinfo.sendFunc(latencyEdgeEvent)
	return &stats, nil
}

// Send a ServerEdgeEvent with Latency Request Event to all clients connected to specified AppInst (and also have an initiated persistent connection)
// When client receives this event, it will measure latency from itself to appinst and back.
// Client will then send those latency samples back to be processed in the HandleLatencySamples function
// Finally, DME will send the processed latency samples in the form of dme.Latency struct (with calculated avg, min, max, stddev) back to client
func (e *EdgeEventsHandlerPlugin) SendLatencyRequestEdgeEvent(ctx context.Context, appInstKey edgeproto.AppInstKey) {
	e.Lock()
	defer e.Unlock()
	// Get appinstinfo for specified appinst
	appinstinfo, err := e.getAppInstInfo(ctx, appInstKey)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot find appinst. no clients connected to appinst have edge events connection.", "appInstKey", appInstKey, "error", err)
		return
	}
	// Build map of LatencyRequestEdgeEvents mapped to the sendFunc that will send the event to the correct client
	m := make(map[*dme.ServerEdgeEvent]func(event *dme.ServerEdgeEvent))
	for _, clientinfo := range appinstinfo.Clients {
		latencyRequestEdgeEvent := new(dme.ServerEdgeEvent)
		latencyRequestEdgeEvent.EventType = dme.ServerEdgeEvent_EVENT_LATENCY_REQUEST
		m[latencyRequestEdgeEvent] = clientinfo.sendFunc
	}
	// Send latency request to each client on appinst
	go e.sendEdgeEventsToClients(m)
}

// Send a AppInstState EdgeEvent with specified Event to all clients connected to specified AppInst (and also have initiated persistent connection)
func (e *EdgeEventsHandlerPlugin) SendAppInstStateEdgeEvent(ctx context.Context, appinstState *dmecommon.DmeAppInstState, appInstKey edgeproto.AppInstKey, eventType dme.ServerEdgeEvent_ServerEventType) {
	e.Lock()
	defer e.Unlock()
	// Get appinstinfo for specified appinst
	appinstinfo, err := e.getAppInstInfo(ctx, appInstKey)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot find appinst. no clients connected to appinst have edge events connection.", "appInstKey", appInstKey, "error", err)
		return
	}
	// Check if appinst is usable. If not do a FindCloudlet for each client
	usability := getUsability(appinstState)
	// Build map of AppInstStateEdgeEvents mapped to the sendFunc that will send the event to the correct client
	m := make(map[*dme.ServerEdgeEvent]func(event *dme.ServerEdgeEvent))
	for _, clientinfo := range appinstinfo.Clients {
		appInstStateEdgeEvent := e.createAppInstStateEdgeEvent(ctx, appinstState, appInstKey, clientinfo, eventType, usability)
		m[appInstStateEdgeEvent] = clientinfo.sendFunc
	}
	// Send appinst state event to each client on affected appinst
	go e.sendEdgeEventsToClients(m)
}

func (e *EdgeEventsHandlerPlugin) SendCloudletStateEdgeEvent(ctx context.Context, appinstState *dmecommon.DmeAppInstState, cloudletKey edgeproto.CloudletKey) {
	e.Lock()
	defer e.Unlock()
	// Get cloudletinfo for specified cloudlet
	cloudletinfo, err := e.getCloudletInfo(ctx, cloudletKey)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot find cloudlet. no appinsts on cloudlet", "cloudlet", cloudletKey, "error", err)
		return
	}
	// Check if cloudlet is usable. If not do a FindCloudlet for each client (only use cloudlet.State)
	appinstState.MaintenanceState = dme.MaintenanceState_NORMAL_OPERATION
	appinstState.AppInstHealth = dme.HealthCheck_HEALTH_CHECK_OK
	usability := getUsability(appinstState)
	// Build map of CloudletStateEdgeEvents mapped to the sendFunc that will send the event to the correct client
	m := make(map[*dme.ServerEdgeEvent]func(event *dme.ServerEdgeEvent))
	for appinstkey, appinstinfo := range cloudletinfo.AppInsts {
		for _, clientinfo := range appinstinfo.Clients {
			cloudletStateEdgeEvent := e.createCloudletStateEdgeEvent(ctx, appinstState, appinstkey, clientinfo, usability)
			m[cloudletStateEdgeEvent] = clientinfo.sendFunc
		}
	}
	// Send cloudlet state event to each client on each appinst on the affected cloudlet
	go e.sendEdgeEventsToClients(m)
}

func (e *EdgeEventsHandlerPlugin) SendCloudletMaintenanceStateEdgeEvent(ctx context.Context, appinstState *dmecommon.DmeAppInstState, cloudletKey edgeproto.CloudletKey) {
	e.Lock()
	defer e.Unlock()
	// Get cloudlet info for specified cloudlet
	cloudletinfo, err := e.getCloudletInfo(ctx, cloudletKey)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot find cloudlet. no appinsts on cloudlet", "cloudlet", cloudletKey, "error", err)
		return
	}
	// Check if cloudlet is usable. If not do a FindCloudlet for each client (only use cloudlet.MaintenanceState)
	appinstState.CloudletState = dme.CloudletState_CLOUDLET_STATE_READY
	appinstState.AppInstHealth = dme.HealthCheck_HEALTH_CHECK_OK
	usability := getUsability(appinstState)
	// Build map of CloudletMaintenanceStateEdgeEvents mapped to the sendFunc that will send the event to the correct client
	m := make(map[*dme.ServerEdgeEvent]func(event *dme.ServerEdgeEvent))
	for appinstkey, appinstinfo := range cloudletinfo.AppInsts {
		for _, clientinfo := range appinstinfo.Clients {
			cloudletMaintenanceStateEdgeEvent := e.createCloudletMaintenanceStateEdgeEvent(ctx, appinstState, appinstkey, clientinfo, usability)
			m[cloudletMaintenanceStateEdgeEvent] = clientinfo.sendFunc
		}
	}
	// Send cloudlet maintenance state event to each client on each appinst on the affected cloudlet
	go e.sendEdgeEventsToClients(m)
}

// Send ServerEdgeEvent to specified client via persistent grpc stream
func (e *EdgeEventsHandlerPlugin) SendEdgeEventToClient(ctx context.Context, serverEdgeEvent *dme.ServerEdgeEvent, appInstKey edgeproto.AppInstKey, cookieKey dmecommon.CookieKey) {
	e.Lock()
	defer e.Unlock()
	// Check to see if client is on appinst
	clientinfo, err := e.getClientInfo(ctx, appInstKey, cookieKey)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot find client connected to appinst", "appInstKey", appInstKey, "client", cookieKey, "error", err)
		return
	}
	clientinfo.sendFunc(serverEdgeEvent)
}

func (e *EdgeEventsHandlerPlugin) GetVersionProperties() map[string]string {
	return version.InfraBuildProps("EdgeEvents")
}
