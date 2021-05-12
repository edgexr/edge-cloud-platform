package edgeevents

import (
	"context"
	"fmt"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/version"
	dmecommon "github.com/mobiledgex/edge-cloud/d-match-engine/dme-common"
	dme "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	grpcstats "github.com/mobiledgex/edge-cloud/metrics/grpc"
	"github.com/mobiledgex/edge-cloud/util"
)

// Implements dmecommon.EdgeEventsHandler interface
type EdgeEventsHandlerPlugin struct {
	mux util.Mutex
	// Hashmap containing AppInsts on DME mapped to the clients connected to those AppInsts
	AppInstsStruct             *AppInsts
	EdgeEventsCookieExpiration time.Duration
}

// Map AppInstKey to Clients on appinst
type AppInsts struct {
	AppInstsMap map[edgeproto.AppInstKey]*Clients
}

// Map Client to ClientInfo
type Clients struct {
	ClientsMap map[Client]*ClientInfo
}

// Client uniquely identified by session cookie
type Client struct {
	cookieKey dmecommon.CookieKey
}

// Client info contains the client's specific Send function, last location, and carrier
type ClientInfo struct {
	sendFunc func(event *dme.ServerEdgeEvent)
	lastLoc  *dme.Loc
	carrier  string
}

// Add Client connected to specified AppInst to Map
func (e *EdgeEventsHandlerPlugin) AddClientKey(ctx context.Context, appInstKey edgeproto.AppInstKey, cookieKey dmecommon.CookieKey, lastLoc *dme.Loc, carrier string, sendFunc func(event *dme.ServerEdgeEvent)) {
	e.mux.Lock()
	defer e.mux.Unlock()
	// Initialize AppInstsMap
	if e.AppInstsStruct.AppInstsMap == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "initializing app insts map")
		e.AppInstsStruct.AppInstsMap = make(map[edgeproto.AppInstKey]*Clients)
	}
	// Get clients on specified appinst
	clients, ok := e.AppInstsStruct.AppInstsMap[appInstKey]
	if !ok {
		// add first client for appinst
		newClients := new(Clients)
		newClients.ClientsMap = make(map[Client]*ClientInfo)
		clients = newClients
		e.AppInstsStruct.AppInstsMap[appInstKey] = clients
	}
	// Initialize client info for new client
	client := Client{cookieKey: cookieKey}
	clients.ClientsMap[client] = &ClientInfo{
		sendFunc: sendFunc,
		lastLoc:  lastLoc,
		carrier:  carrier,
	}
}

// Remove Client connected to specified AppInst from Map
func (e *EdgeEventsHandlerPlugin) RemoveClientKey(ctx context.Context, appInstKey edgeproto.AppInstKey, cookieKey dmecommon.CookieKey) {
	e.mux.Lock()
	defer e.mux.Unlock()
	// Get clients on specified appinst
	clients, ok := e.AppInstsStruct.AppInstsMap[appInstKey]
	if !ok {
		log.SpanLog(ctx, log.DebugLevelInfra, "unable to find appinst to remove", "appInstKey", appInstKey)
		return
	}
	// Remove specified client
	client := Client{cookieKey}
	delete(clients.ClientsMap, client)
}

// Update Client's last location
func (e *EdgeEventsHandlerPlugin) UpdateClientLastLocation(ctx context.Context, appInstKey edgeproto.AppInstKey, cookieKey dmecommon.CookieKey, lastLoc *dme.Loc) {
	e.mux.Lock()
	defer e.mux.Unlock()
	// Get clients on specified appinst
	clients, ok := e.AppInstsStruct.AppInstsMap[appInstKey]
	if !ok {
		log.SpanLog(ctx, log.DebugLevelInfra, "unable to find appinst to remove", "appInstKey", appInstKey)
		return
	}
	// Update lastLoc field in cliientinfo for specified client
	client := Client{cookieKey}
	clientinfo, ok := clients.ClientsMap[client]
	if !ok {
		log.SpanLog(ctx, log.DebugLevelInfra, "unable to find client to update", "client", client)
		return
	}
	clientinfo.lastLoc = lastLoc
}

// Remove AppInst from Map of AppInsts
func (e *EdgeEventsHandlerPlugin) RemoveAppInstKey(ctx context.Context, appInstKey edgeproto.AppInstKey) {
	e.mux.Lock()
	defer e.mux.Unlock()
	// Check to see if appinst exists
	_, ok := e.AppInstsStruct.AppInstsMap[appInstKey]
	if !ok {
		log.SpanLog(ctx, log.DebugLevelInfra, "unable to find appinst to remove", "appInstKey", appInstKey)
		return
	}
	// Remove appinst from map of appinsts
	delete(e.AppInstsStruct.AppInstsMap, appInstKey)
}

// Handle processing of latency samples and then send back to client
// For now: Avg, Min, Max, StdDev
func (e *EdgeEventsHandlerPlugin) ProcessLatencySamples(ctx context.Context, appInstKey edgeproto.AppInstKey, cookieKey dmecommon.CookieKey, samples []*dme.Sample) (*dme.Statistics, error) {
	e.mux.Lock()
	defer e.mux.Unlock()
	// Get clients on specified appinst
	clients, ok := e.AppInstsStruct.AppInstsMap[appInstKey]
	if !ok {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot find appinst, no clients connected to appinst have edge events connection", "appInstKey", appInstKey)
		return nil, fmt.Errorf("Cannot find specified appinst %v. No clients connected to appinst have edge events connection", appInstKey)
	}
	// Check to see if client is on appinst
	client := Client{cookieKey}
	clientinfo, ok := clients.ClientsMap[client]
	if !ok {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot find client connected to appinst", "appInstKey", appInstKey, "client", client)
		return nil, fmt.Errorf("Cannot find client connected to appinst %v", appInstKey)
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
// When client recieves this event, it will measure latency from itself to appinst and back.
// Client will then send those latency samples back to be processed in the HandleLatencySamples function
// Finally, DME will send the processed latency samples in the form of dme.Latency struct (with calculated avg, min, max, stddev) back to client
func (e *EdgeEventsHandlerPlugin) SendLatencyRequestEdgeEvent(ctx context.Context, appInstKey edgeproto.AppInstKey) {
	e.mux.Lock()
	defer e.mux.Unlock()
	// Get clients on specified appinst
	clients, ok := e.AppInstsStruct.AppInstsMap[appInstKey]
	if !ok {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot find appinst. no clients connected to appinst have edge events connection.", "appInstKey", appInstKey)
		return
	}
	// Send latency request to each client on appinst
	go func() {
		e.mux.Lock()
		defer e.mux.Unlock()
		for _, clientinfo := range clients.ClientsMap {
			latencyRequestEdgeEvent := new(dme.ServerEdgeEvent)
			latencyRequestEdgeEvent.EventType = dme.ServerEdgeEvent_EVENT_LATENCY_REQUEST
			clientinfo.sendFunc(latencyRequestEdgeEvent)
		}
	}()
}

// Send a ServerEdgeEvent with specified Event to all clients connected to specified AppInst (and also have initiated persistent connection)
func (e *EdgeEventsHandlerPlugin) SendAppInstStateEvent(ctx context.Context, appInst *dmecommon.DmeAppInst, appInstKey edgeproto.AppInstKey, eventType dme.ServerEdgeEvent_ServerEventType) {
	e.mux.Lock()
	defer e.mux.Unlock()
	// Get clients on specified appinst
	clients, ok := e.AppInstsStruct.AppInstsMap[appInstKey]
	if !ok {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot find appinst. no clients connected to appinst have edge events connection.", "appInstKey", appInstKey)
		return
	}
	// Check if appinst is usable. If not do a FindCloudlet for each client
	appInstUsable := dmecommon.IsAppInstUsable(appInst)
	// Send appinst state event to each client on affected appinst
	go func() {
		e.mux.Lock()
		defer e.mux.Unlock()
		for _, clientinfo := range clients.ClientsMap {
			// Look for a new cloudlet if the appinst is not usable
			newCloudlet := new(dme.FindCloudletReply)
			var err error
			if !appInstUsable {
				err = dmecommon.FindCloudlet(ctx, &appInstKey.AppKey, clientinfo.carrier, clientinfo.lastLoc, newCloudlet, e.EdgeEventsCookieExpiration)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "Current appinst is unusable, but error doing FindCloudlet", "err", err)
					err = fmt.Errorf("Current appinst is unusable, but error doing FindCloudlet - error is %s", err.Error())
					newCloudlet = nil
				} else if newCloudlet.Status != dme.FindCloudletReply_FIND_FOUND {
					log.SpanLog(ctx, log.DebugLevelInfra, "Current appinst is unusable, but unable to find any cloudlets", "FindStatus", newCloudlet.Status)
					err = fmt.Errorf("Current appinst is unusable, but unable to find any cloudlets - FindStatus is %s", newCloudlet.Status)
					newCloudlet = nil
				}
			}
			// Send the client the state event
			updateServerEdgeEvent := createAppInstStateEvent(ctx, appInst, eventType, newCloudlet)
			if err != nil {
				updateServerEdgeEvent.ErrorMsg = err.Error()
			}
			clientinfo.sendFunc(updateServerEdgeEvent)
		}
	}()
}

// Send ServerEdgeEvent to specified client via persistent grpc stream
func (e *EdgeEventsHandlerPlugin) SendEdgeEventToClient(ctx context.Context, serverEdgeEvent *dme.ServerEdgeEvent, appInstKey edgeproto.AppInstKey, cookieKey dmecommon.CookieKey) {
	e.mux.Lock()
	defer e.mux.Unlock()
	// Get clients on specified appinst
	clients, ok := e.AppInstsStruct.AppInstsMap[appInstKey]
	if !ok {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot find appinst, no clients connected to appinst have edge events connection", "appInstKey", appInstKey)
		return
	}
	// Check to see if client is on appinst
	client := Client{cookieKey}
	clientinfo, ok := clients.ClientsMap[client]
	if !ok {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot find client connected to appinst", "appInstKey", appInstKey, "client", client)
		return
	}
	clientinfo.sendFunc(serverEdgeEvent)
}

// Create the ServerEdgeEvent with specified Event
func createAppInstStateEvent(ctx context.Context, appInst *dmecommon.DmeAppInst, eventType dme.ServerEdgeEvent_ServerEventType, newCloudlet *dme.FindCloudletReply) *dme.ServerEdgeEvent {
	updateServerEdgeEvent := new(dme.ServerEdgeEvent)
	updateServerEdgeEvent.EventType = eventType
	updateServerEdgeEvent.NewCloudlet = newCloudlet
	// Populate the corresponding ServerEdgeEvent field based on eventType
	switch eventType {
	case dme.ServerEdgeEvent_EVENT_CLOUDLET_STATE:
		updateServerEdgeEvent.CloudletState = appInst.CloudletState
	case dme.ServerEdgeEvent_EVENT_CLOUDLET_MAINTENANCE:
		updateServerEdgeEvent.MaintenanceState = appInst.MaintenanceState
	case dme.ServerEdgeEvent_EVENT_APPINST_HEALTH:
		updateServerEdgeEvent.HealthCheck = appInst.AppInstHealth
	default:
	}
	return updateServerEdgeEvent
}

func (e *EdgeEventsHandlerPlugin) GetVersionProperties() map[string]string {
	return version.InfraBuildProps("EdgeEvents")
}
