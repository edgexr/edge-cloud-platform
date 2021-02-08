package edgeevents

import (
	"context"
	"fmt"

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
	AppInstsStruct *AppInsts
}

type AppInsts struct {
	AppInstsMap map[edgeproto.AppInstKey]Clients
}

// Map Client to specific Send function
type Clients struct {
	ClientsMap map[Client]func(event *dme.ServerEdgeEvent)
}

// Client uniquely identified by session cookie
type Client struct {
	cookieKey dmecommon.CookieKey
}

// Add Client connected to specified AppInst to Map
func (e *EdgeEventsHandlerPlugin) AddClientKey(ctx context.Context, appInstKey edgeproto.AppInstKey, cookieKey dmecommon.CookieKey, sendFunc func(event *dme.ServerEdgeEvent)) {
	e.mux.Lock()
	defer e.mux.Unlock()
	if e.AppInstsStruct.AppInstsMap == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "initializing app insts map")
		e.AppInstsStruct.AppInstsMap = make(map[edgeproto.AppInstKey]Clients)
	}

	clients, ok := e.AppInstsStruct.AppInstsMap[appInstKey]
	if !ok {
		// add first client for appinst
		newClients := new(Clients)
		newClients.ClientsMap = make(map[Client]func(event *dme.ServerEdgeEvent))
		clients = *newClients
	}

	client := Client{cookieKey}
	clients.ClientsMap[client] = sendFunc
	e.AppInstsStruct.AppInstsMap[appInstKey] = clients
}

// Remove Client connected to specified AppInst from Map
func (e *EdgeEventsHandlerPlugin) RemoveClientKey(ctx context.Context, appInstKey edgeproto.AppInstKey, cookieKey dmecommon.CookieKey) {
	e.mux.Lock()
	defer e.mux.Unlock()
	clients, ok := e.AppInstsStruct.AppInstsMap[appInstKey]
	if !ok {
		log.SpanLog(ctx, log.DebugLevelInfra, "unable to find appinst to remove", "appInstKey", appInstKey)
		return
	}

	client := Client{cookieKey}
	delete(clients.ClientsMap, client)
}

// Remove AppInst from Map of AppInsts
func (e *EdgeEventsHandlerPlugin) RemoveAppInstKey(ctx context.Context, appInstKey edgeproto.AppInstKey) {
	e.mux.Lock()
	defer e.mux.Unlock()
	_, ok := e.AppInstsStruct.AppInstsMap[appInstKey]
	if !ok {
		log.SpanLog(ctx, log.DebugLevelInfra, "unable to find appinst to remove", "appInstKey", appInstKey)
		return
	}

	delete(e.AppInstsStruct.AppInstsMap, appInstKey)
}

// Handle processing of latency samples and then send back to client
// For now: Avg, Min, Max, StdDev
func (e *EdgeEventsHandlerPlugin) ProcessLatencySamples(ctx context.Context, appInstKey edgeproto.AppInstKey, cookieKey dmecommon.CookieKey, samples []*dme.Sample) (*dme.Statistics, error) {
	e.mux.Lock()
	defer e.mux.Unlock()
	clients, ok := e.AppInstsStruct.AppInstsMap[appInstKey]
	if !ok {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot find appinst, no clients connected to appinst have edge events connection", "appInstKey", appInstKey)
		return nil, fmt.Errorf("Cannot find specified appinst %v. No clients connected to appinst have edge events connection", appInstKey)
	}

	client := Client{cookieKey}
	sendFunc, ok := clients.ClientsMap[client]
	if !ok {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot find client connected to appinst", "appInstKey", appInstKey, "client", client)
		return nil, fmt.Errorf("Cannot find client connected to appinst %v", appInstKey)
	}

	latencyEdgeEvent := new(dme.ServerEdgeEvent)
	latencyEdgeEvent.EventType = dme.ServerEdgeEvent_EVENT_LATENCY_PROCESSED

	stats := grpcstats.CalculateStatistics(samples)
	latencyEdgeEvent.Statistics = &stats

	sendFunc(latencyEdgeEvent)
	return &stats, nil
}

// Send a ServerEdgeEvent with Latency Request Event to all clients connected to specified AppInst (and also have an initiated persistent connection)
// When client recieves this event, it will measure latency from itself to appinst and back.
// Client will then send those latency samples back to be processed in the HandleLatencySamples function
// Finally, DME will send the processed latency samples in the form of dme.Latency struct (with calculated avg, min, max, stddev) back to client
func (e *EdgeEventsHandlerPlugin) SendLatencyRequestEdgeEvent(ctx context.Context, appInstKey edgeproto.AppInstKey) {
	e.mux.Lock()
	defer e.mux.Unlock()
	clients, ok := e.AppInstsStruct.AppInstsMap[appInstKey]
	if !ok {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot find appinst. no clients connected to appinst have edge events connection.", "appInstKey", appInstKey)
		return
	}

	for _, sendFunc := range clients.ClientsMap {
		go func(sendFunc func(event *dme.ServerEdgeEvent)) {
			latencyRequestEdgeEvent := new(dme.ServerEdgeEvent)
			latencyRequestEdgeEvent.EventType = dme.ServerEdgeEvent_EVENT_LATENCY_REQUEST
			sendFunc(latencyRequestEdgeEvent)
		}(sendFunc)
	}
}

// Send a ServerEdgeEvent with specified Event to all clients connected to specified AppInst (and also have initiated persistent connection)
func (e *EdgeEventsHandlerPlugin) SendAppInstStateEvent(ctx context.Context, appInst *dmecommon.DmeAppInst, appInstKey edgeproto.AppInstKey, eventType dme.ServerEdgeEvent_ServerEventType) {
	e.mux.Lock()
	defer e.mux.Unlock()
	clients, ok := e.AppInstsStruct.AppInstsMap[appInstKey]
	if !ok {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot find appinst. no clients connected to appinst have edge events connection.", "appInstKey", appInstKey)
		return
	}

	for _, sendFunc := range clients.ClientsMap {
		updateServerEdgeEvent := createAppInstStateEvent(ctx, appInst, eventType)
		sendFunc(updateServerEdgeEvent)
	}
}

// Send ServerEdgeEvent to specified client via persistent grpc stream
func (e *EdgeEventsHandlerPlugin) SendEdgeEventToClient(ctx context.Context, serverEdgeEvent *dme.ServerEdgeEvent, appInstKey edgeproto.AppInstKey, cookieKey dmecommon.CookieKey) {
	e.mux.Lock()
	defer e.mux.Unlock()
	clients, ok := e.AppInstsStruct.AppInstsMap[appInstKey]
	if !ok {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot find appinst, no clients connected to appinst have edge events connection", "appInstKey", appInstKey)
		return
	}

	client := Client{cookieKey}
	sendFunc, ok := clients.ClientsMap[client]
	if !ok {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot find client connected to appinst", "appInstKey", appInstKey, "client", client)
		return
	}
	sendFunc(serverEdgeEvent)
}

// Create the ServerEdgeEvent with specified Event
func createAppInstStateEvent(ctx context.Context, appInst *dmecommon.DmeAppInst, eventType dme.ServerEdgeEvent_ServerEventType) *dme.ServerEdgeEvent {
	updateServerEdgeEvent := new(dme.ServerEdgeEvent)
	updateServerEdgeEvent.EventType = eventType

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
