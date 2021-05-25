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
	util.Mutex
	// Hashmap containing Cloudlets mapped to AppInsts mapped to the clients connected to those AppInsts
	Cloudlets
	EdgeEventsCookieExpiration time.Duration
}

// Map CloudletKey to AppInsts on that cloudlet
type Cloudlets struct {
	CloudletsMap map[edgeproto.CloudletKey]*AppInsts
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
	e.Lock()
	defer e.Unlock()
	// Initialize CloudletsMap
	if e.CloudletsMap == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "initializing cloudlets map")
		e.CloudletsMap = make(map[edgeproto.CloudletKey]*AppInsts)
	}
	cloudletKey := appInstKey.ClusterInstKey.CloudletKey
	appinsts, ok := e.CloudletsMap[cloudletKey]
	if !ok {
		// add first appinst
		appinsts = new(AppInsts)
		appinsts.AppInstsMap = make(map[edgeproto.AppInstKey]*Clients)
		e.CloudletsMap[cloudletKey] = appinsts
	}
	// Get clients on specified appinst
	clients, ok := appinsts.AppInstsMap[appInstKey]
	if !ok {
		// add first client for appinst
		clients = new(Clients)
		clients.ClientsMap = make(map[Client]*ClientInfo)
		appinsts.AppInstsMap[appInstKey] = clients
	}
	// Initialize client info for new client
	client := Client{cookieKey: cookieKey}
	clients.ClientsMap[client] = &ClientInfo{
		sendFunc: sendFunc,
		lastLoc:  lastLoc,
		carrier:  carrier,
	}
}

// Update Client's last location
func (e *EdgeEventsHandlerPlugin) UpdateClientLastLocation(ctx context.Context, appInstKey edgeproto.AppInstKey, cookieKey dmecommon.CookieKey, lastLoc *dme.Loc) {
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

// Remove Client connected to specified AppInst from Map
func (e *EdgeEventsHandlerPlugin) RemoveClientKey(ctx context.Context, appInstKey edgeproto.AppInstKey, cookieKey dmecommon.CookieKey) {
	e.Lock()
	defer e.Unlock()
	e.removeClientKey(ctx, appInstKey, cookieKey)
}

// Remove AppInst from Map of AppInsts
func (e *EdgeEventsHandlerPlugin) RemoveAppInstKey(ctx context.Context, appInstKey edgeproto.AppInstKey) {
	e.Lock()
	defer e.Unlock()
	e.removeAppInstKey(ctx, appInstKey)
}

func (e *EdgeEventsHandlerPlugin) RemoveCloudletKey(ctx context.Context, cloudletKey edgeproto.CloudletKey) {
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
// When client recieves this event, it will measure latency from itself to appinst and back.
// Client will then send those latency samples back to be processed in the HandleLatencySamples function
// Finally, DME will send the processed latency samples in the form of dme.Latency struct (with calculated avg, min, max, stddev) back to client
func (e *EdgeEventsHandlerPlugin) SendLatencyRequestEdgeEvent(ctx context.Context, appInstKey edgeproto.AppInstKey) {
	e.Lock()
	defer e.Unlock()
	// Get clients on specified appinst
	clients, err := e.getClients(ctx, appInstKey)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot find appinst. no clients connected to appinst have edge events connection.", "appInstKey", appInstKey, "error", err)
		return
	}
	// Build map of LatencyRequestEdgeEvents mapped to the sendFunc that will send the event to the correct client
	m := make(map[*dme.ServerEdgeEvent]func(event *dme.ServerEdgeEvent))
	for _, clientinfo := range clients.ClientsMap {
		latencyRequestEdgeEvent := new(dme.ServerEdgeEvent)
		latencyRequestEdgeEvent.EventType = dme.ServerEdgeEvent_EVENT_LATENCY_REQUEST
		m[latencyRequestEdgeEvent] = clientinfo.sendFunc
	}
	// Send latency request to each client on appinst
	go e.sendEdgeEventsToClients(m)
}

// Send a AppInstState EdgeEvent with specified Event to all clients connected to specified AppInst (and also have initiated persistent connection)
func (e *EdgeEventsHandlerPlugin) SendAppInstStateEdgeEvent(ctx context.Context, appInst *dmecommon.DmeAppInst, appInstKey edgeproto.AppInstKey, eventType dme.ServerEdgeEvent_ServerEventType) {
	e.Lock()
	defer e.Unlock()
	// Get clients on specified appinst
	clients, err := e.getClients(ctx, appInstKey)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot find appinst. no clients connected to appinst have edge events connection.", "appInstKey", appInstKey, "error", err)
		return
	}
	// Check if appinst is usable. If not do a FindCloudlet for each client
	usability := getUsability(appInst.MaintenanceState, appInst.CloudletState, appInst.AppInstHealth)
	// Build map of AppInstStateEdgeEvents mapped to the sendFunc that will send the event to the correct client
	m := make(map[*dme.ServerEdgeEvent]func(event *dme.ServerEdgeEvent))
	for _, clientinfo := range clients.ClientsMap {
		appInstStateEdgeEvent := e.createAppInstStateEdgeEvent(ctx, appInst, appInstKey, clientinfo, eventType, usability)
		m[appInstStateEdgeEvent] = clientinfo.sendFunc
	}
	// Send appinst state event to each client on affected appinst
	go e.sendEdgeEventsToClients(m)
}

func (e *EdgeEventsHandlerPlugin) SendCloudletStateEdgeEvent(ctx context.Context, cloudlet *dmecommon.DmeCloudlet, cloudletKey edgeproto.CloudletKey) {
	e.Lock()
	defer e.Unlock()
	// Get appinsts on specified cloudlet
	appinsts, err := e.getAppInsts(ctx, cloudletKey)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot find cloudlet. no appinsts on cloudlet", "cloudlet", cloudletKey, "error", err)
		return
	}
	// Check if cloudlet is usable. If not do a FindCloudlet for each client (only use cloudlet.State)
	usability := getUsability(dme.MaintenanceState_NORMAL_OPERATION, cloudlet.State, dme.HealthCheck_HEALTH_CHECK_OK)
	// Build map of CloudletStateEdgeEvents mapped to the sendFunc that will send the event to the correct client
	m := make(map[*dme.ServerEdgeEvent]func(event *dme.ServerEdgeEvent))
	for key, clients := range appinsts.AppInstsMap {
		for _, clientinfo := range clients.ClientsMap {
			cloudletStateEdgeEvent := e.createCloudletStateEdgeEvent(ctx, cloudlet, key, clientinfo, usability)
			m[cloudletStateEdgeEvent] = clientinfo.sendFunc
		}
	}
	// Send cloudlet state event to each client on each appinst on the affected cloudlet
	go e.sendEdgeEventsToClients(m)
}

func (e *EdgeEventsHandlerPlugin) SendCloudletMaintenanceStateEdgeEvent(ctx context.Context, cloudlet *dmecommon.DmeCloudlet, cloudletKey edgeproto.CloudletKey) {
	e.Lock()
	defer e.Unlock()
	// Get appinsts on specified cloudlet
	appinsts, err := e.getAppInsts(ctx, cloudletKey)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot find cloudlet. no appinsts on cloudlet", "cloudlet", cloudletKey, "error", err)
		return
	}
	// Check if cloudlet is usable. If not do a FindCloudlet for each client (only use cloudlet.MaintenanceState)
	usability := getUsability(cloudlet.MaintenanceState, dme.CloudletState_CLOUDLET_STATE_READY, dme.HealthCheck_HEALTH_CHECK_OK)
	// Build map of CloudletMaintenanceStateEdgeEvents mapped to the sendFunc that will send the event to the correct client
	m := make(map[*dme.ServerEdgeEvent]func(event *dme.ServerEdgeEvent))
	for key, clients := range appinsts.AppInstsMap {
		for _, clientinfo := range clients.ClientsMap {
			cloudletMaintenanceStateEdgeEvent := e.createCloudletMaintenanceStateEdgeEvent(ctx, cloudlet, key, clientinfo, usability)
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
