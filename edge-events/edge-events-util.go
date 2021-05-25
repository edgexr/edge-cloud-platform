package edgeevents

import (
	"context"
	"fmt"

	dmecommon "github.com/mobiledgex/edge-cloud/d-match-engine/dme-common"
	dme "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

type Usability int

const (
	Unusable Usability = iota
	Usable
)

func getUsability(maintenanceState dme.MaintenanceState, cloudletState dme.CloudletState, appInstHealth dme.HealthCheck) Usability {
	isUsable := dmecommon.AreStatesUsable(maintenanceState, cloudletState, appInstHealth)
	if isUsable {
		return Usable
	} else {
		return Unusable
	}
}

// Helper function to create the ServerEdgeEvent when AppInst state is bad
func (e *EdgeEventsHandlerPlugin) createAppInstStateEdgeEvent(ctx context.Context, appInst *dmecommon.DmeAppInst, appInstKey edgeproto.AppInstKey, clientinfo *ClientInfo, eventType dme.ServerEdgeEvent_ServerEventType, usability Usability) *dme.ServerEdgeEvent {
	serverEdgeEvent := new(dme.ServerEdgeEvent)
	serverEdgeEvent.EventType = eventType
	// Populate the corresponding ServerEdgeEvent field based on eventType
	switch eventType {
	case dme.ServerEdgeEvent_EVENT_CLOUDLET_STATE:
		serverEdgeEvent.CloudletState = appInst.CloudletState
	case dme.ServerEdgeEvent_EVENT_CLOUDLET_MAINTENANCE:
		serverEdgeEvent.MaintenanceState = appInst.MaintenanceState
	case dme.ServerEdgeEvent_EVENT_APPINST_HEALTH:
		serverEdgeEvent.HealthCheck = appInst.AppInstHealth
	default:
	}
	// Look for a new cloudlet if the appinst is not usable
	if usability == Unusable {
		e.addNewCloudletToServerEdgeEvent(ctx, serverEdgeEvent, appInstKey, clientinfo)
	}
	return serverEdgeEvent
}

// Helper function to create the ServerEdgeEvent when CloudletState is bad
func (e *EdgeEventsHandlerPlugin) createCloudletStateEdgeEvent(ctx context.Context, cloudlet *dmecommon.DmeCloudlet, appInstKey edgeproto.AppInstKey, clientinfo *ClientInfo, usability Usability) *dme.ServerEdgeEvent {
	serverEdgeEvent := new(dme.ServerEdgeEvent)
	serverEdgeEvent.EventType = dme.ServerEdgeEvent_EVENT_CLOUDLET_STATE
	serverEdgeEvent.CloudletState = cloudlet.State
	// Look for a new cloudlet if the appinst is not usable
	if usability == Unusable {
		e.addNewCloudletToServerEdgeEvent(ctx, serverEdgeEvent, appInstKey, clientinfo)
	}
	return serverEdgeEvent
}

// Helper function to create the ServerEdgeEvent when CloudletMaintenanceState is bad
func (e *EdgeEventsHandlerPlugin) createCloudletMaintenanceStateEdgeEvent(ctx context.Context, cloudlet *dmecommon.DmeCloudlet, appInstKey edgeproto.AppInstKey, clientinfo *ClientInfo, usability Usability) *dme.ServerEdgeEvent {
	serverEdgeEvent := new(dme.ServerEdgeEvent)
	serverEdgeEvent.EventType = dme.ServerEdgeEvent_EVENT_CLOUDLET_MAINTENANCE
	serverEdgeEvent.MaintenanceState = cloudlet.MaintenanceState
	// Look for a new cloudlet if the appinst is not usable
	if usability == Unusable {
		e.addNewCloudletToServerEdgeEvent(ctx, serverEdgeEvent, appInstKey, clientinfo)
	}
	return serverEdgeEvent
}

// Helper function that adds a NewCloudlet to the given serverEdgeEvent if usability is Unusable
// If there is an error doing FindCloudlet, the error is put in ErrorMsg field of the given serverEdgeEvent
func (e *EdgeEventsHandlerPlugin) addNewCloudletToServerEdgeEvent(ctx context.Context, serverEdgeEvent *dme.ServerEdgeEvent, appInstKey edgeproto.AppInstKey, clientinfo *ClientInfo) {
	// Look for a new cloudlet if the appinst is not usable
	newCloudlet := new(dme.FindCloudletReply)
	var err error
	err = dmecommon.FindCloudlet(ctx, &appInstKey.AppKey, clientinfo.carrier, clientinfo.lastLoc, newCloudlet, e.EdgeEventsCookieExpiration)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Current appinst is unusable. Unable to find alternate cloudlet", "err", err)
		err = fmt.Errorf("Current appinst is unusable. Unable to find alternate cloudlet doing FindCloudlet - error is %s", err.Error())
		newCloudlet = nil
	} else if newCloudlet.Status != dme.FindCloudletReply_FIND_FOUND {
		log.SpanLog(ctx, log.DebugLevelInfra, "Current appinst is unusable. Unable to find any cloudlets", "FindStatus", newCloudlet.Status)
		err = fmt.Errorf("Current appinst is unusable. Unable to find any cloudlets doing FindCloudlet - FindStatus is %s", newCloudlet.Status)
		newCloudlet = nil
	}
	if err != nil {
		serverEdgeEvent.ErrorMsg = err.Error()
	}
	serverEdgeEvent.NewCloudlet = newCloudlet
}

// Helper function that iterates through map of ServerEdgeEvents and sendFuncs and sends each ServerEdgeEvent to via the correct sendFunc
func (e *EdgeEventsHandlerPlugin) sendEdgeEventsToClients(m map[*dme.ServerEdgeEvent]func(event *dme.ServerEdgeEvent)) {
	for edgeEvent, sendFunc := range m {
		sendFunc(edgeEvent)
	}
}

// Helper function that gets the ClientInfo for the specified Client on the specified AppInst on the specified Cloudlet
// Must lock EdgeEventsHandlerPlugin before calling this function
func (e *EdgeEventsHandlerPlugin) getClientInfo(ctx context.Context, appInstKey edgeproto.AppInstKey, cookieKey dmecommon.CookieKey) (*ClientInfo, error) {
	// Get clients on specified appinst on specified cloudlet
	clients, err := e.getClients(ctx, appInstKey)
	if err != nil {
		return nil, err
	}
	// Make sure ClientsMap is initialized
	if clients.ClientsMap == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot get clientinfo - ClientsMap is uninitialized, because no clients are on the appinst yet", "appInstKey", "appInstKey")
		return nil, fmt.Errorf("cannot get clientinfo - CLientsMap is uninitialized for appInst %v", appInstKey)
	}
	// Get clientinfo for the specified client
	client := Client{cookieKey}
	clientinfo, ok := clients.ClientsMap[client]
	if !ok {
		log.SpanLog(ctx, log.DebugLevelInfra, "unable to find client connected to appinst", "appInstKey", appInstKey, "client", client)
		return nil, fmt.Errorf("unable to find client %v on appinst %v", client, appInstKey)
	}
	return clientinfo, nil
}

// Helper function that gets the Clients on the specified AppInst on the specified Cloudlet
// Must lock EdgeEventsHandlerPlugin before calling this function
func (e *EdgeEventsHandlerPlugin) getClients(ctx context.Context, appInstKey edgeproto.AppInstKey) (*Clients, error) {
	// Get appinsts on specified cloudlet
	appinsts, err := e.getAppInsts(ctx, appInstKey.ClusterInstKey.CloudletKey)
	if err != nil {
		return nil, err
	}
	// Make sure AppInstsMap is initialized
	if appinsts.AppInstsMap == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot get clients - AppInstsMap is uninitialized, because no appinsts are on the clouudlet yet", "cloudletKey", appInstKey.ClusterInstKey.CloudletKey)
		return nil, fmt.Errorf("cannot get clients - AppInstsMap is uninitialized for cloudlet %v", appInstKey.ClusterInstKey.CloudletKey)
	}
	// Get clients on specified appinst
	clients, ok := appinsts.AppInstsMap[appInstKey]
	if !ok {
		log.SpanLog(ctx, log.DebugLevelInfra, "unable to find appinst on cloudlet", "appInstKey", appInstKey)
		return nil, fmt.Errorf("unable to find appinst on cloudlet: %v", appInstKey)
	}
	return clients, nil
}

// Helper function that gets the AppInsts on the specified Cloudlet
// Must lock EdgeEventsHandlerPlugin before calling this function
func (e *EdgeEventsHandlerPlugin) getAppInsts(ctx context.Context, cloudletKey edgeproto.CloudletKey) (*AppInsts, error) {
	// Make sure CloudletsMap is initialized
	if e.CloudletsMap == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot get appinsts - CloudletsMap is uninitialized, because no cloudlets are up yet")
		return nil, fmt.Errorf("cannot get appinsts - CloudletsMap is uninitialized")
	}
	// Get appinsts on specified cloudlet
	appinsts, ok := e.CloudletsMap[cloudletKey]
	if !ok {
		log.SpanLog(ctx, log.DebugLevelInfra, "unable to find cloudlet", "cloudletKey", cloudletKey)
		return nil, fmt.Errorf("unable to find cloudlet: %v", cloudletKey)
	}
	return appinsts, nil
}

// Helper function that removes ClientKey from clients.ClientsMap
// Will also remove AppInstKey if clients is empty
// Will also remove CloudletKey if appinsts is empty
// Must lock EdgeEventsHandlerPlugin before calling this function
func (e *EdgeEventsHandlerPlugin) removeClientKey(ctx context.Context, appInstKey edgeproto.AppInstKey, cookieKey dmecommon.CookieKey) {
	// Get clients on specified appinst
	clients, err := e.getClients(ctx, appInstKey)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "unable to find appinst to remove", "appInstKey", appInstKey, "error", err)
		return
	}
	// Remove specified client
	client := Client{cookieKey}
	delete(clients.ClientsMap, client)
	// If there are no clients on appinst, remove appinst
	if len(clients.ClientsMap) == 0 {
		e.removeAppInstKey(ctx, appInstKey)
	}
}

// Helper function that removes AppInstKey from appinsts.AppInstsMap
// Will also remove CloudletKey if appinsts is empty
// Must lock EdgeEventsHandlerPlugin before calling this function
func (e *EdgeEventsHandlerPlugin) removeAppInstKey(ctx context.Context, appInstKey edgeproto.AppInstKey) {
	// Check to see if appinst exists
	appinsts, err := e.getAppInsts(ctx, appInstKey.ClusterInstKey.CloudletKey)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "unable to find appinst to remove", "appInstKey", appInstKey, "error", err)
		return
	}
	// Remove appinst from map of appinsts
	delete(appinsts.AppInstsMap, appInstKey)
	if len(appinsts.AppInstsMap) == 0 {
		e.removeCloudletKey(ctx, appInstKey.ClusterInstKey.CloudletKey)
	}
}

// Helper function that removes CloudletKey from Cloudlets.CloudletsMap
// Must lock EdgeEventsHandlerPlugin before calling this function
func (e *EdgeEventsHandlerPlugin) removeCloudletKey(ctx context.Context, cloudletKey edgeproto.CloudletKey) {
	// Remove cloudlet from map of cloudlets
	delete(e.CloudletsMap, cloudletKey)
}
