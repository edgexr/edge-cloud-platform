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

	dmecommon "github.com/edgexr/edge-cloud/d-match-engine/dme-common"
	dme "github.com/edgexr/edge-cloud/d-match-engine/dme-proto"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
)

type Usability int

const (
	Unusable Usability = iota
	Usable
)

func getUsability(appinstState *dmecommon.DmeAppInstState) Usability {
	isUsable := dmecommon.AreStatesUsable(appinstState.MaintenanceState, appinstState.CloudletState, appinstState.AppInstHealth)
	if isUsable {
		return Usable
	} else {
		return Unusable
	}
}

// Helper function to create the ServerEdgeEvent when AppInst state is bad
func (e *EdgeEventsHandlerPlugin) createAppInstStateEdgeEvent(ctx context.Context, appinstState *dmecommon.DmeAppInstState, appInstKey edgeproto.AppInstKey, clientinfo *ClientInfo, eventType dme.ServerEdgeEvent_ServerEventType, usability Usability) *dme.ServerEdgeEvent {
	serverEdgeEvent := new(dme.ServerEdgeEvent)
	serverEdgeEvent.EventType = eventType
	// Populate the corresponding ServerEdgeEvent field based on eventType
	switch eventType {
	case dme.ServerEdgeEvent_EVENT_CLOUDLET_STATE:
		serverEdgeEvent.CloudletState = appinstState.CloudletState
	case dme.ServerEdgeEvent_EVENT_CLOUDLET_MAINTENANCE:
		serverEdgeEvent.MaintenanceState = appinstState.MaintenanceState
	case dme.ServerEdgeEvent_EVENT_APPINST_HEALTH:
		serverEdgeEvent.HealthCheck = appinstState.AppInstHealth
	default:
	}
	// Look for a new cloudlet if the appinst is not usable
	if usability == Unusable {
		e.addNewCloudletToServerEdgeEvent(ctx, serverEdgeEvent, appInstKey, clientinfo)
	}
	return serverEdgeEvent
}

// Helper function to create the ServerEdgeEvent when CloudletState is bad
func (e *EdgeEventsHandlerPlugin) createCloudletStateEdgeEvent(ctx context.Context, appinstState *dmecommon.DmeAppInstState, appInstKey edgeproto.AppInstKey, clientinfo *ClientInfo, usability Usability) *dme.ServerEdgeEvent {
	serverEdgeEvent := new(dme.ServerEdgeEvent)
	serverEdgeEvent.EventType = dme.ServerEdgeEvent_EVENT_CLOUDLET_STATE
	serverEdgeEvent.CloudletState = appinstState.CloudletState
	// Look for a new cloudlet if the appinst is not usable
	if usability == Unusable {
		e.addNewCloudletToServerEdgeEvent(ctx, serverEdgeEvent, appInstKey, clientinfo)
	}
	return serverEdgeEvent
}

// Helper function to create the ServerEdgeEvent when CloudletMaintenanceState is bad
func (e *EdgeEventsHandlerPlugin) createCloudletMaintenanceStateEdgeEvent(ctx context.Context, appinstState *dmecommon.DmeAppInstState, appInstKey edgeproto.AppInstKey, clientinfo *ClientInfo, usability Usability) *dme.ServerEdgeEvent {
	serverEdgeEvent := new(dme.ServerEdgeEvent)
	serverEdgeEvent.EventType = dme.ServerEdgeEvent_EVENT_CLOUDLET_MAINTENANCE
	serverEdgeEvent.MaintenanceState = appinstState.MaintenanceState
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
	err, _ = dmecommon.FindCloudlet(ctx, &appInstKey.AppKey, clientinfo.carrier, &clientinfo.lastLoc, newCloudlet, e.EdgeEventsCookieExpiration)
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
	// Get appinstinfo for specified appinst on specified cloudlet
	appinstinfo, err := e.getAppInstInfo(ctx, appInstKey)
	if err != nil {
		return nil, err
	}
	// Make sure Clients map is initialized
	if appinstinfo.Clients == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot get clientinfo - ClientsMap is uninitialized, because no clients are on the appinst yet", "appInstKey", "appInstKey")
		return nil, fmt.Errorf("cannot get clientinfo - CLientsMap is uninitialized for appInst %v", appInstKey)
	}
	// Get clientinfo for the specified client
	client := Client{cookieKey}
	clientinfo, ok := appinstinfo.Clients[client]
	if !ok {
		log.SpanLog(ctx, log.DebugLevelInfra, "unable to find client connected to appinst", "appInstKey", appInstKey, "client", client)
		return nil, fmt.Errorf("unable to find client %v on appinst %v", client, appInstKey)
	}
	return clientinfo, nil
}

// Helper function that gets the AppInstInfo for the specified AppInst on the specified Cloudlet
// Must lock EdgeEventsHandlerPlugin before calling this function
func (e *EdgeEventsHandlerPlugin) getAppInstInfo(ctx context.Context, appInstKey edgeproto.AppInstKey) (*AppInstInfo, error) {
	// Get cloudletinfo for specified cloudlet
	cloudletinfo, err := e.getCloudletInfo(ctx, appInstKey.ClusterInstKey.CloudletKey)
	if err != nil {
		return nil, err
	}
	// Make sure AppInsts map is initialized
	if cloudletinfo.AppInsts == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot get appinstinfo - AppInsts map is uninitialized, because no appinsts are on the clouudlet yet", "cloudletKey", appInstKey.ClusterInstKey.CloudletKey)
		return nil, fmt.Errorf("cannot get appisntinfo - AppInsts map is uninitialized for cloudlet %v", appInstKey.ClusterInstKey.CloudletKey)
	}
	// Get clients on specified appinst
	appinstinfo, ok := cloudletinfo.AppInsts[appInstKey]
	if !ok {
		log.SpanLog(ctx, log.DebugLevelInfra, "unable to find appinst on cloudlet", "appInstKey", appInstKey)
		return nil, fmt.Errorf("unable to find appinst on cloudlet: %v", appInstKey)
	}
	return appinstinfo, nil
}

// Helper function that gets the CloudletInfo for the specified Cloudlet
// Must lock EdgeEventsHandlerPlugin before calling this function
func (e *EdgeEventsHandlerPlugin) getCloudletInfo(ctx context.Context, cloudletKey edgeproto.CloudletKey) (*CloudletInfo, error) {
	// Get cloudletinfo for specified cloudlet
	cloudletinfo, ok := e.Cloudlets[cloudletKey]
	if !ok {
		log.SpanLog(ctx, log.DebugLevelInfra, "unable to find cloudlet", "cloudletKey", cloudletKey)
		return nil, fmt.Errorf("unable to find cloudlet: %v", cloudletKey)
	}
	return cloudletinfo, nil
}

// Helper function that removes ClientKey from appinstinfo.Clients
// Must lock EdgeEventsHandlerPlugin before calling this function
func (e *EdgeEventsHandlerPlugin) removeClientKey(ctx context.Context, appInstKey edgeproto.AppInstKey, cookieKey dmecommon.CookieKey) {
	// Get appinstinfo for specified appinst
	appinstinfo, err := e.getAppInstInfo(ctx, appInstKey)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "unable to find appinst to remove", "appInstKey", appInstKey, "error", err)
		return
	}
	// Remove specified client
	client := Client{cookieKey}
	delete(appinstinfo.Clients, client)
}

// Helper function that removes AppInstKey from cloudletinfo.AppInsts
// Will also remove CloudletKey if appinsts is empty
// Must lock EdgeEventsHandlerPlugin before calling this function
func (e *EdgeEventsHandlerPlugin) removeAppInstKey(ctx context.Context, appInstKey edgeproto.AppInstKey) {
	// Check to see if appinst exists
	cloudletinfo, err := e.getCloudletInfo(ctx, appInstKey.ClusterInstKey.CloudletKey)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "unable to find appinst to remove", "appInstKey", appInstKey, "error", err)
		return
	}
	// Remove appinst from map of appinsts
	delete(cloudletinfo.AppInsts, appInstKey)
	if len(cloudletinfo.AppInsts) == 0 {
		e.removeCloudletKey(ctx, appInstKey.ClusterInstKey.CloudletKey)
	}
}

// Helper function that removes CloudletKey from Cloudlets.CloudletsMap
// Must lock EdgeEventsHandlerPlugin before calling this function
func (e *EdgeEventsHandlerPlugin) removeCloudletKey(ctx context.Context, cloudletKey edgeproto.CloudletKey) {
	// Remove cloudlet from map of cloudlets
	delete(e.Cloudlets, cloudletKey)
}
