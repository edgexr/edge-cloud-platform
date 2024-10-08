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
	"context"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
)

type EdgeEventsHandler interface {
	GetVersionProperties(ctx context.Context) map[string]string
	AddClient(ctx context.Context, appInstKey edgeproto.AppInstKey, cookieKey CookieKey, lastLoc dme.Loc, carrier string, sendFunc func(event *dme.ServerEdgeEvent))
	RemoveClient(ctx context.Context, appInstKey edgeproto.AppInstKey, cookieKey CookieKey)
	UpdateClientLastLocation(ctx context.Context, appInstKey edgeproto.AppInstKey, cookieKey CookieKey, lastLoc dme.Loc)
	UpdateClientCarrier(ctx context.Context, appInstKey edgeproto.AppInstKey, cookieKey CookieKey, carrier string)
	SendAvailableAppInst(ctx context.Context, app *DmeApp, newAppInstKey edgeproto.AppInstKey, newAppInst *DmeAppInst, newAppInstCarrier string)
	RemoveAppInst(ctx context.Context, appInstKey edgeproto.AppInstKey)
	SendLatencyRequestEdgeEvent(ctx context.Context, appInstKey edgeproto.AppInstKey)
	ProcessLatencySamples(ctx context.Context, appInstKey edgeproto.AppInstKey, cookieKey CookieKey, samples []*dme.Sample) (*dme.Statistics, error)
	SendAppInstStateEdgeEvent(ctx context.Context, appinstState *DmeAppInstState, appInstKey edgeproto.AppInstKey, appKey *edgeproto.AppKey, eventType dme.ServerEdgeEvent_ServerEventType)
	SendCloudletStateEdgeEvent(ctx context.Context, appinstState *DmeAppInstState, cloudletKey edgeproto.CloudletKey)
	SendCloudletMaintenanceStateEdgeEvent(ctx context.Context, appinstState *DmeAppInstState, cloudletKey edgeproto.CloudletKey)
	SendEdgeEventToClient(ctx context.Context, serverEdgeEvent *dme.ServerEdgeEvent, appInstKey edgeproto.AppInstKey, cookieKey CookieKey)
}

type EmptyEdgeEventsHandler struct{}

func (e *EmptyEdgeEventsHandler) AddClient(ctx context.Context, appInstKey edgeproto.AppInstKey, cookieKey CookieKey, lastLoc dme.Loc, carrier string, sendFunc func(event *dme.ServerEdgeEvent)) {
	log.DebugLog(log.DebugLevelDmereq, "AddClient not implemented for EmptyEdgeEventHandler. Returning")
	return
}

func (e *EmptyEdgeEventsHandler) RemoveClient(ctx context.Context, appInstKey edgeproto.AppInstKey, cookieKey CookieKey) {
	log.DebugLog(log.DebugLevelDmereq, "RemoveClient not implemented for EmptyEdgeEventHandler. Returning")
	return
}

func (e *EmptyEdgeEventsHandler) UpdateClientLastLocation(ctx context.Context, appInstKey edgeproto.AppInstKey, cookieKey CookieKey, lastLoc dme.Loc) {
	log.DebugLog(log.DebugLevelDmereq, "UpdateClientLastLocation not implemented for EmptyEdgeEventHandler. Returning")
	return
}

func (e *EmptyEdgeEventsHandler) UpdateClientCarrier(ctx context.Context, appInstKey edgeproto.AppInstKey, cookieKey CookieKey, carrier string) {
	log.DebugLog(log.DebugLevelDmereq, "UpdateClientCarrier not implemented for EmptyEdgeEventHandler. Returning")
	return
}

func (e *EmptyEdgeEventsHandler) RemoveCloudlet(ctx context.Context, cloudletKey edgeproto.CloudletKey) {
	log.DebugLog(log.DebugLevelDmereq, "RemoveCloudlet not implemented for EmptyEdgeEventHandler. Returning")
	return
}

func (e *EmptyEdgeEventsHandler) SendAvailableAppInst(ctx context.Context, app *DmeApp, newAppInstKey edgeproto.AppInstKey, newAppInst *DmeAppInst, newAppInstCarrier string) {
	log.DebugLog(log.DebugLevelDmereq, "SendAvailableAppInst not implemented for EmptyEdgeEventHandler. Returning")
	return
}

func (e *EmptyEdgeEventsHandler) RemoveAppInst(ctx context.Context, appInstKey edgeproto.AppInstKey) {
	log.DebugLog(log.DebugLevelDmereq, "RemoveAppInst not implemented for EmptyEdgeEventHandler. Returning")
	return
}

func (e *EmptyEdgeEventsHandler) SendLatencyRequestEdgeEvent(ctx context.Context, appInstKey edgeproto.AppInstKey) {
	log.DebugLog(log.DebugLevelDmereq, "SendLatencyRequestEdgeEvent not implemented for EmptyEdgeEventHandler. Returning")
	return
}

func (e *EmptyEdgeEventsHandler) ProcessLatencySamples(ctx context.Context, appInstKey edgeproto.AppInstKey, cookieKey CookieKey, samples []*dme.Sample) (*dme.Statistics, error) {
	log.DebugLog(log.DebugLevelDmereq, "ProcessLatency in EmptyEdgeEventHandler returning fake latency")
	fakestats := &dme.Statistics{
		Avg:        3.21,
		Min:        1.34,
		Max:        6.3453,
		StdDev:     1.0,
		Variance:   1.0,
		NumSamples: 7,
		Timestamp: &dme.Timestamp{
			Seconds: 1,
			Nanos:   1000000000,
		},
	}
	return fakestats, nil
}

func (e *EmptyEdgeEventsHandler) SendAppInstStateEdgeEvent(ctx context.Context, appinstState *DmeAppInstState, appInstKey edgeproto.AppInstKey, appKey *edgeproto.AppKey, eventType dme.ServerEdgeEvent_ServerEventType) {
	log.DebugLog(log.DebugLevelDmereq, "SendAppInstStateEdgeEvent not implemented for EmptyEdgeEventHandler. Returning")
	return
}

func (e *EmptyEdgeEventsHandler) SendCloudletStateEdgeEvent(ctx context.Context, appinstState *DmeAppInstState, cloudletKey edgeproto.CloudletKey) {
	log.DebugLog(log.DebugLevelDmereq, "SendCloudletStateEdgeEvent not implemented for EmptyEdgeEventHandler. Returning")
	return
}

func (e *EmptyEdgeEventsHandler) SendCloudletMaintenanceStateEdgeEvent(ctx context.Context, appinstState *DmeAppInstState, cloudletKey edgeproto.CloudletKey) {
	log.DebugLog(log.DebugLevelDmereq, "SendCloudletMaintenanceStateEdgeEvent not implemented for EmptyEdgeEventHandler. Returning")
	return
}

func (e *EmptyEdgeEventsHandler) SendEdgeEventToClient(ctx context.Context, serverEdgeEvent *dme.ServerEdgeEvent, appInstKey edgeproto.AppInstKey, cookieKey CookieKey) {
	log.DebugLog(log.DebugLevelDmereq, "SendEdgeEventToClient not implemented for EmptyEdgeEventHandler. Returning")
	return
}

func (e *EmptyEdgeEventsHandler) GetVersionProperties(ctx context.Context) map[string]string {
	return map[string]string{}
}
