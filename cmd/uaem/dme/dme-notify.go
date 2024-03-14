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

package main

import (
	"context"
	"strings"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/notify"
	uaemcommon "github.com/edgexr/edge-cloud-platform/pkg/uaem-common"
	"google.golang.org/grpc"
)

// Implement notify.RecvAppInstHandler
type AppHandler struct {
}

type AppInstHandler struct {
}

type CloudletHandler struct {
}

type CloudletInfoHandler struct {
}

type FlowRateLimitSettingsHandler struct {
}

type MaxReqsRateLimitSettingsHandler struct {
}

func (s *AppHandler) Update(ctx context.Context, in *edgeproto.App, rev int64) {
	uaemcommon.AddApp(ctx, in)
}

func (s *AppHandler) Delete(ctx context.Context, in *edgeproto.App, rev int64) {
	uaemcommon.RemoveApp(ctx, in)
}

func (s *AppHandler) Prune(ctx context.Context, keys map[edgeproto.AppKey]struct{}) {
	uaemcommon.PruneApps(ctx, keys)
}

func (s *AppHandler) Flush(ctx context.Context, notifyId int64) {}

func (s *AppInstHandler) Update(ctx context.Context, in *edgeproto.AppInst, rev int64) {
	uaemcommon.AddAppInst(ctx, in)
}

func (s *AppInstHandler) Delete(ctx context.Context, in *edgeproto.AppInst, rev int64) {
	uaemcommon.RemoveAppInst(ctx, in)
}

func (s *AppInstHandler) Prune(ctx context.Context, keys map[edgeproto.AppInstKey]struct{}) {
	uaemcommon.PruneAppInsts(ctx, keys)
}

func (s *AppInstHandler) Flush(ctx context.Context, notifyId int64) {}

func (s *CloudletHandler) Update(ctx context.Context, in *edgeproto.Cloudlet, rev int64) {
	// * use cloudlet object for maintenance state as this state is used
	//   by controller to avoid end-user interacting with cloudlets for
	//   appinst/clusterinst actions. Refer SetInstMaintenanceStateForCloudlet
	// * use cloudletInfo object for cloudlet state as this correctly gives
	//   information if cloudlet is online or not
	uaemcommon.SetInstStateFromCloudlet(ctx, in)
}

func (s *CloudletHandler) Delete(ctx context.Context, in *edgeproto.Cloudlet, rev int64) {
	// If cloudlet object, doesn't exist then delete it from DME refs
	// even if cloudletInfo for the same exists
	uaemcommon.DeleteCloudletInfo(ctx, &in.Key)
}

func (s *CloudletHandler) Prune(ctx context.Context, keys map[edgeproto.CloudletKey]struct{}) {
	// If cloudlet object, doesn't exist then delete it from DME refs
	// even if cloudletInfo for the same exists
	uaemcommon.PruneCloudlets(ctx, keys)
}

func (s *CloudletHandler) Flush(ctx context.Context, notifyId int64) {}

func (s *CloudletInfoHandler) Update(ctx context.Context, in *edgeproto.CloudletInfo, rev int64) {
	// * use cloudlet object for maintenance state as this state is used
	//   by controller to avoid end-user interacting with cloudlets for
	//   appinst/clusterinst actions. Refer SetInstMaintenanceStateForCloudlet
	// * use cloudletInfo object for cloudlet state as this correctly gives
	//   information if cloudlet is online or not
	uaemcommon.SetInstStateFromCloudletInfo(ctx, in)
}

func (s *CloudletInfoHandler) Delete(ctx context.Context, in *edgeproto.CloudletInfo, rev int64) {
	// set cloudlet state for the instance accordingly
	in.State = dme.CloudletState_CLOUDLET_STATE_NOT_PRESENT
	uaemcommon.SetInstStateFromCloudletInfo(ctx, in)
}

func (s *CloudletInfoHandler) Prune(ctx context.Context, keys map[edgeproto.CloudletKey]struct{}) {
	// set cloudlet state for all the instances accordingly
	uaemcommon.PruneInstsCloudletState(ctx, keys)
}

func (s *CloudletInfoHandler) Flush(ctx context.Context, notifyId int64) {}

func (r *FlowRateLimitSettingsHandler) Update(ctx context.Context, in *edgeproto.FlowRateLimitSettings, rev int64) {
	if in.Key.RateLimitKey.ApiEndpointType == edgeproto.ApiEndpointType_DME {
		// Update RateLimitMgr with updated RateLimitSettings
		uaemcommon.RateLimitMgr.UpdateFlowRateLimitSettings(in)
	}
}

func (r *FlowRateLimitSettingsHandler) Delete(ctx context.Context, in *edgeproto.FlowRateLimitSettings, rev int64) {
	if in.Key.RateLimitKey.ApiEndpointType == edgeproto.ApiEndpointType_DME {
		uaemcommon.RateLimitMgr.RemoveFlowRateLimitSettings(in.Key)
	}
}

func (r *FlowRateLimitSettingsHandler) Prune(ctx context.Context, keys map[edgeproto.FlowRateLimitSettingsKey]struct{}) {
	uaemcommon.RateLimitMgr.PruneFlowRateLimitSettings(keys)
}

func (r *FlowRateLimitSettingsHandler) Flush(ctx context.Context, notifyId int64) {}

func (r *MaxReqsRateLimitSettingsHandler) Update(ctx context.Context, in *edgeproto.MaxReqsRateLimitSettings, rev int64) {
	if in.Key.RateLimitKey.ApiEndpointType == edgeproto.ApiEndpointType_DME {
		// Update RateLimitMgr with updated RateLimitSettings
		uaemcommon.RateLimitMgr.UpdateMaxReqsRateLimitSettings(in)
	}
}

func (r *MaxReqsRateLimitSettingsHandler) Delete(ctx context.Context, in *edgeproto.MaxReqsRateLimitSettings, rev int64) {
	if in.Key.RateLimitKey.ApiEndpointType == edgeproto.ApiEndpointType_DME {
		uaemcommon.RateLimitMgr.RemoveMaxReqsRateLimitSettings(in.Key)
	}
}

func (r *MaxReqsRateLimitSettingsHandler) Prune(ctx context.Context, keys map[edgeproto.MaxReqsRateLimitSettingsKey]struct{}) {
	uaemcommon.RateLimitMgr.PruneMaxReqsRateLimitSettings(keys)
}

func (r *MaxReqsRateLimitSettingsHandler) Flush(ctx context.Context, notifyId int64) {}

var nodeCache edgeproto.NodeCache
var flowRateLimitSettingsCache edgeproto.FlowRateLimitSettingsCache
var maxReqsRateLimitSettingsCache edgeproto.MaxReqsRateLimitSettingsCache

func initNotifyClient(ctx context.Context, addrs string, tlsDialOption grpc.DialOption, notifyOps ...notify.ClientOp) *notify.Client {
	edgeproto.InitNodeCache(&nodeCache)
	edgeproto.InitAppInstClientKeyCache(&uaemcommon.AppInstClientKeyCache)
	edgeproto.InitDeviceCache(&uaemcommon.PlatformClientsCache)
	uaemcommon.AppInstClientKeyCache.SetUpdatedCb(uaemcommon.SendCachedClients)
	edgeproto.InitFlowRateLimitSettingsCache(&flowRateLimitSettingsCache)
	edgeproto.InitMaxReqsRateLimitSettingsCache(&maxReqsRateLimitSettingsCache)
	notifyClient := notify.NewClient(nodeMgr.Name(), strings.Split(addrs, ","), tlsDialOption, notifyOps...)
	notifyClient.RegisterRecv(notify.GlobalSettingsRecv(&uaemcommon.Settings, uaemcommon.SettingsUpdated))
	notifyClient.RegisterRecv(notify.NewAutoProvPolicyRecv(&uaemcommon.AutoProvPolicyHandler{}))
	notifyClient.RegisterRecv(notify.NewOperatorCodeRecv(&uaemcommon.DmeAppTbl.OperatorCodes))
	notifyClient.RegisterRecv(notify.NewAppRecv(&AppHandler{}))
	notifyClient.RegisterRecv(notify.NewCloudletRecv(&CloudletHandler{}))
	notifyClient.RegisterRecv(notify.NewAppInstRecv(&AppInstHandler{}))
	notifyClient.RegisterRecv(notify.NewClusterInstRecv(&uaemcommon.DmeAppTbl.FreeReservableClusterInsts))
	notifyClient.RegisterRecv(notify.NewFlowRateLimitSettingsRecv(&FlowRateLimitSettingsHandler{}))
	notifyClient.RegisterRecv(notify.NewMaxReqsRateLimitSettingsRecv(&MaxReqsRateLimitSettingsHandler{}))
	notifyClient.RegisterRecvAppInstClientKeyCache(&uaemcommon.AppInstClientKeyCache)

	notifyClient.RegisterSendNodeCache(&nodeCache)
	notifyClient.RegisterSendDeviceCache(&uaemcommon.PlatformClientsCache)
	uaemcommon.PlatformClientsCache.SetFlushAll()
	notifyClient.RegisterRecv(notify.NewCloudletInfoRecv(&CloudletInfoHandler{}))
	uaemcommon.ClientSender = notify.NewAppInstClientSend()
	notifyClient.RegisterSend(uaemcommon.ClientSender)

	log.SpanLog(ctx, log.DebugLevelInfo, "notify client to", "addrs", addrs)
	return notifyClient
}
