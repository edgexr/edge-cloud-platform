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
	"github.com/edgexr/edge-cloud/cloudcommon/node"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/notify"
)

type CacheData struct {
	appCache            edgeproto.AppCache
	appInstCache        edgeproto.AppInstCache
	appInstRefsCache    edgeproto.AppInstRefsCache
	autoProvPolicyCache edgeproto.AutoProvPolicyCache
	cloudletCache       *edgeproto.CloudletCache
	cloudletInfoCache   edgeproto.CloudletInfoCache
	frClusterInsts      edgeproto.FreeReservableClusterInstCache
	alertCache          edgeproto.AlertCache
	autoProvInfoCache   edgeproto.AutoProvInfoCache
}

func (s *CacheData) init(nodeMgr *node.NodeMgr) {
	edgeproto.InitAppCache(&s.appCache)
	edgeproto.InitAppInstCache(&s.appInstCache)
	edgeproto.InitAppInstRefsCache(&s.appInstRefsCache)
	edgeproto.InitAutoProvPolicyCache(&s.autoProvPolicyCache)
	if nodeMgr != nil {
		s.cloudletCache = nodeMgr.CloudletLookup.GetCloudletCache(node.NoRegion)
	} else {
		s.cloudletCache = &edgeproto.CloudletCache{}
		edgeproto.InitCloudletCache(s.cloudletCache)
	}
	edgeproto.InitCloudletInfoCache(&s.cloudletInfoCache)
	s.frClusterInsts.Init()
	edgeproto.InitAlertCache(&s.alertCache)
	edgeproto.InitAutoProvInfoCache(&s.autoProvInfoCache)
}

func (s *CacheData) initNotifyClient(client *notify.Client) {
	notifyClient.RegisterRecvAppCache(&s.appCache)
	notifyClient.RegisterRecvAppInstCache(&s.appInstCache)
	notifyClient.RegisterRecvAppInstRefsCache(&s.appInstRefsCache)
	notifyClient.RegisterRecvAutoProvPolicyCache(&s.autoProvPolicyCache)
	notifyClient.RegisterRecvCloudletCache(s.cloudletCache)
	notifyClient.RegisterRecvCloudletInfoCache(&s.cloudletInfoCache)
	notifyClient.RegisterRecv(notify.NewClusterInstRecv(&s.frClusterInsts))
	notifyClient.RegisterRecvAlertCache(&s.alertCache)
	notifyClient.RegisterSendAutoProvInfoCache(&s.autoProvInfoCache)
}
