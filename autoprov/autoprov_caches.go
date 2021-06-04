package main

import (
	"github.com/mobiledgex/edge-cloud/cloudcommon/node"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/notify"
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
