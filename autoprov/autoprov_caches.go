package main

import (
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/notify"
)

type CacheData struct {
	appCache            edgeproto.AppCache
	appInstCache        edgeproto.AppInstCache
	appInstRefsCache    edgeproto.AppInstRefsCache
	autoProvPolicyCache edgeproto.AutoProvPolicyCache
	cloudletInfoCache   edgeproto.CloudletInfoCache
	frClusterInsts      edgeproto.FreeReservableClusterInstCache
	alertCache          edgeproto.AlertCache
}

func (s *CacheData) init() {
	edgeproto.InitAppCache(&s.appCache)
	edgeproto.InitAppInstCache(&s.appInstCache)
	edgeproto.InitAppInstRefsCache(&s.appInstRefsCache)
	edgeproto.InitAutoProvPolicyCache(&s.autoProvPolicyCache)
	edgeproto.InitCloudletInfoCache(&s.cloudletInfoCache)
	s.frClusterInsts.Init()
	edgeproto.InitAlertCache(&s.alertCache)
}

func (s *CacheData) initCb(autoProvAggr *AutoProvAggr, minMaxChecker *MinMaxChecker) {
	// set callbacks to respond to changes
	s.appCache.SetUpdatedKeyCb(autoProvAggr.UpdateApp)
	s.appCache.SetDeletedKeyCb(autoProvAggr.DeleteApp)
	s.appCache.SetUpdatedCb(minMaxChecker.UpdatedApp)
	s.appInstCache.SetUpdatedCb(minMaxChecker.UpdatedAppInst)
	s.appInstCache.SetDeletedKeyCb(minMaxChecker.DeletedAppInst)
	s.autoProvPolicyCache.SetUpdatedKeyCb(autoProvAggr.UpdatePolicy)
	s.autoProvPolicyCache.SetUpdatedCb(minMaxChecker.UpdatedPolicy)
	s.cloudletInfoCache.SetUpdatedCb(minMaxChecker.UpdatedCloudletInfo)
	s.appInstRefsCache.SetUpdatedCb(minMaxChecker.UpdatedAppInstRefs)
	s.alertCache.SetUpdatedCb(alertChanged)
}

func (s *CacheData) initNotifyClient(client *notify.Client) {
	notifyClient.RegisterRecvAppCache(&s.appCache)
	notifyClient.RegisterRecvAppInstCache(&s.appInstCache)
	notifyClient.RegisterRecvAppInstRefsCache(&s.appInstRefsCache)
	notifyClient.RegisterRecvAutoProvPolicyCache(&s.autoProvPolicyCache)
	notifyClient.RegisterRecvCloudletInfoCache(&s.cloudletInfoCache)
	notifyClient.RegisterRecv(notify.NewClusterInstRecv(&s.frClusterInsts))
	notifyClient.RegisterRecvAlertCache(&s.alertCache)
}
