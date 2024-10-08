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

package controller

import (
	"context"
	"strconv"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/objstore"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"go.etcd.io/etcd/client/v3/concurrency"
)

type AlertApi struct {
	all         *AllApis
	sync        *regiondata.Sync
	store       edgeproto.AlertStore
	cache       edgeproto.AlertCache
	sourceCache edgeproto.AlertCache // source of truth from crm/etc
}

var ControllerCreatedAlerts = "ControllerCreatedAlerts"

func NewAlertApi(sync *regiondata.Sync, all *AllApis) *AlertApi {
	alertApi := AlertApi{}
	alertApi.all = all
	alertApi.sync = sync
	alertApi.store = edgeproto.NewAlertStore(sync.GetKVStore())
	edgeproto.InitAlertCache(&alertApi.cache)
	edgeproto.InitAlertCache(&alertApi.sourceCache)
	alertApi.sourceCache.SetUpdatedCb(alertApi.StoreUpdate)
	alertApi.sourceCache.SetDeletedCb(alertApi.StoreDelete)
	sync.RegisterCache(&alertApi.cache)
	return &alertApi
}

// AppInstDown alert needs to set the HealthCheck in AppInst
func (s *AlertApi) appInstSetStateFromHealthCheckAlert(ctx context.Context, alert *edgeproto.Alert, state dme.HealthCheck) {
	appInstName, ok := alert.Labels[edgeproto.AppInstKeyTagName]
	if !ok {
		log.SpanLog(ctx, log.DebugLevelNotify, "Could not find AppInst Name label in Alert", "alert", alert)
		return
	}
	appInstOrg, ok := alert.Labels[edgeproto.AppInstKeyTagOrganization]
	if !ok {
		log.SpanLog(ctx, log.DebugLevelNotify, "Could not find AppInst Org label in Alert", "alert", alert)
		return
	}
	appInstKey := edgeproto.AppInstKey{
		Name:         appInstName,
		Organization: appInstOrg,
	}
	s.all.appInstApi.HealthCheckUpdate(ctx, &appInstKey, state)
}

func (s *AlertApi) setAlertMetadata(in *edgeproto.Alert) {
	in.Controller = ControllerId
	// Add a region label
	in.Labels["region"] = *region
}

func (s *AlertApi) Update(ctx context.Context, in *edgeproto.Alert, rev int64) {
	// for now, only store needed alerts
	name, ok := in.Labels["alertname"]
	if !ok {
		log.SpanLog(ctx, log.DebugLevelNotify, "alertname not found", "labels", in.Labels)
		return
	}
	if !cloudcommon.IsMonitoredAlert(in.Labels) {
		log.SpanLog(ctx, log.DebugLevelNotify, "ignoring alert", "name", name)
		return
	}
	s.setAlertMetadata(in)
	// The CRM is the source of truth for Alerts.
	// We keep a local copy (sourceCache) of all alerts sent by the CRM.
	// If we lose the keep-alive lease with etcd and it deletes all these
	// alerts, we can push them back again from the source cache once the
	// keep-alive lease is reestablished.
	// All alert changes must pass through the source cache before going
	// to etcd.
	s.sourceCache.Update(ctx, in, rev)
	// Note that any further actions should done as part of StoreUpdate.
	// This is because if the keep-alive is lost and we resync, then
	// these additional actions should be performed again as part of StoreUpdate.
}

func (s *AlertApi) StoreUpdate(ctx context.Context, old, new *edgeproto.Alert) {
	_, err := s.store.Put(ctx, new, nil, objstore.WithLease(s.all.syncLeaseData.ControllerAliveLease()))
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelNotify, "Failed to store alert in objstore", "key", new.GetKeyVal(), "err", err)
		return
	}
	name, ok := new.Labels["alertname"]
	if !ok {
		return
	}
	if name == cloudcommon.AlertAppInstDown {
		state, ok := new.Labels[cloudcommon.AlertHealthCheckStatus]
		if !ok {
			log.SpanLog(ctx, log.DebugLevelNotify, "HealthCheck status not found",
				"labels", new.Labels)
			return
		}
		hcState, ok := dme.HealthCheck_CamelValue[state]
		if !ok {
			// NOTE: we might have an old alert that has a number value for state
			intHcState, err := strconv.Atoi(state)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelNotify, "failed to parse Health Check state",
					"state", state, "error", err)
				return
			}
			hcState = int32(intHcState)
		}
		s.appInstSetStateFromHealthCheckAlert(ctx, new, dme.HealthCheck(hcState))
	}
}

func (s *AlertApi) Delete(ctx context.Context, in *edgeproto.Alert, rev int64) {
	// Add a region label
	in.Labels["region"] = *region
	// Controller created alerts, so delete directly
	_, ok := ctx.Value(ControllerCreatedAlerts).(*string)
	if ok {
		s.sourceCache.Delete(ctx, in, rev)
		s.store.Delete(ctx, in, s.sync.SyncWait)
		// Reset HealthCheck state back to OK
		name, ok := in.Labels["alertname"]
		if ok && name == cloudcommon.AlertAppInstDown {
			s.appInstSetStateFromHealthCheckAlert(ctx, in, dme.HealthCheck_HEALTH_CHECK_OK)
		}
	} else {
		s.sourceCache.DeleteCondFunc(ctx, in, rev, func(old *edgeproto.Alert) bool {
			if old.NotifyId != in.NotifyId {
				// already updated by another thread, don't delete
				return false
			}
			return true
		})
	}
	// Note that any further actions should done as part of StoreDelete.
}

func (s *AlertApi) StoreDelete(ctx context.Context, in *edgeproto.Alert) {
	buf := edgeproto.Alert{}
	var foundAlert bool
	err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		if !s.store.STMGet(stm, in.GetKey(), &buf) {
			return nil
		}
		if buf.NotifyId != in.NotifyId || buf.Controller != ControllerId {
			// updated by another thread or controller
			return nil
		}
		s.store.STMDel(stm, in.GetKey())
		foundAlert = true
		return nil
	})
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelNotify, "notify delete Alert", "key", in.GetKeyVal(), "err", err)
	}
	// Reset HealthCheck state back to OK
	name, ok := in.Labels["alertname"]
	if ok && foundAlert && name == cloudcommon.AlertAppInstDown {
		s.appInstSetStateFromHealthCheckAlert(ctx, in, dme.HealthCheck_HEALTH_CHECK_OK)
	}
}

func (s *AlertApi) Flush(ctx context.Context, notifyId int64) {
	// Delete all data from sourceCache. This will trigger StoreDelete calls
	// for every item.
	s.sourceCache.Flush(ctx, notifyId)
}

func (s *AlertApi) Prune(ctx context.Context, keys map[edgeproto.AlertKey]struct{}) {}

func (s *AlertApi) ShowAlert(in *edgeproto.Alert, cb edgeproto.AlertApi_ShowAlertServer) error {
	err := s.cache.Show(in, func(obj *edgeproto.Alert) error {
		err := cb.Send(obj)
		return err
	})
	return err
}

func (s *AlertApi) CleanupCloudletAlerts(ctx context.Context, key *edgeproto.CloudletKey) {
	matches := []*edgeproto.Alert{}
	s.cache.Mux.Lock()
	for _, data := range s.cache.Objs {
		val := data.Obj
		if cloudletName, found := val.Labels[edgeproto.CloudletKeyTagName]; !found ||
			cloudletName != key.Name {
			continue
		}
		if cloudletOrg, found := val.Labels[edgeproto.CloudletKeyTagOrganization]; !found ||
			cloudletOrg != key.Organization {
			continue
		}
		matches = append(matches, val)
	}
	s.cache.Mux.Unlock()
	for _, val := range matches {
		s.sourceCache.Delete(ctx, val, 0)
		s.store.Delete(ctx, val, s.sync.SyncWait)
	}
}

func (s *AlertApi) CleanupAppInstAlerts(ctx context.Context, key *edgeproto.AppInstKey) {
	log.SpanLog(ctx, log.DebugLevelApi, "CleanupAppInstAlerts", "key", key)

	matches := []*edgeproto.Alert{}
	s.cache.Mux.Lock()
	labels := key.GetTags()
	for _, data := range s.cache.Objs {
		val := data.Obj
		matched := true
		for appLabelName, appLabelVal := range labels {
			if val, found := val.Labels[appLabelName]; !found || val != appLabelVal {
				matched = false
				break
			}
		}
		if matched {
			matches = append(matches, val)
		}
	}
	s.cache.Mux.Unlock()
	for _, val := range matches {
		s.sourceCache.Delete(ctx, val, 0)
		s.store.Delete(ctx, val, s.sync.SyncWait)
	}
}

func (s *AlertApi) CleanupClusterInstAlerts(ctx context.Context, key *edgeproto.ClusterKey, cloudletKey *edgeproto.CloudletKey) {
	matches := []*edgeproto.Alert{}
	s.cache.Mux.Lock()
	for _, data := range s.cache.Objs {
		val := data.Obj
		if cloudletName, found := val.Labels[edgeproto.CloudletKeyTagName]; !found ||
			cloudletName != cloudletKey.Name {
			continue
		}
		if cloudletOrg, found := val.Labels[edgeproto.CloudletKeyTagOrganization]; !found ||
			cloudletOrg != cloudletKey.Organization {
			continue
		}
		if clusterName, found := val.Labels[edgeproto.ClusterKeyTagName]; !found ||
			clusterName != key.Name {
			continue
		}
		if clusterOrg, found := val.Labels[edgeproto.ClusterKeyTagOrganization]; !found ||
			clusterOrg != key.Organization {
			continue
		}
		matches = append(matches, val)
	}
	s.cache.Mux.Unlock()
	for _, val := range matches {
		s.sourceCache.Delete(ctx, val, 0)
		s.store.Delete(ctx, val, s.sync.SyncWait)
	}
}

func (s *AlertApi) syncSourceData(ctx context.Context) error {
	// Note that we don't need to delete "stale" data, because
	// if the lease expired, it will be deleted automatically.
	alerts := make([]*edgeproto.Alert, 0)
	s.sourceCache.Mux.Lock()
	for _, data := range s.sourceCache.Objs {
		alert := edgeproto.Alert{}
		alert.DeepCopyIn(data.Obj)
		alerts = append(alerts, &alert)
	}
	s.sourceCache.Mux.Unlock()

	for _, alert := range alerts {
		s.StoreUpdate(ctx, nil, alert)
	}
	return nil
}
