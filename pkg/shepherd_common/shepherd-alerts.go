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

package shepherd_common

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/promutils"
)

type PruneAlertsFunc func(key any, keys map[edgeproto.AlertKey]*edgeproto.Alert)

// Don't consider alerts, which are not destined for this cluster Instance and not clusterInst alerts
func PruneClusterForeignAlerts(key any, keys map[edgeproto.AlertKey]*edgeproto.Alert) {
	clusterKey, ok := key.(*edgeproto.ClusterKey)
	if !ok {
		// just return original list
		return
	}
	alertFromKey := edgeproto.Alert{}
	for key := range keys {
		edgeproto.AlertKeyStringParse(string(key), &alertFromKey)
		if !isClusterMonitoredUserAlert(alertFromKey.Labels) {
			delete(keys, key)
			continue
		}
		// Skip health-check alerts here - envoy adds "job" label
		if _, found := alertFromKey.Labels["job"]; found ||
			alertFromKey.Labels[edgeproto.ClusterKeyTagOrganization] != clusterKey.Organization ||
			alertFromKey.Labels[edgeproto.ClusterKeyTagName] != clusterKey.Name {
			delete(keys, key)
		}
	}
}

// Cluster Prometheus tracked user alerts are identified by pod label (label_mexAppName)
func isClusterMonitoredUserAlert(labels map[string]string) bool {
	if !cloudcommon.IsMonitoredAlert(labels) {
		return false
	}
	if _, found := labels[promutils.ClusterPrometheusAppLabel]; found {
		return true
	}
	return false
}

// Cloudlet Prometheus tracks active connection based user alerts
func isCloudletMonitoredUserAlert(labels map[string]string) bool {
	if !cloudcommon.IsMonitoredAlert(labels) {
		return false
	}
	// on cloudlet alert label_mexAppName is not added
	if _, found := labels[promutils.ClusterPrometheusAppLabel]; !found {
		return true
	}
	return false
}

// We have only a pre-defined set of alerts that are available at the cloudlet level
func PruneCloudletForeignAlerts(key any, keys map[edgeproto.AlertKey]*edgeproto.Alert) {
	cloudletKey, ok := key.(*edgeproto.CloudletKey)
	if !ok {
		// just return original list
		return
	}
	alertFromKey := edgeproto.Alert{}
	for key := range keys {
		edgeproto.AlertKeyStringParse(string(key), &alertFromKey)
		if !isCloudletMonitoredUserAlert(alertFromKey.Labels) {
			delete(keys, key)
		}
		if alertFromKey.Labels[edgeproto.CloudletKeyTagName] != cloudletKey.Name || alertFromKey.Labels[edgeproto.CloudletKeyTagOrganization] != cloudletKey.Organization {
			delete(keys, key)
		}
	}
}

func UpdateAlertsCache(ctx context.Context, alerts []edgeproto.Alert, cache *edgeproto.AlertCache, filterKey any, pruneFunc PruneAlertsFunc) int {
	if alerts == nil {
		// some error occurred, do not modify existing cache set
		return 0
	}

	stale := make(map[edgeproto.AlertKey]*edgeproto.Alert)
	cache.GetAllLocked(ctx, func(alert *edgeproto.Alert, modRev int64) {
		stale[alert.GetKeyVal()] = alert.Clone()
	})

	change := ResolveAlertsChange(ctx, alerts, stale, filterKey, pruneFunc)
	for _, alert := range change.Update {
		cache.Update(ctx, alert, 0)
	}
	for _, alert := range change.Delete {
		cache.Delete(ctx, alert, 0)
	}

	return len(change.Update) + len(change.Delete)
}

type AlertsChange struct {
	Update []*edgeproto.Alert
	Delete []*edgeproto.Alert
}

func ResolveAlertsChange(ctx context.Context, newAlerts []edgeproto.Alert, existingAlerts map[edgeproto.AlertKey]*edgeproto.Alert, pruneFilterKey any, pruneFunc PruneAlertsFunc) *AlertsChange {
	change := &AlertsChange{}
	if newAlerts == nil {
		// no change
		return change
	}
	for _, alert := range newAlerts {
		existing, ok := existingAlerts[alert.GetKeyVal()]
		if !ok || !alert.Matches(existing) {
			// something has changed
			change.Update = append(change.Update, &alert)
			log.SpanLog(ctx, log.DebugLevelMetrics, "Update changed alert", "alert", alert)
		}
		delete(existingAlerts, alert.GetKeyVal())
	}
	// filter out alerts we don't care about
	pruneFunc(pruneFilterKey, existingAlerts)

	for _, alert := range existingAlerts {
		alertName := alert.Labels["alertname"]
		if alertName == cloudcommon.AlertClusterAutoScale {
			// handled by cluster autoscaler
			continue
		}
		log.SpanLog(ctx, log.DebugLevelMetrics, "Delete alert that is no longer firing", "alert", alert)
		change.Delete = append(change.Delete, alert)
	}
	return change
}

// FlushAlerts removes Alerts for clusters that have been deleted
func FlushAlerts(ctx context.Context, key *edgeproto.ClusterKey, cache *edgeproto.AlertCache) {
	toflush := []edgeproto.AlertKey{}
	cache.Mux.Lock()
	for k, data := range cache.Objs {
		v := data.Obj
		if v.Labels[edgeproto.ClusterKeyTagOrganization] == key.Organization &&
			v.Labels[edgeproto.ClusterKeyTagName] == key.Name {
			toflush = append(toflush, k)
		}
	}
	cache.Mux.Unlock()
	for _, k := range toflush {
		buf := edgeproto.Alert{}
		buf.SetKey(&k)
		cache.Delete(ctx, &buf, 0)
	}
}
