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

	"github.com/edgexr/edge-cloud-infra/promutils"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
)

func addClusterDetailsToAlerts(alerts []edgeproto.Alert, clusterInstKey *edgeproto.ClusterInstKey) []edgeproto.Alert {
	for ii := range alerts {
		alert := &alerts[ii]
		alert.Labels[edgeproto.ClusterInstKeyTagOrganization] = clusterInstKey.Organization
		alert.Labels[edgeproto.CloudletKeyTagOrganization] = clusterInstKey.CloudletKey.Organization
		alert.Labels[edgeproto.CloudletKeyTagName] = clusterInstKey.CloudletKey.Name
		alert.Labels[edgeproto.ClusterKeyTagName] = clusterInstKey.ClusterKey.Name
	}
	return alerts
}

// Don't consider alerts, which are not destined for this cluster Instance and not clusterInst alerts
func pruneClusterForeignAlerts(key interface{}, keys map[edgeproto.AlertKey]struct{}) map[edgeproto.AlertKey]struct{} {
	clusterInstKey, ok := key.(*edgeproto.ClusterInstKey)
	if !ok {
		// just return original list
		return keys
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
			alertFromKey.Labels[edgeproto.ClusterInstKeyTagOrganization] != clusterInstKey.Organization ||
			alertFromKey.Labels[edgeproto.CloudletKeyTagOrganization] != clusterInstKey.CloudletKey.Organization ||
			alertFromKey.Labels[edgeproto.CloudletKeyTagName] != clusterInstKey.CloudletKey.Name ||
			alertFromKey.Labels[edgeproto.ClusterKeyTagName] != clusterInstKey.ClusterKey.Name {
			delete(keys, key)
		}
	}
	return keys
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
func pruneCloudletForeignAlerts(key interface{}, keys map[edgeproto.AlertKey]struct{}) map[edgeproto.AlertKey]struct{} {
	alertFromKey := edgeproto.Alert{}
	for key := range keys {
		edgeproto.AlertKeyStringParse(string(key), &alertFromKey)
		if !isCloudletMonitoredUserAlert(alertFromKey.Labels) {
			delete(keys, key)
		}
	}
	return keys
}

func UpdateAlerts(ctx context.Context, alerts []edgeproto.Alert, filterKey interface{}, pruneFunc func(filterKey interface{}, keys map[edgeproto.AlertKey]struct{}) map[edgeproto.AlertKey]struct{}) {
	if alerts == nil {
		// some error occurred, do not modify existing cache set
		return
	}

	stale := make(map[edgeproto.AlertKey]struct{})
	AlertCache.GetAllKeys(ctx, func(k *edgeproto.AlertKey, modRev int64) {
		stale[*k] = struct{}{}
	})

	changeCount := 0
	for ii := range alerts {
		alert := &alerts[ii]
		AlertCache.UpdateModFunc(ctx, alert.GetKey(), 0, func(old *edgeproto.Alert) (*edgeproto.Alert, bool) {
			if old == nil {
				log.SpanLog(ctx, log.DebugLevelMetrics, "Update new alert", "alert", alert, "key", alert.GetKey())
				changeCount++
				return alert, true
			}
			// don't update if nothing changed
			changed := !alert.Matches(old)
			if changed {
				changeCount++
				log.SpanLog(ctx, log.DebugLevelMetrics, "Update changed alert", "alert", alert)
			}
			return alert, changed
		})
		delete(stale, alert.GetKeyVal())
	}
	pruneFunc(filterKey, stale)
	// delete our stale entries
	for key := range stale {
		buf := edgeproto.Alert{}
		buf.SetKey(&key)
		alertName := buf.Labels["alertname"]
		if alertName == cloudcommon.AlertClusterAutoScale {
			// handled by cluster autoscaler
			continue
		}
		log.SpanLog(ctx, log.DebugLevelMetrics, "Delete alert that is no longer firing", "alert", buf)
		AlertCache.Delete(ctx, &buf, 0)
		changeCount++
	}
	if changeCount == 0 {
		// suppress span log since nothing logged
		span := log.SpanFromContext(ctx)
		log.NoLogSpan(span)
	}

}

// flushAlerts removes Alerts for clusters that have been deleted
func flushAlerts(ctx context.Context, key *edgeproto.ClusterInstKey) {
	toflush := []edgeproto.AlertKey{}
	AlertCache.Mux.Lock()
	for k, data := range AlertCache.Objs {
		v := data.Obj
		if v.Labels[edgeproto.ClusterInstKeyTagOrganization] == key.Organization &&
			v.Labels[edgeproto.CloudletKeyTagOrganization] == key.CloudletKey.Organization &&
			v.Labels[edgeproto.CloudletKeyTagName] == key.CloudletKey.Name &&
			v.Labels[edgeproto.ClusterKeyTagName] == key.ClusterKey.Name {
			toflush = append(toflush, k)
		}
	}
	AlertCache.Mux.Unlock()
	for _, k := range toflush {
		buf := edgeproto.Alert{}
		buf.SetKey(&k)
		AlertCache.Delete(ctx, &buf, 0)
	}
}
