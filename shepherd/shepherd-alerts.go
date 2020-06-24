package main

import (
	"context"

	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

func addClusterDetailsToAlerts(alerts []edgeproto.Alert, clusterInstKey *edgeproto.ClusterInstKey) []edgeproto.Alert {
	for ii, _ := range alerts {
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
	for key, _ := range keys {
		edgeproto.AlertKeyStringParse(string(key), &alertFromKey)
		if _, found := alertFromKey.Labels[edgeproto.AppKeyTagName]; found ||
			alertFromKey.Labels[edgeproto.ClusterInstKeyTagOrganization] != clusterInstKey.Organization ||
			alertFromKey.Labels[edgeproto.CloudletKeyTagOrganization] != clusterInstKey.CloudletKey.Organization ||
			alertFromKey.Labels[edgeproto.CloudletKeyTagName] != clusterInstKey.CloudletKey.Name ||
			alertFromKey.Labels[edgeproto.ClusterKeyTagName] != clusterInstKey.ClusterKey.Name {
			delete(keys, key)
		}
	}
	return keys
}

// We have only a pre-defined set of alerts that are available at the cloudlet level
func pruneCloudletForeignAlerts(key interface{}, keys map[edgeproto.AlertKey]struct{}) map[edgeproto.AlertKey]struct{} {
	alertFromKey := edgeproto.Alert{}
	for key, _ := range keys {
		edgeproto.AlertKeyStringParse(string(key), &alertFromKey)
		if alertName, found := alertFromKey.Labels["alertname"]; !found ||
			(alertName != cloudcommon.AlertAppInstDown &&
				alertName != cloudcommon.AlertAutoProvDown) {
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
	for ii, _ := range alerts {
		alert := &alerts[ii]
		AlertCache.UpdateModFunc(ctx, alert.GetKey(), 0, func(old *edgeproto.Alert) (*edgeproto.Alert, bool) {
			if old == nil {
				log.SpanLog(ctx, log.DebugLevelMetrics, "Update new alert", "alert", alert)
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
	for key, _ := range stale {
		buf := edgeproto.Alert{}
		buf.SetKey(&key)
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
