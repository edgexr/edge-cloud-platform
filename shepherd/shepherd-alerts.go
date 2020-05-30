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
		alert.Labels[cloudcommon.AlertLabelClusterOrg] = clusterInstKey.Organization
		alert.Labels[cloudcommon.AlertLabelCloudletOrg] = clusterInstKey.CloudletKey.Organization
		alert.Labels[cloudcommon.AlertLabelCloudlet] = clusterInstKey.CloudletKey.Name
		alert.Labels[cloudcommon.AlertLabelCluster] = clusterInstKey.ClusterKey.Name
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
		if _, found := alertFromKey.Labels[cloudcommon.AlertLabelApp]; found ||
			alertFromKey.Labels[cloudcommon.AlertLabelClusterOrg] != clusterInstKey.Organization ||
			alertFromKey.Labels[cloudcommon.AlertLabelCloudletOrg] != clusterInstKey.CloudletKey.Organization ||
			alertFromKey.Labels[cloudcommon.AlertLabelCloudlet] != clusterInstKey.CloudletKey.Name ||
			alertFromKey.Labels[cloudcommon.AlertLabelCluster] != clusterInstKey.ClusterKey.Name {
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
		if v.Labels[cloudcommon.AlertLabelClusterOrg] == key.Organization &&
			v.Labels[cloudcommon.AlertLabelCloudletOrg] == key.CloudletKey.Organization &&
			v.Labels[cloudcommon.AlertLabelCloudlet] == key.CloudletKey.Name &&
			v.Labels[cloudcommon.AlertLabelCluster] == key.ClusterKey.Name {
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
