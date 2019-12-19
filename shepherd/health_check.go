package main

import (
	"context"
	"strconv"

	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	opentracing "github.com/opentracing/opentracing-go"
)

func setupHealthCheckSpan(appInstKey *edgeproto.AppInstKey) (opentracing.Span, context.Context) {
	span := log.StartSpan(log.DebugLevelInfo, "health-check")
	span.SetTag("app", appInstKey.AppKey.Name)
	span.SetTag("cloudlet", appInstKey.ClusterInstKey.CloudletKey.Name)
	span.SetTag("operator", appInstKey.ClusterInstKey.CloudletKey.OperatorKey.Name)
	span.SetTag("cluster", appInstKey.ClusterInstKey.ClusterKey.Name)
	ctx := log.ContextWithSpan(context.Background(), span)
	return span, ctx
}

func getAlertFromAppInst(appInstKey *edgeproto.AppInstKey) *edgeproto.Alert {
	alert := edgeproto.Alert{}
	alert.Labels = make(map[string]string)
	alert.Annotations = make(map[string]string)
	alert.Labels["alertname"] = cloudcommon.AlertAppInstDown
	alert.Labels[cloudcommon.AlertLabelDev] = appInstKey.AppKey.DeveloperKey.Name
	alert.Labels[cloudcommon.AlertLabelOperator] = appInstKey.ClusterInstKey.CloudletKey.OperatorKey.Name
	alert.Labels[cloudcommon.AlertLabelCloudlet] = appInstKey.ClusterInstKey.CloudletKey.Name
	alert.Labels[cloudcommon.AlertLabelCluster] = appInstKey.ClusterInstKey.ClusterKey.Name
	alert.Labels[cloudcommon.AlertLabelApp] = appInstKey.AppKey.Name
	alert.Labels[cloudcommon.AlertLabelAppVer] = appInstKey.AppKey.Version
	return &alert
}

func shouldSendAlertForHealthCheckCount(ctx context.Context, appInstKey *edgeproto.AppInstKey) bool {
	// Update the scrape point number of failures
	ProxyMutex.Lock()
	defer ProxyMutex.Unlock()
	scrapePoint, found := ProxyMap[getProxyKey(appInstKey)]

	if !found {
		// Already deleted
		log.SpanLog(ctx, log.DebugLevelMetrics, "AppInst deleted while updating health check",
			"appInst", appInstKey)
		return false
	}

	// don't send alert first several failures
	if scrapePoint.FailedChecksCount < cloudcommon.ShepherdHealthCheckRetries {
		scrapePoint.FailedChecksCount++
		ProxyMap[getProxyKey(appInstKey)] = scrapePoint
		return false
	}
	// reset the failed retries count
	scrapePoint.FailedChecksCount = 0
	return true
}

func HealthCheckDown(ctx context.Context, appInstKey *edgeproto.AppInstKey) {
	span, ctx := setupHealthCheckSpan(appInstKey)
	defer span.Finish()

	appInst := edgeproto.AppInst{}
	found := AppInstCache.Get(appInstKey, &appInst)
	if !found {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Unable to find appInst ", "appInst", appInst.Key)
		return
	}
	if appInst.State != edgeproto.TrackedState_READY ||
		appInst.HealthCheck != edgeproto.HealthCheck_HEALTH_CHECK_OK {
		return
	}
	if !shouldSendAlertForHealthCheckCount(ctx, appInstKey) {
		return
	}

	// Create and send the Alert - for now only due to rootLb going down
	alert := getAlertFromAppInst(appInstKey)
	alert.Annotations[cloudcommon.AlertHealthCheckStatus] =
		strconv.Itoa(int(edgeproto.HealthCheck_HEALTH_CHECK_FAIL_ROOTLB_OFFLINE))
	AlertCache.UpdateModFunc(ctx, alert.GetKey(), 0, func(old *edgeproto.Alert) (*edgeproto.Alert, bool) {
		if old == nil {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Update alert", "alert", alert)
			return alert, true
		}
		// don't update if nothing changed
		changed := !alert.Matches(old)
		if changed {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Update alert", "alert", alert)
		}
		return alert, changed
	})
}

func HealthCheckUp(ctx context.Context, appInstKey *edgeproto.AppInstKey) {
	span, ctx := setupHealthCheckSpan(appInstKey)
	defer span.Finish()

	appInst := edgeproto.AppInst{}
	found := AppInstCache.Get(appInstKey, &appInst)
	if !found {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Unable to find appInst ", "appInst", appInst.Key)
		return
	}
	// Delete the alert if we can find it
	alert := getAlertFromAppInst(appInstKey)
	if AlertCache.HasKey(alert.GetKey()) {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Deleting alert ", "alert", alert, "appInst", appInst.Key)
		AlertCache.Delete(ctx, alert, 0)
		// Reset failure count
		ProxyMutex.Lock()
		defer ProxyMutex.Unlock()
		scrapePoint, found := ProxyMap[getProxyKey(appInstKey)]
		if !found {
			// Already deleted
			log.SpanLog(ctx, log.DebugLevelMetrics, "AppInst deleted while updating health check",
				"appInst", appInstKey)
			return
		}
		scrapePoint.FailedChecksCount = 0
	}
	return
}
