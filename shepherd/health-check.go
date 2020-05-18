package main

import (
	"context"
	"fmt"
	"strconv"

	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	opentracing "github.com/opentracing/opentracing-go"
)

const (
	HealthCheckEnvoyOk   = "healthy"
	HealthCheckEnvoyFail = "/failed_active_hc"
)

func SetupHealthCheckSpan(appInstKey *edgeproto.AppInstKey) (opentracing.Span, context.Context) {
	span := log.StartSpan(log.DebugLevelInfo, "health-check")
	span.SetTag("app", appInstKey.AppKey.Name)
	span.SetTag("cloudlet", appInstKey.ClusterInstKey.CloudletKey.Name)
	span.SetTag("operator", appInstKey.ClusterInstKey.CloudletKey.Organization)
	span.SetTag("cluster", appInstKey.ClusterInstKey.ClusterKey.Name)
	ctx := log.ContextWithSpan(context.Background(), span)
	return span, ctx
}

func getAlertFromAppInst(appInstKey *edgeproto.AppInstKey) *edgeproto.Alert {
	alert := edgeproto.Alert{}
	alert.Labels = make(map[string]string)
	alert.Annotations = make(map[string]string)
	alert.Labels["alertname"] = cloudcommon.AlertAppInstDown
	alert.Labels[cloudcommon.AlertLabelClusterOrg] = appInstKey.AppKey.Organization
	alert.Labels[cloudcommon.AlertLabelCloudletOrg] = appInstKey.ClusterInstKey.CloudletKey.Organization
	alert.Labels[cloudcommon.AlertLabelCloudlet] = appInstKey.ClusterInstKey.CloudletKey.Name
	alert.Labels[cloudcommon.AlertLabelCluster] = appInstKey.ClusterInstKey.ClusterKey.Name
	alert.Labels[cloudcommon.AlertLabelApp] = appInstKey.AppKey.Name
	alert.Labels[cloudcommon.AlertLabelAppVer] = appInstKey.AppKey.Version
	return &alert
}

func shouldSendAlertForHealthCheckCount(ctx context.Context, appInstKey *edgeproto.AppInstKey, reason edgeproto.HealthCheck) bool {
	// EnvoyHealthCheck does its own retries
	if reason == edgeproto.HealthCheck_HEALTH_CHECK_FAIL_SERVER_FAIL {
		return true
	}

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

	// don't send alert first several failures(starting from 0, so maxRetries-1 )
	if scrapePoint.FailedChecksCount < int(settings.ShepherdHealthCheckRetries)-1 {
		scrapePoint.FailedChecksCount++
		ProxyMap[getProxyKey(appInstKey)] = scrapePoint
		return false
	}
	// reset the failed retries count
	scrapePoint.FailedChecksCount = 0
	ProxyMap[getProxyKey(appInstKey)] = scrapePoint
	return true
}

func HealthCheckRootLbDown(ctx context.Context, appInstKey *edgeproto.AppInstKey) {
	HealthCheckDown(ctx, appInstKey, edgeproto.HealthCheck_HEALTH_CHECK_FAIL_ROOTLB_OFFLINE)
}

func HealthCheckRootLbUp(ctx context.Context, appInstKey *edgeproto.AppInstKey) {
	HealthCheckUp(ctx, appInstKey, edgeproto.HealthCheck_HEALTH_CHECK_FAIL_ROOTLB_OFFLINE)
}

// Find cluster healthcheck status in resp:
// backend8008::10.192.1.2:8008::health_flags::healthy
func isEnvoyClusterHealthy(ctx context.Context, envoyResponse string, ports []int32) bool {
	respMap := parseEnvoyClusterResp(ctx, envoyResponse)
	for _, port := range ports {
		key := fmt.Sprintf("backend%d::health_flags", port)
		if health, found := respMap[key]; found {
			if health != HealthCheckEnvoyOk {
				log.SpanLog(ctx, log.DebugLevelMetrics, "Port Failing HealthCheck",
					"port", port, "healthcheck", health)
				return false
			}
		}
	}
	return true
}

func CheckEnvoyClusterHealth(ctx context.Context, scrapePoint *ProxyScrapePoint) {
	request := fmt.Sprintf("docker exec %s curl -s -S http://127.0.0.1:%d/clusters", scrapePoint.ProxyContainer, cloudcommon.ProxyMetricsPort)
	resp, err := scrapePoint.Client.OutputWithTimeout(request, shepherd_common.ShepherdSshConnectTimeout)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Cluster status unknown", "request", request, "err", err.Error())
		return
	}
	if isEnvoyClusterHealthy(ctx, resp, scrapePoint.Ports) {
		HealthCheckUp(ctx, &scrapePoint.Key, edgeproto.HealthCheck_HEALTH_CHECK_FAIL_SERVER_FAIL)
	} else {
		HealthCheckDown(ctx, &scrapePoint.Key, edgeproto.HealthCheck_HEALTH_CHECK_FAIL_SERVER_FAIL)
	}
}

func HealthCheckDown(ctx context.Context, appInstKey *edgeproto.AppInstKey, reason edgeproto.HealthCheck) {
	appInst := edgeproto.AppInst{}
	found := AppInstCache.Get(appInstKey, &appInst)
	if !found {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Unable to find appInst ", "appInst", appInst.Key)
		return
	}

	// AppInst is either not ready, or already failed this health check
	if appInst.State != edgeproto.TrackedState_READY ||
		appInst.HealthCheck == reason {
		return
	}
	if !shouldSendAlertForHealthCheckCount(ctx, appInstKey, reason) {
		return
	}

	// Create and send the Alert
	alert := getAlertFromAppInst(appInstKey)
	alert.Annotations[cloudcommon.AlertHealthCheckStatus] = strconv.Itoa(int(reason))
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

func HealthCheckUp(ctx context.Context, appInstKey *edgeproto.AppInstKey, reason edgeproto.HealthCheck) {
	appInst := edgeproto.AppInst{}
	found := AppInstCache.Get(appInstKey, &appInst)
	if !found {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Unable to find appInst ", "appInst", appInst.Key)
		return
	}

	// Trying to clear a reason which is not active
	if appInst.HealthCheck != reason {
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
		ProxyMap[getProxyKey(appInstKey)] = scrapePoint
	}
	return
}
