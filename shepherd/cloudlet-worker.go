package main

import (
	"context"
	"time"

	intprocess "github.com/mobiledgex/edge-cloud-infra/e2e-tests/int-process"
	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

var cloudletMetrics shepherd_common.CloudletMetrics

// Don't need to do much, just spin up a metrics collection thread
func InitPlatformMetrics(done chan bool) {
	go CloudletScraper(done)
	go CloudletPrometheusScraper(done)
}

func CloudletScraper(done chan bool) {
	for {
		// check if there are any new apps we need to start/stop scraping for
		select {
		case <-time.After(3 * settings.ShepherdMetricsCollectionInterval.TimeDuration()):
			span := log.StartSpan(log.DebugLevelSampled, "send-cloudlet-metric")
			log.SetTags(span, cloudletKey.GetTags())
			ctx := log.ContextWithSpan(context.Background(), span)
			cloudletStats, err := myPlatform.GetPlatformStats(ctx)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelMetrics, "Error retrieving platform metrics", "Platform", myPlatform, "error", err.Error())
			} else {
				metrics := MarshalCloudletMetrics(&cloudletStats)
				for _, metric := range metrics {
					MetricSender.Update(context.Background(), metric)
				}
			}
			span.Finish()
		case <-done:
			// process killed/interrupted, so quit
			return
		}
	}
}

func CloudletPrometheusScraper(done chan bool) {
	for {
		// check if there are any new apps we need to start/stop scraping for
		select {
		case <-time.After(settings.ShepherdMetricsCollectionInterval.TimeDuration()):
			//TODO  - cloudletEnvoyStats, err := getEnvoyStats
			aspan := log.StartSpan(log.DebugLevelMetrics, "send-cloudlet-alerts")
			log.SetTags(aspan, cloudletKey.GetTags())
			actx := log.ContextWithSpan(context.Background(), aspan)
			// platform client is a local ssh
			alerts, err := getPromAlerts(actx, CloudletPrometheusAddr, &pc.LocalClient{})
			if err != nil {
				log.SpanLog(actx, log.DebugLevelMetrics, "Could not collect alerts",
					"prometheus port", intprocess.CloudletPrometheusPort, "err", err)
			}
			// key is nil, since we just check against the predefined set of rules
			UpdateAlerts(actx, alerts, nil, pruneCloudletForeignAlerts)
			aspan.Finish()
		case <-done:
			// process killed/interrupted, so quit
			return

		}
	}
}

func MarshalCloudletMetrics(data *shepherd_common.CloudletMetrics) []*edgeproto.Metric {
	var metrics []*edgeproto.Metric
	cMetric := edgeproto.Metric{}
	nMetric := edgeproto.Metric{}
	iMetric := edgeproto.Metric{}

	// bail out if we get no metrics
	if data == nil {
		return nil
	}

	// If the timestamp for any given metric is null, don't send anything
	if data.CollectTime != nil {
		cMetric.Name = "cloudlet-utilization"
		cMetric.Timestamp = *data.CollectTime
		cMetric.AddTag("cloudletorg", cloudletKey.Organization)
		cMetric.AddTag("cloudlet", cloudletKey.Name)
		cMetric.AddIntVal("vCpuUsed", data.VCpuUsed)
		cMetric.AddIntVal("vCpuMax", data.VCpuMax)
		cMetric.AddIntVal("memUsed", data.MemUsed)
		cMetric.AddIntVal("memMax", data.MemMax)
		cMetric.AddIntVal("diskUsed", data.DiskUsed)
		cMetric.AddIntVal("diskMax", data.DiskMax)
		metrics = append(metrics, &cMetric)

		nMetric.Name = "cloudlet-network"
		nMetric.Timestamp = *data.CollectTime
		nMetric.AddTag("cloudletorg", cloudletKey.Organization)
		nMetric.AddTag("cloudlet", cloudletKey.Name)
		nMetric.AddIntVal("netSent", data.NetSent)
		nMetric.AddIntVal("netRecv", data.NetRecv)
		metrics = append(metrics, &nMetric)

		iMetric.Name = "cloudlet-ipusage"
		iMetric.Timestamp = *data.CollectTime
		iMetric.AddTag("cloudletorg", cloudletKey.Organization)
		iMetric.AddTag("cloudlet", cloudletKey.Name)
		iMetric.AddIntVal("ipv4Max", data.Ipv4Max)
		iMetric.AddIntVal("ipv4Used", data.Ipv4Used)
		iMetric.AddIntVal("floatingIpsMax", data.FloatingIpsMax)
		iMetric.AddIntVal("floatingIpsUsed", data.FloatingIpsUsed)
		metrics = append(metrics, &iMetric)
	}
	return metrics
}
