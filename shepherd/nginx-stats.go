package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gogo/protobuf/types"
	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

var nginxMap map[string]NginxScrapePoint
var nginxMutex *sync.Mutex

// variables for unit testing only
var nginxUnitTest = false
var nginxUnitTestPort = int64(0)

type NginxScrapePoint struct {
	App     string
	Cluster string
	Dev     string
	Client  pc.PlatformClient
}

func InitNginxScraper() {
	nginxMap = make(map[string]NginxScrapePoint)
	nginxMutex = &sync.Mutex{}
	go NginxScraper()
}

func CollectNginxStats(ctx context.Context, appInst *edgeproto.AppInst) {
	// ignore apps not exposed to the outside world as they dont have an nginx lb
	app := edgeproto.App{}
	found := AppCache.Get(&appInst.Key.AppKey, &app)
	if !found {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Unable to find app", "app", appInst.Key.AppKey.Name)
		return
	} else if app.InternalPorts {
		return
	}
	nginxMapKey := appInst.Key.AppKey.Name + "-" + appInst.Key.ClusterInstKey.ClusterKey.Name + "-" + appInst.Key.AppKey.DeveloperKey.Name
	// add/remove from the list of nginx endpoints to hit
	if appInst.State == edgeproto.TrackedState_READY {
		scrapePoint := NginxScrapePoint{
			App:     k8smgmt.NormalizeName(appInst.Key.AppKey.Name),
			Cluster: appInst.Key.ClusterInstKey.ClusterKey.Name,
			Dev:     appInst.Key.AppKey.DeveloperKey.Name,
		}

		clusterInst := edgeproto.ClusterInst{}
		found := ClusterInstCache.Get(&appInst.Key.ClusterInstKey, &clusterInst)
		if !found {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Unable to find clusterInst for "+appInst.Key.AppKey.Name)
			return
		}
		var err error
		scrapePoint.Client, err = pf.GetPlatformClient(ctx, &clusterInst)
		if err != nil {
			// If we cannot get a platform client no point in trying to get metrics
			log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to acquire platform client", "cluster", clusterInst.Key, "error", err)
			return
		}
		nginxMutex.Lock()
		nginxMap[nginxMapKey] = scrapePoint
		nginxMutex.Unlock()
	} else {
		// if the app is anything other than ready, stop tracking it
		nginxMutex.Lock()
		delete(nginxMap, nginxMapKey)
		nginxMutex.Unlock()
	}
}

func copyMapValues() []NginxScrapePoint {
	nginxMutex.Lock()
	scrapePoints := make([]NginxScrapePoint, 0, len(nginxMap))
	for _, value := range nginxMap {
		scrapePoints = append(scrapePoints, value)
	}
	nginxMutex.Unlock()
	return scrapePoints
}

func NginxScraper() {
	for {
		// check if there are any new apps we need to start/stop scraping for
		select {
		case <-time.After(*collectInterval):
			scrapePoints := copyMapValues()
			for _, v := range scrapePoints {
				span := log.StartSpan(log.DebugLevelSampled, "send-metric")
				span.SetTag("operator", cloudletKey.OperatorKey.Name)
				span.SetTag("cloudlet", cloudletKey.Name)
				span.SetTag("cluster", v.Cluster)
				ctx := log.ContextWithSpan(context.Background(), span)

				metrics, err := QueryNginx(v)
				if err != nil {
					log.DebugLog(log.DebugLevelMetrics, "Error retrieving nginx metrics", "appinst", v.App, "error", err.Error())
				} else {
					// send to crm->controller->influx
					influxData := MarshallNginxMetric(v, metrics)
					MetricSender.Update(ctx, influxData)
				}
				span.Finish()
			}
		}
	}

}

func QueryNginx(scrapePoint NginxScrapePoint) (*shepherd_common.NginxMetrics, error) {
	// build the query
	request := fmt.Sprintf("docker exec %s curl http://127.0.0.1:%d/nginx_metrics", scrapePoint.App, cloudcommon.NginxMetricsPort)
	if nginxUnitTest {
		request = fmt.Sprintf("curl http://127.0.0.1:%d/nginx_metrics", nginxUnitTestPort)
	}
	resp, err := scrapePoint.Client.Output(request)
	// if this is the first time, or the container got restarted, install curl (for old deployments)
	if strings.Contains(resp, "executable file not found") {
		log.DebugLog(log.DebugLevelMexos, "Installing curl onto docker container ", "Container", scrapePoint.App)
		installer := fmt.Sprintf("docker exec %s apt-get update; docker exec %s apt-get --assume-yes install curl", scrapePoint.App, scrapePoint.App)
		resp, err = scrapePoint.Client.Output(installer)
		if err != nil {
			return nil, fmt.Errorf("can't install curl on nginx container %s, %s, %v", *name, resp, err)
		}
		// now retry curling
		resp, err = scrapePoint.Client.Output(request)
	}
	if err != nil {
		log.DebugLog(log.DebugLevelMetrics, "Failed to run request", "request", request, "err", err.Error())
		return nil, err
	}
	metrics := &shepherd_common.NginxMetrics{}
	err = parseNginxResp(resp, metrics)
	if err != nil {
		return nil, fmt.Errorf("Error parsing response: %v", err)
	}
	return metrics, nil
}

// view here: https://github.com/nginxinc/nginx-prometheus-exporter/blob/29ec94bdee98668e358efac7316bd8d12b05a130/client/nginx.go#L70
func parseNginxResp(resp string, metrics *shepherd_common.NginxMetrics) error {
	// sometimes the response lines get cycled around, so break it up based on the start of the actual content
	trimmedResp := strings.Split(resp, "Active connections:")
	if len(trimmedResp) < 2 {
		return fmt.Errorf("Unexpected output format")
	}
	lines := strings.Split(trimmedResp[1], "\n")

	var err error
	//fix this hardcoding later
	if len(lines) < 4 {
		return fmt.Errorf("Unexpected output format")
	}

	// first line has active connections
	stats := strings.Split(lines[0], " ")
	if metrics.ActiveConn, err = strconv.ParseUint(stats[1], 10, 64); err != nil {
		return err
	}
	// third line for accepts, handled, and requests
	stats = strings.Split(lines[2], " ")
	if metrics.Accepts, err = strconv.ParseUint(stats[1], 10, 64); err != nil {
		return err
	}
	if metrics.HandledConn, err = strconv.ParseUint(stats[2], 10, 64); err != nil {
		return err
	}
	if metrics.Requests, err = strconv.ParseUint(stats[3], 10, 64); err != nil {
		return err
	}
	// last line has reading, writing, waiting
	stats = strings.Split(lines[3], " ")
	if metrics.Reading, err = strconv.ParseUint(stats[1], 10, 64); err != nil {
		return err
	}
	if metrics.Writing, err = strconv.ParseUint(stats[3], 10, 64); err != nil {
		return err
	}
	if metrics.Waiting, err = strconv.ParseUint(stats[5], 10, 64); err != nil {
		return err
	}
	metrics.Ts, _ = types.TimestampProto(time.Now())
	return nil
}

func MarshallNginxMetric(scrapePoint NginxScrapePoint, data *shepherd_common.NginxMetrics) *edgeproto.Metric {
	RemoveShepherdMetrics(data)
	metric := edgeproto.Metric{}
	metric.Name = "appinst-nginx"
	metric.Timestamp = *data.Ts
	metric.AddTag("operator", cloudletKey.OperatorKey.Name)
	metric.AddTag("cloudlet", cloudletKey.Name)
	metric.AddTag("cluster", scrapePoint.Cluster)
	metric.AddTag("dev", scrapePoint.Dev)
	metric.AddTag("app", scrapePoint.App)

	metric.AddIntVal("active", data.ActiveConn)
	metric.AddIntVal("accepts", data.Accepts)
	metric.AddIntVal("handled", data.HandledConn)
	return &metric
}

func RemoveShepherdMetrics(data *shepherd_common.NginxMetrics) {
	data.ActiveConn = data.ActiveConn - 1
	data.Accepts = data.Accepts - data.Requests
	data.HandledConn = data.HandledConn - data.Requests
}
