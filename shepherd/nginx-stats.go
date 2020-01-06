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
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/proxy"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	dme "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

var ProxyMap map[string]ProxyScrapePoint
var ProxyMutex *sync.Mutex

// stat names in envoy
var envoyClusterName = "cluster.backend"
var envoyActive = "upstream_cx_active"
var envoyTotal = "upstream_cx_total"
var envoyDropped = "upstream_cx_connect_fail" // this one might not be right/enough

type ProxyScrapePoint struct {
	Key               edgeproto.AppInstKey
	FailedChecksCount int
	App               string
	Cluster           string
	Dev               string
	Ports             []int32
	Client            pc.PlatformClient
}

func InitProxyScraper() {
	ProxyMap = make(map[string]ProxyScrapePoint)
	ProxyMutex = &sync.Mutex{}
}

func StartProxyScraper() {
	if ProxyMap == nil {
		return
	}
	go ProxyScraper()
}

func getProxyKey(appInstKey *edgeproto.AppInstKey) string {
	return appInstKey.AppKey.Name + "-" + appInstKey.ClusterInstKey.ClusterKey.Name + "-" + appInstKey.AppKey.DeveloperKey.Name
}

func CollectProxyStats(ctx context.Context, appInst *edgeproto.AppInst) {
	// ignore apps not exposed to the outside world as they dont have an nginx proxy
	app := edgeproto.App{}
	found := AppCache.Get(&appInst.Key.AppKey, &app)
	if !found {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Unable to find app", "app", appInst.Key.AppKey.Name)
		return
	} else if app.InternalPorts {
		return
	}
	ProxyMapKey := getProxyKey(appInst.GetKey())
	// add/remove from the list of proxy endpoints to hit
	if appInst.State == edgeproto.TrackedState_READY {
		scrapePoint := ProxyScrapePoint{
			Key:     appInst.Key,
			App:     k8smgmt.NormalizeName(appInst.Key.AppKey.Name),
			Cluster: appInst.Key.ClusterInstKey.ClusterKey.Name,
			Dev:     appInst.Key.AppKey.DeveloperKey.Name,
			Ports:   make([]int32, 0),
		}
		// TODO: track udp ports as well (when we add udp to envoy)
		for _, p := range appInst.MappedPorts {
			if p.Proto == dme.LProto_L_PROTO_TCP {
				scrapePoint.Ports = append(scrapePoint.Ports, p.PublicPort)
			}
		}

		clusterInst := edgeproto.ClusterInst{}
		found := ClusterInstCache.Get(&appInst.Key.ClusterInstKey, &clusterInst)
		if !found {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Unable to find clusterInst for "+appInst.Key.AppKey.Name)
			return
		}
		var err error
		scrapePoint.Client, err = myPlatform.GetPlatformClient(ctx, &clusterInst)
		if err != nil {
			// If we cannot get a platform client no point in trying to get metrics
			log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to acquire platform client", "cluster", clusterInst.Key, "error", err)
			return
		}
		ProxyMutex.Lock()
		ProxyMap[ProxyMapKey] = scrapePoint
		ProxyMutex.Unlock()
	} else {
		// if the app is anything other than ready, stop tracking it
		ProxyMutex.Lock()
		delete(ProxyMap, ProxyMapKey)
		ProxyMutex.Unlock()
	}
}

func copyMapValues() []ProxyScrapePoint {
	ProxyMutex.Lock()
	scrapePoints := make([]ProxyScrapePoint, 0, len(ProxyMap))
	for _, value := range ProxyMap {
		scrapePoints = append(scrapePoints, value)
	}
	ProxyMutex.Unlock()
	return scrapePoints
}

func ProxyScraper() {
	for {
		// check if there are any new apps we need to start/stop scraping for
		select {
		case <-time.After(collectInterval):
			scrapePoints := copyMapValues()
			for _, v := range scrapePoints {
				span := log.StartSpan(log.DebugLevelSampled, "send-metric")
				span.SetTag("operator", cloudletKey.OperatorKey.Name)
				span.SetTag("cloudlet", cloudletKey.Name)
				span.SetTag("cluster", v.Cluster)
				ctx := log.ContextWithSpan(context.Background(), span)

				metrics, err := QueryProxy(ctx, &v)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelMetrics, "Error retrieving proxy metrics", "appinst", v.App, "error", err.Error())
				} else {
					// send to crm->controller->influx
					influxData := MarshallProxyMetric(v, metrics)
					for _, datapoint := range influxData {
						MetricSender.Update(ctx, datapoint)
					}
				}
				span.Finish()
			}
		}
	}
}

func QueryProxy(ctx context.Context, scrapePoint *ProxyScrapePoint) (*shepherd_common.ProxyMetrics, error) {
	// set up health check context
	span, hcCtx := SetupHealthCheckSpan(&scrapePoint.Key)
	defer span.Finish()
	// query envoy
	container := proxy.GetEnvoyContainerName(scrapePoint.App)
	request := fmt.Sprintf("docker exec %s curl http://127.0.0.1:%d/stats", container, cloudcommon.ProxyMetricsPort)
	resp, err := scrapePoint.Client.Output(request)
	if err != nil {
		if strings.Contains(resp, "No such container") {
			return QueryNginx(ctx, scrapePoint) //if envoy isnt there(for legacy apps) query nginx
		}
		log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to run request", "request", request, "err", err.Error())
		// Also this means that we need to notify the controller that this AppInst is no longer recheable
		HealthCheckRootLbDown(hcCtx, &scrapePoint.Key)
		return nil, err
	}
	HealthCheckRootLbUp(hcCtx, &scrapePoint.Key)
	CheckEnvoyClusterHealth(hcCtx, scrapePoint)
	metrics := &shepherd_common.ProxyMetrics{Nginx: false}
	respMap := parseEnvoyResp(ctx, resp)
	err = envoyConnections(ctx, respMap, scrapePoint.Ports, metrics)
	if err != nil {
		return nil, fmt.Errorf("Error parsing response: %v", err)
	}
	return metrics, nil
}

func envoyConnections(ctx context.Context, respMap map[string]string, ports []int32, metrics *shepherd_common.ProxyMetrics) error {
	var err error
	metrics.EnvoyStats = make(map[int32]shepherd_common.ConnectionsMetric)
	for _, port := range ports {
		new := shepherd_common.ConnectionsMetric{}
		//active, accepts, handled conn
		activeSearch := envoyClusterName + strconv.Itoa(int(port)) + "." + envoyActive
		droppedSearch := envoyClusterName + strconv.Itoa(int(port)) + "." + envoyDropped
		totalSearch := envoyClusterName + strconv.Itoa(int(port)) + "." + envoyTotal

		new.ActiveConn, err = getUIntStat(respMap, activeSearch)
		if err != nil {
			return fmt.Errorf("Error retrieving envoy active connections stats: %v", err)
		}
		new.Accepts, err = getUIntStat(respMap, totalSearch)
		if err != nil {
			return fmt.Errorf("Error retrieving envoy accepts connections stats: %v", err)
		}
		var droppedVal uint64
		droppedVal, err = getUIntStat(respMap, droppedSearch)
		if err != nil {
			return fmt.Errorf("Error retrieving envoy handled connections stats: %v", err)
		}
		new.HandledConn = new.Accepts - droppedVal
		metrics.Ts, _ = types.TimestampProto(time.Now())
		metrics.EnvoyStats[port] = new
	}
	return nil
}

// converts the envoy stats page into a map for easy reading
func parseEnvoyResp(ctx context.Context, resp string) map[string]string {
	lines := strings.Split(outputTrim(resp), "\n")
	newMap := make(map[string]string)
	for _, line := range lines {
		keyValPair := strings.Split(line, ": ")
		if len(keyValPair) == 2 {
			newMap[keyValPair[0]] = keyValPair[1]
		} else {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Could not parse line", "line", line)
		}
	}
	return newMap
}

// converts envoy cluster ouptut into a map
// Example of cluster output string: backend8008::10.192.1.2:8008::health_flags::healthy
func parseEnvoyClusterResp(ctx context.Context, resp string) map[string]string {
	lines := strings.Split(outputTrim(resp), "\n")
	newMap := make(map[string]string)
	for _, line := range lines {
		items := strings.Split(line, "::")
		cnt := len(items)
		// at least 3
		if cnt < 3 {
			continue
		}
		// First is unique with respect to port, next to last is the keyname and last is value
		newMap[items[0]+"::"+items[cnt-2]] = items[cnt-1]
	}
	return newMap
}

// this function only retrieves stats from envoy that are expected to be int values
func getUIntStat(respMap map[string]string, statName string) (uint64, error) {
	stat, exists := respMap[statName]
	if !exists {
		return 0, fmt.Errorf("stat not found: %s", statName)
	}
	val, err := strconv.ParseUint(stat, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("Error retrieving stats: %v", err)
	}
	return val, nil
}

func QueryNginx(ctx context.Context, scrapePoint *ProxyScrapePoint) (*shepherd_common.ProxyMetrics, error) {
	// set up health check context
	span, hcCtx := SetupHealthCheckSpan(&scrapePoint.Key)
	defer span.Finish()
	// build the query
	request := fmt.Sprintf("docker exec %s curl http://127.0.0.1:%d/nginx_metrics", scrapePoint.App, cloudcommon.ProxyMetricsPort)
	resp, err := scrapePoint.Client.Output(request)
	// if this is the first time, or the container got restarted, install curl (for old deployments)
	if strings.Contains(resp, "executable file not found") {
		log.SpanLog(ctx, log.DebugLevelMexos, "Installing curl onto docker container ", "Container", scrapePoint.App)
		installer := fmt.Sprintf("docker exec %s apt-get update; docker exec %s apt-get --assume-yes install curl", scrapePoint.App, scrapePoint.App)
		resp, err = scrapePoint.Client.Output(installer)
		if err != nil {
			return nil, fmt.Errorf("can't install curl on nginx container %s, %s, %v", *name, resp, err)
		}
		// now retry curling
		resp, err = scrapePoint.Client.Output(request)
	}
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to run request", "request", request, "err", err.Error())
		// Also this means that we need to notify the controller that this AppInst is no longer recheable
		HealthCheckRootLbDown(hcCtx, &scrapePoint.Key)
		return nil, err
	}
	HealthCheckRootLbUp(hcCtx, &scrapePoint.Key)
	metrics := &shepherd_common.ProxyMetrics{Nginx: true}
	err = parseNginxResp(resp, metrics)
	if err != nil {
		return nil, fmt.Errorf("Error parsing response: %v", err)
	}
	return metrics, nil
}

// view here: https://github.com/nginxinc/nginx-prometheus-exporter/blob/29ec94bdee98668e358efac7316bd8d12b05a130/client/nginx.go#L70
func parseNginxResp(resp string, metrics *shepherd_common.ProxyMetrics) error {
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

func MarshallProxyMetric(scrapePoint ProxyScrapePoint, data *shepherd_common.ProxyMetrics) []*edgeproto.Metric {
	if data.Nginx {
		return []*edgeproto.Metric{MarshallNginxMetric(scrapePoint, data)}
	}
	metricList := make([]*edgeproto.Metric, 0)
	for _, port := range scrapePoint.Ports {
		metric := edgeproto.Metric{}
		metric.Name = "appinst-connections"
		metric.Timestamp = *data.Ts
		metric.AddTag("operator", cloudletKey.OperatorKey.Name)
		metric.AddTag("cloudlet", cloudletKey.Name)
		metric.AddTag("cluster", scrapePoint.Cluster)
		metric.AddTag("dev", scrapePoint.Dev)
		metric.AddTag("app", scrapePoint.App)
		metric.AddTag("port", strconv.Itoa(int(port)))

		metric.AddIntVal("active", data.EnvoyStats[port].ActiveConn)
		metric.AddIntVal("accepts", data.EnvoyStats[port].Accepts)
		metric.AddIntVal("handled", data.EnvoyStats[port].HandledConn)
		metricList = append(metricList, &metric)
	}
	return metricList
}

func MarshallNginxMetric(scrapePoint ProxyScrapePoint, data *shepherd_common.ProxyMetrics) *edgeproto.Metric {
	RemoveShepherdMetrics(data)
	metric := edgeproto.Metric{}
	metric.Name = "appinst-connections"
	metric.Timestamp = *data.Ts
	metric.AddTag("operator", cloudletKey.OperatorKey.Name)
	metric.AddTag("cloudlet", cloudletKey.Name)
	metric.AddTag("cluster", scrapePoint.Cluster)
	metric.AddTag("dev", scrapePoint.Dev)
	metric.AddTag("app", scrapePoint.App)
	metric.AddTag("port", "") //nginx doesnt support stats per port

	metric.AddIntVal("active", data.ActiveConn)
	metric.AddIntVal("accepts", data.Accepts)
	metric.AddIntVal("handled", data.HandledConn)
	return &metric
}

func RemoveShepherdMetrics(data *shepherd_common.ProxyMetrics) {
	data.ActiveConn = data.ActiveConn - 1
	data.Accepts = data.Accepts - data.Requests
	data.HandledConn = data.HandledConn - data.Requests
}
