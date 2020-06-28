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
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/dockermgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/proxy"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	dme "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/util"
	ssh "github.com/mobiledgex/golang-ssh"
)

var ProxyMap map[string]ProxyScrapePoint
var ProxyMutex *sync.Mutex

// stat names in envoy
var envoyClusterName = "cluster.backend"
var envoyActive = "upstream_cx_active"
var envoyTotal = "upstream_cx_total"
var envoyDropped = "upstream_cx_connect_fail" // this one might not be right/enough
var envoyBytesSent = "upstream_cx_tx_bytes_total"
var envoyBytesRecvd = "upstream_cx_rx_bytes_total"
var envoySessionTime = "upstream_cx_length_ms"

var envoyUnseen = "No recorded values"
var envoyHistogramBuckets = []string{"P0", "P25", "P50", "P75", "P90", "P95", "P99", "P99.5", "P99.9", "P100"}

type ProxyScrapePoint struct {
	Key               edgeproto.AppInstKey
	FailedChecksCount int
	App               string
	Cluster           string
	ClusterOrg        string
	Ports             []int32
	Client            ssh.Client
	ProxyContainer    string
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
	return appInstKey.AppKey.Name + "-" + appInstKey.ClusterInstKey.ClusterKey.Name + "-" +
		appInstKey.AppKey.Organization + "-" + appInstKey.AppKey.Version
}

// Figure out envoy proxy container name
func getProxyContainerName(ctx context.Context, scrapePoint ProxyScrapePoint) (string, error) {
	container := proxy.GetEnvoyContainerName(scrapePoint.App)
	request := fmt.Sprintf("docker exec %s echo hello", container)
	resp, err := scrapePoint.Client.Output(request)
	if err != nil && strings.Contains(resp, "No such container") {
		// try the docker name if it fails
		container = proxy.GetEnvoyContainerName(dockermgmt.GetContainerName(&scrapePoint.Key.AppKey))
		request = fmt.Sprintf("docker exec %s echo hello", container)
		resp, err = scrapePoint.Client.Output(request)
		// Perhaps this is nginx
		if err != nil && strings.Contains(resp, "No such container") {
			container = "nginx"
			request := fmt.Sprintf("docker exec %s echo hello", scrapePoint.App)
			resp, err = scrapePoint.Client.Output(request)
		}
	}
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to find envoy proxy for app", "scrapepoint", scrapePoint, "err", err)
		return "", err
	}
	return container, nil
}

func CollectProxyStats(ctx context.Context, appInst *edgeproto.AppInst) string {
	// ignore apps not exposed to the outside world as they dont have a envoy/nginx proxy
	app := edgeproto.App{}
	found := AppCache.Get(&appInst.Key.AppKey, &app)
	if !found {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Unable to find app", "app", appInst.Key.AppKey.Name)
		return ""
	} else if app.InternalPorts {
		return ""
	} else if app.AccessType != edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER {
		return ""
	}
	ProxyMapKey := getProxyKey(appInst.GetKey())
	// add/remove from the list of proxy endpoints to hit
	if appInst.State == edgeproto.TrackedState_READY {
		scrapePoint := ProxyScrapePoint{
			Key:        appInst.Key,
			App:        k8smgmt.NormalizeName(appInst.Key.AppKey.Name),
			Cluster:    appInst.Key.ClusterInstKey.ClusterKey.Name,
			ClusterOrg: appInst.Key.ClusterInstKey.Organization,
			Ports:      make([]int32, 0),
		}
		// TODO: track udp ports as well (when we add udp to envoy)
		for _, p := range appInst.MappedPorts {
			if p.Proto == dme.LProto_L_PROTO_TCP {
				scrapePoint.Ports = append(scrapePoint.Ports, p.InternalPort)
			}
		}

		clusterInst := edgeproto.ClusterInst{}
		found := ClusterInstCache.Get(&appInst.Key.ClusterInstKey, &clusterInst)
		if !found {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Unable to find clusterInst for "+appInst.Key.AppKey.Name)
			return ""
		}
		var err error
		scrapePoint.Client, err = myPlatform.GetClusterPlatformClient(ctx, &clusterInst, cloudcommon.ClientTypeRootLB)
		if err != nil {
			// If we cannot get a platform client no point in trying to get metrics
			log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to acquire platform client", "cluster", clusterInst.Key, "error", err)
			return ""
		}
		// Now that we have a client - figure out what container name we should ping
		scrapePoint.ProxyContainer, err = getProxyContainerName(ctx, scrapePoint)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to find envoy proxy for app", "scrapepoint", scrapePoint, "err", err)
			return ""
		}
		ProxyMutex.Lock()
		ProxyMap[ProxyMapKey] = scrapePoint
		ProxyMutex.Unlock()
		return ProxyMapKey
	}
	// if the app is anything other than ready, stop tracking it
	ProxyMutex.Lock()
	delete(ProxyMap, ProxyMapKey)
	ProxyMutex.Unlock()
	return ProxyMapKey
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

func getProxyScrapePoint(key string) *ProxyScrapePoint {
	ProxyMutex.Lock()
	defer ProxyMutex.Unlock()
	scrapePoint, found := ProxyMap[key]
	if !found {
		return nil
	}
	return &scrapePoint
}

func ProxyScraper() {
	for {
		// check if there are any new apps we need to start/stop scraping for
		select {
		case <-time.After(settings.ShepherdMetricsCollectionInterval.TimeDuration()):
			scrapePoints := copyMapValues()
			for _, v := range scrapePoints {
				span := log.StartSpan(log.DebugLevelSampled, "send-metric")
				log.SetTags(span, cloudletKey.GetTags())
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
	// query envoy
	if scrapePoint.ProxyContainer == "nginx" {
		return QueryNginx(ctx, scrapePoint) //if envoy isnt there(for legacy apps) query nginx
	}
	request := fmt.Sprintf("docker exec %s curl -s -S http://127.0.0.1:%d/stats", scrapePoint.ProxyContainer, cloudcommon.ProxyMetricsPort)
	resp, err := scrapePoint.Client.OutputWithTimeout(request, shepherd_common.ShepherdSshConnectTimeout)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to run request", "request", request, "err", err.Error())
		return nil, err
	}
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
	var droppedVal uint64
	metrics.EnvoyStats = make(map[int32]shepherd_common.ConnectionsMetric)
	for _, port := range ports {
		new := shepherd_common.ConnectionsMetric{}
		//active, accepts, handled conn, bytes sent/recvd
		envoyCluster := envoyClusterName + strconv.Itoa(int(port)) + "."
		activeSearch := envoyCluster + envoyActive
		droppedSearch := envoyCluster + envoyDropped
		totalSearch := envoyCluster + envoyTotal
		bytesSentSearch := envoyCluster + envoyBytesSent
		bytesRecvdSearch := envoyCluster + envoyBytesRecvd
		sessionTimeSearch := envoyCluster + envoySessionTime
		new.ActiveConn, err = getUIntStat(respMap, activeSearch)
		if err != nil {
			return fmt.Errorf("Error retrieving envoy active connections stats: %v", err)
		}
		new.Accepts, err = getUIntStat(respMap, totalSearch)
		if err != nil {
			return fmt.Errorf("Error retrieving envoy accepts connections stats: %v", err)
		}
		droppedVal, err = getUIntStat(respMap, droppedSearch)
		if err != nil {
			return fmt.Errorf("Error retrieving envoy handled connections stats: %v", err)
		}
		new.HandledConn = new.Accepts - droppedVal
		new.BytesSent, err = getUIntStat(respMap, bytesSentSearch)
		if err != nil {
			return fmt.Errorf("Error retrieving envoy bytes_sent connections stats: %v", err)
		}
		new.BytesRecvd, err = getUIntStat(respMap, bytesRecvdSearch)
		if err != nil {
			return fmt.Errorf("Error retrieving envoy bytes_recvd connections stats: %v", err)
		}

		// session time histogram
		var sessionTimeHistogram map[string]float64
		sessionTimeHistogram, err = getHistogramIntStats(respMap, sessionTimeSearch)
		if err != nil {
			return fmt.Errorf("Error retrieving envoy session time connections stats: %v", err)
		}
		new.SessionTime = sessionTimeHistogram
		metrics.Ts, _ = types.TimestampProto(time.Now())
		metrics.EnvoyStats[port] = new
	}
	return nil
}

// converts the envoy stats page into a map for easy reading
func parseEnvoyResp(ctx context.Context, resp string) map[string]string {
	lines := strings.Split(resp, "\n")
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
	lines := strings.Split(resp, "\n")
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

// parses envoy histograms into a map form. Envoy histograms look like this:
// cluster.backend4321.upstream_cx_length_ms: P0(nan,2) P25(nan,5.1) P50(nan,11) P75(nan,105) P90(nan,182) P95(nan,186) P99(nan,189.2) P99.5(nan,189.6) P99.9(nan,189.92) P100(nan,190)
func getHistogramIntStats(respMap map[string]string, statName string) (map[string]float64, error) {
	histogramStr, exists := respMap[statName]
	if !exists {
		return nil, fmt.Errorf("stat not found: %s", statName)
	}
	histogram := make(map[string]float64)
	for _, v := range envoyHistogramBuckets {
		histogram[v] = 0
	}
	// if theres no connections yet to measure default everything to zeros
	if histogramStr == envoyUnseen {
		return histogram, nil
	}
	buckets := strings.Split(histogramStr, " ")
	if len(buckets) != len(envoyHistogramBuckets) {
		return nil, fmt.Errorf("Error parsing histogram")
	}
	for i, bucket := range buckets {
		// P0(nan,3300)
		// check if the percentile matches
		if !strings.HasPrefix(bucket, envoyHistogramBuckets[i]) {
			return nil, fmt.Errorf("Error parsing histogram")
		}
		start := strings.Index(bucket, ",")
		end := strings.Index(bucket, ")")
		if start == -1 || end == -1 {
			return nil, fmt.Errorf("Error parsing histogram")
		}
		start = start + 1
		val, err := strconv.ParseFloat(bucket[start:end], 64)
		if err != nil {
			return nil, fmt.Errorf("Error parsing histogram: %v", err)
		}
		histogram[envoyHistogramBuckets[i]] = val
	}
	return histogram, nil
}

func QueryNginx(ctx context.Context, scrapePoint *ProxyScrapePoint) (*shepherd_common.ProxyMetrics, error) {
	// set up health check context
	// build the query
	request := fmt.Sprintf("docker exec %s curl http://127.0.0.1:%d/nginx_metrics", scrapePoint.App, cloudcommon.ProxyMetricsPort)
	resp, err := scrapePoint.Client.OutputWithTimeout(request, shepherd_common.ShepherdSshConnectTimeout)
	// if this is the first time, or the container got restarted, install curl (for old deployments)
	if strings.Contains(resp, "executable file not found") {
		log.SpanLog(ctx, log.DebugLevelInfra, "Installing curl onto docker container ", "Container", scrapePoint.App)
		installer := fmt.Sprintf("docker exec %s apt-get update; docker exec %s apt-get --assume-yes install curl", scrapePoint.App, scrapePoint.App)
		resp, err = scrapePoint.Client.Output(installer)
		if err != nil {
			return nil, fmt.Errorf("can't install curl on nginx container %s, %s, %v", *name, resp, err)
		}
		// now retry curling
		resp, err = scrapePoint.Client.OutputWithTimeout(request, shepherd_common.ShepherdSshConnectTimeout)
	}
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to run request", "request", request, "err", err.Error())
		return nil, err
	}
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
		metric.AddTag("cloudletorg", cloudletKey.Organization)
		metric.AddTag("cloudlet", cloudletKey.Name)
		metric.AddTag("cluster", scrapePoint.Cluster)
		metric.AddTag("clusterorg", scrapePoint.ClusterOrg)
		metric.AddTag("apporg", scrapePoint.Key.AppKey.Organization)
		metric.AddTag("app", util.DNSSanitize(scrapePoint.Key.AppKey.Name))
		metric.AddTag("ver", util.DNSSanitize(scrapePoint.Key.AppKey.Version))
		metric.AddTag("port", strconv.Itoa(int(port)))

		metric.AddIntVal("active", data.EnvoyStats[port].ActiveConn)
		metric.AddIntVal("accepts", data.EnvoyStats[port].Accepts)
		metric.AddIntVal("handled", data.EnvoyStats[port].HandledConn)
		metric.AddIntVal("bytesSent", data.EnvoyStats[port].BytesSent)
		metric.AddIntVal("bytesRecvd", data.EnvoyStats[port].BytesRecvd)

		//session time historgram
		for k, v := range data.EnvoyStats[port].SessionTime {
			metric.AddDoubleVal(k, v)
		}
		metricList = append(metricList, &metric)
	}
	return metricList
}

func MarshallNginxMetric(scrapePoint ProxyScrapePoint, data *shepherd_common.ProxyMetrics) *edgeproto.Metric {
	RemoveShepherdMetrics(data)
	metric := edgeproto.Metric{}
	metric.Name = "appinst-connections"
	metric.Timestamp = *data.Ts
	metric.AddTag("cloudletorg", cloudletKey.Organization)
	metric.AddTag("cloudlet", cloudletKey.Name)
	metric.AddTag("cluster", scrapePoint.Cluster)
	metric.AddTag("clusterorg", scrapePoint.ClusterOrg)
	metric.AddTag("apporg", scrapePoint.Key.AppKey.Organization)
	metric.AddTag("app", util.DNSSanitize(scrapePoint.Key.AppKey.Name))
	metric.AddTag("ver", util.DNSSanitize(scrapePoint.Key.AppKey.Version))
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
