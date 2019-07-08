package main

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gogo/protobuf/types"
	platform "github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_platform"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

type MetricAppInstKey struct {
	operator  string
	cloudlet  string
	cluster   string
	pod       string
	developer string
}

type PodPromStat struct {
	cpu       float64
	cpuTS     *types.Timestamp
	mem       uint64
	memTS     *types.Timestamp
	disk      float64
	diskTS    *types.Timestamp
	netSend   uint64
	netSendTS *types.Timestamp
	netRecv   uint64
	netRecvTS *types.Timestamp
}

type ClustPromStat struct {
	cpu          float64
	cpuTS        *types.Timestamp
	mem          float64
	memTS        *types.Timestamp
	disk         float64
	diskTS       *types.Timestamp
	netSend      uint64
	netSendTS    *types.Timestamp
	netRecv      uint64
	netRecvTS    *types.Timestamp
	tcpConns     uint64
	tcpConnsTS   *types.Timestamp
	tcpRetrans   uint64
	tcpRetransTS *types.Timestamp
	udpSend      uint64
	udpSendTS    *types.Timestamp
	udpRecv      uint64
	udpRecvTS    *types.Timestamp
	udpRecvErr   uint64
	udpRecvErrTS *types.Timestamp
}

type PromStats struct {
	promAddr     string
	interval     time.Duration
	appStatsMap  map[MetricAppInstKey]*PodPromStat
	clusterStat  *ClustPromStat
	send         func(metric *edgeproto.Metric)
	waitGrp      sync.WaitGroup
	stop         chan struct{}
	operatorName string
	cloudletName string
	clusterName  string
	developer    string
	client       pc.PlatformClient
}

type PromResp struct {
	Status string   `json:"status,omitempty"`
	Data   PromData `json:"data,omitempty"`
}
type PromData struct {
	ResType string       `json:"resultType,omitempty"`
	Result  []PromMetric `json:"result,omitempty"`
}
type PromMetric struct {
	Labels PromLables    `json:"metric,omitempty"`
	Values []interface{} `json:"value,omitempty"`
}
type PromLables struct {
	PodName string `json:"pod_name,omitempty"`
}

const platformClientHeaderSize = 3

func NewPromStats(promAddr string, interval time.Duration, send func(metric *edgeproto.Metric), clusterInst *edgeproto.ClusterInst, pf platform.Platform) *PromStats {
	var err error
	p := PromStats{}
	p.promAddr = promAddr
	p.appStatsMap = make(map[MetricAppInstKey]*PodPromStat)
	p.clusterStat = &ClustPromStat{}
	p.interval = interval
	p.send = send
	p.operatorName = clusterInst.Key.CloudletKey.OperatorKey.Name
	p.cloudletName = clusterInst.Key.CloudletKey.Name
	p.clusterName = clusterInst.Key.ClusterKey.Name
	p.developer = clusterInst.Key.Developer
	p.client, err = pf.GetPlatformClient(clusterInst)
	if err != nil {
		//should this be a fatal log???
		log.FatalLog("Failed to acquire platform client", "error", err)
	}
	return &p
}

//trims the output from the pc.PlatformClient.Output request so that to get rid of the header stuff tacked on by it
func outputTrim(output string) string {
	lines := strings.SplitN(output, "\n", platformClientHeaderSize+1)
	if len(lines) == 0 {
		return ""
	}
	return lines[len(lines)-1]
}

func getPromMetrics(addr string, query string, client pc.PlatformClient) (*PromResp, error) {
	reqURI := "'http://" + addr + "/api/v1/query?query=" + query + "'"

	resp, err := client.Output("curl " + reqURI)
	if err != nil {
		errstr := fmt.Sprintf("Failed to run <%s>", reqURI)
		log.DebugLog(log.DebugLevelMetrics, errstr, "err", err.Error())
		return nil, err
	}
	trimmedResp := outputTrim(resp)
	promResp := &PromResp{}
	if err = json.Unmarshal([]byte(trimmedResp), promResp); err != nil {
		return nil, err
	}
	return promResp, nil
}

//this takes a float64 representation of a time(in sec) given to use by prometheus
//and turns it into a type.Timestamp format for writing into influxDB
func parseTime(timeFloat float64) *types.Timestamp {
	sec, dec := math.Modf(timeFloat)
	time := time.Unix(int64(sec), int64(dec*(1e9)))
	ts, _ := types.TimestampProto(time)
	return ts
}

func (p *PromStats) CollectPromStats() error {
	appKey := MetricAppInstKey{
		operator:  p.operatorName,
		cloudlet:  p.cloudletName,
		cluster:   p.clusterName,
		developer: p.developer,
	}
	// Get Pod CPU usage percentage
	resp, err := getPromMetrics(p.promAddr, promQCpuPod, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			appKey.pod = metric.Labels.PodName
			stat, found := p.appStatsMap[appKey]
			if !found {
				stat = &PodPromStat{}
				p.appStatsMap[appKey] = stat
			}
			stat.cpuTS = parseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseFloat(metric.Values[1].(string), 64); err == nil {
				stat.cpu = val
			}
		}
	}
	// Get Pod Mem usage
	resp, err = getPromMetrics(p.promAddr, promQMemPod, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			appKey.pod = metric.Labels.PodName
			stat, found := p.appStatsMap[appKey]
			if !found {
				stat = &PodPromStat{}
				p.appStatsMap[appKey] = stat
			}
			stat.memTS = parseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseUint(metric.Values[1].(string), 10, 64); err == nil {
				stat.mem = val
			}
		}
	}
	// Get Pod NetRecv bytes rate averaged over 1m
	resp, err = getPromMetrics(p.promAddr, promQNetRecvRate, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			appKey.pod = metric.Labels.PodName
			stat, found := p.appStatsMap[appKey]
			if !found {
				stat = &PodPromStat{}
				p.appStatsMap[appKey] = stat
			}
			stat.netRecvTS = parseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseFloat(metric.Values[1].(string), 64); err == nil {
				stat.netRecv = uint64(val)
			}
		}
	}
	// Get Pod NetRecv bytes rate averaged over 1m
	resp, err = getPromMetrics(p.promAddr, promQNetSendRate, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			appKey.pod = metric.Labels.PodName
			stat, found := p.appStatsMap[appKey]
			if !found {
				stat = &PodPromStat{}
				p.appStatsMap[appKey] = stat
			}
			//copy only if we can parse the value
			stat.netSendTS = parseTime(metric.Values[0].(float64))
			if val, err := strconv.ParseFloat(metric.Values[1].(string), 64); err == nil {
				stat.netSend = uint64(val)
			}
		}
	}

	// Get Cluster CPU usage
	resp, err = getPromMetrics(p.promAddr, promQCpuClust, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			p.clusterStat.cpuTS = parseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseFloat(metric.Values[1].(string), 64); err == nil {
				p.clusterStat.cpu = val
				// We should have only one value here
				break
			}
		}
	}
	// Get Cluster Mem usage
	resp, err = getPromMetrics(p.promAddr, promQMemClust, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			p.clusterStat.memTS = parseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseFloat(metric.Values[1].(string), 64); err == nil {
				p.clusterStat.mem = val
				// We should have only one value here
				break
			}
		}
	}
	// Get Cluster Disk usage percentage
	resp, err = getPromMetrics(p.promAddr, promQDiskClust, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			p.clusterStat.diskTS = parseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseFloat(metric.Values[1].(string), 64); err == nil {
				p.clusterStat.disk = val
				// We should have only one value here
				break
			}
		}
	}
	// Get Cluster NetRecv bytes rate averaged over 1m
	resp, err = getPromMetrics(p.promAddr, promQRecvBytesRateClust, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			p.clusterStat.netRecvTS = parseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseFloat(metric.Values[1].(string), 64); err == nil {
				p.clusterStat.netRecv = uint64(val)
				// We should have only one value here
				break
			}
		}
	}
	// Get Cluster NetSend bytes rate averaged over 1m
	resp, err = getPromMetrics(p.promAddr, promQSendBytesRateClust, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			p.clusterStat.netSendTS = parseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseFloat(metric.Values[1].(string), 64); err == nil {
				p.clusterStat.netSend = uint64(val)
				// We should have only one value here
				break
			}
		}
	}

	// Get Cluster Established TCP connections
	resp, err = getPromMetrics(p.promAddr, promQTcpConnClust, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			p.clusterStat.tcpConnsTS = parseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseUint(metric.Values[1].(string), 10, 64); err == nil {
				p.clusterStat.tcpConns = val
				// We should have only one value here
				break
			}
		}
	}
	// Get Cluster TCP retransmissions
	resp, err = getPromMetrics(p.promAddr, promQTcpRetransClust, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			p.clusterStat.tcpRetransTS = parseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseUint(metric.Values[1].(string), 10, 64); err == nil {
				p.clusterStat.tcpRetrans = val
				// We should have only one value here
				break
			}
		}
	}
	// Get Cluster UDP Send Datagrams
	resp, err = getPromMetrics(p.promAddr, promQUdpSendPktsClust, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			p.clusterStat.udpSendTS = parseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseUint(metric.Values[1].(string), 10, 64); err == nil {
				p.clusterStat.udpSend = val
				// We should have only one value here
				break
			}
		}
	}
	// Get Cluster UDP Recv Datagrams
	resp, err = getPromMetrics(p.promAddr, promQUdpRecvPktsClust, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			p.clusterStat.udpRecvTS = parseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseUint(metric.Values[1].(string), 10, 64); err == nil {
				p.clusterStat.udpRecv = val
				// We should have only one value here
				break
			}
		}
	}
	// Get Cluster UDP Recv Errors
	resp, err = getPromMetrics(p.promAddr, promQUdpRecvErr, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			p.clusterStat.udpRecvErrTS = parseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseUint(metric.Values[1].(string), 10, 64); err == nil {
				p.clusterStat.udpRecvErr = val
				// We should have only one value here
				break
			}
		}
	}

	return nil
}

func (p *PromStats) Start() {
	p.stop = make(chan struct{})
	p.waitGrp.Add(1)
	go p.RunNotify()
}

func (p *PromStats) Stop() {
	log.DebugLog(log.DebugLevelMetrics, "Stopping PromStats thread\n")
	close(p.stop)
	p.waitGrp.Wait()
}

func (p *PromStats) RunNotify() {
	log.DebugLog(log.DebugLevelMetrics, "Started PromStats thread\n")
	done := false
	for !done {
		select {
		case <-time.After(p.interval):
			if p.CollectPromStats() != nil {
				continue
			}
			log.DebugLog(log.DebugLevelMetrics, fmt.Sprintf("Sending metrics for (%s-%s)%s\n", p.operatorName, p.cloudletName, p.clusterName))
			for key, stat := range p.appStatsMap {
				appMetrics := PodStatToMetrics(&key, stat)
				for _, metric := range appMetrics {
					p.send(metric)
				}
			}
			clusterMetrics := ClusterStatToMetrics(p)
			for _, metric := range clusterMetrics {
				p.send(metric)
			}
		case <-p.stop:
			done = true
		}
	}
	p.waitGrp.Done()
}

func newMetric(operator, cloudlet, cluster, developer, name string, key *MetricAppInstKey, ts *types.Timestamp) *edgeproto.Metric {
	metric := edgeproto.Metric{}
	metric.Name = name
	metric.Timestamp = *ts
	metric.AddTag("operator", operator)
	metric.AddTag("cloudlet", cloudlet)
	metric.AddTag("cluster", cluster)
	metric.AddTag("dev", developer)
	if key != nil {
		metric.AddTag("app", key.pod)
	}
	return &metric
}

func ClusterStatToMetrics(p *PromStats) []*edgeproto.Metric {
	var metrics []*edgeproto.Metric
	var metric *edgeproto.Metric

	metric = newMetric(p.operatorName, p.cloudletName, p.clusterName, p.developer, "crm-cluster-cpu", nil, p.clusterStat.cpuTS)
	metric.AddDoubleVal("cpu", p.clusterStat.cpu)
	metrics = append(metrics, metric)

	metric = newMetric(p.operatorName, p.cloudletName, p.clusterName, p.developer, "crm-cluster-mem", nil, p.clusterStat.memTS)
	metric.AddDoubleVal("mem", p.clusterStat.mem)
	metrics = append(metrics, metric)

	metric = newMetric(p.operatorName, p.cloudletName, p.clusterName, p.developer, "crm-cluster-disk", nil, p.clusterStat.diskTS)
	metric.AddDoubleVal("disk", p.clusterStat.disk)
	metrics = append(metrics, metric)

	//for measurements with multiple values just pick one timestamp to use
	metric = newMetric(p.operatorName, p.cloudletName, p.clusterName, p.developer, "crm-cluster-network", nil, p.clusterStat.netSendTS)
	metric.AddIntVal("sendBytes", p.clusterStat.netSend)
	metric.AddIntVal("recvBytes", p.clusterStat.netRecv)
	metrics = append(metrics, metric)

	metric = newMetric(p.operatorName, p.cloudletName, p.clusterName, p.developer, "crm-cluster-tcp", nil, p.clusterStat.tcpConnsTS)
	metric.AddIntVal("tcpConns", p.clusterStat.tcpConns)
	metric.AddIntVal("tcpRetrans", p.clusterStat.tcpRetrans)
	metrics = append(metrics, metric)

	metric = newMetric(p.operatorName, p.cloudletName, p.clusterName, p.developer, "crm-cluster-udp", nil, p.clusterStat.udpSendTS)
	metric.AddIntVal("udpSend", p.clusterStat.udpSend)
	metric.AddIntVal("udpRecv", p.clusterStat.udpRecv)
	metric.AddIntVal("udpRecvErr", p.clusterStat.udpRecvErr)
	metrics = append(metrics, metric)

	return metrics
}

func PodStatToMetrics(key *MetricAppInstKey, stat *PodPromStat) []*edgeproto.Metric {
	var metrics []*edgeproto.Metric
	var metric *edgeproto.Metric

	metric = newMetric(key.operator, key.cloudlet, key.cluster, key.developer, "crm-appinst-cpu", key, stat.cpuTS)
	metric.AddDoubleVal("cpu", stat.cpu)
	metrics = append(metrics, metric)

	metric = newMetric(key.operator, key.cloudlet, key.cluster, key.developer, "crm-appinst-mem", key, stat.memTS)
	metric.AddIntVal("mem", stat.mem)
	metrics = append(metrics, metric)

	//use the memTS for now until we get an actual disk query so we can get disk time
	//metric = newMetric(key.operator, key.cloudlet, key.cluster, key.developer, "crm-appinst-disk", key, stat.diskTS)
	metric = newMetric(key.operator, key.cloudlet, key.cluster, key.developer, "crm-appinst-disk", key, stat.memTS)
	metric.AddDoubleVal("disk", stat.disk)
	metrics = append(metrics, metric)

	//for measurements with multiple values just pick one timestamp to use
	metric = newMetric(key.operator, key.cloudlet, key.cluster, key.developer, "crm-appinst-network", key, stat.netSendTS)
	metric.AddIntVal("sendBytes", stat.netSend)
	metric.AddIntVal("recvBytes", stat.netRecv)
	metrics = append(metrics, metric)

	return metrics
}
