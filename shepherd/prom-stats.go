package main

import (
	"encoding/json"
	"fmt"
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
	cpu     float64
	mem     uint64
	disk    float64
	netSend uint64
	netRecv uint64
}

type ClustPromStat struct {
	cpu        float64
	mem        float64
	disk       float64
	netSend    uint64
	netRecv    uint64
	tcpConns   uint64
	tcpRetrans uint64
	udpSend    uint64
	udpRecv    uint64
	udpRecvErr uint64
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
			if val, err := strconv.ParseFloat(metric.Values[1].(string), 64); err == nil {
				stat.netSend = uint64(val)
			}
		}
	}

	// Get Cluster CPU usage
	resp, err = getPromMetrics(p.promAddr, promQCpuClust, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
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
			ts, _ := types.TimestampProto(time.Now())
			if p.CollectPromStats() != nil {
				continue
			}
			log.DebugLog(log.DebugLevelMetrics, fmt.Sprintf("Sending metrics for (%s-%s)%s with timestamp %s\n", p.operatorName, p.cloudletName,
				p.clusterName, ts.String()))
			for key, stat := range p.appStatsMap {
				appMetrics := PodStatToMetrics(ts, &key, stat)
				for _, metric := range appMetrics {
					p.send(metric)
				}
			}
			clusterMetrics := ClusterStatToMetrics(ts, p)
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
	metric.Timestamp = *ts
	metric.Name = name
	metric.AddTag("operator", operator)
	metric.AddTag("cloudlet", cloudlet)
	metric.AddTag("cluster", cluster)
	metric.AddTag("dev", developer)
	if key != nil {
		metric.AddTag("app", key.pod)
	}
	return &metric
}

func ClusterStatToMetrics(ts *types.Timestamp, p *PromStats) []*edgeproto.Metric {
	var metrics []*edgeproto.Metric
	var metric *edgeproto.Metric

	metric = newMetric(p.operatorName, p.cloudletName, p.clusterName, p.developer, "crm-cluster-cpu", nil, ts)
	metric.AddDoubleVal("cpu", p.clusterStat.cpu)
	metrics = append(metrics, metric)

	metric = newMetric(p.operatorName, p.cloudletName, p.clusterName, p.developer, "crm-cluster-mem", nil, ts)
	metric.AddDoubleVal("mem", p.clusterStat.mem)
	metrics = append(metrics, metric)

	metric = newMetric(p.operatorName, p.cloudletName, p.clusterName, p.developer, "crm-cluster-disk", nil, ts)
	metric.AddDoubleVal("disk", p.clusterStat.disk)
	metrics = append(metrics, metric)

	metric = newMetric(p.operatorName, p.cloudletName, p.clusterName, p.developer, "crm-cluster-network", nil, ts)
	metric.AddIntVal("sendBytes", p.clusterStat.netSend)
	metric.AddIntVal("recvBytes", p.clusterStat.netRecv)
	metrics = append(metrics, metric)

	metric = newMetric(p.operatorName, p.cloudletName, p.clusterName, p.developer, "crm-cluster-tcp", nil, ts)
	metric.AddIntVal("tcpConns", p.clusterStat.tcpConns)
	metric.AddIntVal("tcpRetrans", p.clusterStat.tcpRetrans)
	metrics = append(metrics, metric)

	metric = newMetric(p.operatorName, p.cloudletName, p.clusterName, p.developer, "crm-cluster-udp", nil, ts)
	metric.AddIntVal("udpSend", p.clusterStat.udpSend)
	metric.AddIntVal("udpRecv", p.clusterStat.udpRecv)
	metric.AddIntVal("udpRecvErr", p.clusterStat.udpRecvErr)
	metrics = append(metrics, metric)

	return metrics
}

func PodStatToMetrics(ts *types.Timestamp, key *MetricAppInstKey, stat *PodPromStat) []*edgeproto.Metric {
	var metrics []*edgeproto.Metric
	var metric *edgeproto.Metric

	metric = newMetric(key.operator, key.cloudlet, key.cluster, key.developer, "crm-appinst-cpu", key, ts)
	metric.AddDoubleVal("cpu", stat.cpu)
	metrics = append(metrics, metric)

	metric = newMetric(key.operator, key.cloudlet, key.cluster, key.developer, "crm-appinst-mem", key, ts)
	metric.AddIntVal("mem", stat.mem)
	metrics = append(metrics, metric)

	metric = newMetric(key.operator, key.cloudlet, key.cluster, key.developer, "crm-appinst-disk", key, ts)
	metric.AddDoubleVal("disk", stat.disk)
	metrics = append(metrics, metric)

	metric = newMetric(key.operator, key.cloudlet, key.cluster, key.developer, "crm-appinst-network", key, ts)
	metric.AddIntVal("sendBytes", stat.netSend)
	metric.AddIntVal("recvBytes", stat.netRecv)
	metrics = append(metrics, metric)

	return metrics
}
