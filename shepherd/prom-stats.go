package main

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/gogo/protobuf/types"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/log"
)

var promQCpuClust = "sum(rate(container_cpu_usage_seconds_total%7Bid%3D%22%2F%22%7D%5B1m%5D))%2Fsum(machine_cpu_cores)*100"
var promQMemClust = "sum(container_memory_working_set_bytes%7Bid%3D%22%2F%22%7D)%2Fsum(machine_memory_bytes)*100"
var promQDiskClust = "sum(container_fs_usage_bytes%7Bdevice%3D~%22%5E%2Fdev%2F%5Bsv%5Dd%5Ba-z%5D%5B1-9%5D%24%22%2Cid%3D%22%2F%22%7D)%2Fsum(container_fs_limit_bytes%7Bdevice%3D~%22%5E%2Fdev%2F%5Bsv%5Dd%5Ba-z%5D%5B1-9%5D%24%22%2Cid%3D%22%2F%22%7D)*100"
var promQSendBytesRateClust = "sum(irate(container_network_transmit_bytes_total%5B1m%5D))"
var promQRecvBytesRateClust = "sum(irate(container_network_receive_bytes_total%5B1m%5D))"
var promQTcpConnClust = "node_netstat_Tcp_CurrEstab"
var promQTcpRetransClust = "node_netstat_Tcp_RetransSegs"
var promQUdpSendPktsClust = "node_netstat_Udp_OutDatagrams"
var promQUdpRecvPktsClust = "node_netstat_Udp_InDatagrams"
var promQUdpRecvErr = "node_netstat_Udp_InErrors"

var promQCpuPod = "sum(rate(container_cpu_usage_seconds_total%7Bimage!%3D%22%22%7D%5B1m%5D))by(pod_name)"
var promQMemPod = "sum(container_memory_working_set_bytes%7Bimage!%3D%22%22%7D)by(pod_name)"
var promQDiskPod = "sum(container_fs_usage_bytes%7Bimage!%3D%22%22%7D)by(pod_name)"
var promQNetRecvRate = "sum(irate(container_network_receive_bytes_total%7Bimage!%3D%22%22%7D%5B1m%5D))by(pod_name)"
var promQNetSendRate = "sum(irate(container_network_transmit_bytes_total%7Bimage!%3D%22%22%7D%5B1m%5D))by(pod_name)"

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

func collectAppPrometheusMetrics(p *K8sClusterStats) map[MetricAppInstKey]*AppMetrics {
	appStatsMap := make(map[MetricAppInstKey]*AppMetrics)

	appKey := MetricAppInstKey{
		clusterInstKey: p.key,
	}
	// Get Pod CPU usage percentage
	resp, err := getPromMetrics(p.promAddr, promQCpuPod, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			appKey.pod = metric.Labels.PodName
			stat, found := appStatsMap[appKey]
			if !found {
				stat = &AppMetrics{}
				appStatsMap[appKey] = stat
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
			stat, found := appStatsMap[appKey]
			if !found {
				stat = &AppMetrics{}
				appStatsMap[appKey] = stat
			}
			stat.memTS = parseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseUint(metric.Values[1].(string), 10, 64); err == nil {
				stat.mem = val
			}
		}
	}
	// Get Pod Disk usage
	resp, err = getPromMetrics(p.promAddr, promQDiskPod, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			appKey.pod = metric.Labels.PodName
			stat, found := appStatsMap[appKey]
			if !found {
				stat = &AppMetrics{}
				appStatsMap[appKey] = stat
			}
			stat.diskTS = parseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseUint(metric.Values[1].(string), 10, 64); err == nil {
				stat.disk = val
			}
		}
	}
	// Get Pod NetRecv bytes rate averaged over 1m
	resp, err = getPromMetrics(p.promAddr, promQNetRecvRate, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			appKey.pod = metric.Labels.PodName
			stat, found := appStatsMap[appKey]
			if !found {
				stat = &AppMetrics{}
				appStatsMap[appKey] = stat
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
			stat, found := appStatsMap[appKey]
			if !found {
				stat = &AppMetrics{}
				appStatsMap[appKey] = stat
			}
			//copy only if we can parse the value
			stat.netSendTS = parseTime(metric.Values[0].(float64))
			if val, err := strconv.ParseFloat(metric.Values[1].(string), 64); err == nil {
				stat.netSend = uint64(val)
			}
		}
	}
	return appStatsMap
}

func collectClusterPrometheusMetrics(p *K8sClusterStats) error {
	// Get Cluster CPU usage
	resp, err := getPromMetrics(p.promAddr, promQCpuClust, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			p.cpuTS = parseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseFloat(metric.Values[1].(string), 64); err == nil {
				p.cpu = val
				// We should have only one value here
				break
			}
		}
	}
	// Get Cluster Mem usage
	resp, err = getPromMetrics(p.promAddr, promQMemClust, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			p.memTS = parseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseFloat(metric.Values[1].(string), 64); err == nil {
				p.mem = val
				// We should have only one value here
				break
			}
		}
	}
	// Get Cluster Disk usage percentage
	resp, err = getPromMetrics(p.promAddr, promQDiskClust, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			p.diskTS = parseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseFloat(metric.Values[1].(string), 64); err == nil {
				p.disk = val
				// We should have only one value here
				break
			}
		}
	}
	// Get Cluster NetRecv bytes rate averaged over 1m
	resp, err = getPromMetrics(p.promAddr, promQRecvBytesRateClust, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			p.netRecvTS = parseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseFloat(metric.Values[1].(string), 64); err == nil {
				p.netRecv = uint64(val)
				// We should have only one value here
				break
			}
		}
	}
	// Get Cluster NetSend bytes rate averaged over 1m
	resp, err = getPromMetrics(p.promAddr, promQSendBytesRateClust, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			p.netSendTS = parseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseFloat(metric.Values[1].(string), 64); err == nil {
				p.netSend = uint64(val)
				// We should have only one value here
				break
			}
		}
	}

	// Get Cluster Established TCP connections
	resp, err = getPromMetrics(p.promAddr, promQTcpConnClust, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			p.tcpConnsTS = parseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseUint(metric.Values[1].(string), 10, 64); err == nil {
				p.tcpConns = val
				// We should have only one value here
				break
			}
		}
	}
	// Get Cluster TCP retransmissions
	resp, err = getPromMetrics(p.promAddr, promQTcpRetransClust, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			p.tcpRetransTS = parseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseUint(metric.Values[1].(string), 10, 64); err == nil {
				p.tcpRetrans = val
				// We should have only one value here
				break
			}
		}
	}
	// Get Cluster UDP Send Datagrams
	resp, err = getPromMetrics(p.promAddr, promQUdpSendPktsClust, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			p.udpSendTS = parseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseUint(metric.Values[1].(string), 10, 64); err == nil {
				p.udpSend = val
				// We should have only one value here
				break
			}
		}
	}
	// Get Cluster UDP Recv Datagrams
	resp, err = getPromMetrics(p.promAddr, promQUdpRecvPktsClust, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			p.udpRecvTS = parseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseUint(metric.Values[1].(string), 10, 64); err == nil {
				p.udpRecv = val
				// We should have only one value here
				break
			}
		}
	}
	// Get Cluster UDP Recv Errors
	resp, err = getPromMetrics(p.promAddr, promQUdpRecvErr, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			p.udpRecvErrTS = parseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseUint(metric.Values[1].(string), 10, 64); err == nil {
				p.udpRecvErr = val
				// We should have only one value here
				break
			}
		}
	}
	return nil
}
