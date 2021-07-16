package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/mobiledgex/edge-cloud-infra/promutils"
	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

func getPromMetrics(ctx context.Context, addr string, query string, client ssh.Client) (*promutils.PromResp, error) {
	// escape the url, since promQL uses some non-compliant characters
	reqURI := "'http://" + addr + "/api/v1/query?query=" + query + "'"
	resp, err := client.Output("curl -s -S " + reqURI)
	if err != nil {
		log.ForceLogSpan(log.SpanFromContext(ctx))
		log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to get prom metrics", "reqURI", reqURI, "err", err, "resp", resp)
		return nil, err
	}
	PromResp := &promutils.PromResp{}
	if err = json.Unmarshal([]byte(resp), PromResp); err != nil {
		return nil, err
	}
	return PromResp, nil
}

func getPromAlerts(ctx context.Context, addr string, client ssh.Client) ([]edgeproto.Alert, error) {
	reqURI := "'http://" + addr + "/api/v1/alerts'"
	out, err := client.Output("curl -s -S " + reqURI)
	if err != nil {
		return nil, fmt.Errorf("Failed to run <%s>, %v[%s]", reqURI, err, out)
	}
	resp := struct {
		Status string
		Data   struct {
			Alerts []promutils.PromAlert
		}
	}{}
	if err = json.Unmarshal([]byte(out), &resp); err != nil {
		return nil, err
	}
	if resp.Status != "success" {
		return nil, fmt.Errorf("Resp to <%s> is %s instead of success", reqURI, resp.Status)
	}
	alerts := []edgeproto.Alert{}
	for _, pa := range resp.Data.Alerts {
		// skip pending alerts
		if pa.State != "firing" {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Skip pending alert", "alert", pa)
			continue
		}
		alert := edgeproto.Alert{}
		alert.Labels = pa.Labels
		alert.Annotations = pa.Annotations
		alert.State = pa.State
		alert.Value = float64(pa.Value)
		if pa.ActiveAt != nil {
			alert.ActiveAt = cloudcommon.TimeToTimestamp(*pa.ActiveAt)
		}
		alerts = append(alerts, alert)
	}
	return alerts, nil
}

func getAppMetricFromPrometheusData(p *K8sClusterStats, appStatsMap map[shepherd_common.MetricAppInstKey]*shepherd_common.AppMetrics, metric *promutils.PromMetric) *shepherd_common.AppMetrics {
	appKey := shepherd_common.MetricAppInstKey{
		ClusterInstKey: p.key,
		Pod:            metric.Labels.PodName,
		App:            metric.Labels.App,
		Version:        metric.Labels.Version,
	}
	stat, found := appStatsMap[appKey]
	if !found {
		stat = &shepherd_common.AppMetrics{}
		appStatsMap[appKey] = stat
	}
	return stat
}

func collectAppPrometheusMetrics(ctx context.Context, p *K8sClusterStats) map[shepherd_common.MetricAppInstKey]*shepherd_common.AppMetrics {
	appStatsMap := make(map[shepherd_common.MetricAppInstKey]*shepherd_common.AppMetrics)

	// Get Pod CPU usage percentage
	resp, err := getPromMetrics(ctx, p.promAddr, promutils.PromQCpuPodUrlEncoded, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			// skip system pods
			if metric.Labels.App == "" {
				continue
			}
			stat := getAppMetricFromPrometheusData(p, appStatsMap, &metric)
			stat.CpuTS = promutils.ParseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseFloat(metric.Values[1].(string), 64); err == nil {
				stat.Cpu = val
			}
		}
	}
	// Get Pod Mem usage
	resp, err = getPromMetrics(ctx, p.promAddr, promutils.PromQMemPodUrlEncoded, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			// skip system pods
			if metric.Labels.App == "" {
				continue
			}
			stat := getAppMetricFromPrometheusData(p, appStatsMap, &metric)
			stat.MemTS = promutils.ParseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseUint(metric.Values[1].(string), 10, 64); err == nil {
				stat.Mem = val
			}
		}
	}
	// Get Pod Disk usage
	resp, err = getPromMetrics(ctx, p.promAddr, promutils.PromQDiskPodUrlEncoded, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			// skip system pods
			if metric.Labels.App == "" {
				continue
			}
			stat := getAppMetricFromPrometheusData(p, appStatsMap, &metric)
			stat.DiskTS = promutils.ParseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseUint(metric.Values[1].(string), 10, 64); err == nil {
				stat.Disk = val
			}
		}
	}
	// Get Pod NetRecv bytes rate averaged over 1m
	resp, err = getPromMetrics(ctx, p.promAddr, promutils.PromQNetRecvRateUrlEncoded, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			// skip system pods
			if metric.Labels.App == "" {
				continue
			}
			stat := getAppMetricFromPrometheusData(p, appStatsMap, &metric)
			stat.NetRecvTS = promutils.ParseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseFloat(metric.Values[1].(string), 64); err == nil {
				stat.NetRecv = uint64(val)
			}
		}
	}
	// Get Pod NetRecv bytes rate averaged over 1m
	resp, err = getPromMetrics(ctx, p.promAddr, promutils.PromQNetSentRateUrlEncoded, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			// skip system pods
			if metric.Labels.App == "" {
				continue
			}
			stat := getAppMetricFromPrometheusData(p, appStatsMap, &metric)
			//copy only if we can parse the value
			stat.NetSentTS = promutils.ParseTime(metric.Values[0].(float64))
			if val, err := strconv.ParseFloat(metric.Values[1].(string), 64); err == nil {
				stat.NetSent = uint64(val)
			}
		}
	}
	return appStatsMap
}

func collectClusterPrometheusMetrics(ctx context.Context, p *K8sClusterStats) error {
	// Get Cluster CPU usage
	resp, err := getPromMetrics(ctx, p.promAddr, promutils.PromQCpuClustUrlEncoded, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			p.CpuTS = promutils.ParseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseFloat(metric.Values[1].(string), 64); err == nil {
				p.Cpu = val
				// We should have only one value here
				break
			}
		}
	}
	// Get Cluster Mem usage
	resp, err = getPromMetrics(ctx, p.promAddr, promutils.PromQMemClustUrlEncoded, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			p.MemTS = promutils.ParseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseFloat(metric.Values[1].(string), 64); err == nil {
				p.Mem = val
				// We should have only one value here
				break
			}
		}
	}
	// Get Cluster Disk usage percentage
	resp, err = getPromMetrics(ctx, p.promAddr, promutils.PromQDiskClustUrlEncoded, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			p.DiskTS = promutils.ParseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseFloat(metric.Values[1].(string), 64); err == nil {
				p.Disk = val
				// We should have only one value here
				break
			}
		}
	}
	// Get Cluster NetRecv bytes rate averaged over 1m
	resp, err = getPromMetrics(ctx, p.promAddr, promutils.PromQRecvBytesRateClustUrlEncoded, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			p.NetRecvTS = promutils.ParseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseFloat(metric.Values[1].(string), 64); err == nil {
				p.NetRecv = uint64(val)
				// We should have only one value here
				break
			}
		}
	}
	// Get Cluster NetSent bytes rate averaged over 1m
	resp, err = getPromMetrics(ctx, p.promAddr, promutils.PromQSentBytesRateClustUrlEncoded, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			p.NetSentTS = promutils.ParseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseFloat(metric.Values[1].(string), 64); err == nil {
				p.NetSent = uint64(val)
				// We should have only one value here
				break
			}
		}
	}

	// Get Cluster Established TCP connections
	resp, err = getPromMetrics(ctx, p.promAddr, promutils.PromQTcpConnClustUrlEncoded, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			p.TcpConnsTS = promutils.ParseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseUint(metric.Values[1].(string), 10, 64); err == nil {
				p.TcpConns = val
				// We should have only one value here
				break
			}
		}
	}
	// Get Cluster TCP retransmissions
	resp, err = getPromMetrics(ctx, p.promAddr, promutils.PromQTcpRetransClustUrlEncoded, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			p.TcpRetransTS = promutils.ParseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseUint(metric.Values[1].(string), 10, 64); err == nil {
				p.TcpRetrans = val
				// We should have only one value here
				break
			}
		}
	}
	// Get Cluster UDP Sent Datagrams
	resp, err = getPromMetrics(ctx, p.promAddr, promutils.PromQUdpSentPktsClustUrlEncoded, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			p.UdpSentTS = promutils.ParseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseUint(metric.Values[1].(string), 10, 64); err == nil {
				p.UdpSent = val
				// We should have only one value here
				break
			}
		}
	}
	// Get Cluster UDP Recv Datagrams
	resp, err = getPromMetrics(ctx, p.promAddr, promutils.PromQUdpRecvPktsClustUrlEncoded, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			p.UdpRecvTS = promutils.ParseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseUint(metric.Values[1].(string), 10, 64); err == nil {
				p.UdpRecv = val
				// We should have only one value here
				break
			}
		}
	}
	// Get Cluster UDP Recv Errors
	resp, err = getPromMetrics(ctx, p.promAddr, promutils.PromQUdpRecvErrUrlEncoded, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			p.UdpRecvErrTS = promutils.ParseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseUint(metric.Values[1].(string), 10, 64); err == nil {
				p.UdpRecvErr = val
				// We should have only one value here
				break
			}
		}
	}
	return nil
}

func collectClusterAutoScaleMetrics(ctx context.Context, p *K8sClusterStats) error {
	// Get Stabilized max total worker node cpu utilization
	resp, err := getPromMetrics(ctx, p.promAddr, promutils.PromQAutoScaleCpuTotalUUrlEncoded, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			//copy only if we can parse the value
			if val, err := strconv.ParseFloat(metric.Values[1].(string), 64); err == nil {
				p.AutoScaleCpu = val
				// We should have only one value here
				break
			}
		}
	}
	// Get Stabilized max total worker node memory utilization
	resp, err = getPromMetrics(ctx, p.promAddr, promutils.PromQAutoScaleMemTotalUUrlEncoded, p.client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			//copy only if we can parse the value
			if val, err := strconv.ParseFloat(metric.Values[1].(string), 64); err == nil {
				p.AutoScaleMem = val
				// We should have only one value here
				break
			}
		}
	}
	return nil
}
