// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/edgexr/edge-cloud-infra/promutils"
	"github.com/edgexr/edge-cloud-infra/shepherd/shepherd_common"
	dme "github.com/edgexr/edge-cloud/d-match-engine/dme-proto"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

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
			alert.ActiveAt = dme.TimeToTimestamp(*pa.ActiveAt)
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
	log.SpanLog(ctx, log.DebugLevelMetrics, "collectAppPrometheusMetrics")

	// Get Pod CPU usage percentage
	resp, err := promutils.GetPromMetrics(ctx, p.promAddr, promutils.PromQCpuPodUrlEncoded, p.client)
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
	resp, err = promutils.GetPromMetrics(ctx, p.promAddr, promutils.PromQMemPodUrlEncoded, p.client)
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
	resp, err = promutils.GetPromMetrics(ctx, p.promAddr, promutils.PromQDiskPodUrlEncoded, p.client)
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
	return appStatsMap
}

func collectClusterPrometheusMetrics(ctx context.Context, p *K8sClusterStats) error {
	// Get Cluster CPU usage
	resp, err := promutils.GetPromMetrics(ctx, p.promAddr, promutils.PromQCpuClustUrlEncoded, p.client)
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
	resp, err = promutils.GetPromMetrics(ctx, p.promAddr, promutils.PromQMemClustUrlEncoded, p.client)
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
	resp, err = promutils.GetPromMetrics(ctx, p.promAddr, promutils.PromQDiskClustUrlEncoded, p.client)
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

	// Get Cluster Established TCP connections
	resp, err = promutils.GetPromMetrics(ctx, p.promAddr, promutils.PromQTcpConnClustUrlEncoded, p.client)
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
	resp, err = promutils.GetPromMetrics(ctx, p.promAddr, promutils.PromQTcpRetransClustUrlEncoded, p.client)
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
	resp, err = promutils.GetPromMetrics(ctx, p.promAddr, promutils.PromQUdpSentPktsClustUrlEncoded, p.client)
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
	resp, err = promutils.GetPromMetrics(ctx, p.promAddr, promutils.PromQUdpRecvPktsClustUrlEncoded, p.client)
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
	resp, err = promutils.GetPromMetrics(ctx, p.promAddr, promutils.PromQUdpRecvErrUrlEncoded, p.client)
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
	resp, err := promutils.GetPromMetrics(ctx, p.promAddr, promutils.PromQAutoScaleCpuTotalUUrlEncoded, p.client)
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
	resp, err = promutils.GetPromMetrics(ctx, p.promAddr, promutils.PromQAutoScaleMemTotalUUrlEncoded, p.client)
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
