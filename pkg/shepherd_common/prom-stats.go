// Copyright 2025 EdgeXR, Inc
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

package shepherd_common

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/promutils"
)

func GetPromAlerts(ctx context.Context, client promutils.PromClient) ([]edgeproto.Alert, error) {
	reqPath := "/api/v1/alerts"
	out, err := client.Get(reqPath)
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("Resp to <%s> is %s instead of success", reqPath, resp.Status)
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

func getAppMetricFromPrometheusData(ctx context.Context, p *K8sStats, appStatsMap map[MetricAppInstKey]*AppMetrics, metric *promutils.PromMetric) *AppMetrics {
	labelKey := cloudcommon.AppInstLabels{
		AppInstNameLabel: metric.Labels.AppInstName,
		AppInstOrgLabel:  metric.Labels.AppInstOrg,
	}
	labelKeyOld := cloudcommon.AppInstLabelsOld{
		AppNameLabel:    metric.Labels.AppName,
		AppVersionLabel: metric.Labels.AppVersion,
	}
	appInstInfo, found := p.getAppInstInfo(labelKey, labelKeyOld)
	if !found {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to find appInstKey for cluster from labels", "labels", metric.Labels, "labelKey", labelKey, "labelKeyOld", labelKeyOld, "cluster", p.Key)
	}
	appKey := MetricAppInstKey{
		ClusterKey:  p.Key,
		CloudletKey: p.CloudletKey,
		Pod:         metric.Labels.PodName,
		AppInstName: appInstInfo.AppInstKey.Name,
		AppInstOrg:  appInstInfo.AppInstKey.Organization,
	}
	stat, found := appStatsMap[appKey]
	if !found {
		stat = &AppMetrics{}
		appStatsMap[appKey] = stat
	}
	return stat
}

func (p *K8sStats) collectAppPrometheusMetrics(ctx context.Context, client promutils.PromClient) map[MetricAppInstKey]*AppMetrics {
	appStatsMap := make(map[MetricAppInstKey]*AppMetrics)
	log.SpanLog(ctx, log.DebugLevelMetrics, "collectAppPrometheusMetrics")

	// Get Pod CPU usage percentage
	resp, err := promutils.GetPromMetrics(ctx, promutils.PromQCpuPodUrlEncoded, client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			// skip system pods
			if metric.Labels.AppName == "" && metric.Labels.AppInstName == "" {
				continue
			}
			stat := getAppMetricFromPrometheusData(ctx, p, appStatsMap, &metric)
			stat.CpuTS = promutils.ParseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseFloat(metric.Values[1].(string), 64); err == nil {
				stat.Cpu = val
			}
		}
	}
	// Get Pod Mem usage
	resp, err = promutils.GetPromMetrics(ctx, promutils.PromQMemPodUrlEncoded, client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			// skip system pods
			if metric.Labels.AppName == "" && metric.Labels.AppInstName == "" {
				continue
			}
			stat := getAppMetricFromPrometheusData(ctx, p, appStatsMap, &metric)
			stat.MemTS = promutils.ParseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseUint(metric.Values[1].(string), 10, 64); err == nil {
				stat.Mem = val
			}
		}
	}
	// Get Pod Disk usage
	resp, err = promutils.GetPromMetrics(ctx, promutils.PromQDiskPodUrlEncoded, client)
	if err == nil && resp.Status == "success" {
		for _, metric := range resp.Data.Result {
			// skip system pods
			if metric.Labels.AppName == "" && metric.Labels.AppInstName == "" {
				continue
			}
			stat := getAppMetricFromPrometheusData(ctx, p, appStatsMap, &metric)
			stat.DiskTS = promutils.ParseTime(metric.Values[0].(float64))
			//copy only if we can parse the value
			if val, err := strconv.ParseUint(metric.Values[1].(string), 10, 64); err == nil {
				stat.Disk = val
			}
		}
	}
	return appStatsMap
}

func (p *K8sStats) collectClusterPrometheusMetrics(ctx context.Context, client promutils.PromClient) error {
	// Get Cluster CPU usage
	resp, err := promutils.GetPromMetrics(ctx, promutils.PromQCpuClustUrlEncoded, client)
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
	resp, err = promutils.GetPromMetrics(ctx, promutils.PromQMemClustUrlEncoded, client)
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
	resp, err = promutils.GetPromMetrics(ctx, promutils.PromQDiskClustUrlEncoded, client)
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
	resp, err = promutils.GetPromMetrics(ctx, promutils.PromQTcpConnClustUrlEncoded, client)
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
	resp, err = promutils.GetPromMetrics(ctx, promutils.PromQTcpRetransClustUrlEncoded, client)
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
	resp, err = promutils.GetPromMetrics(ctx, promutils.PromQUdpSentPktsClustUrlEncoded, client)
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
	resp, err = promutils.GetPromMetrics(ctx, promutils.PromQUdpRecvPktsClustUrlEncoded, client)
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
	resp, err = promutils.GetPromMetrics(ctx, promutils.PromQUdpRecvErrUrlEncoded, client)
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

func (p *K8sStats) collectClusterAutoScaleMetrics(ctx context.Context, client promutils.PromClient) error {
	// Get Stabilized max total worker node cpu utilization
	resp, err := promutils.GetPromMetrics(ctx, promutils.PromQAutoScaleCpuTotalUUrlEncoded, client)
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
	resp, err = promutils.GetPromMetrics(ctx, promutils.PromQAutoScaleMemTotalUUrlEncoded, client)
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
