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

package promutils

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"time"

	"github.com/gogo/protobuf/types"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

var ClusterPrometheusAppLabel = "label_" + cloudcommon.MexAppNameLabel
var ClusterPrometheusAppVersionLabel = "label_" + cloudcommon.MexAppVersionLabel

var PromLabelsAllMobiledgeXApps = `{` + ClusterPrometheusAppLabel + `!=""}`

const (
	PromQCpuClust           = `sum(rate(container_cpu_usage_seconds_total{id="/"}[1m]))/sum(machine_cpu_cores)*100`
	PromQMemClust           = `sum(container_memory_working_set_bytes{id="/"})/sum(machine_memory_bytes)*100`
	PromQDiskClust          = `sum(container_fs_usage_bytes{device=~"^/dev/[sv]d[a-z][1-9]$",id="/"})/sum(container_fs_limit_bytes{device=~"^/dev/[sv]d[a-z][1-9]$",id="/"})*100`
	PromQSentBytesRateClust = `sum(irate(container_network_transmit_bytes_total[1m]))`
	PromQRecvBytesRateClust = `sum(irate(container_network_receive_bytes_total[1m]))`
	PromQTcpConnClust       = "node_netstat_Tcp_CurrEstab"
	PromQTcpRetransClust    = "node_netstat_Tcp_RetransSegs"
	PromQUdpSentPktsClust   = "node_netstat_Udp_OutDatagrams"
	PromQUdpRecvPktsClust   = "node_netstat_Udp_InDatagrams"
	PromQUdpRecvErr         = "node_netstat_Udp_InErrors"

	PromQCloudletCpuTotal  = "sum(machine_cpu_cores)"
	PromQCloudletMemUse    = `sum(container_memory_working_set_bytes{id="/"})`
	PromQCloudletMemTotal  = "sum(machine_memory_bytes)"
	PromQCloudletDiskUse   = `sum(container_fs_usage_bytes{device=~"^/dev/[sv]d[a-z][1-9]$",id="/"})`
	PromQCloudletDiskTotal = `sum(container_fs_limit_bytes{device=~"^/dev/[sv]d[a-z][1-9]$",id="/"})`

	// This is a template which takes a pod query and adds instance label to it
	PromQAppLabelsWrapperFmt = "max(kube_pod_labels%s)by(label_mexAppName,label_mexAppVersion,pod)*on(pod)group_right(label_mexAppName,label_mexAppVersion)(%s)"

	PromQCpuPod         = `sum(rate(container_cpu_usage_seconds_total{image!=""}[1m])) by (pod) / ignoring (pod) group_left sum(machine_cpu_cores) * 100 `
	PromQMemPod         = `sum(container_memory_working_set_bytes{image!=""})by(pod)`
	PromQMemPercentPod  = `sum(container_memory_working_set_bytes{image!=""})by(pod) / ignoring (pod) group_left sum( machine_memory_bytes{}) * 100`
	PromQDiskPod        = `sum(container_fs_usage_bytes{image!=""})by(pod)`
	PromQDiskPercentPod = `sum(container_fs_usage_bytes{image!=""})by(pod) / ignoring (pod) group_left sum(container_fs_limit_bytes{device=~"^/dev/[sv]d[a-z][1-9]$",id="/"})*100`
	PromQNetRecvRate    = `sum(irate(container_network_receive_bytes_total{image!=""}[1m]))by(pod)`
	PromQNetSentRate    = `sum(irate(container_network_transmit_bytes_total{image!=""}[1m]))by(pod)`

	PromQAutoScaleCpuTotalU = "stabilized_max_total_worker_node_cpu_utilisation"
	PromQAutoScaleMemTotalU = "stabilized_max_total_worker_node_mem_utilisation"

	PromQConnections = "envoy_cluster_upstream_cx_active"
)

// Url-encoded strings, so we don't have to encode them every time
var (
	PromQCpuClustUrlEncoded           = url.QueryEscape(PromQCpuClust)
	PromQMemClustUrlEncoded           = url.QueryEscape(PromQMemClust)
	PromQDiskClustUrlEncoded          = url.QueryEscape(PromQDiskClust)
	PromQSentBytesRateClustUrlEncoded = url.QueryEscape(PromQSentBytesRateClust)
	PromQRecvBytesRateClustUrlEncoded = url.QueryEscape(PromQRecvBytesRateClust)
	PromQTcpConnClustUrlEncoded       = url.QueryEscape(PromQTcpConnClust)
	PromQTcpRetransClustUrlEncoded    = url.QueryEscape(PromQTcpRetransClust)
	PromQUdpSentPktsClustUrlEncoded   = url.QueryEscape(PromQUdpSentPktsClust)
	PromQUdpRecvPktsClustUrlEncoded   = url.QueryEscape(PromQUdpRecvPktsClust)
	PromQUdpRecvErrUrlEncoded         = url.QueryEscape(PromQUdpRecvErr)

	// For bare metal k8s CloudletMetrics
	PromQCloudletCpuTotalEncoded  = url.QueryEscape(PromQCloudletCpuTotal)
	PromQCloudletMemUseEncoded    = url.QueryEscape(PromQCloudletMemUse)
	PromQCloudletMemTotalEncoded  = url.QueryEscape(PromQCloudletMemTotal)
	PromQCloudletDiskUseEncoded   = url.QueryEscape(PromQCloudletDiskUse)
	PromQCloudletDiskTotalEncoded = url.QueryEscape(PromQCloudletDiskTotal)

	// For Pod metrics we need to join them with k8s pod labels
	PromQCpuPodUrlEncoded         = url.QueryEscape(GetPromQueryWithK8sLabels(PromLabelsAllMobiledgeXApps, PromQCpuPod))
	PromQMemPodUrlEncoded         = url.QueryEscape(GetPromQueryWithK8sLabels(PromLabelsAllMobiledgeXApps, PromQMemPod))
	PromQMemPercentPodUrlEncoded  = url.QueryEscape(GetPromQueryWithK8sLabels(PromLabelsAllMobiledgeXApps, PromQMemPercentPod))
	PromQDiskPodUrlEncoded        = url.QueryEscape(GetPromQueryWithK8sLabels(PromLabelsAllMobiledgeXApps, PromQDiskPod))
	PromQDiskPercentPodUrlEncoded = url.QueryEscape(GetPromQueryWithK8sLabels(PromLabelsAllMobiledgeXApps, PromQDiskPercentPod))
	PromQNetRecvRateUrlEncoded    = url.QueryEscape(GetPromQueryWithK8sLabels(PromLabelsAllMobiledgeXApps, PromQNetRecvRate))
	PromQNetSentRateUrlEncoded    = url.QueryEscape(GetPromQueryWithK8sLabels(PromLabelsAllMobiledgeXApps, PromQNetSentRate))

	PromQAutoScaleCpuTotalUUrlEncoded = url.QueryEscape(PromQAutoScaleCpuTotalU)
	PromQAutoScaleMemTotalUUrlEncoded = url.QueryEscape(PromQAutoScaleMemTotalU)
)

type PromResp struct {
	Status string   `json:"status,omitempty"`
	Data   PromData `json:"data,omitempty"`
}
type PromData struct {
	ResType string       `json:"resultType,omitempty"`
	Result  []PromMetric `json:"result,omitempty"`
}
type PromMetric struct {
	Labels PromLabels    `json:"metric,omitempty"`
	Values []interface{} `json:"value,omitempty"`
}
type PromLabels struct {
	PodName string `json:"pod,omitempty"`
	App     string `json:"label_mexAppName,omitempty"`
	Version string `json:"label_mexAppVersion,omitempty"`
}
type PromAlert struct {
	Labels      map[string]string
	Annotations map[string]string
	State       string
	ActiveAt    *time.Time `json:"activeAt,omitempty"`
	Value       PromAlertValue
}

// Prometheus Alert Value may be a string or a numeric, depending on
// the version of the prometheus operator used. Handle either.
type PromAlertValue float64

func (s PromAlertValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(float64(s))
}

func (s *PromAlertValue) UnmarshalJSON(b []byte) error {
	var val float64
	err := json.Unmarshal(b, &val)
	if err == nil {
		*s = PromAlertValue(val)
		return nil
	}
	var str string
	err = json.Unmarshal(b, &str)
	if err == nil {
		val, err = strconv.ParseFloat(str, 64)
		if err == nil {
			*s = PromAlertValue(val)
			return nil
		}
		return err
	}
	return err
}

// Takes a float64 representation of a time(in sec) given to use by prometheus
// and turns it into a type.Timestamp format for writing into influxDB
func ParseTime(timeFloat float64) *types.Timestamp {
	sec, dec := math.Modf(timeFloat)
	time := time.Unix(int64(sec), int64(dec*(1e9)))
	ts, _ := types.TimestampProto(time)
	return ts
}

// Returns a prometheus pod-based query joined with k8s labels series
// Function also takes an optional label filter string of form "{label1="val1",label2="val2",..}"
func GetPromQueryWithK8sLabels(labelFilter, podQuery string) string {
	return fmt.Sprintf(PromQAppLabelsWrapperFmt, labelFilter, podQuery)
}

func GetPromMetrics(ctx context.Context, addr string, query string, client ssh.Client) (*PromResp, error) {
	reqURI := "'http://" + addr + "/api/v1/query?query=" + query + "'"
	resp, err := client.Output("curl -s -S " + reqURI)
	if err != nil {
		log.ForceLogSpan(log.SpanFromContext(ctx))
		log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to get prom metrics", "reqURI", reqURI, "err", err, "resp", resp)
		return nil, err
	}
	PromResp := &PromResp{}
	if err = json.Unmarshal([]byte(resp), PromResp); err != nil {
		return nil, err
	}
	return PromResp, nil
}
