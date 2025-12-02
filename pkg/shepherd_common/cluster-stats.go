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
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/gogo/protobuf/types"
)

// newMetric is called for both Cluster and App stats
func newMetric(clusterKey edgeproto.ClusterKey, cloudletKey edgeproto.CloudletKey, zoneKey edgeproto.ZoneKey, reservedBy string, name string, key *MetricAppInstKey, ts *types.Timestamp) *edgeproto.Metric {
	metric := edgeproto.Metric{}
	metric.Name = name
	metric.Timestamp = *ts
	cloudletKey.AddTagsByFunc(metric.AddTag)
	zoneKey.AddTagsByFunc(metric.AddTag)
	metric.AddTag(edgeproto.ClusterKeyTagName, clusterKey.Name)
	// TODO: general comment for the below XXX, perhaps we should have a
	// reservedby tag that would be better than overridding the other org tags.
	if key != nil {
		metric.AddStringVal("pod", key.Pod)
		metric.AddTag(edgeproto.AppInstKeyTagName, key.AppInstName)
		// XXX we know the appinst org, why are setting it to reservedBy
		// field (which, if set, should always equal the appinst org)?
		// XXX why do we set the appinst org to the cluster org?
		// those may be different orgs.
		if reservedBy != "" {
			metric.AddTag(edgeproto.AppInstKeyTagOrganization, reservedBy)
		} else {
			metric.AddTag(edgeproto.AppInstKeyTagOrganization, clusterKey.Organization)
		}
		metric.AddTag(edgeproto.ClusterKeyTagOrganization, clusterKey.Organization)
	} else {
		// XXX why do we override the clusterorg with the reservedBy field,
		// which is the appinst org?
		if reservedBy != "" {
			metric.AddTag(edgeproto.ClusterKeyTagOrganization, reservedBy)
		} else {
			metric.AddTag(edgeproto.ClusterKeyTagOrganization, clusterKey.Organization)
		}
	}
	return &metric
}

type MetricClusterKey struct {
	ClusterKey  edgeproto.ClusterKey
	CloudletKey edgeproto.CloudletKey
	ZoneKey     edgeproto.ZoneKey
	ReservedBy  string
}

func MarshalClusterMetrics(cm *ClusterMetrics, key MetricClusterKey) []*edgeproto.Metric {
	var metrics []*edgeproto.Metric
	var metric *edgeproto.Metric

	// bail out if we get no metrics
	if cm == nil {
		return nil
	}

	// nil timestamps mean the curl request failed. So do not write the metric in
	if cm.CpuTS != nil {
		metric = newMetric(key.ClusterKey, key.CloudletKey, key.ZoneKey, key.ReservedBy, "cluster-cpu", nil, cm.CpuTS)
		metric.AddDoubleVal("cpu", cm.Cpu)
		metrics = append(metrics, metric)
		//reset to nil for the next collection
		cm.CpuTS = nil
	}

	if cm.MemTS != nil {
		metric = newMetric(key.ClusterKey, key.CloudletKey, key.ZoneKey, key.ReservedBy, "cluster-mem", nil, cm.MemTS)
		metric.AddDoubleVal("mem", cm.Mem)
		metrics = append(metrics, metric)
		cm.MemTS = nil
	}

	if cm.DiskTS != nil {
		metric = newMetric(key.ClusterKey, key.CloudletKey, key.ZoneKey, key.ReservedBy, "cluster-disk", nil, cm.DiskTS)
		metric.AddDoubleVal("disk", cm.Disk)
		metrics = append(metrics, metric)
		cm.DiskTS = nil
	}

	if cm.TcpConnsTS != nil && cm.TcpRetransTS != nil {
		metric = newMetric(key.ClusterKey, key.CloudletKey, key.ZoneKey, key.ReservedBy, "cluster-tcp", nil, cm.TcpConnsTS)
		metric.AddIntVal("tcpConns", cm.TcpConns)
		metric.AddIntVal("tcpRetrans", cm.TcpRetrans)
		metrics = append(metrics, metric)
	}
	cm.TcpConnsTS = nil
	cm.TcpRetransTS = nil

	if cm.UdpSentTS != nil && cm.UdpRecvTS != nil && cm.UdpRecvErrTS != nil {
		metric = newMetric(key.ClusterKey, key.CloudletKey, key.ZoneKey, key.ReservedBy, "cluster-udp", nil, cm.UdpSentTS)
		metric.AddIntVal("udpSent", cm.UdpSent)
		metric.AddIntVal("udpRecv", cm.UdpRecv)
		metric.AddIntVal("udpRecvErr", cm.UdpRecvErr)
		metrics = append(metrics, metric)
	}
	cm.UdpSentTS = nil
	cm.UdpRecvTS = nil
	cm.UdpRecvErrTS = nil

	return metrics
}

func MarshalAppMetrics(key *MetricAppInstKey, stat *AppMetrics, reservedBy string, zoneKey edgeproto.ZoneKey) []*edgeproto.Metric {
	var metrics []*edgeproto.Metric
	var metric *edgeproto.Metric

	// bail out if we get no metrics
	if stat == nil {
		return nil
	}

	if stat.CpuTS != nil {
		metric = newMetric(key.ClusterKey, key.CloudletKey, zoneKey, reservedBy, "appinst-cpu", key, stat.CpuTS)
		metric.AddDoubleVal("cpu", stat.Cpu)
		metrics = append(metrics, metric)
		stat.CpuTS = nil
	}

	if stat.MemTS != nil {
		metric = newMetric(key.ClusterKey, key.CloudletKey, zoneKey, reservedBy, "appinst-mem", key, stat.MemTS)
		metric.AddIntVal("mem", stat.Mem)
		metrics = append(metrics, metric)
		stat.MemTS = nil
	}

	if stat.DiskTS != nil {
		metric = newMetric(key.ClusterKey, key.CloudletKey, zoneKey, reservedBy, "appinst-disk", key, stat.DiskTS)
		metric.AddIntVal("disk", stat.Disk)
		metrics = append(metrics, metric)
		stat.DiskTS = nil
	}

	return metrics
}

func AddClusterDetailsToAlerts(alerts []edgeproto.Alert, clusterKey *edgeproto.ClusterKey, cloudletKey *edgeproto.CloudletKey, zoneKey edgeproto.ZoneKey) []edgeproto.Alert {
	for ii := range alerts {
		alert := &alerts[ii]
		alert.Labels[edgeproto.ClusterKeyTagOrganization] = clusterKey.Organization
		alert.Labels[edgeproto.CloudletKeyTagOrganization] = cloudletKey.Organization
		alert.Labels[edgeproto.CloudletKeyTagName] = cloudletKey.Name
		alert.Labels[edgeproto.ClusterKeyTagName] = clusterKey.Name
		alert.Labels[edgeproto.ZoneKeyTagName] = zoneKey.Name
		alert.Labels[edgeproto.ZoneKeyTagOrganization] = zoneKey.Organization
	}
	return alerts
}
