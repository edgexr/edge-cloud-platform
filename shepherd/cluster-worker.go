package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/gogo/protobuf/types"
	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_common"
	platform "github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_platform"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

// For each cluster the notify worker is created
type ClusterWorker struct {
	clusterInstKey edgeproto.ClusterInstKey
	deployment     string
	promAddr       string
	interval       time.Duration
	clusterStat    shepherd_common.ClusterStats
	send           func(ctx context.Context, metric *edgeproto.Metric) bool
	waitGrp        sync.WaitGroup
	stop           chan struct{}
	client         pc.PlatformClient
}

func NewClusterWorker(ctx context.Context, promAddr string, interval time.Duration, send func(ctx context.Context, metric *edgeproto.Metric) bool, clusterInst *edgeproto.ClusterInst, pf platform.Platform) (*ClusterWorker, error) {
	var err error
	p := ClusterWorker{}
	p.promAddr = promAddr
	p.deployment = clusterInst.Deployment
	p.interval = interval
	p.send = send
	p.clusterInstKey = clusterInst.Key
	p.client, err = pf.GetPlatformClient(ctx, clusterInst)
	if err != nil {
		// If we cannot get a platform client no point in trying to get metrics
		log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to acquire platform client", "cluster", clusterInst.Key, "error", err)
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelMetrics, "NewClusterWorker", "cluster", clusterInst.Key, "promAddr", promAddr)
	// only support K8s deployments
	if p.deployment == cloudcommon.AppDeploymentTypeKubernetes {
		p.clusterStat = &K8sClusterStats{
			key:      p.clusterInstKey,
			client:   p.client,
			promAddr: p.promAddr,
		}
	} else if p.deployment == cloudcommon.AppDeploymentTypeDocker {
		p.clusterStat = &DockerClusterStats{
			key:    p.clusterInstKey,
			client: p.client,
		}
	} else {
		return nil, fmt.Errorf("Unsupported deployment %s", clusterInst.Deployment)
	}

	return &p, nil
}

func (p *ClusterWorker) Start(ctx context.Context) {
	p.stop = make(chan struct{})
	p.waitGrp.Add(1)
	go p.RunNotify()
	log.SpanLog(ctx, log.DebugLevelMetrics, "Started ClusterWorker thread\n")
}

func (p *ClusterWorker) Stop(ctx context.Context) {
	log.SpanLog(ctx, log.DebugLevelMetrics, "Stopping ClusterWorker thread\n")
	close(p.stop)
	p.waitGrp.Wait()
}

func (p *ClusterWorker) RunNotify() {
	done := false
	for !done {
		select {
		case <-time.After(p.interval):
			span := log.StartSpan(log.DebugLevelSampled, "send-metric")
			span.SetTag("operator", p.clusterInstKey.CloudletKey.OperatorKey.Name)
			span.SetTag("cloudlet", p.clusterInstKey.CloudletKey.Name)
			span.SetTag("cluster", p.clusterInstKey.ClusterKey.Name)
			ctx := log.ContextWithSpan(context.Background(), span)
			clusterStats := p.clusterStat.GetClusterStats(ctx)
			appStatsMap := p.clusterStat.GetAppStats(ctx)

			for key, stat := range appStatsMap {
				appMetrics := MarshalAppMetrics(&key, stat)
				for _, metric := range appMetrics {
					p.send(ctx, metric)
				}
			}
			clusterMetrics := MarshalClusterMetrics(p.clusterInstKey, clusterStats)
			for _, metric := range clusterMetrics {
				p.send(ctx, metric)
			}
			span.Finish()
		case <-p.stop:
			done = true
		}
	}
	p.waitGrp.Done()
}

func newMetric(clusterInstKey edgeproto.ClusterInstKey, name string, key *shepherd_common.MetricAppInstKey, ts *types.Timestamp) *edgeproto.Metric {
	metric := edgeproto.Metric{}
	metric.Name = name
	metric.Timestamp = *ts
	metric.AddTag("operator", clusterInstKey.CloudletKey.OperatorKey.Name)
	metric.AddTag("cloudlet", clusterInstKey.CloudletKey.Name)
	metric.AddTag("cluster", clusterInstKey.ClusterKey.Name)
	metric.AddTag("dev", clusterInstKey.Developer)
	if key != nil {
		metric.AddTag("app", key.Pod)
	}
	return &metric
}

func MarshalClusterMetrics(key edgeproto.ClusterInstKey, cm *shepherd_common.ClusterMetrics) []*edgeproto.Metric {
	var metrics []*edgeproto.Metric
	var metric *edgeproto.Metric

	// bail out if we get no metrics
	if cm == nil {
		return nil
	}

	//nil timestamps mean the curl request failed. So do not write the metric in
	if cm.CpuTS != nil {
		metric = newMetric(key, "cluster-cpu", nil, cm.CpuTS)
		metric.AddDoubleVal("cpu", cm.Cpu)
		metrics = append(metrics, metric)
		//reset to nil for the next collection
		cm.CpuTS = nil
	}

	if cm.MemTS != nil {
		metric = newMetric(key, "cluster-mem", nil, cm.MemTS)
		metric.AddDoubleVal("mem", cm.Mem)
		metrics = append(metrics, metric)
		cm.MemTS = nil
	}

	if cm.DiskTS != nil {
		metric = newMetric(key, "cluster-disk", nil, cm.DiskTS)
		metric.AddDoubleVal("disk", cm.Disk)
		metrics = append(metrics, metric)
		cm.DiskTS = nil
	}

	if cm.NetSentTS != nil && cm.NetRecvTS != nil {
		//for measurements with multiple values just pick one timestamp to use
		metric = newMetric(key, "cluster-network", nil, cm.NetSentTS)
		metric.AddIntVal("sendBytes", cm.NetSent)
		metric.AddIntVal("recvBytes", cm.NetRecv)
		metrics = append(metrics, metric)
	}
	cm.NetSentTS = nil
	cm.NetRecvTS = nil

	if cm.TcpConnsTS != nil && cm.TcpRetransTS != nil {
		metric = newMetric(key, "cluster-tcp", nil, cm.TcpConnsTS)
		metric.AddIntVal("tcpConns", cm.TcpConns)
		metric.AddIntVal("tcpRetrans", cm.TcpRetrans)
		metrics = append(metrics, metric)
	}
	cm.NetSentTS = nil
	cm.NetRecvTS = nil

	if cm.UdpSentTS != nil && cm.UdpRecvTS != nil && cm.UdpRecvErrTS != nil {
		metric = newMetric(key, "cluster-udp", nil, cm.UdpSentTS)
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

func MarshalAppMetrics(key *shepherd_common.MetricAppInstKey, stat *shepherd_common.AppMetrics) []*edgeproto.Metric {
	var metrics []*edgeproto.Metric
	var metric *edgeproto.Metric

	// bail out if we get no metrics
	if stat == nil {
		return nil
	}

	if stat.CpuTS != nil {
		metric = newMetric(key.ClusterInstKey, "appinst-cpu", key, stat.CpuTS)
		metric.AddDoubleVal("cpu", stat.Cpu)
		metrics = append(metrics, metric)
		stat.CpuTS = nil
	}

	if stat.MemTS != nil {
		metric = newMetric(key.ClusterInstKey, "appinst-mem", key, stat.MemTS)
		metric.AddIntVal("mem", stat.Mem)
		metrics = append(metrics, metric)
		stat.MemTS = nil
	}

	if stat.DiskTS != nil {
		metric = newMetric(key.ClusterInstKey, "appinst-disk", key, stat.DiskTS)
		metric.AddIntVal("disk", stat.Disk)
		metrics = append(metrics, metric)
		stat.DiskTS = nil
	}

	if stat.NetSentTS != nil && stat.NetRecvTS != nil {
		//for measurements with multiple values just pick one timestamp to use
		metric = newMetric(key.ClusterInstKey, "appinst-network", key, stat.NetSentTS)
		metric.AddIntVal("sendBytes", stat.NetSent)
		metric.AddIntVal("recvBytes", stat.NetRecv)
		metrics = append(metrics, metric)
	}
	stat.NetSentTS = nil
	stat.NetRecvTS = nil

	return metrics
}
