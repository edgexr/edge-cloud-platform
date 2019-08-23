package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/gogo/protobuf/types"
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
	clusterStat    ClusterStats
	send           func(ctx context.Context, metric *edgeproto.Metric) bool
	waitGrp        sync.WaitGroup
	stop           chan struct{}
	client         pc.PlatformClient
}

func NewClusterWorker(promAddr string, interval time.Duration, send func(ctx context.Context, metric *edgeproto.Metric) bool, clusterInst *edgeproto.ClusterInst, pf platform.Platform) (*ClusterWorker, error) {
	var err error
	p := ClusterWorker{}
	p.promAddr = promAddr
	p.deployment = clusterInst.Deployment
	p.interval = interval
	p.send = send
	p.clusterInstKey = clusterInst.Key
	p.client, err = pf.GetPlatformClient(clusterInst)
	if err != nil {
		// If we cannot get a platform client no point in trying to get metrics
		log.DebugLog(log.DebugLevelMetrics, "Failed to acquire platform client", "cluster", clusterInst.Key, "error", err)
		return nil, err
	}
	// only support K8s deployments
	if p.deployment == cloudcommon.AppDeploymentTypeKubernetes {
		p.clusterStat = &K8sClusterStats{
			key:      p.clusterInstKey,
			client:   p.client,
			promAddr: p.promAddr,
		}
	} else {
		return nil, fmt.Errorf("Unsupported deployment %s", clusterInst.Deployment)
	}

	return &p, nil
}

func (p *ClusterWorker) Start() {
	p.stop = make(chan struct{})
	p.waitGrp.Add(1)
	go p.RunNotify()
}

func (p *ClusterWorker) Stop() {
	log.DebugLog(log.DebugLevelMetrics, "Stopping ClusterWorker thread\n")
	close(p.stop)
	p.waitGrp.Wait()
}

func (p *ClusterWorker) RunNotify() {
	log.DebugLog(log.DebugLevelMetrics, "Started ClusterWorker thread\n")
	done := false
	for !done {
		select {
		case <-time.After(p.interval):
			clusterStats := p.clusterStat.GetClusterStats()
			appStatsMap := p.clusterStat.GetAppStats()
			span := log.StartSpan(log.DebugLevelSampled, "send-metric")
			span.SetTag("operator", p.clusterInstKey.CloudletKey.OperatorKey.Name)
			span.SetTag("cloudlet", p.clusterInstKey.CloudletKey.Name)
			span.SetTag("cluster", p.clusterInstKey.ClusterKey.Name)
			ctx := log.ContextWithSpan(context.Background(), span)

			for key, stat := range appStatsMap {
				appMetrics := MarshalAppMetrics(&key, stat)
				for _, metric := range appMetrics {
					p.send(ctx, metric)
				}
			}
			clusterMetrics := MarshalClusterMetrics(clusterStats, p.clusterInstKey)
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

func newMetric(clusterInstKey edgeproto.ClusterInstKey, name string, key *MetricAppInstKey, ts *types.Timestamp) *edgeproto.Metric {
	metric := edgeproto.Metric{}
	metric.Name = name
	metric.Timestamp = *ts
	metric.AddTag("operator", clusterInstKey.CloudletKey.OperatorKey.Name)
	metric.AddTag("cloudlet", clusterInstKey.CloudletKey.Name)
	metric.AddTag("cluster", clusterInstKey.ClusterKey.Name)
	metric.AddTag("dev", clusterInstKey.Developer)
	if key != nil {
		metric.AddTag("app", key.pod)
	}
	return &metric
}

func MarshalClusterMetrics(cm *ClusterMetrics, key edgeproto.ClusterInstKey) []*edgeproto.Metric {
	var metrics []*edgeproto.Metric
	var metric *edgeproto.Metric

	//nil timestamps mean the curl request failed. So do not write the metric in
	if cm.cpuTS != nil {
		metric = newMetric(key, "cluster-cpu", nil, cm.cpuTS)
		metric.AddDoubleVal("cpu", cm.cpu)
		metrics = append(metrics, metric)
		//reset to nil for the next collection
		cm.cpuTS = nil
	}

	if cm.memTS != nil {
		metric = newMetric(key, "cluster-mem", nil, cm.memTS)
		metric.AddDoubleVal("mem", cm.mem)
		metrics = append(metrics, metric)
		cm.memTS = nil
	}

	if cm.diskTS != nil {
		metric = newMetric(key, "cluster-disk", nil, cm.diskTS)
		metric.AddDoubleVal("disk", cm.disk)
		metrics = append(metrics, metric)
		cm.diskTS = nil
	}

	if cm.netSendTS != nil && cm.netRecvTS != nil {
		//for measurements with multiple values just pick one timestamp to use
		metric = newMetric(key, "cluster-network", nil, cm.netSendTS)
		metric.AddIntVal("sendBytes", cm.netSend)
		metric.AddIntVal("recvBytes", cm.netRecv)
		metrics = append(metrics, metric)
	}
	cm.netSendTS = nil
	cm.netRecvTS = nil

	if cm.tcpConnsTS != nil && cm.tcpRetransTS != nil {
		metric = newMetric(key, "cluster-tcp", nil, cm.tcpConnsTS)
		metric.AddIntVal("tcpConns", cm.tcpConns)
		metric.AddIntVal("tcpRetrans", cm.tcpRetrans)
		metrics = append(metrics, metric)
	}
	cm.netSendTS = nil
	cm.netRecvTS = nil

	if cm.udpSendTS != nil && cm.udpRecvTS != nil && cm.udpRecvErrTS != nil {
		metric = newMetric(key, "cluster-udp", nil, cm.udpSendTS)
		metric.AddIntVal("udpSend", cm.udpSend)
		metric.AddIntVal("udpRecv", cm.udpRecv)
		metric.AddIntVal("udpRecvErr", cm.udpRecvErr)
		metrics = append(metrics, metric)
	}
	cm.udpSendTS = nil
	cm.udpRecvTS = nil
	cm.udpRecvErrTS = nil

	return metrics
}

func MarshalAppMetrics(key *MetricAppInstKey, stat *AppMetrics) []*edgeproto.Metric {
	var metrics []*edgeproto.Metric
	var metric *edgeproto.Metric

	if stat.cpuTS != nil {
		metric = newMetric(key.clusterInstKey, "appinst-cpu", key, stat.cpuTS)
		metric.AddDoubleVal("cpu", stat.cpu)
		metrics = append(metrics, metric)
		stat.cpuTS = nil
	}

	if stat.memTS != nil {
		metric = newMetric(key.clusterInstKey, "appinst-mem", key, stat.memTS)
		metric.AddIntVal("mem", stat.mem)
		metrics = append(metrics, metric)
		stat.memTS = nil
	}

	if stat.diskTS != nil {
		metric = newMetric(key.clusterInstKey, "appinst-disk", key, stat.diskTS)
		metric.AddIntVal("disk", stat.disk)
		metrics = append(metrics, metric)
		stat.diskTS = nil
	}

	if stat.netSendTS != nil && stat.netRecvTS != nil {
		//for measurements with multiple values just pick one timestamp to use
		metric = newMetric(key.clusterInstKey, "appinst-network", key, stat.netSendTS)
		metric.AddIntVal("sendBytes", stat.netSend)
		metric.AddIntVal("recvBytes", stat.netRecv)
		metrics = append(metrics, metric)
	}
	stat.netSendTS = nil
	stat.netRecvTS = nil

	return metrics
}
