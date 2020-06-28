package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/gogo/protobuf/types"
	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_common"
	platform "github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_platform"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

// For each cluster the notify worker is created
type ClusterWorker struct {
	clusterInstKey edgeproto.ClusterInstKey
	reservedBy     string
	deployment     string
	promAddr       string
	interval       time.Duration
	clusterStat    shepherd_common.ClusterStats
	send           func(ctx context.Context, metric *edgeproto.Metric) bool
	waitGrp        sync.WaitGroup
	stop           chan struct{}
	client         ssh.Client
}

func NewClusterWorker(ctx context.Context, promAddr string, interval time.Duration, send func(ctx context.Context, metric *edgeproto.Metric) bool, clusterInst *edgeproto.ClusterInst, pf platform.Platform) (*ClusterWorker, error) {
	var err error
	p := ClusterWorker{}
	p.promAddr = promAddr
	p.deployment = clusterInst.Deployment
	p.interval = interval
	p.send = send
	p.clusterInstKey = clusterInst.Key
	p.client, err = pf.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		// If we cannot get a platform client no point in trying to get metrics
		log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to acquire platform client", "cluster", clusterInst.Key, "error", err)
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelMetrics, "NewClusterWorker", "cluster", clusterInst.Key, "promAddr", promAddr)
	// only support K8s deployments
	if p.deployment == cloudcommon.DeploymentTypeKubernetes {
		p.clusterStat = &K8sClusterStats{
			key:      p.clusterInstKey,
			client:   p.client,
			promAddr: p.promAddr,
		}
	} else if p.deployment == cloudcommon.DeploymentTypeDocker {
		clusterClient, err := pf.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeClusterVM)
		if err != nil {
			// If we cannot get a platform client no point in trying to get metrics
			log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to acquire clusterVM client", "cluster", clusterInst.Key, "error", err)
			return nil, err
		}
		p.clusterStat = &DockerClusterStats{
			key:           p.clusterInstKey,
			client:        p.client,
			clusterClient: clusterClient,
		}
	} else {
		return nil, fmt.Errorf("Unsupported deployment %s", clusterInst.Deployment)
	}
	if clusterInst.Reservable {
		p.reservedBy = clusterInst.ReservedBy
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
	// For dedicated clusters try to clean up ssh client cache
	cluster := edgeproto.ClusterInst{}
	found := ClusterInstCache.Get(&p.clusterInstKey, &cluster)
	if found && cluster.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		p.client.StopPersistentConn()
	}
	p.waitGrp.Wait()
	flushAlerts(ctx, &p.clusterInstKey)
}

func (p *ClusterWorker) RunNotify() {
	done := false
	for !done {
		select {
		case <-time.After(p.interval):
			span := log.StartSpan(log.DebugLevelSampled, "send-metric")
			log.SetTags(span, p.clusterInstKey.GetTags())
			ctx := log.ContextWithSpan(context.Background(), span)
			clusterStats := p.clusterStat.GetClusterStats(ctx)
			appStatsMap := p.clusterStat.GetAppStats(ctx)

			// create another span for alerts that is always logged
			aspan := log.StartSpan(log.DebugLevelMetrics, "alerts check")
			log.SetTags(aspan, p.clusterInstKey.GetTags())
			actx := log.ContextWithSpan(context.Background(), aspan)

			for key, stat := range appStatsMap {
				appMetrics := MarshalAppMetrics(&key, stat)
				for _, metric := range appMetrics {
					p.send(ctx, metric)
				}
			}
			clusterMetrics := p.MarshalClusterMetrics(clusterStats)
			for _, metric := range clusterMetrics {
				p.send(ctx, metric)
			}

			clusterAlerts := p.clusterStat.GetAlerts(actx)
			clusterAlerts = addClusterDetailsToAlerts(clusterAlerts, &p.clusterInstKey)
			UpdateAlerts(actx, clusterAlerts, &p.clusterInstKey, pruneClusterForeignAlerts)
			span.Finish()
			aspan.Finish()
		case <-p.stop:
			done = true
		}
	}
	p.waitGrp.Done()
}

// newMetric is called for both Cluster and App stats
func newMetric(clusterInstKey edgeproto.ClusterInstKey, reservedBy string, name string, key *shepherd_common.MetricAppInstKey, ts *types.Timestamp) *edgeproto.Metric {
	metric := edgeproto.Metric{}
	metric.Name = name
	metric.Timestamp = *ts
	metric.AddTag("cloudletorg", clusterInstKey.CloudletKey.Organization)
	metric.AddTag("cloudlet", clusterInstKey.CloudletKey.Name)
	metric.AddTag("cluster", clusterInstKey.ClusterKey.Name)
	if reservedBy != "" {
		metric.AddTag("clusterorg", reservedBy)
	} else {
		metric.AddTag("clusterorg", clusterInstKey.Organization)
	}
	if key != nil {
		metric.AddTag("pod", key.Pod)
		metric.AddTag("app", key.App)
		metric.AddTag("ver", key.Version)
		//TODO: this should be changed when we have the actual app key
		metric.AddTag("apporg", key.ClusterInstKey.Organization)
	}
	return &metric
}

func (p *ClusterWorker) MarshalClusterMetrics(cm *shepherd_common.ClusterMetrics) []*edgeproto.Metric {
	var metrics []*edgeproto.Metric
	var metric *edgeproto.Metric

	// bail out if we get no metrics
	if cm == nil {
		return nil
	}

	// nil timestamps mean the curl request failed. So do not write the metric in
	if cm.CpuTS != nil {
		metric = newMetric(p.clusterInstKey, p.reservedBy, "cluster-cpu", nil, cm.CpuTS)
		metric.AddDoubleVal("cpu", cm.Cpu)
		metrics = append(metrics, metric)
		//reset to nil for the next collection
		cm.CpuTS = nil
	}

	if cm.MemTS != nil {
		metric = newMetric(p.clusterInstKey, p.reservedBy, "cluster-mem", nil, cm.MemTS)
		metric.AddDoubleVal("mem", cm.Mem)
		metrics = append(metrics, metric)
		cm.MemTS = nil
	}

	if cm.DiskTS != nil {
		metric = newMetric(p.clusterInstKey, p.reservedBy, "cluster-disk", nil, cm.DiskTS)
		metric.AddDoubleVal("disk", cm.Disk)
		metrics = append(metrics, metric)
		cm.DiskTS = nil
	}

	if cm.NetSentTS != nil && cm.NetRecvTS != nil {
		//for measurements with multiple values just pick one timestamp to use
		metric = newMetric(p.clusterInstKey, p.reservedBy, "cluster-network", nil, cm.NetSentTS)
		metric.AddIntVal("sendBytes", cm.NetSent)
		metric.AddIntVal("recvBytes", cm.NetRecv)
		metrics = append(metrics, metric)
	}
	cm.NetSentTS = nil
	cm.NetRecvTS = nil

	if cm.TcpConnsTS != nil && cm.TcpRetransTS != nil {
		metric = newMetric(p.clusterInstKey, p.reservedBy, "cluster-tcp", nil, cm.TcpConnsTS)
		metric.AddIntVal("tcpConns", cm.TcpConns)
		metric.AddIntVal("tcpRetrans", cm.TcpRetrans)
		metrics = append(metrics, metric)
	}
	cm.NetSentTS = nil
	cm.NetRecvTS = nil

	if cm.UdpSentTS != nil && cm.UdpRecvTS != nil && cm.UdpRecvErrTS != nil {
		metric = newMetric(p.clusterInstKey, p.reservedBy, "cluster-udp", nil, cm.UdpSentTS)
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
		metric = newMetric(key.ClusterInstKey, "", "appinst-cpu", key, stat.CpuTS)
		metric.AddDoubleVal("cpu", stat.Cpu)
		metrics = append(metrics, metric)
		stat.CpuTS = nil
	}

	if stat.MemTS != nil {
		metric = newMetric(key.ClusterInstKey, "", "appinst-mem", key, stat.MemTS)
		metric.AddIntVal("mem", stat.Mem)
		metrics = append(metrics, metric)
		stat.MemTS = nil
	}

	if stat.DiskTS != nil {
		metric = newMetric(key.ClusterInstKey, "", "appinst-disk", key, stat.DiskTS)
		metric.AddIntVal("disk", stat.Disk)
		metrics = append(metrics, metric)
		stat.DiskTS = nil
	}

	if stat.NetSentTS != nil && stat.NetRecvTS != nil {
		//for measurements with multiple values just pick one timestamp to use
		metric = newMetric(key.ClusterInstKey, "", "appinst-network", key, stat.NetSentTS)
		metric.AddIntVal("sendBytes", stat.NetSent)
		metric.AddIntVal("recvBytes", stat.NetRecv)
		metrics = append(metrics, metric)
	}
	stat.NetSentTS = nil
	stat.NetRecvTS = nil

	return metrics
}
