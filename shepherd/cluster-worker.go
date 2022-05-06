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
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gogo/protobuf/types"
	"github.com/edgexr/edge-cloud-infra/shepherd/shepherd_common"
	platform "github.com/edgexr/edge-cloud-infra/shepherd/shepherd_platform"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

// For each cluster the notify worker is created
type ClusterWorker struct {
	clusterInstKey edgeproto.ClusterInstKey
	reservedBy     string
	deployment     string
	promAddr       string
	scrapeInterval time.Duration
	pushInterval   time.Duration
	lastPushedLock sync.Mutex
	lastPushed     time.Time
	clusterStat    shepherd_common.ClusterStats
	send           func(ctx context.Context, metric *edgeproto.Metric) bool
	waitGrp        sync.WaitGroup
	stop           chan struct{}
	client         ssh.Client
	autoScaler     ClusterAutoScaler
}

func NewClusterWorker(ctx context.Context, promAddr string, promPort int32, scrapeInterval time.Duration, pushInterval time.Duration, send func(ctx context.Context, metric *edgeproto.Metric) bool, clusterInst *edgeproto.ClusterInst, kubeNames *k8smgmt.KubeNames, pf platform.Platform) (*ClusterWorker, error) {
	var err error
	var nCores int
	p := ClusterWorker{}
	p.promAddr = promAddr
	p.deployment = clusterInst.Deployment
	p.send = send
	p.clusterInstKey = clusterInst.Key
	p.UpdateIntervals(ctx, scrapeInterval, pushInterval)
	if p.deployment == cloudcommon.DeploymentTypeKubernetes {
		p.autoScaler.policyName = clusterInst.AutoScalePolicy
	}
	p.client, err = pf.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeRootLB)
	if err != nil {
		// If we cannot get a platform client no point in trying to get metrics
		log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to acquire platform client", "cluster", clusterInst.Key, "error", err)
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelMetrics, "NewClusterWorker", "cluster", clusterInst.Key, "promAddr", promAddr, "promPort", promPort)
	// only support K8s deployments
	if p.deployment == cloudcommon.DeploymentTypeKubernetes {
		p.clusterStat = &K8sClusterStats{
			key:       p.clusterInstKey,
			client:    p.client,
			promAddr:  p.promAddr,
			promPort:  promPort,
			kubeNames: kubeNames,
		}
	} else if p.deployment == cloudcommon.DeploymentTypeDocker {
		clusterClient, err := pf.GetClusterPlatformClient(ctx, clusterInst, cloudcommon.ClientTypeClusterVM)
		if err != nil {
			// If we cannot get a platform client no point in trying to get metrics
			log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to acquire clusterVM client", "cluster", clusterInst.Key, "error", err)
			return nil, err
		}
		// cache the  number of cores on the docker node so we can use it in the future
		vmCores, err := clusterClient.Output("nproc")
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to run <nproc> on ClusterVM", "err", err.Error())
		} else {
			nCores, err = strconv.Atoi(strings.TrimSpace(vmCores))
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to parse <nproc> output", "output", vmCores, "err", err.Error())
			}
		}
		if nCores == 0 {
			nCores = 1
		}
		p.clusterStat = &DockerClusterStats{
			key:           p.clusterInstKey,
			client:        p.client,
			clusterClient: clusterClient,
			vCPUs:         nCores,
		}
	} else {
		return nil, fmt.Errorf("Unsupported deployment %s", clusterInst.Deployment)
	}
	if clusterInst.Reservable {
		p.reservedBy = clusterInst.ReservedBy
	}
	return &p, nil
}

func getClusterWorkerMapKey(key *edgeproto.ClusterInstKey) string {
	return k8smgmt.GetK8sNodeNameSuffix(key)
}

func getClusterWorkerAutoScaler(key *edgeproto.ClusterInstKey) *ClusterAutoScaler {
	workerMapMutex.Lock()
	defer workerMapMutex.Unlock()
	mapKey := getClusterWorkerMapKey(key)
	clusterWorker, found := workerMap[mapKey]
	if !found {
		return nil
	}
	return &clusterWorker.autoScaler
}

func (p *ClusterWorker) Start(ctx context.Context) {
	p.stop = make(chan struct{})
	p.waitGrp.Add(1)
	go p.RunNotify()
	log.SpanLog(ctx, log.DebugLevelMetrics, "Started ClusterWorker thread",
		"cluster", p.clusterInstKey)
}

func (p *ClusterWorker) Stop(ctx context.Context) {
	log.SpanLog(ctx, log.DebugLevelMetrics, "Stopping ClusterWorker thread",
		"cluster", p.clusterInstKey)
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

func (p *ClusterWorker) UpdateIntervals(ctx context.Context, scrapeInterval time.Duration, pushInterval time.Duration) {
	p.lastPushedLock.Lock()
	defer p.lastPushedLock.Unlock()
	p.pushInterval = pushInterval
	// scrape interval cannot be longer than push interval
	if scrapeInterval > pushInterval {
		p.scrapeInterval = p.pushInterval
	} else {
		p.scrapeInterval = scrapeInterval
	}
	// reset when we last pushed to allign scrape and push intervals
	p.lastPushed = time.Now()
}

func (p *ClusterWorker) checkAndSetLastPushMetrics(ts time.Time) bool {
	p.lastPushedLock.Lock()
	defer p.lastPushedLock.Unlock()
	lastPushedAddInterval := p.lastPushed.Add(p.pushInterval)
	if ts.After(lastPushedAddInterval) {
		// reset when we last pushed (time.Now() instead of ts for ease of testing)
		p.lastPushed = time.Now()
		return true
	}
	return false
}

func (p *ClusterWorker) RunNotify() {
	done := false
	for !done {
		select {
		case <-time.After(p.scrapeInterval):
			span := log.StartSpan(log.DebugLevelSampled, "send-metric")
			log.SetTags(span, p.clusterInstKey.GetTags())
			ctx := log.ContextWithSpan(context.Background(), span)
			statOps := []shepherd_common.StatsOp{}
			if p.autoScaler.policyName != "" {
				statOps = append(statOps, shepherd_common.WithAutoScaleStats())
			}
			clusterStats := p.clusterStat.GetClusterStats(ctx, statOps...)
			appStatsMap := p.clusterStat.GetAppStats(ctx)
			log.SpanLog(ctx, log.DebugLevelMetrics, "Collected cluster metrics",
				"cluster", p.clusterInstKey, "cluster stats", clusterStats)
			if p.autoScaler.policyName != "" {
				p.autoScaler.updateClusterStats(ctx, p.clusterInstKey, clusterStats)
			}

			// Marshaling and sending only every push interval
			if p.checkAndSetLastPushMetrics(time.Now()) {
				for key, stat := range appStatsMap {
					log.SpanLog(ctx, log.DebugLevelMetrics, "App metrics",
						"AppInst key", key, "stats", stat)
					appMetrics := MarshalAppMetrics(&key, stat, p.reservedBy)
					for _, metric := range appMetrics {
						p.send(context.Background(), metric)
					}
				}
				clusterMetrics := p.MarshalClusterMetrics(clusterStats)
				for _, metric := range clusterMetrics {
					p.send(context.Background(), metric)
				}
			}
			span.Finish()

			// create another span for alerts that is always logged
			aspan := log.StartSpan(log.DebugLevelMetrics, "alerts check")
			log.SetTags(aspan, p.clusterInstKey.GetTags())
			actx := log.ContextWithSpan(context.Background(), aspan)
			clusterAlerts := p.clusterStat.GetAlerts(actx)
			clusterAlerts = addClusterDetailsToAlerts(clusterAlerts, &p.clusterInstKey)
			UpdateAlerts(actx, clusterAlerts, &p.clusterInstKey, pruneClusterForeignAlerts)
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
	if key != nil {
		metric.AddStringVal("pod", key.Pod)
		metric.AddTag("app", key.App)
		metric.AddTag("ver", key.Version)
		//TODO: this should be changed when we have the actual app key
		if reservedBy != "" {
			metric.AddTag("apporg", reservedBy)
		} else {
			metric.AddTag("apporg", clusterInstKey.Organization)
		}
		metric.AddTag("clusterorg", clusterInstKey.Organization)
	} else {
		if reservedBy != "" {
			metric.AddTag("clusterorg", reservedBy)
		} else {
			metric.AddTag("clusterorg", clusterInstKey.Organization)
		}
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

	if cm.TcpConnsTS != nil && cm.TcpRetransTS != nil {
		metric = newMetric(p.clusterInstKey, p.reservedBy, "cluster-tcp", nil, cm.TcpConnsTS)
		metric.AddIntVal("tcpConns", cm.TcpConns)
		metric.AddIntVal("tcpRetrans", cm.TcpRetrans)
		metrics = append(metrics, metric)
	}
	cm.TcpConnsTS = nil
	cm.TcpRetransTS = nil

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

func MarshalAppMetrics(key *shepherd_common.MetricAppInstKey, stat *shepherd_common.AppMetrics, reservedBy string) []*edgeproto.Metric {
	var metrics []*edgeproto.Metric
	var metric *edgeproto.Metric

	// bail out if we get no metrics
	if stat == nil {
		return nil
	}

	if stat.CpuTS != nil {
		metric = newMetric(key.ClusterInstKey, reservedBy, "appinst-cpu", key, stat.CpuTS)
		metric.AddDoubleVal("cpu", stat.Cpu)
		metrics = append(metrics, metric)
		stat.CpuTS = nil
	}

	if stat.MemTS != nil {
		metric = newMetric(key.ClusterInstKey, reservedBy, "appinst-mem", key, stat.MemTS)
		metric.AddIntVal("mem", stat.Mem)
		metrics = append(metrics, metric)
		stat.MemTS = nil
	}

	if stat.DiskTS != nil {
		metric = newMetric(key.ClusterInstKey, reservedBy, "appinst-disk", key, stat.DiskTS)
		metric.AddIntVal("disk", stat.Disk)
		metrics = append(metrics, metric)
		stat.DiskTS = nil
	}

	return metrics
}
