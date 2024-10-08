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

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/shepherd_common"
	platform "github.com/edgexr/edge-cloud-platform/pkg/shepherd_platform"
	ssh "github.com/edgexr/golang-ssh"
	"github.com/gogo/protobuf/types"
)

// For each cluster the notify worker is created
type ClusterWorker struct {
	clusterKey     edgeproto.ClusterKey
	cloudletKey    edgeproto.CloudletKey
	zoneKey        edgeproto.ZoneKey
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
	p.clusterKey = clusterInst.Key
	p.cloudletKey = clusterInst.CloudletKey
	p.zoneKey = clusterInst.ZoneKey
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
			key:         p.clusterKey,
			cloudletKey: p.cloudletKey,
			client:      p.client,
			promAddr:    p.promAddr,
			promPort:    promPort,
			kubeNames:   kubeNames,
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
			key:           p.clusterKey,
			cloudletKey:   p.cloudletKey,
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

func getClusterWorkerAutoScaler(key *edgeproto.ClusterKey) *ClusterAutoScaler {
	workerMapMutex.Lock()
	defer workerMapMutex.Unlock()
	clusterWorker, found := workerMap[*key]
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
		"cluster", p.clusterKey)
}

func (p *ClusterWorker) Stop(ctx context.Context) {
	log.SpanLog(ctx, log.DebugLevelMetrics, "Stopping ClusterWorker thread",
		"cluster", p.clusterKey)
	close(p.stop)
	// For dedicated clusters try to clean up ssh client cache
	cluster := edgeproto.ClusterInst{}
	found := ClusterInstCache.Get(&p.clusterKey, &cluster)
	if found && cluster.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		p.client.StopPersistentConn()
	}
	p.waitGrp.Wait()
	flushAlerts(ctx, &p.clusterKey)
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
			log.SetTags(span, p.clusterKey.GetTags())
			ctx := log.ContextWithSpan(context.Background(), span)
			statOps := []shepherd_common.StatsOp{}
			if p.autoScaler.policyName != "" {
				statOps = append(statOps, shepherd_common.WithAutoScaleStats())
			}
			clusterStats := p.clusterStat.GetClusterStats(ctx, statOps...)
			appStatsMap := p.clusterStat.GetAppStats(ctx)
			log.SpanLog(ctx, log.DebugLevelMetrics, "Collected cluster metrics",
				"cluster", p.clusterKey, "cluster stats", clusterStats)
			if p.autoScaler.policyName != "" {
				p.autoScaler.updateClusterStats(ctx, p.clusterKey, clusterStats)
			}
			zoneKey := edgeproto.ZoneKey{}
			cloudlet := edgeproto.Cloudlet{}
			if CloudletCache.Get(&cloudletKey, &cloudlet) {
				// zonekey may change dynamically for the cloudlet
				zoneKey = *cloudlet.GetZone()
			}
			// Marshaling and sending only every push interval
			if p.checkAndSetLastPushMetrics(time.Now()) {
				for key, stat := range appStatsMap {
					log.SpanLog(ctx, log.DebugLevelMetrics, "App metrics",
						"AppInst key", key, "stats", stat)
					appMetrics := MarshalAppMetrics(&key, stat, p.reservedBy, zoneKey)
					for _, metric := range appMetrics {
						p.send(context.Background(), metric)
					}
				}
				clusterMetrics := p.MarshalClusterMetrics(clusterStats, zoneKey)
				for _, metric := range clusterMetrics {
					p.send(context.Background(), metric)
				}
			}
			span.Finish()

			// create another span for alerts that is always logged
			aspan := log.StartSpan(log.DebugLevelMetrics, "alerts check", log.WithSuppressWithoutLogs{})
			log.SetTags(aspan, p.clusterKey.GetTags())
			actx := log.ContextWithSpan(context.Background(), aspan)
			clusterAlerts := p.clusterStat.GetAlerts(actx)
			clusterAlerts = addClusterDetailsToAlerts(clusterAlerts, &p.clusterKey, &p.cloudletKey, zoneKey)
			UpdateAlerts(actx, clusterAlerts, &p.clusterKey, pruneClusterForeignAlerts)
			aspan.Finish()
		case <-p.stop:
			done = true
		}
	}
	p.waitGrp.Done()
}

// newMetric is called for both Cluster and App stats
func newMetric(clusterKey edgeproto.ClusterKey, cloudletKey edgeproto.CloudletKey, zoneKey edgeproto.ZoneKey, reservedBy string, name string, key *shepherd_common.MetricAppInstKey, ts *types.Timestamp) *edgeproto.Metric {
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

func (p *ClusterWorker) MarshalClusterMetrics(cm *shepherd_common.ClusterMetrics, zoneKey edgeproto.ZoneKey) []*edgeproto.Metric {
	var metrics []*edgeproto.Metric
	var metric *edgeproto.Metric

	// bail out if we get no metrics
	if cm == nil {
		return nil
	}

	// nil timestamps mean the curl request failed. So do not write the metric in
	if cm.CpuTS != nil {
		metric = newMetric(p.clusterKey, p.cloudletKey, zoneKey, p.reservedBy, "cluster-cpu", nil, cm.CpuTS)
		metric.AddDoubleVal("cpu", cm.Cpu)
		metrics = append(metrics, metric)
		//reset to nil for the next collection
		cm.CpuTS = nil
	}

	if cm.MemTS != nil {
		metric = newMetric(p.clusterKey, p.cloudletKey, zoneKey, p.reservedBy, "cluster-mem", nil, cm.MemTS)
		metric.AddDoubleVal("mem", cm.Mem)
		metrics = append(metrics, metric)
		cm.MemTS = nil
	}

	if cm.DiskTS != nil {
		metric = newMetric(p.clusterKey, p.cloudletKey, zoneKey, p.reservedBy, "cluster-disk", nil, cm.DiskTS)
		metric.AddDoubleVal("disk", cm.Disk)
		metrics = append(metrics, metric)
		cm.DiskTS = nil
	}

	if cm.TcpConnsTS != nil && cm.TcpRetransTS != nil {
		metric = newMetric(p.clusterKey, p.cloudletKey, zoneKey, p.reservedBy, "cluster-tcp", nil, cm.TcpConnsTS)
		metric.AddIntVal("tcpConns", cm.TcpConns)
		metric.AddIntVal("tcpRetrans", cm.TcpRetrans)
		metrics = append(metrics, metric)
	}
	cm.TcpConnsTS = nil
	cm.TcpRetransTS = nil

	if cm.UdpSentTS != nil && cm.UdpRecvTS != nil && cm.UdpRecvErrTS != nil {
		metric = newMetric(p.clusterKey, p.cloudletKey, p.zoneKey, p.reservedBy, "cluster-udp", nil, cm.UdpSentTS)
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

func MarshalAppMetrics(key *shepherd_common.MetricAppInstKey, stat *shepherd_common.AppMetrics, reservedBy string, zoneKey edgeproto.ZoneKey) []*edgeproto.Metric {
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
