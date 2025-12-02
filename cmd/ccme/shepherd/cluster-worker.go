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
			K8sStats: shepherd_common.K8sStats{
				Key:         p.clusterKey,
				CloudletKey: p.cloudletKey,
			},
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
			promClient, err := p.clusterStat.GetPromClient(ctx)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to get prometheus client", "cluster", p.clusterKey, "err", err)
				span.Finish()
				continue
			}
			clusterStats := p.clusterStat.GetClusterStats(ctx, promClient, statOps...)
			appStatsMap := p.clusterStat.GetAppStats(ctx, promClient)
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
					appMetrics := shepherd_common.MarshalAppMetrics(&key, stat, p.reservedBy, zoneKey)
					for _, metric := range appMetrics {
						p.send(context.Background(), metric)
					}
				}
				key := shepherd_common.MetricClusterKey{
					ClusterKey:  p.clusterKey,
					CloudletKey: p.cloudletKey,
					ZoneKey:     zoneKey,
					ReservedBy:  p.reservedBy,
				}
				clusterMetrics := shepherd_common.MarshalClusterMetrics(clusterStats, key)
				for _, metric := range clusterMetrics {
					p.send(context.Background(), metric)
				}
			}
			span.Finish()

			// create another span for alerts that is always logged
			aspan := log.StartSpan(log.DebugLevelMetrics, "alerts check", log.WithSuppressWithoutLogs{})
			log.SetTags(aspan, p.clusterKey.GetTags())
			actx := log.ContextWithSpan(context.Background(), aspan)
			clusterAlerts := p.clusterStat.GetAlerts(actx, promClient)
			clusterAlerts = shepherd_common.AddClusterDetailsToAlerts(clusterAlerts, &p.clusterKey, &p.cloudletKey, zoneKey)
			UpdateAlerts(actx, clusterAlerts, &p.clusterKey, pruneClusterForeignAlerts)
			aspan.Finish()
		case <-p.stop:
			done = true
		}
	}
	p.waitGrp.Done()
}
