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
	"sync"
	"time"

	"github.com/edgexr/edge-cloud-infra/shepherd/shepherd_common"
	platform "github.com/edgexr/edge-cloud-infra/shepherd/shepherd_platform"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/util"
)

// For each cluster the notify worker is created
type AppInstWorker struct {
	pf         platform.Platform
	appInstKey edgeproto.AppInstKey
	interval   time.Duration
	send       func(ctx context.Context, metric *edgeproto.Metric) bool
	waitGrp    sync.WaitGroup
	stop       chan struct{}
}

func NewAppInstWorker(ctx context.Context, interval time.Duration, send func(ctx context.Context, metric *edgeproto.Metric) bool, appinst *edgeproto.AppInst, pf platform.Platform) *AppInstWorker {
	p := AppInstWorker{}
	p.pf = pf
	p.interval = pf.GetMetricsCollectInterval()
	if p.interval == 0 {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Platform Collection interval is 0, will not create appinst worker", "app", appinst)
		return nil
	}
	p.send = send
	p.appInstKey = appinst.Key
	log.SpanLog(ctx, log.DebugLevelMetrics, "NewAppInstWorker", "app", appinst)
	return &p
}

func (p *AppInstWorker) Start(ctx context.Context) {
	p.stop = make(chan struct{})
	p.waitGrp.Add(1)
	go p.RunNotify()
	log.SpanLog(ctx, log.DebugLevelMetrics, "Started AppInstWorker thread\n")
}

func (p *AppInstWorker) Stop(ctx context.Context) {
	log.SpanLog(ctx, log.DebugLevelMetrics, "Stopping AppInstWorker thread\n")
	close(p.stop)
	p.waitGrp.Wait()
}

func (p *AppInstWorker) sendMetrics() {
	span := log.StartSpan(log.DebugLevelSampled, "send-metric")
	log.SetTags(span, p.appInstKey.GetTags())
	ctx := log.ContextWithSpan(context.Background(), span)
	defer span.Finish()
	key := shepherd_common.MetricAppInstKey{
		// no real cluster name since these are VM apps
		ClusterInstKey: *p.appInstKey.ClusterInstKey.Real(""),
		Pod:            p.appInstKey.AppKey.Name,
		App:            util.DNSSanitize(p.appInstKey.AppKey.Name),
		Version:        util.DNSSanitize(p.appInstKey.AppKey.Version),
	}
	log.SpanLog(ctx, log.DebugLevelMetrics, "Collecting metrics for app", "key", key)
	stat, err := p.pf.GetVmStats(ctx, &p.appInstKey)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Failed to get metrics from VM", "app", p.appInstKey, "err", err)
		span.Finish()
		return
	}
	log.SpanLog(ctx, log.DebugLevelMetrics, "metrics for app", "key", key, "metrics", stat)
	appMetrics := MarshalAppMetrics(&key, &stat, "")
	for _, metric := range appMetrics {
		p.send(context.Background(), metric)
	}
}

func (p *AppInstWorker) RunNotify() {
	done := false
	// Run the collection as a first step to avoid an initial wait
	p.sendMetrics()
	for !done {
		select {
		case <-time.After(p.interval):
			p.sendMetrics()
		case <-p.stop:
			done = true
		}
	}
	p.waitGrp.Done()
}
