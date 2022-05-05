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
	"sync"
	"time"

	influxdb "github.com/influxdata/influxdb/client/v2"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/cloudcommon/influxsup"
	influxq "github.com/edgexr/edge-cloud/controller/influxq_client"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/util"
)

// AutoProvAggr aggregates auto-provisioning stats pulled from influxdb,
// and deploys or undeploys AppInsts if they meet the policy criteria.
type AutoProvAggr struct {
	mux         sync.Mutex
	intervalSec float64
	offsetSec   float64
	waitGroup   sync.WaitGroup
	stop        chan struct{}
	caches      *CacheData
	allStats    map[edgeproto.AppKey]*apAppStats
	intervalNum uint64
}

// An App may have multiple AutoProv Policies. However, DME stats
// are independent of the policies, and only care that a client
// wants to access the App on a particular Cloudlet.
// Each policy must be checked to see if the stats meet its
// threshold for deployment. Only one AppInst per Cloudlet will be
// deployed even if multiple policies meet the deployment criteria.
type apAppStats struct {
	policies  map[string]*apPolicyTracker
	cloudlets map[edgeproto.CloudletKey]*apCloudletStats
}

type apPolicyTracker struct {
	deployClientCount   uint32 // cached from policy
	deployIntervalCount uint32 // cached from policy
	cloudletTrackers    map[edgeproto.CloudletKey]*apCloudletTracker
}

type apCloudletStats struct {
	count       uint64 // absolute count
	lastCount   uint64 // absolute count
	intervalNum uint64
}

type apCloudletTracker struct {
	deployIntervalsMet uint32
}

func NewAutoProvAggr(intervalSec, offsetSec float64, caches *CacheData) *AutoProvAggr {
	s := AutoProvAggr{}
	s.intervalSec = intervalSec
	s.offsetSec = offsetSec
	s.caches = caches
	s.allStats = make(map[edgeproto.AppKey]*apAppStats)
	// set callbacks to respond to changes
	caches.appCache.AddUpdatedKeyCb(s.UpdateApp)
	caches.appCache.AddDeletedKeyCb(s.DeleteApp)
	caches.autoProvPolicyCache.AddUpdatedKeyCb(s.UpdatePolicy)
	return &s
}

func (s *AutoProvAggr) Start() {
	s.mux.Lock()
	defer s.mux.Unlock()
	if s.stop != nil {
		// already started
		return
	}
	s.stop = make(chan struct{})
	s.waitGroup.Add(1)
	go s.Run()
}

func (s *AutoProvAggr) Stop() {
	s.mux.Lock()
	close(s.stop)
	s.mux.Unlock()
	s.waitGroup.Wait()
	s.mux.Lock()
	s.stop = nil
	s.mux.Unlock()
}

func (s *AutoProvAggr) UpdateSettings(ctx context.Context, intervalSec, offsetSec float64) {
	if s.intervalSec == intervalSec && s.offsetSec == offsetSec {
		return
	}
	restart := false
	if s.allStats != nil {
		s.Stop()
		restart = true
	}
	s.mux.Lock()
	s.intervalSec = intervalSec
	s.offsetSec = offsetSec
	s.mux.Unlock()
	if restart {
		log.SpanLog(ctx, log.DebugLevelApi, "restarting autoProvAggr thread")
		s.Start()
	}
}

func (s *AutoProvAggr) Run() {
	done := false

	// Run iter once first to grab initial values.
	span := log.StartSpan(log.DebugLevelMetrics, "auto-prov-aggr init")
	ctx := log.ContextWithSpan(context.Background(), span)
	err := s.runIter(ctx, true)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelMetrics, "runIter failed", "err", err)
	}
	span.Finish()

	for !done {
		waitTime := util.GetWaitTime(time.Now(), s.intervalSec, s.offsetSec)
		select {
		case <-time.After(waitTime):
			span := log.StartSpan(log.DebugLevelMetrics, "auto-prov-aggr")
			ctx := log.ContextWithSpan(context.Background(), span)
			err := s.runIter(ctx, false)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelMetrics, "runIter failed", "err", err)
			}
			retryTracker.doRetry(ctx, minMaxChecker)
			span.Finish()
		case <-s.stop:
			done = true
		}
	}
	s.waitGroup.Done()
}

func (s *AutoProvAggr) runIter(ctx context.Context, init bool) error {
	// get last data from influxdb
	creds, err := cloudcommon.GetInfluxDataAuth(vaultConfig, *region)
	if err != nil {
		return err
	}
	client, err := influxsup.GetClient(*influxAddr, creds.User, creds.Pass)
	if err != nil {
		return err
	}
	defer client.Close()

	// Get any data that has changed in the last time interval.
	cmd := fmt.Sprintf(`SELECT * FROM "%s" WHERE time > now() - %ds ORDER by time desc LIMIT 1`, cloudcommon.AutoProvMeasurement, int(s.intervalSec))
	if init {
		// Get initial count in case we restarted and lost our
		// cached values for the previous iteration.
		cmd = fmt.Sprintf(`SELECT * FROM "%s" ORDER by time desc LIMIT 1`, cloudcommon.AutoProvMeasurement)
	}
	query := influxdb.NewQuery(cmd, cloudcommon.DeveloperMetricsDbName, "")
	resp, err := client.Query(query)
	if err != nil {
		return err
	}
	if resp.Error() != nil {
		return resp.Error()
	}

	// aggregate data by app + cloudlet (aggregates over all DME counts)
	stats := make(map[edgeproto.AppKey]map[edgeproto.CloudletKey]uint64)
	numStats := 0
	for ii, _ := range resp.Results {
		for jj, _ := range resp.Results[ii].Series {
			row := &resp.Results[ii].Series[jj]
			// should only be one value
			if len(row.Values) < 1 {
				continue
			}
			ap, _, _, err := influxq.ParseAutoProvCount(row.Columns, row.Values[0])
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelMetrics, "failed to parse auto-prov-counts", "err", err)
				continue
			}
			appStats, found := stats[ap.AppKey]
			if !found {
				appStats = make(map[edgeproto.CloudletKey]uint64)
				stats[ap.AppKey] = appStats
			}
			appStats[ap.CloudletKey] += ap.Count
			numStats++
			log.SpanLog(ctx, log.DebugLevelMetrics, "stats", "app", ap.AppKey, "cloudlet", ap.CloudletKey, "count", ap.Count)
		}
	}

	s.mux.Lock()
	s.intervalNum++
	numDeploy := 0
	numUndeploy := 0
	for appKey, cloudlets := range stats {
		appStats, found := s.allStats[appKey]
		if !found {
			// may have been deleted
			continue
		}
		app := edgeproto.App{}
		if !s.caches.appCache.Get(&appKey, &app) {
			// deleted
			continue
		}
		for ckey, count := range cloudlets {
			cstats, found := appStats.cloudlets[ckey]
			if !found {
				cstats = &apCloudletStats{}
				// if not found, treat last iteration as 0 count
				cstats.intervalNum = s.intervalNum - 1
				appStats.cloudlets[ckey] = cstats
			}
			if init {
				// just initialize count
				cstats.count = count
				cstats.intervalNum = s.intervalNum
				continue
			}
			log.SpanLog(ctx, log.DebugLevelMetrics, "runIter cloudlet", "interval", s.intervalNum, "app", appKey, "cloudlet", ckey, "count", count, "lastCount", cstats.count)
			// We are looking for consecutive intervals that
			// match the deployment/undeployment criteria.
			resetIntervalsMet := false
			if (s.intervalNum - 1) != cstats.intervalNum {
				// missed interval means no change, so reset
				// consecutive counter
				resetIntervalsMet = true
			}
			// check all policies to see if any meet criteria
			doDeploy := false
			for name, ap := range appStats.policies {
				tracker, found := ap.cloudletTrackers[ckey]
				if !found {
					continue
				}
				if resetIntervalsMet {
					tracker.deployIntervalsMet = 0
				}
				if (count - cstats.count) >= uint64(ap.deployClientCount) {
					tracker.deployIntervalsMet++
				} else {
					tracker.deployIntervalsMet = 0
				}
				if tracker.deployIntervalsMet >= ap.deployIntervalCount {
					doDeploy = true
				}
				log.SpanLog(ctx, log.DebugLevelMetrics, "runIter deploy check", "policy", name, "intervalsMet", tracker.deployIntervalsMet, "doDeploy", doDeploy)
			}
			cstats.lastCount = cstats.count
			cstats.count = count
			cstats.intervalNum = s.intervalNum

			if doDeploy {
				s.deploy(ctx, &app, &ckey)
				numDeploy++
			}

			// TODO: undeployment
		}
	}
	if init {
		// Don't treat the init as an iteration. First because
		// it isn't run at the correct time, and second because
		// the count may be from a long time ago due to the influx
		// query not being limited to the last time interval.
		s.intervalNum--
	}
	s.mux.Unlock()

	log.SpanLog(ctx, log.DebugLevelMetrics, "runIter", "numstats", numStats, "numDeploy", numDeploy, "numUndeploy", numUndeploy)
	return nil
}

func (s *AutoProvAggr) deploy(ctx context.Context, app *edgeproto.App, cloudletKey *edgeproto.CloudletKey) {
	log.SpanLog(ctx, log.DebugLevelApi, "auto-prov deploy App", "app", app.Key, "cloudlet", *cloudletKey)

	inst := edgeproto.AppInst{}
	inst.Key.AppKey = app.Key
	// let Controller pick or create a reservable ClusterInst.
	inst.Key.ClusterInstKey.CloudletKey = *cloudletKey
	inst.Key.ClusterInstKey.ClusterKey.Name = cloudcommon.AutoProvClusterName
	inst.Key.ClusterInstKey.Organization = cloudcommon.OrganizationMobiledgeX

	go goAppInstApi(ctx, &inst, cloudcommon.Create, cloudcommon.AutoProvReasonDemand, "")
}

func (s *AutoProvAggr) DeleteApp(ctx context.Context, appKey *edgeproto.AppKey) {
	s.mux.Lock()
	defer s.mux.Unlock()
	delete(s.allStats, *appKey)
}

func (s *AutoProvAggr) UpdateApp(ctx context.Context, appKey *edgeproto.AppKey) {
	s.mux.Lock()
	defer s.mux.Unlock()

	app := edgeproto.App{}
	if !s.caches.appCache.Get(appKey, &app) {
		// must have been deleted
		delete(s.allStats, *appKey)
		return
	}
	inAP := make(map[string]struct{})
	if app.AutoProvPolicy != "" {
		inAP[app.AutoProvPolicy] = struct{}{}
	}
	for _, name := range app.AutoProvPolicies {
		inAP[name] = struct{}{}
	}
	if len(inAP) == 0 {
		delete(s.allStats, app.Key)
		return
	}
	appStats, found := s.allStats[app.Key]
	if !found {
		appStats = &apAppStats{}
		appStats.policies = make(map[string]*apPolicyTracker)
		appStats.cloudlets = make(map[edgeproto.CloudletKey]*apCloudletStats)
		s.allStats[app.Key] = appStats
	}
	// remove policies
	for name, _ := range appStats.policies {
		if _, found := inAP[name]; !found {
			delete(appStats.policies, name)
		}
	}
	// add policies
	for name, _ := range inAP {
		_, found := appStats.policies[name]
		if !found {
			policy := edgeproto.AutoProvPolicy{}
			policyKey := edgeproto.PolicyKey{
				Organization: appKey.Organization,
				Name:         name,
			}
			if !s.caches.autoProvPolicyCache.Get(&policyKey, &policy) {
				log.SpanLog(ctx, log.DebugLevelMetrics, "cannot find policy for app", "app", app.Key, "policy", name)
				continue
			}
			ap := &apPolicyTracker{}
			updatePolicyTracker(ctx, ap, &policy)
			appStats.policies[name] = ap
		}
	}
}

func updatePolicyTracker(ctx context.Context, ap *apPolicyTracker, policy *edgeproto.AutoProvPolicy) {
	ap.deployClientCount = policy.DeployClientCount
	ap.deployIntervalCount = policy.DeployIntervalCount

	oldTrackers := ap.cloudletTrackers
	ap.cloudletTrackers = make(map[edgeproto.CloudletKey]*apCloudletTracker, len(policy.Cloudlets))
	for ii, _ := range policy.Cloudlets {
		key := policy.Cloudlets[ii].Key

		tr, found := oldTrackers[key]
		if !found {
			tr = &apCloudletTracker{}
		}
		ap.cloudletTrackers[key] = tr
	}
}

func (s *AutoProvAggr) UpdatePolicy(ctx context.Context, key *edgeproto.PolicyKey) {
	s.mux.Lock()
	defer s.mux.Unlock()

	policy := edgeproto.AutoProvPolicy{}
	if !s.caches.autoProvPolicyCache.Get(key, &policy) {
		// deleted
		return
	}
	for appKey, appStats := range s.allStats {
		if appKey.Organization != policy.Key.Organization {
			continue
		}
		ap, found := appStats.policies[policy.Key.Name]
		if !found {
			continue
		}
		updatePolicyTracker(ctx, ap, &policy)
	}
}
