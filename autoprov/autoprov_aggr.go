package main

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	influxdb "github.com/influxdata/influxdb/client/v2"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/cloudcommon/influxsup"
	influxq "github.com/mobiledgex/edge-cloud/controller/influxq_client"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/util"
	"github.com/opentracing/opentracing-go"
	"google.golang.org/grpc"
)

// AutoProvAggr aggregates auto-provisioning stats pulled from influxdb,
// and deploys or undeploys AppInsts if they meet the policy criteria.
type AutoProvAggr struct {
	mux          sync.Mutex
	intervalSec  float64
	offsetSec    float64
	waitGroup    sync.WaitGroup
	stop         chan struct{}
	appCache     *edgeproto.AppCache
	policyCache  *edgeproto.AutoProvPolicyCache
	freeClusters *edgeproto.FreeReservableClusterInstCache
	allStats     map[edgeproto.AppKey]*apAppStats
	intervalNum  uint64
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
	intervalNum uint64
}

type apCloudletTracker struct {
	deployIntervalsMet uint32
}

func NewAutoProvAggr(intervalSec, offsetSec float64, appCache *edgeproto.AppCache, policyCache *edgeproto.AutoProvPolicyCache, freeClusters *edgeproto.FreeReservableClusterInstCache) *AutoProvAggr {
	s := AutoProvAggr{}
	s.intervalSec = intervalSec
	s.offsetSec = offsetSec
	s.appCache = appCache
	s.freeClusters = freeClusters
	s.policyCache = policyCache
	return &s
}

func (s *AutoProvAggr) Start() {
	s.mux.Lock()
	defer s.mux.Unlock()
	if s.allStats != nil {
		// already started
		return
	}
	s.allStats = make(map[edgeproto.AppKey]*apAppStats)
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
	s.allStats = nil
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
		if !s.appCache.Get(&appKey, &app) {
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
			cstats.count = count
			cstats.intervalNum = s.intervalNum

			if doDeploy {
				go func() {
					dspan := log.StartSpan(log.DebugLevelApi, "auto-prov-deploy", opentracing.ChildOf(log.SpanFromContext(ctx).Context()))
					dspan.SetTag("app", appKey)
					dspan.SetTag("cloudlet", ckey)
					defer dspan.Finish()
					dctx := log.ContextWithSpan(context.Background(), dspan)
					err := s.deploy(dctx, &app, &ckey)
					log.SpanLog(dctx, log.DebugLevelApi, "auto-prov result", "err", err)
				}()
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

func (s *AutoProvAggr) deploy(ctx context.Context, app *edgeproto.App, cloudletKey *edgeproto.CloudletKey) error {
	// find free reservable ClusterInst
	cinstKey := s.freeClusters.GetForCloudlet(cloudletKey, app.Deployment)
	if cinstKey == nil {
		return fmt.Errorf("no free ClusterInst found")
	}
	inst := edgeproto.AppInst{}
	inst.Key.AppKey = app.Key
	inst.Key.ClusterInstKey = *cinstKey

	log.SpanLog(ctx, log.DebugLevelApi, "auto-prov deploy AppInst", "AppInst", inst)
	conn, err := grpc.Dial(*ctrlAddr, dialOpts, grpc.WithBlock(), grpc.WithWaitForHandshake(), grpc.WithUnaryInterceptor(log.UnaryClientTraceGrpc), grpc.WithStreamInterceptor(log.StreamClientTraceGrpc))
	if err != nil {
		return fmt.Errorf("failed to connect to controller, %v", err)
	}
	defer conn.Close()

	client := edgeproto.NewAppInstApiClient(conn)
	stream, err := client.CreateAppInst(ctx, &inst)
	if err != nil {
		return err
	}
	for {
		_, err = stream.Recv()
		if err == io.EOF {
			err = nil
			break
		}
		if err != nil {
			break
		}
	}
	return err
}

func (s *AutoProvAggr) DeleteApp(ctx context.Context, appKey *edgeproto.AppKey) {
	s.mux.Lock()
	defer s.mux.Unlock()
	delete(s.allStats, *appKey)
}

func (s *AutoProvAggr) Prune(apps map[edgeproto.AppKey]struct{}) {
	s.mux.Lock()
	defer s.mux.Unlock()
	for akey, _ := range s.allStats {
		if _, found := apps[akey]; !found {
			delete(s.allStats, akey)
		}
	}
}

func (s *AutoProvAggr) UpdateApp(ctx context.Context, appKey *edgeproto.AppKey) {
	s.mux.Lock()
	defer s.mux.Unlock()

	app := edgeproto.App{}
	if !s.appCache.Get(appKey, &app) {
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
			if !s.policyCache.Get(&policyKey, &policy) {
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

func (s *AutoProvAggr) UpdatePolicy(ctx context.Context, policy *edgeproto.AutoProvPolicy) {
	s.mux.Lock()
	defer s.mux.Unlock()

	for appKey, appStats := range s.allStats {
		if appKey.Organization != policy.Key.Organization {
			continue
		}
		ap, found := appStats.policies[policy.Key.Name]
		if !found {
			continue
		}
		updatePolicyTracker(ctx, ap, policy)
	}
}
