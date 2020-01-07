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

type apAppStats struct {
	deployClientCount   uint32 // cached from policy
	deployIntervalCount uint32 // cached from policy
	cloudlets           map[edgeproto.CloudletKey]*apCloudletStats
}

type apCloudletStats struct {
	count              uint64 // absolute count
	intervalNum        uint64
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
	s.waitGroup.Wait()
	s.allStats = nil
	s.mux.Unlock()
}

func (s *AutoProvAggr) UpdateSettings(intervalSec, offsetSec float64) {
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
			log.DebugLog(log.DebugLevelMetrics, "stats", "app", ap.AppKey, "cloudlet", ap.CloudletKey, "count", ap.Count)
		}
	}

	s.mux.Lock()
	s.intervalNum++
	numDeploy := 0
	numUndeploy := 0
	for appKey, cloudlets := range stats {
		appStats, found := s.allStats[appKey]
		if !found {
			// lookup policy
			// TODO: update cached policy params if policy changes
			app := edgeproto.App{}
			if !s.appCache.Get(&appKey, &app) {
				log.SpanLog(ctx, log.DebugLevelMetrics, "cannot find app", "app", appKey)
				continue
			}
			policy := edgeproto.AutoProvPolicy{}
			policyKey := edgeproto.PolicyKey{}
			policyKey.Name = app.AutoProvPolicy
			policyKey.Developer = appKey.DeveloperKey.Name
			if !s.policyCache.Get(&policyKey, &policy) {
				log.SpanLog(ctx, log.DebugLevelMetrics, "cannot find policy for app", "app", appKey, "policy", app.AutoProvPolicy)
				continue
			}
			appStats = &apAppStats{}
			appStats.cloudlets = make(map[edgeproto.CloudletKey]*apCloudletStats)
			appStats.deployClientCount = policy.DeployClientCount
			appStats.deployIntervalCount = policy.DeployIntervalCount
			s.allStats[appKey] = appStats
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
			// We are looking for consecutive intervals that
			// match the deployment/undeployment criteria.
			if (s.intervalNum-1) == cstats.intervalNum &&
				(count-cstats.count) >= uint64(appStats.deployClientCount) {
				cstats.deployIntervalsMet++
			} else {
				cstats.deployIntervalsMet = 0
			}
			cstats.count = count
			cstats.intervalNum = s.intervalNum
			log.DebugLog(log.DebugLevelMetrics, "intervalsMet", "app", appKey, "cloudlet", ckey, "deploysMet", cstats.deployIntervalsMet)

			if cstats.deployIntervalsMet >= appStats.deployIntervalCount {
				go func() {
					dspan := log.StartSpan(log.DebugLevelApi, "auto-prov-deploy", opentracing.ChildOf(log.SpanFromContext(ctx).Context()))
					dspan.SetTag("app", appKey)
					dspan.SetTag("cloudlet", ckey)
					defer dspan.Finish()
					dctx := log.ContextWithSpan(context.Background(), dspan)
					err := s.deploy(dctx, &appKey, &ckey)
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

func (s *AutoProvAggr) deploy(ctx context.Context, appKey *edgeproto.AppKey, cloudletKey *edgeproto.CloudletKey) error {
	// find free reservable ClusterInst
	cinstKey := s.freeClusters.GetForCloudlet(cloudletKey)
	if cinstKey == nil {
		return fmt.Errorf("no free ClusterInst found")
	}
	inst := edgeproto.AppInst{}
	inst.Key.AppKey = *appKey
	inst.Key.ClusterInstKey = *cinstKey

	log.SpanLog(ctx, log.DebugLevelApi, "auto-prov deploy AppInst", "AppInst", inst)
	conn, err := grpc.Dial(*ctrlAddr, dialOpts, grpc.WithBlock(), grpc.WithWaitForHandshake())
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

func (s *AutoProvAggr) Clear(appKey *edgeproto.AppKey) {
	s.mux.Lock()
	defer s.mux.Unlock()
	for akey, _ := range s.allStats {
		if akey.Matches(appKey) {
			delete(s.allStats, akey)
		}
	}
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
