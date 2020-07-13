package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/util/tasks"
)

// MinMaxChecker maintains the minimum and maximum number of
// AppInsts if specified in the policy.
type MinMaxChecker struct {
	caches           *CacheData
	needsCheck       map[edgeproto.AppKey]struct{}
	failoverRequests map[edgeproto.CloudletKey]*failoverReq
	mux              sync.Mutex
	// maintain reverse relationships to be able to look up
	// which Apps are affected by cloudlet state changes.
	policiesByCloudlet edgeproto.AutoProvPolicyByCloudletKey
	appsByPolicy       edgeproto.AppByAutoProvPolicy
	workers            tasks.KeyWorkers
}

func newMinMaxChecker(caches *CacheData) *MinMaxChecker {
	s := MinMaxChecker{}
	s.caches = caches
	s.failoverRequests = make(map[edgeproto.CloudletKey]*failoverReq)
	s.workers.Init("autoprov-minmax", s.CheckApp)
	s.policiesByCloudlet.Init()
	s.appsByPolicy.Init()
	// set callbacks to respond to changes
	caches.appCache.AddUpdatedCb(s.UpdatedApp)
	caches.appCache.AddDeletedCb(s.DeletedApp)
	caches.appInstCache.AddUpdatedCb(s.UpdatedAppInst)
	caches.appInstCache.AddDeletedKeyCb(s.DeletedAppInst)
	caches.autoProvPolicyCache.AddUpdatedCb(s.UpdatedPolicy)
	caches.autoProvPolicyCache.AddDeletedCb(s.DeletedPolicy)
	caches.cloudletCache.AddUpdatedCb(s.UpdatedCloudlet)
	caches.cloudletInfoCache.AddUpdatedCb(s.UpdatedCloudletInfo)
	caches.appInstRefsCache.AddUpdatedCb(s.UpdatedAppInstRefs)
	return &s
}

// Maintenace request for a cloudlet
type failoverReq struct {
	info         edgeproto.AutoProvInfo
	appsToCheck  map[edgeproto.AppKey]struct{}
	mux          sync.Mutex
	waitApiCalls sync.WaitGroup
}

func (s *failoverReq) addCompleted(msg string) {
	s.mux.Lock()
	defer s.mux.Unlock()

	s.info.Completed = append(s.info.Completed, msg)
}

func (s *failoverReq) addError(err string) {
	s.mux.Lock()
	defer s.mux.Unlock()

	s.info.Errors = append(s.info.Errors, err)
}

// Returns true if all apps have been processed
func (s *failoverReq) appDone(ctx context.Context, key edgeproto.AppKey) bool {
	s.mux.Lock()
	defer s.mux.Unlock()

	if _, found := s.appsToCheck[key]; !found {
		// avoid spawning another go thread if already finished
		return false
	}
	delete(s.appsToCheck, key)
	return len(s.appsToCheck) == 0
}

func (s *MinMaxChecker) UpdatedPolicy(ctx context.Context, old *edgeproto.AutoProvPolicy, new *edgeproto.AutoProvPolicy) {
	s.policiesByCloudlet.Updated(old, new)
	// check all Apps that use policy
	for _, appKey := range s.appsByPolicy.Find(new.Key) {
		s.workers.NeedsWork(ctx, appKey)
	}
}

func (s *MinMaxChecker) DeletedPolicy(ctx context.Context, old *edgeproto.AutoProvPolicy) {
	s.policiesByCloudlet.Deleted(old)
}

func (s *MinMaxChecker) UpdatedApp(ctx context.Context, old *edgeproto.App, new *edgeproto.App) {
	changed := s.appsByPolicy.Updated(old, new)
	if len(changed) > 0 {
		s.workers.NeedsWork(ctx, new.Key)
	}
}

func (s *MinMaxChecker) DeletedApp(ctx context.Context, old *edgeproto.App) {
	s.appsByPolicy.Deleted(old)
}

func (s *MinMaxChecker) UpdatedCloudletInfo(ctx context.Context, old *edgeproto.CloudletInfo, new *edgeproto.CloudletInfo) {
	s.mux.Lock()
	defer s.mux.Unlock()

	if old != nil && cloudcommon.AutoProvCloudletInfoOnline(old) == cloudcommon.AutoProvCloudletInfoOnline(new) {
		// no change
		return
	}
	log.SpanLog(ctx, log.DebugLevelMetrics, "cloudlet info online change", "new", new)
	appsToCheck := s.cloudletNeedsCheck(new.Key)
	for appKey, _ := range appsToCheck {
		s.workers.NeedsWork(ctx, appKey)
	}
}

func (s *MinMaxChecker) cloudletNeedsCheck(key edgeproto.CloudletKey) map[edgeproto.AppKey]struct{} {
	appsToCheck := make(map[edgeproto.AppKey]struct{})
	policies := s.policiesByCloudlet.Find(key)
	for _, policyKey := range policies {
		apps := s.appsByPolicy.Find(policyKey)
		for _, appKey := range apps {
			appsToCheck[appKey] = struct{}{}
		}
	}
	return appsToCheck
}

func (s *MinMaxChecker) UpdatedCloudlet(ctx context.Context, old *edgeproto.Cloudlet, new *edgeproto.Cloudlet) {
	s.mux.Lock()
	defer s.mux.Unlock()

	if old == nil {
		return
	}
	if cloudcommon.AutoProvCloudletOnline(old) == cloudcommon.AutoProvCloudletOnline(new) {
		// no change
		return
	}
	log.SpanLog(ctx, log.DebugLevelMetrics, "cloudlet online change", "new", new)
	appsToCheck := s.cloudletNeedsCheck(new.Key)
	req, found := s.failoverRequests[new.Key]
	if !found {
		req = &failoverReq{}
		req.info.Key = new.Key
		req.appsToCheck = make(map[edgeproto.AppKey]struct{})
		s.failoverRequests[new.Key] = req
	}
	req.mux.Lock()
	for appKey, _ := range appsToCheck {
		req.appsToCheck[appKey] = struct{}{}
		s.workers.NeedsWork(ctx, appKey)
	}
	req.mux.Unlock()
}

func (s *MinMaxChecker) UpdatedAppInst(ctx context.Context, old *edgeproto.AppInst, new *edgeproto.AppInst) {
	s.mux.Lock()
	defer s.mux.Unlock()

	if !s.isAutoProvApp(&new.Key.AppKey) {
		return
	}

	// recheck if online state changed
	if old != nil {
		cloudletInfo := edgeproto.CloudletInfo{}
		if !s.caches.cloudletInfoCache.Get(&new.Key.ClusterInstKey.CloudletKey, &cloudletInfo) {
			log.SpanLog(ctx, log.DebugLevelMetrics, "UpdatedAppInst cloudletInfo not found", "app", new.Key, "cloudlet", new.Key.ClusterInstKey.CloudletKey)
			return
		}
		cloudlet := edgeproto.Cloudlet{}
		if !s.caches.cloudletCache.Get(&new.Key.ClusterInstKey.CloudletKey, &cloudlet) {
			log.SpanLog(ctx, log.DebugLevelMetrics, "UpdatedAppInst cloudlet not found", "app", new.Key, "cloudlet", new.Key.ClusterInstKey.CloudletKey)
			return
		}
		if cloudcommon.AutoProvAppInstOnline(old, &cloudletInfo, &cloudlet) ==
			cloudcommon.AutoProvAppInstOnline(new, &cloudletInfo, &cloudlet) {
			// no state change, no check needed
			return
		}
	}
	s.workers.NeedsWork(ctx, new.Key.AppKey)
}

func (s *MinMaxChecker) DeletedAppInst(ctx context.Context, key *edgeproto.AppInstKey) {
	s.mux.Lock()
	defer s.mux.Unlock()

	if !s.isAutoProvApp(&key.AppKey) {
		return
	}
	s.workers.NeedsWork(ctx, key.AppKey)
}

func (s *MinMaxChecker) UpdatedAppInstRefs(ctx context.Context, old *edgeproto.AppInstRefs, new *edgeproto.AppInstRefs) {
	s.mux.Lock()
	defer s.mux.Unlock()

	if !s.isAutoProvApp(&new.Key) {
		return
	}
	s.workers.NeedsWork(ctx, new.Key)
}

func (s *MinMaxChecker) isAutoProvApp(key *edgeproto.AppKey) bool {
	s.caches.appCache.Mux.Lock()
	defer s.caches.appCache.Mux.Unlock()

	data, found := s.caches.appCache.Objs[*key]
	if found && (data.Obj.AutoProvPolicy != "" || len(data.Obj.AutoProvPolicies) > 0) {
		return true
	}
	return false
}

func (s *MinMaxChecker) CheckApp(ctx context.Context, k interface{}) {
	key, ok := k.(edgeproto.AppKey)
	if !ok {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Unexpected failure, key not AppKey", "key", key)
		return
	}
	log.SetContextTags(ctx, key.GetTags())
	log.SpanLog(ctx, log.DebugLevelMetrics, "CheckApp", "App", key)

	// get failover requests to that need to check the App.
	failoverReqs := []*failoverReq{}
	s.mux.Lock()
	for _, req := range s.failoverRequests {
		if _, found := req.appsToCheck[key]; found {
			failoverReqs = append(failoverReqs, req)
		}
	}
	s.mux.Unlock()

	ac := newAppChecker(s.caches, key, failoverReqs)
	ac.Check(ctx)

	for _, req := range failoverReqs {
		finished := req.appDone(ctx, key)
		if !finished {
			continue
		}
		s.mux.Lock()
		delete(s.failoverRequests, req.info.Key)
		s.mux.Unlock()
		// wait for any App API calls to finish, then send back result
		go func(ctx context.Context, r *failoverReq) {
			span, ctx := log.ChildSpan(ctx, log.DebugLevelApi, "failover request done")
			defer span.Finish()
			log.SetTags(span, r.info.Key.GetTags())

			r.waitApiCalls.Wait()
			if len(r.info.Errors) == 0 {
				r.info.MaintenanceState = edgeproto.MaintenanceState_FAILOVER_DONE
			} else {
				r.info.MaintenanceState = edgeproto.MaintenanceState_FAILOVER_ERROR
			}
			s.caches.autoProvInfoCache.Update(ctx, &r.info, 0)
		}(ctx, req)
	}
}

// AppChecker maintains the min and max number of AppInsts for
// the specified App, based on the policies on the App.
type AppChecker struct {
	appKey          edgeproto.AppKey
	caches          *CacheData
	cloudletInsts   map[edgeproto.CloudletKey]map[edgeproto.AppInstKey]struct{}
	policyCloudlets map[edgeproto.CloudletKey]struct{}
	failoverReqs    []*failoverReq
	apiCallWait     sync.WaitGroup
}

func newAppChecker(caches *CacheData, key edgeproto.AppKey, failoverReqs []*failoverReq) *AppChecker {
	checker := AppChecker{
		appKey:       key,
		caches:       caches,
		failoverReqs: failoverReqs,
	}
	// AppInsts organized by Cloudlet
	checker.cloudletInsts = make(map[edgeproto.CloudletKey]map[edgeproto.AppInstKey]struct{})
	// Cloudlets in use by the policies on this App.
	// We will use this to delete any auto-provisioned instances
	// of this App that are orphaned.
	checker.policyCloudlets = make(map[edgeproto.CloudletKey]struct{})
	return &checker
}

func (s *AppChecker) Check(ctx context.Context) {
	// Check for various policy violations which we must correct.
	// 1. Num Active AppInsts below a policy min.
	// 2. Total AppInsts above a policy max.
	// 3. Orphaned AutoProvisioned AppInsts (cloudlet no longer part
	// of policy, or policy no longer on App)
	app := edgeproto.App{}
	if !s.caches.appCache.Get(&s.appKey, &app) {
		// may have been deleted
		return
	}

	refs := edgeproto.AppInstRefs{}
	if !s.caches.appInstRefsCache.Get(&s.appKey, &refs) {
		// Refs should always exist for app. If refs does not
		// exist, that means we aren't fully updated via notify.
		// Wait until we get the refs (will trigger another check).
		return
	}
	// existing AppInsts by cloudlet
	for keyStr, _ := range refs.Insts {
		key := edgeproto.AppInstKey{}
		edgeproto.AppInstKeyStringParse(keyStr, &key)

		cloudletKey := &key.ClusterInstKey.CloudletKey
		insts, found := s.cloudletInsts[*cloudletKey]
		if !found {
			insts = make(map[edgeproto.AppInstKey]struct{})
			s.cloudletInsts[*cloudletKey] = insts
		}
		insts[key] = struct{}{}
	}

	prevPolicyCloudlets := make(map[edgeproto.CloudletKey]struct{})
	policies := app.GetAutoProvPolicies()
	for pname, _ := range policies {
		s.checkPolicy(ctx, &app, pname, prevPolicyCloudlets)
	}

	// delete any AppInsts that are orphaned
	// (no longer on policy cloudlets)
	for ckey, insts := range s.cloudletInsts {
		if _, found := s.policyCloudlets[ckey]; found {
			continue
		}
		for appInstKey, _ := range insts {
			if !s.isAutoProvInst(&appInstKey) {
				continue
			}
			inst := edgeproto.AppInst{
				Key: appInstKey,
			}
			go goAppInstApi(ctx, &inst, cloudcommon.Delete, cloudcommon.AutoProvReasonOrphaned, "")
		}
	}
}

func (s *AppChecker) checkPolicy(ctx context.Context, app *edgeproto.App, pname string, prevPolicyCloudlets map[edgeproto.CloudletKey]struct{}) {
	log.SpanLog(ctx, log.DebugLevelMetrics, "checkPolicy", "app", s.appKey, "policy", pname)
	policy := edgeproto.AutoProvPolicy{}
	policyKey := edgeproto.PolicyKey{
		Name:         pname,
		Organization: app.Key.Organization,
	}
	if !s.caches.autoProvPolicyCache.Get(&policyKey, &policy) {
		log.SpanLog(ctx, log.DebugLevelMetrics, "checkApp policy not found", "policy", policyKey)
		return
	}

	// get counts
	potentialDelete := []edgeproto.AppInstKey{}
	potentialCreate := []edgeproto.AppInstKey{}
	onlineCount := 0
	totalCount := 0
	// check AppInsts on the policy's cloudlets
	for _, apCloudlet := range policy.Cloudlets {
		s.policyCloudlets[apCloudlet.Key] = struct{}{}

		insts, found := s.cloudletInsts[apCloudlet.Key]
		if !found {
			if !s.cloudletOnline(&apCloudlet.Key) {
				continue
			}
			// see if free reservable ClusterInst exists
			freeClustKey := s.caches.frClusterInsts.GetForCloudlet(&apCloudlet.Key, app.Deployment)
			if freeClustKey != nil {
				appInstKey := edgeproto.AppInstKey{
					AppKey:         s.appKey,
					ClusterInstKey: *freeClustKey,
				}
				potentialCreate = append(potentialCreate, appInstKey)
			}
		} else {
			for appInstKey, _ := range insts {
				totalCount++
				if s.appInstOnline(&appInstKey) {
					onlineCount++
				}
				if s.isAutoProvInst(&appInstKey) {
					potentialDelete = append(potentialDelete, appInstKey)
				}
			}
		}
	}
	log.SpanLog(ctx, log.DebugLevelMetrics, "checkPolicy stats", "policy", policyKey, "onlineCount", onlineCount, "min", policy.MinActiveInstances, "totalCount", totalCount, "max", policy.MaxInstances, "potentialCreate", potentialCreate, "potentialDelete", potentialDelete)

	// Check max first. If we meet or exceed max,
	// we cannot deploy to try to meet min.
	deleteKeys := s.chooseDelete(ctx, potentialDelete, totalCount-int(policy.MaxInstances))
	for _, key := range deleteKeys {
		inst := edgeproto.AppInst{
			Key: key,
		}
		go goAppInstApi(ctx, &inst, cloudcommon.Delete, cloudcommon.AutoProvReasonMinMax, pname)
	}

	if totalCount >= int(policy.MaxInstances) && policy.MaxInstances != 0 {
		// don't bother with min because we're already at max
		return
	}

	// Check min
	createKeys := s.chooseCreate(ctx, potentialCreate, int(policy.MinActiveInstances)-onlineCount)
	if len(createKeys) < int(policy.MinActiveInstances)-onlineCount {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Not enough potential Cloudlets to meet min constraint", "App", s.appKey, "policy", pname, "min", policy.MinActiveInstances)
		str := fmt.Sprintf("Not enough potential cloudlets to deploy to for App %s to meet policy %s min constraint %d", s.appKey.GetKeyString(), pname, policy.MinActiveInstances)
		for _, req := range s.failoverReqs {
			req.addError(str)
		}
	}
	for _, key := range createKeys {
		inst := edgeproto.AppInst{
			Key: key,
		}
		for _, req := range s.failoverReqs {
			req.waitApiCalls.Add(1)
		}
		go func() {
			err := goAppInstApi(ctx, &inst, cloudcommon.Create, cloudcommon.AutoProvReasonMinMax, pname)
			if err == nil {
				str := fmt.Sprintf("Created AppInst %s to meet policy %s min constraint %d", inst.Key.GetKeyString(), pname, policy.MinActiveInstances)
				for _, req := range s.failoverReqs {
					req.addCompleted(str)
				}
			} else if !strings.Contains(err.Error(), "Create to satisfy min already met, ignoring") {
				str := fmt.Sprintf("Failed to create AppInst %s to meet policy %s min constraint %d: %s", inst.Key.GetKeyString(), pname, policy.MinActiveInstances, err)
				for _, req := range s.failoverReqs {
					req.addError(str)
				}
			}
			for _, req := range s.failoverReqs {
				req.waitApiCalls.Done()
			}
		}()
	}
}

func (s *AppChecker) chooseDelete(ctx context.Context, potential []edgeproto.AppInstKey, count int) []edgeproto.AppInstKey {
	if count <= 0 {
		return []edgeproto.AppInstKey{}
	}
	if count >= len(potential) {
		count = len(potential)
	}
	// TODO: We can improve how we decide which
	// AppInst to delete, for example by sorting by
	// the active connections to see which one has the
	// lowest active clients.
	// For now favor deleting from Cloudlets at the
	// end of the policy's Cloudlet list.
	return potential[len(potential)-count : len(potential)]
}

func (s *AppChecker) chooseCreate(ctx context.Context, potential []edgeproto.AppInstKey, count int) []edgeproto.AppInstKey {
	if count <= 0 {
		return []edgeproto.AppInstKey{}
	}
	if count >= len(potential) {
		count = len(potential)
	}

	autoProvAggr.mux.Lock()
	defer autoProvAggr.mux.Unlock()

	appStats, found := autoProvAggr.allStats[s.appKey]
	if !found {
		return potential[:count]
	}

	// sort to put highest client demand first
	// client demand is only tracked for the last interval,
	// and is scaled by the deploy client count.
	sort.Slice(potential, func(i, j int) bool {
		ckey1 := potential[i].ClusterInstKey.CloudletKey
		ckey2 := potential[j].ClusterInstKey.CloudletKey

		var incr1, incr2 uint64
		if cstats, found := appStats.cloudlets[ckey1]; found && cstats.intervalNum == autoProvAggr.intervalNum {
			incr1 = cstats.count - cstats.lastCount
		}
		if cstats, found := appStats.cloudlets[ckey2]; found && cstats.intervalNum == autoProvAggr.intervalNum {
			incr2 = cstats.count - cstats.lastCount
		}
		log.SpanLog(ctx, log.DebugLevelMetrics, "chooseCreate stats", "cloudlet1", ckey1, "cloudlet2", ckey2, "incr1", incr1, "incr2", incr2)
		return incr1 > incr2
	})
	return potential[:count]
}

func (s *AppChecker) appInstOnline(key *edgeproto.AppInstKey) bool {
	cloudletInfo := edgeproto.CloudletInfo{}
	if !s.caches.cloudletInfoCache.Get(&key.ClusterInstKey.CloudletKey, &cloudletInfo) {
		return false
	}
	cloudlet := edgeproto.Cloudlet{}
	if !s.caches.cloudletCache.Get(&key.ClusterInstKey.CloudletKey, &cloudlet) {
		return false
	}
	appInst := edgeproto.AppInst{}
	if !s.caches.appInstCache.Get(key, &appInst) {
		return false
	}
	return cloudcommon.AutoProvAppInstOnline(&appInst, &cloudletInfo, &cloudlet)
}

func (s *AppChecker) cloudletOnline(key *edgeproto.CloudletKey) bool {
	cloudletInfo := edgeproto.CloudletInfo{}
	if !s.caches.cloudletInfoCache.Get(key, &cloudletInfo) {
		return false
	}
	cloudlet := edgeproto.Cloudlet{}
	if !s.caches.cloudletCache.Get(key, &cloudlet) {
		return false
	}
	return cloudcommon.AutoProvCloudletOnline(&cloudlet) && cloudcommon.AutoProvCloudletInfoOnline(&cloudletInfo)
}

func (s *AppChecker) isAutoProvInst(key *edgeproto.AppInstKey) bool {
	// direct lookup to avoid copy
	s.caches.appInstCache.Mux.Lock()
	defer s.caches.appInstCache.Mux.Unlock()

	data, found := s.caches.appInstCache.Objs[*key]
	if found && data.Obj.Liveness == edgeproto.Liveness_LIVENESS_AUTOPROV {
		return true
	}
	return false
}
