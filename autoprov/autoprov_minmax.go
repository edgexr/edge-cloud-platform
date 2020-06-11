package main

import (
	"context"
	"sort"
	"sync"

	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

// MinMaxChecker maintains the minimum and maximum number of
// AppInsts if specified in the policy.
type MinMaxChecker struct {
	caches     *CacheData
	needsCheck map[edgeproto.AppKey]struct{}
	mux        sync.Mutex
	waitGroup  sync.WaitGroup
	signal     chan bool
	stop       chan struct{}
	// maintain reverse relationships to be able to look up
	// which Apps are affected by cloudlet state changes.
	cloudletPolicies map[edgeproto.CloudletKey]map[edgeproto.PolicyKey]struct{}
	policyApps       map[edgeproto.PolicyKey]map[edgeproto.AppKey]struct{}
}

func newMinMaxChecker(caches *CacheData) *MinMaxChecker {
	s := MinMaxChecker{}
	s.caches = caches
	s.signal = make(chan bool, 1)
	s.needsCheck = make(map[edgeproto.AppKey]struct{})
	s.cloudletPolicies = make(map[edgeproto.CloudletKey]map[edgeproto.PolicyKey]struct{})
	s.policyApps = make(map[edgeproto.PolicyKey]map[edgeproto.AppKey]struct{})
	return &s
}

func (s *MinMaxChecker) Start() {
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

func (s *MinMaxChecker) Stop() {
	s.mux.Lock()
	if s.stop == nil {
		// already stopped
		s.mux.Unlock()
		return
	}
	close(s.stop)
	s.mux.Unlock()
	s.waitGroup.Wait()
	s.mux.Lock()
	s.stop = nil
	s.mux.Unlock()
}

func (s *MinMaxChecker) Run() {
	done := false

	// check all apps initially
	s.mux.Lock()
	s.caches.appCache.Mux.Lock()
	for k, _ := range s.caches.appCache.Objs {
		s.needsCheck[k] = struct{}{}
	}
	s.caches.appCache.Mux.Unlock()
	s.mux.Unlock()
	// trigger initial run
	s.wakeup()

	for !done {
		select {
		case <-s.signal:
			span := log.StartSpan(log.DebugLevelMetrics, "autoprov-refs-checker")
			ctx := log.ContextWithSpan(context.Background(), span)
			s.runIter(ctx)
			span.Finish()
		case <-s.stop:
			done = true
		}
	}
	s.waitGroup.Done()

}

func (s *MinMaxChecker) runIter(ctx context.Context) {
	s.mux.Lock()
	checks := s.needsCheck
	s.needsCheck = make(map[edgeproto.AppKey]struct{})
	s.mux.Unlock()

	for k, _ := range checks {
		newAppChecker(s.caches, &k).check(ctx)
	}
}

func (s *MinMaxChecker) wakeup() {
	select {
	case s.signal <- true:
	default:
	}
}

func (s *MinMaxChecker) UpdatedPolicy(ctx context.Context, old *edgeproto.AutoProvPolicy, new *edgeproto.AutoProvPolicy) {
	oldCloudlets := getCloudlets(old)
	newCloudlets := getCloudlets(new)
	for key, _ := range newCloudlets {
		if _, found := oldCloudlets[key]; found {
			delete(oldCloudlets, key)
			delete(newCloudlets, key)
		}
	}

	// reverse lookup cache
	s.mux.Lock()
	defer s.mux.Unlock()

	for key, _ := range oldCloudlets {
		// removed cloudlet
		policies, found := s.cloudletPolicies[key]
		if found {
			delete(policies, new.Key)
		}
	}
	for key, _ := range newCloudlets {
		// added cloudlet
		policies, found := s.cloudletPolicies[key]
		if !found {
			policies = make(map[edgeproto.PolicyKey]struct{})
			s.cloudletPolicies[key] = policies
		}
		policies[new.Key] = struct{}{}
	}

	// check all Apps that use policy
	apps := s.policyApps[new.Key]
	if len(apps) > 0 {
		for appKey, _ := range apps {
			s.needsCheck[appKey] = struct{}{}
		}
		s.wakeup()
	}
}

func (s *MinMaxChecker) UpdatedApp(ctx context.Context, old *edgeproto.App, new *edgeproto.App) {
	// only need to check App if a policy was added or removed
	oldPolicies := getPolicies(old)
	newPolicies := getPolicies(new)
	for name, _ := range newPolicies {
		if _, found := oldPolicies[name]; found {
			delete(oldPolicies, name)
			delete(newPolicies, name)
		}
	}

	// reverse lookup caches
	s.mux.Lock()
	defer s.mux.Unlock()

	for name, _ := range oldPolicies {
		// removed policy
		policyKey := edgeproto.PolicyKey{
			Name:         name,
			Organization: new.Key.Organization,
		}
		apps, found := s.policyApps[policyKey]
		if found {
			delete(apps, new.Key)
		}
	}
	for name, _ := range newPolicies {
		// added policy
		policyKey := edgeproto.PolicyKey{
			Name:         name,
			Organization: new.Key.Organization,
		}
		apps, found := s.policyApps[policyKey]
		if !found {
			apps = make(map[edgeproto.AppKey]struct{})
			s.policyApps[policyKey] = apps
		}
		apps[new.Key] = struct{}{}
	}

	if len(oldPolicies) > 0 || len(newPolicies) > 0 {
		s.needsCheck[new.Key] = struct{}{}
		s.wakeup()
	}
}

func (s *MinMaxChecker) UpdatedCloudletInfo(ctx context.Context, old *edgeproto.CloudletInfo, new *edgeproto.CloudletInfo) {
	s.mux.Lock()
	defer s.mux.Unlock()

	if old != nil && cloudcommon.AutoProvCloudletOnline(old) == cloudcommon.AutoProvCloudletOnline(new) {
		// no change
		return
	}

	policies, found := s.cloudletPolicies[new.Key]
	if !found {
		// no policies using cloudlet
		return
	}
	for policyKey, _ := range policies {
		apps, found := s.policyApps[policyKey]
		if !found {
			// no apps using policy
			continue
		}
		for appKey, _ := range apps {
			s.needsCheck[appKey] = struct{}{}
			s.wakeup()
		}
	}
}

func (s *MinMaxChecker) UpdatedAppInst(ctx context.Context, old *edgeproto.AppInst, new *edgeproto.AppInst) {
	s.mux.Lock()
	defer s.mux.Unlock()

	// recheck if online state changed
	if old != nil {
		cloudletInfo := edgeproto.CloudletInfo{}
		if !s.caches.cloudletInfoCache.Get(&new.Key.ClusterInstKey.CloudletKey, &cloudletInfo) {
			log.SpanLog(ctx, log.DebugLevelMetrics, "UpdatedAppInst cloudlet not found", "app", new.Key, "cloudlet", new.Key.ClusterInstKey.CloudletKey)
			return
		}
		if cloudcommon.AutoProvAppInstOnline(old, &cloudletInfo) ==
			cloudcommon.AutoProvAppInstOnline(new, &cloudletInfo) {
			// no state change, no check needed
			return
		}
	}
	s.needsCheck[new.Key.AppKey] = struct{}{}
	s.wakeup()
}

func (s *MinMaxChecker) DeletedAppInst(ctx context.Context, key *edgeproto.AppInstKey) {
	s.mux.Lock()
	defer s.mux.Unlock()

	s.needsCheck[key.AppKey] = struct{}{}
	s.wakeup()
}

func (s *MinMaxChecker) UpdatedAppInstRefs(ctx context.Context, old *edgeproto.AppInstRefs, new *edgeproto.AppInstRefs) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.needsCheck[new.Key] = struct{}{}
	s.wakeup()
}

func getPolicies(app *edgeproto.App) map[string]struct{} {
	policies := make(map[string]struct{})
	if app != nil {
		if app.AutoProvPolicy != "" {
			policies[app.AutoProvPolicy] = struct{}{}
		}
		for _, name := range app.AutoProvPolicies {
			policies[name] = struct{}{}
		}
	}
	return policies
}

func getCloudlets(policy *edgeproto.AutoProvPolicy) map[edgeproto.CloudletKey]struct{} {
	cloudlets := make(map[edgeproto.CloudletKey]struct{})
	if policy == nil {
		return cloudlets
	}
	for _, apCloudlet := range policy.Cloudlets {
		cloudlets[apCloudlet.Key] = struct{}{}
	}
	return cloudlets
}

// AppChecker maintains the min and max number of AppInsts for
// the specified App, based on the policies on the App.
type AppChecker struct {
	appKey          *edgeproto.AppKey
	caches          *CacheData
	app             edgeproto.App
	cloudletInsts   map[edgeproto.CloudletKey]map[edgeproto.AppInstKey]struct{}
	policyCloudlets map[edgeproto.CloudletKey]struct{}
}

func newAppChecker(caches *CacheData, key *edgeproto.AppKey) *AppChecker {
	checker := AppChecker{
		appKey: key,
		caches: caches,
	}
	// AppInsts organized by Cloudlet
	checker.cloudletInsts = make(map[edgeproto.CloudletKey]map[edgeproto.AppInstKey]struct{})
	// Cloudlets in use by the policies on this App.
	// We will use this to delete any auto-provisioned instances
	// of this App that are orphaned.
	checker.policyCloudlets = make(map[edgeproto.CloudletKey]struct{})
	return &checker
}

func (s *AppChecker) check(ctx context.Context) {
	log.SpanLog(ctx, log.DebugLevelMetrics, "checkApp", "app", s.appKey)
	// Check for various policy violations which we must correct.
	// 1. Num Active AppInsts below a policy min.
	// 2. Total AppInsts above a policy max.
	// 3. Orphaned AutoProvisioned AppInsts (cloudlet no longer part
	// of policy, or policy no longer on App)

	if !s.caches.appCache.Get(s.appKey, &s.app) {
		// may have been deleted
		return
	}

	refs := edgeproto.AppInstRefs{}
	if !s.caches.appInstRefsCache.Get(s.appKey, &refs) {
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
	policies := getPolicies(&s.app)
	for pname, _ := range policies {
		s.checkPolicy(ctx, pname, prevPolicyCloudlets)
	}

	// delete any AppInsts that are orphaned
	// (no longer on policy cloudlets)
	for ckey, insts := range s.cloudletInsts {
		if _, found := s.policyCloudlets[ckey]; found {
			continue
		}
		for appInstKey, _ := range insts {
			if !isAutoProvInst(&appInstKey) {
				continue
			}
			inst := edgeproto.AppInst{
				Key: appInstKey,
			}
			go goAppInstApi(ctx, &inst, cloudcommon.Delete, cloudcommon.AutoProvReasonOrphaned, "")
		}
	}
}

func (s *AppChecker) checkPolicy(ctx context.Context, pname string, prevPolicyCloudlets map[edgeproto.CloudletKey]struct{}) {
	log.SpanLog(ctx, log.DebugLevelMetrics, "checkPolicy", "app", s.appKey, "policy", pname)
	policy := edgeproto.AutoProvPolicy{}
	policyKey := edgeproto.PolicyKey{
		Name:         pname,
		Organization: s.app.Key.Organization,
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
			// see if free reservable ClusterInst exists
			freeClustKey := s.caches.frClusterInsts.GetForCloudlet(&apCloudlet.Key, s.app.Deployment)
			if freeClustKey != nil {
				appInstKey := edgeproto.AppInstKey{
					AppKey:         *s.appKey,
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
				if isAutoProvInst(&appInstKey) {
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

	if totalCount >= int(policy.MaxInstances) {
		// don't bother with min because we're already at max
		return
	}

	// Check min
	createKeys := s.chooseCreate(ctx, potentialCreate, int(policy.MinActiveInstances)-onlineCount)
	for _, key := range createKeys {
		inst := edgeproto.AppInst{
			Key: key,
		}
		go goAppInstApi(ctx, &inst, cloudcommon.Create, cloudcommon.AutoProvReasonMinMax, pname)
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

	appStats, found := autoProvAggr.allStats[*s.appKey]
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
	appInst := edgeproto.AppInst{}
	if !s.caches.appInstCache.Get(key, &appInst) {
		return false
	}
	return cloudcommon.AutoProvAppInstOnline(&appInst, &cloudletInfo)
}

func isAutoProvInst(key *edgeproto.AppInstKey) bool {
	// Assumes:
	// 1. this is not a prometheus app
	// 2. users cannot deploy manually to MobiledgeX ClusterInsts
	if key.ClusterInstKey.Organization == cloudcommon.OrganizationMobiledgeX {
		return true
	}
	return false
}
