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

package autoprov

import (
	"context"
	"fmt"
	"sort"
	"sync"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/util/tasks"
)

// MinMaxChecker maintains the minimum and maximum number of
// AppInsts if specified in the policy.
type MinMaxChecker struct {
	caches           *CacheData
	failoverRequests map[edgeproto.CloudletKey]*failoverReq
	mux              sync.Mutex
	// maintain reverse relationships to be able to look up
	// which Apps are affected by cloudlet state changes.
	policiesByZone          edgeproto.AutoProvPolicyByZoneKey
	appsByPolicy            edgeproto.AppByAutoProvPolicy
	autoprovInstsByCloudlet edgeproto.AppInstLookup2ByCloudletKey
	workers                 tasks.KeyWorkers
}

func newMinMaxChecker(caches *CacheData) *MinMaxChecker {
	s := MinMaxChecker{}
	s.caches = caches
	s.failoverRequests = make(map[edgeproto.CloudletKey]*failoverReq)
	s.workers.Init("autoprov-minmax", s.CheckApp)
	s.policiesByZone.Init()
	s.appsByPolicy.Init()
	s.autoprovInstsByCloudlet.Init()
	// set callbacks to respond to changes
	caches.appCache.AddUpdatedCb(s.UpdatedApp)
	caches.appCache.AddDeletedCb(s.DeletedApp)
	caches.appInstCache.AddUpdatedCb(s.UpdatedAppInst)
	caches.appInstCache.AddDeletedCb(s.DeletedAppInst)
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
	s.policiesByZone.Updated(old, new)
	// check all Apps that use policy
	for _, appKey := range s.appsByPolicy.Find(new.Key) {
		s.workers.NeedsWork(ctx, appKey)
	}
}

func (s *MinMaxChecker) DeletedPolicy(ctx context.Context, old *edgeproto.AutoProvPolicy) {
	s.policiesByZone.Deleted(old)
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

	cloudlet := edgeproto.Cloudlet{}
	if !s.caches.cloudletCache.Get(&key, &cloudlet) {
		return appsToCheck
	}
	zoneKey := cloudlet.GetZone()

	policies := s.policiesByZone.Find(*zoneKey)
	for _, policyKey := range policies {
		apps := s.appsByPolicy.Find(policyKey)
		for _, appKey := range apps {
			appsToCheck[appKey] = struct{}{}
		}
	}
	// If orphaned AppInsts cannot be deleted at the time they are
	// removed from the policy, then they end up with no reference to
	// them via the policies. So they are tracked in here so they can
	// be cleaned up later when the Cloudlet comes back online.
	for _, appInstKey := range s.autoprovInstsByCloudlet.Find(key) {
		appInst := edgeproto.AppInst{}
		if !s.caches.appInstCache.Get(&appInstKey, &appInst) {
			continue
		}
		appsToCheck[appInst.AppKey] = struct{}{}
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
		log.SpanLog(ctx, log.DebugLevelApi, "cloudlet no online change", "new", new)
		s.handleFailoverReq(ctx, new, nil)
		return
	}
	log.SpanLog(ctx, log.DebugLevelNotify, "cloudlet online change", "new", new)
	appsToCheck := s.cloudletNeedsCheck(new.Key)
	s.handleFailoverReq(ctx, new, appsToCheck)
	for appKey, _ := range appsToCheck {
		s.workers.NeedsWork(ctx, appKey)
	}
}

// Caller must hold MinMaxChecker.mux
func (s *MinMaxChecker) handleFailoverReq(ctx context.Context, cloudlet *edgeproto.Cloudlet, appsToCheck map[edgeproto.AppKey]struct{}) {
	if cloudlet.MaintenanceState != dme.MaintenanceState_FAILOVER_REQUESTED {
		// not a failover request
		return
	}
	if appsToCheck == nil || len(appsToCheck) == 0 {
		log.SpanLog(ctx, log.DebugLevelApi, "cloudlet failover request but no apps to check", "key", cloudlet.Key)
		// no apps to trigger reply so send reply now
		info := edgeproto.AutoProvInfo{}
		info.Key = cloudlet.Key
		info.MaintenanceState = dme.MaintenanceState_FAILOVER_DONE
		s.caches.autoProvInfoCache.Update(ctx, &info, 0)
		return
	}
	// put request in table, app checker will send response once all apps
	// are processed.
	req, found := s.failoverRequests[cloudlet.Key]
	if !found {
		req = &failoverReq{}
		req.info.Key = cloudlet.Key
		req.appsToCheck = appsToCheck
		s.failoverRequests[cloudlet.Key] = req
	} else {
		req.mux.Lock()
		for appKey, _ := range appsToCheck {
			req.appsToCheck[appKey] = struct{}{}
		}
		req.mux.Unlock()
	}
}

func (s *MinMaxChecker) UpdatedAppInst(ctx context.Context, old *edgeproto.AppInst, new *edgeproto.AppInst) {
	s.mux.Lock()
	defer s.mux.Unlock()

	if !s.isAutoProvApp(&new.AppKey) {
		return
	}

	lookup := edgeproto.AppInstLookup2{
		Key:         new.Key,
		CloudletKey: new.CloudletKey,
	}
	s.autoprovInstsByCloudlet.Updated(&lookup)

	// recheck if online state changed
	if old != nil {
		cloudletInfo := edgeproto.CloudletInfo{}
		if !s.caches.cloudletInfoCache.Get(&new.CloudletKey, &cloudletInfo) {
			log.SpanLog(ctx, log.DebugLevelMetrics, "UpdatedAppInst cloudletInfo not found", "app", new.Key, "cloudlet", new.CloudletKey)
			return
		}
		cloudlet := edgeproto.Cloudlet{}
		if !s.caches.cloudletCache.Get(&new.CloudletKey, &cloudlet) {
			log.SpanLog(ctx, log.DebugLevelMetrics, "UpdatedAppInst cloudlet not found", "app", new.Key, "cloudlet", new.CloudletKey)
			return
		}
		if cloudcommon.AutoProvAppInstOnline(old, &cloudletInfo, &cloudlet) ==
			cloudcommon.AutoProvAppInstOnline(new, &cloudletInfo, &cloudlet) {
			// no state change, no check needed
			return
		}
	}
	s.workers.NeedsWork(ctx, new.AppKey)
}

func (s *MinMaxChecker) DeletedAppInst(ctx context.Context, inst *edgeproto.AppInst) {
	s.mux.Lock()
	defer s.mux.Unlock()

	if inst == nil || !s.isAutoProvApp(&inst.AppKey) {
		return
	}
	lookup := edgeproto.AppInstLookup2{
		Key:         inst.Key,
		CloudletKey: inst.CloudletKey,
	}
	s.autoprovInstsByCloudlet.Deleted(&lookup)

	s.workers.NeedsWork(ctx, inst.AppKey)
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
		log.SpanLog(ctx, log.DebugLevelMetrics, "Unexpected failure, key not AppKey", "key", k)
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
		s.mux.Lock()
		finished := req.appDone(ctx, key)
		if !finished {
			s.mux.Unlock()
			continue
		}
		delete(s.failoverRequests, req.info.Key)
		s.mux.Unlock()

		// wait for any App API calls to finish, then send back result
		go func(ctx context.Context, r *failoverReq) {
			span, ctx := log.ChildSpan(ctx, log.DebugLevelApi, "failover request done")
			defer span.Finish()
			log.SetTags(span, r.info.Key.GetTags())

			r.waitApiCalls.Wait()
			if len(r.info.Errors) == 0 {
				r.info.MaintenanceState = dme.MaintenanceState_FAILOVER_DONE
			} else {
				r.info.MaintenanceState = dme.MaintenanceState_FAILOVER_ERROR
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
	zoneInsts       map[edgeproto.ZoneKey]map[edgeproto.AppInstKey]edgeproto.CloudletKey
	policyZones     map[edgeproto.ZoneKey]struct{}
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
	checker.zoneInsts = make(map[edgeproto.ZoneKey]map[edgeproto.AppInstKey]edgeproto.CloudletKey)
	// Cloudlets in use by the policies on this App.
	// We will use this to delete any auto-provisioned instances
	// of this App that are orphaned.
	checker.policyZones = make(map[edgeproto.ZoneKey]struct{})
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
		refInst := edgeproto.AppInst{}
		if !s.caches.appInstCache.Get(&key, &refInst) {
			continue
		}
		insts, found := s.zoneInsts[refInst.ZoneKey]
		if !found {
			insts = make(map[edgeproto.AppInstKey]edgeproto.CloudletKey)
			s.zoneInsts[refInst.ZoneKey] = insts
		}
		insts[key] = refInst.CloudletKey
	}

	prevPolicyCloudlets := make(map[edgeproto.CloudletKey]struct{})
	policies := app.GetAutoProvPolicies()
	for pname, _ := range policies {
		s.checkPolicy(ctx, &app, pname, prevPolicyCloudlets)
	}

	// delete any AppInsts that are orphaned
	// (no longer on policy cloudlets)
	for zkey, insts := range s.zoneInsts {
		if _, found := s.policyZones[zkey]; found {
			continue
		}
		for appInstKey, ckey := range insts {
			if !s.isAutoProvInst(&appInstKey) {
				continue
			}
			inst := edgeproto.AppInst{
				Key:         appInstKey,
				AppKey:      app.Key,
				CloudletKey: ckey,
				ZoneKey:     zkey,
			}
			go goAppInstApi(ctx, &inst, cloudcommon.Delete, cloudcommon.AutoProvReasonOrphaned, "")
		}
	}
}

type HasItType int

const (
	NotHasIt HasItType = 0
	HasIt    HasItType = 1
)

type potentialCreateSite struct {
	zoneKey edgeproto.ZoneKey
	hasFree HasItType
}

type potentialCreateSites struct {
	sites []*potentialCreateSite
	next  int
	mux   sync.Mutex
}

func (s *potentialCreateSites) getNext() *potentialCreateSite {
	var site *potentialCreateSite
	if s.next < len(s.sites) {
		site = s.sites[s.next]
		s.next++
	}
	return site
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
	potentialCreate := []*potentialCreateSite{}
	onlineCount := 0
	totalCount := 0
	// check AppInsts on the policy's zones
	for _, zkey := range policy.Zones {
		s.policyZones[*zkey] = struct{}{}

		insts, found := s.zoneInsts[*zkey]
		if !found {
			if !s.zoneOnline(zkey) {
				continue
			}
			if retryTracker.hasFailure(ctx, app.Key, *zkey) {
				continue
			}
			pt := &potentialCreateSite{
				zoneKey: *zkey,
			}
			for _, ckey := range s.caches.cloudletCache.CloudletsForZone(zkey) {
				// see if free reservable ClusterInst exists
				freeClusts := s.caches.frClusterInsts.GetForCloudlet(ctx, &ckey, app.Deployment, app.KubernetesResources, app.NodeResources, cloudcommon.AppInstToClusterDeployment)
				if len(freeClusts) > 0 {
					pt.hasFree = HasIt
					break
				}
			}
			potentialCreate = append(potentialCreate, pt)
		} else {
			for appInstKey, _ := range insts {
				totalCount++
				// Also assume AppInsts coming online can be
				// counted as online. This prevents non-deterministic
				// behavior for which cloudlets end up with
				// the AppInst created on them. It could
				// potentially cause problems if AppInsts are
				// stuck in a going-online transitional state,
				// however.
				if s.appInstOnlineOrGoingOnline(ctx, &appInstKey) {
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
	if policy.MaxInstances > 0 {
		deleteKeys := s.chooseDelete(ctx, potentialDelete, totalCount-int(policy.MaxInstances))
		for _, key := range deleteKeys {
			inst := edgeproto.AppInst{
				Key:    key,
				AppKey: app.Key,
			}
			go goAppInstApi(ctx, &inst, cloudcommon.Delete, cloudcommon.AutoProvReasonMinMax, pname)
		}
		if totalCount >= int(policy.MaxInstances) {
			// don't bother with min because we're already at max
			return
		}
	}

	// Check min
	needCreateCount := int(policy.MinActiveInstances) - onlineCount
	potentialCreate = s.sortPotentialCreate(ctx, potentialCreate)
	if len(potentialCreate) < needCreateCount {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Not enough potential Cloudlets to meet min constraint", "App", s.appKey, "policy", pname, "min", policy.MinActiveInstances)
		str := fmt.Sprintf("Not enough potential cloudlets to deploy to for App %s to meet policy %s min constraint %d", s.appKey.GetKeyString(), pname, policy.MinActiveInstances)
		for _, req := range s.failoverReqs {
			req.addError(str)
		}
	}
	createSites := potentialCreateSites{
		sites: potentialCreate,
	}
	// Spawn the same number of threads as the number of AppInsts we need
	// to create. Each thread will try to create a single AppInst.
	// If a create fails, it will retry with the next best potential
	// cloudlet in the list. This will continue until each thread has
	// created a single AppInst, or we've run out of sites to try.
	// These could potentially overlap with a retry of this App,
	// but that's ok for create since the Controller will prevent
	// extra creates to meet the min.
	log.SpanLog(ctx, log.DebugLevelMetrics, "auto-prov create min workers", "needCreateCount", needCreateCount, "numPotential", len(potentialCreate))
	for ii := 0; ii < needCreateCount && ii < len(potentialCreate); ii++ {
		for _, req := range s.failoverReqs {
			req.waitApiCalls.Add(1)
		}
		go func(workerNum int) {
			span, ctx := log.ChildSpan(ctx, log.DebugLevelMetrics, "auto-prov create for min worker")
			defer span.Finish()
			log.SetTags(span, s.appKey.GetTags())
			for attempt := 0; ; attempt++ {
				site := createSites.getNext()
				if site == nil {
					break
				}
				log.SpanLog(ctx, log.DebugLevelMetrics, "auto-prov create min worker", "workerNum", workerNum, "site", site, "attempt", attempt)
				inst := edgeproto.AppInst{}
				inst.Key = cloudcommon.GetAutoProvAppInstKey(&app.Key, &site.zoneKey)
				inst.AppKey = app.Key
				inst.ZoneKey = site.zoneKey

				err := goAppInstApi(ctx, &inst, cloudcommon.Create, cloudcommon.AutoProvReasonMinMax, pname)
				if err == nil {
					str := fmt.Sprintf("Created AppInst %s to meet policy %s min constraint %d", inst.Key.GetKeyString(), pname, policy.MinActiveInstances)
					for _, req := range s.failoverReqs {
						req.addCompleted(str)
					}
				} else if ignoreDeployError(&inst, err) {
					log.SpanLog(ctx, log.DebugLevelMetrics, "auto-prov ignore deploy error", "workerNum", workerNum, "attempt", attempt, "err", err)
					err = nil
				} else {
					str := fmt.Sprintf("Failed to create AppInst %s to meet policy %s min constraint %d: %s", inst.Key.GetKeyString(), pname, policy.MinActiveInstances, err)
					for _, req := range s.failoverReqs {
						req.addError(str)
					}
				}
				if err == nil {
					break
				}
				attempt++
			}
			for _, req := range s.failoverReqs {
				req.waitApiCalls.Done()
			}
		}(ii)
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

func (s *AppChecker) sortPotentialCreate(ctx context.Context, potential []*potentialCreateSite) []*potentialCreateSite {
	if len(potential) <= 1 {
		return potential
	}

	autoProvAggr.mux.Lock()
	defer autoProvAggr.mux.Unlock()

	appStats, statsFound := autoProvAggr.allStats[s.appKey]

	sort.Slice(potential, func(i, j int) bool {
		p1 := potential[i]
		p2 := potential[j]
		if p1.hasFree != p2.hasFree {
			// prefer cloudlets that have a matching free ClusterInst
			return p1.hasFree > p2.hasFree
		}
		if !statsFound {
			// no stats so preserve existing order in list
			return false
		}
		// sort to put highest client demand first
		// client demand is only tracked for the last interval,
		// and is scaled by the deploy client count.
		zkey1 := p1.zoneKey
		zkey2 := p2.zoneKey

		var incr1, incr2 uint64
		if cstats, found := appStats.zones[zkey1]; found && cstats.intervalNum == autoProvAggr.intervalNum {
			incr1 = cstats.count - cstats.lastCount
		}
		if cstats, found := appStats.zones[zkey2]; found && cstats.intervalNum == autoProvAggr.intervalNum {
			incr2 = cstats.count - cstats.lastCount
		}
		log.SpanLog(ctx, log.DebugLevelMetrics, "chooseCreate stats", "cloudlet1", zkey1, "cloudlet2", zkey2, "incr1", incr1, "incr2", incr2)
		return incr1 > incr2
	})
	return potential
}

func (s *AppChecker) appInstOnlineOrGoingOnline(ctx context.Context, key *edgeproto.AppInstKey) (retval bool) {
	cloudletInfo := edgeproto.CloudletInfo{}
	cloudlet := edgeproto.Cloudlet{}
	appInst := edgeproto.AppInst{}
	online := false
	goingOnline := false
	defer func() {
		log.SpanLog(ctx, log.DebugLevelMetrics, "appInstOnlineOrGoingOnline", "cloudletInfo.State", cloudletInfo.State, "cloudlet.State", cloudlet.State, "cloudlet.MaintenanceState", cloudlet.MaintenanceState, "appInst.State", appInst.State, "appInst.HealthCheck", appInst.HealthCheck, "online", online, "goingOnline", goingOnline, "retval", retval)
	}()
	if !s.caches.appInstCache.Get(key, &appInst) {
		log.SpanLog(ctx, log.DebugLevelMetrics, "appInstOnlineOrGoingOnline AppInst not found", "key", key)
		return false
	}
	if !s.caches.cloudletInfoCache.Get(&appInst.CloudletKey, &cloudletInfo) {
		log.SpanLog(ctx, log.DebugLevelMetrics, "appInstOnlineOrGoingOnline CloudletInfo not found", "key", appInst.CloudletKey)
		return false
	}
	if !s.caches.cloudletCache.Get(&appInst.CloudletKey, &cloudlet) {
		log.SpanLog(ctx, log.DebugLevelMetrics, "appInstOnlineOrGoingOnline Cloudlet not found", "key", appInst.CloudletKey)
		return false
	}
	online = cloudcommon.AutoProvAppInstOnline(&appInst, &cloudletInfo, &cloudlet)
	goingOnline = cloudcommon.AutoProvAppInstGoingOnline(&appInst, &cloudletInfo, &cloudlet)
	return online || goingOnline
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

func (s *AppChecker) zoneOnline(key *edgeproto.ZoneKey) bool {
	filter := edgeproto.Cloudlet{
		Key: edgeproto.CloudletKey{
			Organization: key.Organization,
		},
		Zone: key.Name,
	}
	cloudletKeys := []edgeproto.CloudletKey{}
	s.caches.cloudletCache.Show(&filter, func(obj *edgeproto.Cloudlet) error {
		cloudletKeys = append(cloudletKeys, obj.Key)
		return nil
	})
	for _, ckey := range cloudletKeys {
		if s.cloudletOnline(&ckey) {
			return true
		}
	}
	return false
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
