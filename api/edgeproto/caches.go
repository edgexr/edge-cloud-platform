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

package edgeproto

import (
	"fmt"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	context "golang.org/x/net/context"
)

// Common extra support code for caches

type CacheUpdateType int

const (
	UpdateTask CacheUpdateType = 0
	UpdateStep CacheUpdateType = 1

	ResetStatus   bool = true
	NoResetStatus bool = false
)

type ObjCache interface {
	SyncUpdate(ctx context.Context, key, val []byte, rev, modRev int64)
	SyncDelete(ctx context.Context, key []byte, rev, modRev int64)
	SyncListStart(ctx context.Context)
	SyncListEnd(ctx context.Context)
	GetTypeString() string
	UsesOrg(org string) bool
}

type ClusterInstCacheUpdateParms struct {
	cache      *ClusterInstInfoCache
	updateType CacheUpdateType
	value      string
}

// CacheUpdateCallback updates either state or task with the given value
type CacheUpdateCallback func(updateType CacheUpdateType, value string)

// DummyUpdateCallback is used when we don't want any cache status updates
func DummyUpdateCallback(updateType CacheUpdateType, value string) {}

// GetForCloudlet gets all cloudlet nodes associated with the given cloudlet
func (s *CloudletNodeCache) GetForCloudlet(cloudlet *Cloudlet, cb func(cloudletNodeData *CloudletNodeCacheData)) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	for _, v := range s.Objs {
		if v.Obj.Key.CloudletKey.Matches(&cloudlet.Key) {
			cb(v.Clone())
		}
	}
}

// GetAppInstsForCloudlets finds all AppInsts associated with the given cloudlets
func (s *AppInstCache) GetForCloudlet(cloudlet *Cloudlet, cb func(appInstData *AppInstCacheData)) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	for _, v := range s.Objs {
		if v.Obj.Key.CloudletKey == cloudlet.Key {
			cb(v.Clone())
		}
	}
}

func (s *AppInstCache) GetForRealClusterInstKey(key *ClusterInstKey, cb func(appInst *AppInst)) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	for _, v := range s.Objs {
		obj := v.Obj
		clusterInstKey := obj.ClusterInstKey()
		if !key.Matches(clusterInstKey) {
			continue
		}
		cb(obj)
	}
}

// GetForCloudlet finds all ClusterInsts associated with the
// given cloudlets
func (s *ClusterInstCache) GetForCloudlet(cloudlet *Cloudlet, cb func(clusterInstData *ClusterInstCacheData)) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	for _, v := range s.Objs {
		if v.Obj.Key.CloudletKey == cloudlet.Key {
			cb(v.Clone())
		}
	}
}

func (s *ClusterInstInfoCache) SetState(ctx context.Context, key *ClusterInstKey, state TrackedState) error {
	var err error
	s.UpdateModFunc(ctx, key, 0, func(old *ClusterInstInfo) (newObj *ClusterInstInfo, changed bool) {
		info := &ClusterInstInfo{}
		if old == nil {
			info.Key = *key
			info.Status = StatusInfo{}
		} else {
			err = StateConflict(old.State, state)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelApi, "SetState conflict", "oldState", old.State, "newState", state, "err", err)
				return old, false
			}
			*info = *old
		}
		info.Errors = nil
		info.State = state
		return info, true
	})
	return err
}

func (s *ClusterInstInfoCache) SetResources(ctx context.Context, key *ClusterInstKey, resources *InfraResources) error {
	info := ClusterInstInfo{}
	if !s.Get(key, &info) {
		log.SpanLog(ctx, log.DebugLevelApi, "SetResources failed, did not find clusterInst in cache")
		return fmt.Errorf("ClusterInst not found in cache: %s", key.String())
	}
	info.Resources = *resources
	s.Update(ctx, &info, 0)
	return nil
}

func (s *ClusterInstInfoCache) SetStatusTask(ctx context.Context, key *ClusterInstKey, taskName string, resetStatus bool) {
	log.SpanLog(ctx, log.DebugLevelApi, "SetStatusTask", "key", key, "taskName", taskName)
	info := ClusterInstInfo{}
	if !s.Get(key, &info) {
		// we don't want to override the state in the cache if it is not present
		log.InfoLog("SetStatusTask failed, did not find clusterInst in cache")
		return
	}
	if resetStatus {
		info.Status.StatusReset()
	}
	info.Status.SetTask(taskName)
	s.Update(ctx, &info, 0)
}

func (s *ClusterInstInfoCache) SetStatusMaxTasks(ctx context.Context, key *ClusterInstKey, maxTasks uint32) {
	log.SpanLog(ctx, log.DebugLevelApi, "SetStatusMaxTasks", "key", key, "maxTasks", maxTasks)
	info := ClusterInstInfo{}
	if !s.Get(key, &info) {
		// we don't want to override the state in the cache if it is not present
		log.InfoLog("SetStatusMaxTasks failed, did not find clusterInst in cache")
		return
	}
	info.Status.SetMaxTasks(maxTasks)
	s.Update(ctx, &info, 0)
}

func (s *ClusterInstInfoCache) SetStatusStep(ctx context.Context, key *ClusterInstKey, stepName string, resetStatus bool) {
	log.SpanLog(ctx, log.DebugLevelApi, "SetStatusStep", "key", key, "stepName", stepName)
	info := ClusterInstInfo{}
	if !s.Get(key, &info) {
		// we don't want to override the state in the cache if it is not present
		log.InfoLog("SetStatusStep failed, did not find clusterInst in cache")
		return
	}
	if resetStatus {
		info.Status.StatusReset()
	}
	info.Status.SetStep(stepName)
	s.Update(ctx, &info, 0)
}

func (s *ClusterInstInfoCache) SetError(ctx context.Context, key *ClusterInstKey, errState TrackedState, err string) {
	info := ClusterInstInfo{}
	if !s.Get(key, &info) {
		info.Key = *key
	}
	info.Errors = append(info.Errors, err)
	info.State = errState
	s.Update(ctx, &info, 0)
}

func (s *ClusterInstInfoCache) RefreshObj(ctx context.Context, obj *ClusterInst) {
	info := ClusterInstInfo{}
	if s.Get(&obj.Key, &info) {
		// already saved
		return
	}
	info.Key = obj.Key
	info.State = obj.State
	info.Errors = obj.Errors
	info.Resources = obj.Resources
	s.Update(ctx, &info, 0)
}

// If CRM crashes or reconnects to controller, controller will resend
// current state. This is needed to:
// -restart actions that were lost due to a crash
// -update cache for dependent objects (AppInst looks up ClusterInst from
// cache).
// If it was a disconnect and not a restart, there may already be a
// thread in progress. To prevent multiple conflicting threads, check
// the state which can tell us if a thread is in progress.
func StateConflict(oldState, newState TrackedState) error {
	busyStates := []TrackedState{
		TrackedState_CREATING,
		TrackedState_UPDATING,
		TrackedState_DELETING,
	}

	oldBusy := false
	newBusy := false
	for _, state := range busyStates {
		if oldState == state {
			oldBusy = true
		}
		if newState == state {
			newBusy = true
		}
	}
	if oldBusy && newBusy {
		return fmt.Errorf("conflicting state: %s", oldState)
	}
	return nil
}

func PowerStateConflict(oldState, newState PowerState) error {
	busyStates := []PowerState{
		PowerState_POWERING_ON,
		PowerState_POWERING_OFF,
		PowerState_REBOOTING,
	}

	oldBusy := false
	newBusy := false
	for _, state := range busyStates {
		if oldState == state {
			oldBusy = true
		}
		if newState == state {
			newBusy = true
		}
	}
	if oldBusy && newBusy {
		return fmt.Errorf("conflicting state: %s", oldState)
	}
	return nil
}

func IsTransientState(state TrackedState) bool {
	if state == TrackedState_CREATING ||
		state == TrackedState_CREATING_DEPENDENCIES ||
		state == TrackedState_CREATE_REQUESTED ||
		state == TrackedState_UPDATE_REQUESTED ||
		state == TrackedState_DELETE_REQUESTED ||
		state == TrackedState_UPDATING ||
		state == TrackedState_DELETING ||
		state == TrackedState_DELETE_PREPARE {
		return true
	}
	return false
}

func IsDeleteState(state TrackedState) bool {
	if state == TrackedState_DELETE_REQUESTED ||
		state == TrackedState_DELETING ||
		state == TrackedState_DELETE_PREPARE ||
		state == TrackedState_DELETE_DONE {
		return true
	}
	return false
}

type PowerStateType int

const (
	RequestState   PowerStateType = 0
	TransientState PowerStateType = 1
	FinalState     PowerStateType = 2
)

func GetNextPowerState(state PowerState, stateType PowerStateType) PowerState {
	switch stateType {
	case RequestState:
		if state == PowerState_POWER_ON {
			return PowerState_POWER_ON_REQUESTED
		} else if state == PowerState_POWER_OFF {
			return PowerState_POWER_OFF_REQUESTED
		} else if state == PowerState_REBOOT {
			return PowerState_REBOOT_REQUESTED
		}
	case TransientState:
		if state == PowerState_POWER_ON_REQUESTED {
			return PowerState_POWERING_ON
		} else if state == PowerState_POWER_OFF_REQUESTED {
			return PowerState_POWERING_OFF
		} else if state == PowerState_REBOOT_REQUESTED {
			return PowerState_REBOOTING
		}
	case FinalState:
		if state == PowerState_POWERING_ON {
			return PowerState_POWER_ON
		} else if state == PowerState_POWERING_OFF {
			return PowerState_POWER_OFF
		} else if state == PowerState_REBOOTING {
			return PowerState_POWER_ON
		}
	}
	return PowerState_POWER_STATE_UNKNOWN
}

func (s *AppInstInfoCache) SetPowerState(ctx context.Context, key *AppInstKey, state PowerState) error {
	var err error
	s.UpdateModFunc(ctx, key, 0, func(old *AppInstInfo) (newObj *AppInstInfo, changed bool) {
		info := &AppInstInfo{}
		if old == nil {
			info.Key = *key
			info.Status = StatusInfo{}
		} else {
			err = PowerStateConflict(old.PowerState, state)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelApi, "SetPowerState conflict", "oldState", old.PowerState, "newState", state, "err", err)
				return old, false
			}
			*info = *old
		}
		info.Errors = nil
		info.PowerState = state
		return info, true
	})
	return err
}

func (s *AppInstInfoCache) SetState(ctx context.Context, key *AppInstKey, state TrackedState) error {
	var err error
	s.UpdateModFunc(ctx, key, 0, func(old *AppInstInfo) (newObj *AppInstInfo, changed bool) {
		info := &AppInstInfo{}
		if old == nil {
			info.Key = *key
			info.Status = StatusInfo{}
		} else {
			err = StateConflict(old.State, state)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelApi, "SetState conflict", "oldState", old.State, "newState", state, "err", err)
				return old, false
			}
			*info = *old
		}
		info.Errors = nil
		info.State = state
		return info, true
	})
	return err
}

func (s *AppInstInfoCache) SetUri(ctx context.Context, key *AppInstKey, uri string) {
	if uri == "" {
		return
	}
	s.UpdateModFunc(ctx, key, 0, func(old *AppInstInfo) (newObj *AppInstInfo, changed bool) {
		info := &AppInstInfo{}
		if old == nil {
			info.Key = *key
		} else {
			*info = *old
		}
		info.Uri = uri
		return info, true
	})
	return
}

func (s *AppInstInfoCache) SetFedAppInstKey(ctx context.Context, key *AppInstKey, fedKey FedAppInstKey) {
	if fedKey.FederationName == "" {
		return
	}
	s.UpdateModFunc(ctx, key, 0, func(old *AppInstInfo) (newObj *AppInstInfo, changed bool) {
		info := &AppInstInfo{}
		if old == nil {
			info.Key = *key
		} else {
			*info = *old
		}
		info.FedKey = fedKey
		return info, true
	})
	return
}

func (s *AppInstInfoCache) SetStateRuntime(ctx context.Context, key *AppInstKey, state TrackedState, rt *AppInstRuntime) {
	info := AppInstInfo{}
	if !s.Get(key, &info) {
		info.Key = *key
		info.Status = StatusInfo{}
	}
	info.Errors = nil
	info.State = state
	info.RuntimeInfo = *rt
	s.Update(ctx, &info, 0)
}

func (s *AppInstInfoCache) SetStatusMaxTasks(ctx context.Context, key *AppInstKey, maxTasks uint32) {
	log.SpanLog(ctx, log.DebugLevelApi, "SetStatusMaxTasks", "key", key, "maxTasks", maxTasks)
	info := AppInstInfo{}
	if !s.Get(key, &info) {
		// we don't want to override the state in the cache if it is not present
		log.InfoLog("SetStatusTaskMax failed, did not find appInstInfo in cache")
		return
	}
	info.Status.SetMaxTasks(maxTasks)
	s.Update(ctx, &info, 0)
}

func (s *AppInstInfoCache) SetStatusTask(ctx context.Context, key *AppInstKey, taskName string, resetStatus bool) {
	log.SpanLog(ctx, log.DebugLevelApi, "SetStatusTask", "key", key, "taskName", taskName)
	info := AppInstInfo{}
	if !s.Get(key, &info) {
		// we don't want to override the state in the cache if it is not present
		log.InfoLog("SetStatusTask failed, did not find appInstInfo in cache")
		return
	}
	if resetStatus {
		info.Status.StatusReset()
	}
	info.Status.SetTask(taskName)
	s.Update(ctx, &info, 0)
}

func (s *AppInstInfoCache) SetStatusStep(ctx context.Context, key *AppInstKey, stepName string, resetStatus bool) {
	log.SpanLog(ctx, log.DebugLevelApi, "SetStatusStep", "key", key, "stepName", stepName)
	info := AppInstInfo{}
	if !s.Get(key, &info) {
		// we don't want to override the state in the cache if it is not present
		log.InfoLog("SetStatusStep failed, did not find appInstInfo in cache")
		return
	}
	if resetStatus {
		info.Status.StatusReset()
	}
	info.Status.SetStep(stepName)
	s.Update(ctx, &info, 0)
}

func (s *AppInstInfoCache) SetError(ctx context.Context, key *AppInstKey, errState TrackedState, err string) {
	info := AppInstInfo{}
	if !s.Get(key, &info) {
		info.Key = *key
	}
	info.Errors = append(info.Errors, err)
	info.State = errState
	s.Update(ctx, &info, 0)
}

func (s *AppInstInfoCache) RefreshObj(ctx context.Context, obj *AppInst) {
	info := AppInstInfo{}
	if s.Get(&obj.Key, &info) {
		// already saved
		return
	}
	info.Key = obj.Key
	info.State = obj.State
	info.Errors = obj.Errors
	info.RuntimeInfo = obj.RuntimeInfo
	info.PowerState = obj.PowerState
	info.Uri = obj.Uri
	s.Update(ctx, &info, 0)
}

func (s *CloudletInfoCache) SetStatusTask(ctx context.Context, key *CloudletKey, taskName string) {
	log.SpanLog(ctx, log.DebugLevelApi, "SetStatusTask", "key", key, "taskName", taskName)
	info := CloudletInfo{}
	if !s.Get(key, &info) {
		// we don't want to override the state in the cache if it is not present
		log.InfoLog("SetStatusTask failed, did not find CloudletInfo in cache")
		return
	}
	info.Status.SetTask(taskName)
	s.Update(ctx, &info, 0)
}

func (s *CloudletInfoCache) SetStatusStep(ctx context.Context, key *CloudletKey, stepName string) {
	log.SpanLog(ctx, log.DebugLevelApi, "SetStatusStep", "key", key, "stepName", stepName)
	info := CloudletInfo{}
	if !s.Get(key, &info) {
		// we don't want to override the state in the cache if it is not present
		log.InfoLog("SetStatusStep failed, did not find CloudletInfo in cache")
		return
	}
	info.Status.SetStep(stepName)
	s.Update(ctx, &info, 0)
}

func (s *CloudletPoolCache) GetPoolsForCloudletKey(in *CloudletKey) ([]CloudletPoolKey, error) {
	var cloudletPoolKeys []CloudletPoolKey

	log.DebugLog(log.DebugLevelApi, "GetPoolsForCloudletKey()", "len(CloudletPoolCache.Objs):", len(s.Objs), "CloudletKey:", in)

	cloudletPoolKeyFilter := CloudletPoolKey{
		Organization: in.Organization,
	}
	cloudletPoolFilter := CloudletPool{
		Key:       cloudletPoolKeyFilter,
		Cloudlets: []CloudletKey{*in},
	}
	s.Show(&cloudletPoolFilter, func(obj *CloudletPool) error {
		cloudletPoolKeys = append(cloudletPoolKeys, obj.Key)
		log.DebugLog(log.DebugLevelApi, "GetPoolsForCloudletKey() found ", "CloudletPoolCache key:", obj.Key)
		return nil
	})

	if len(cloudletPoolKeys) == 0 {
		log.DebugLog(log.DebugLevelApi, "GetPoolsForCloudletKey() not found ", "CloudletKey:", in)
	}
	return cloudletPoolKeys, nil
}

func (s *VMPoolInfoCache) SetState(ctx context.Context, key *VMPoolKey, state TrackedState) error {
	var err error
	s.UpdateModFunc(ctx, key, 0, func(old *VMPoolInfo) (newObj *VMPoolInfo, changed bool) {
		info := &VMPoolInfo{}
		if old == nil {
			info.Key = *key
			info.Status = StatusInfo{}
		} else {
			err = StateConflict(old.State, state)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelApi, "SetState conflict", "oldState", old.State, "newState", state, "err", err)
				return old, false
			}
			*info = *old
		}
		info.Errors = nil
		info.State = state
		return info, true
	})
	return err
}

func (s *VMPoolInfoCache) SetError(ctx context.Context, key *VMPoolKey, errState TrackedState, err string) {
	info := VMPoolInfo{}
	if !s.Get(key, &info) {
		info.Key = *key
	}
	info.Errors = append(info.Errors, err)
	info.State = errState
	s.Update(ctx, &info, 0)
}

func (s *VMPoolCache) GetForCloudlet(cloudlet *Cloudlet, cb func(data *VMPoolCacheData)) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	for _, v := range s.Objs {
		if cloudlet.Key.Organization != v.Obj.Key.Organization {
			continue
		}
		if cloudlet.VmPool != v.Obj.Key.Name {
			continue
		}
		cb(v.Clone())
	}
}

func (s *GPUDriverCache) GetForCloudlet(cloudlet *Cloudlet, cb func(data *GPUDriverCacheData)) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	for _, v := range s.Objs {
		if v.Obj.Key.Matches(&cloudlet.GpuConfig.Driver) {
			cb(v.Clone())
		}
	}
}

func (s *TrustPolicyExceptionCache) GetForCloudlet(cloudlet *Cloudlet, cb func(data *TrustPolicyExceptionCacheData)) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	for _, v := range s.Objs {
		if cloudlet.Key.Organization == v.Obj.Key.CloudletPoolKey.Organization {
			cb(v.Clone())
		}
	}
}

// GetCloudletTrustPolicy finds the policy from the cache.  If a blank policy name is specified, an empty policy is returned
func GetCloudletTrustPolicy(ctx context.Context, name string, cloudletOrg string, privPolCache *TrustPolicyCache) (*TrustPolicy, error) {
	log.SpanLog(ctx, log.DebugLevelInfo, "GetCloudletTrustPolicy")
	if name != "" {
		pp := TrustPolicy{}
		pk := PolicyKey{
			Name:         name,
			Organization: cloudletOrg,
		}
		if !privPolCache.Get(&pk, &pp) {
			log.SpanLog(ctx, log.DebugLevelInfra, "Cannot find Trust Policy from cache", "pk", pk, "pp", pp)
			return nil, fmt.Errorf("fail to find Trust Policy from cache: %s", pk)
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "Found Trust Policy from cache", "pk", pk, "pp", pp)
			return &pp, nil
		}
	} else {
		log.SpanLog(ctx, log.DebugLevelInfo, "Returning empty trust policy for empty name")
		emptyPol := &TrustPolicy{}
		return emptyPol, nil
	}
}

func GetNetworksForClusterInst(ctx context.Context, clusterInst *ClusterInst, networkCache *NetworkCache) ([]*Network, error) {
	log.SpanLog(ctx, log.DebugLevelInfo, "GetNetworksForClusterInst", "clusterInst", clusterInst)
	networks := []*Network{}
	for _, netName := range clusterInst.Networks {
		net := Network{}
		nk := NetworkKey{
			Name:        netName,
			CloudletKey: clusterInst.Key.CloudletKey,
		}
		if !networkCache.Get(&nk, &net) {
			log.SpanLog(ctx, log.DebugLevelInfra, "Cannot find network from cache", "nk", nk)
			return nil, fmt.Errorf("fail to find network from cache: %s", nk)
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "Found network from cache", "nk", nk, "net", net)
		networks = append(networks, &net)
	}
	return networks, nil
}
