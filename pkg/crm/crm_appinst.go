// Copyright 2024 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crm

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
)

func (s *CRMData) appInstChanged(ctx context.Context, old *edgeproto.AppInst, new *edgeproto.AppInst) {
	if !s.highAvailabilityManager.IsActive() {
		log.SpanLog(ctx, log.DebugLevelInfra, "Ignoring appInst change because not active")
		return
	}
	responseSender := edgeproto.NewAppInstInfoCacheUpdater(ctx, &s.AppInstInfoCache, new.Key)

	go func() {
		span, ctx := log.ChildSpan(ctx, log.DebugLevelApi, "appInstChanged")
		defer span.Finish()

		if new.State == edgeproto.TrackedState_CREATING {
			// Controller may send a CRM transitional state after a
			// disconnect or crash. Controller thinks CRM is creating
			// the appInst, and Controller is waiting for a new state from
			// the CRM. If CRM is not creating, or has not just finished
			// creating (ready), set an error state.
			transStates := map[edgeproto.TrackedState]struct{}{
				edgeproto.TrackedState_CREATING: struct{}{},
			}
			s.appInstInfoCheckState(ctx, &new.Key, transStates,
				edgeproto.TrackedState_READY,
				edgeproto.TrackedState_CREATE_ERROR)
		} else if new.State == edgeproto.TrackedState_UPDATING {
			transStates := map[edgeproto.TrackedState]struct{}{
				edgeproto.TrackedState_UPDATING: struct{}{},
			}
			s.appInstInfoCheckState(ctx, &new.Key, transStates,
				edgeproto.TrackedState_READY,
				edgeproto.TrackedState_UPDATE_ERROR)
		} else if new.State == edgeproto.TrackedState_DELETING {
			transStates := map[edgeproto.TrackedState]struct{}{
				edgeproto.TrackedState_DELETING:    struct{}{},
				edgeproto.TrackedState_DELETE_DONE: struct{}{},
			}
			s.appInstInfoCheckState(ctx, &new.Key, transStates,
				edgeproto.TrackedState_NOT_PRESENT,
				edgeproto.TrackedState_DELETE_ERROR)
		} else {
			if old == nil {
				if new.State == edgeproto.TrackedState_READY {
					// store appInstInfo object on CRM bringup, if state is READY
					s.AppInstInfoCache.RefreshObj(ctx, new)
				}
				new.Fields = edgeproto.AppInstAllFields
			} else {
				new.Fields = old.GetDiffFields(new).Fields()
			}
			updateResources := false
			s.AppInstChanged(ctx, s.cloudletKey, new, &updateResources, responseSender)
			if updateResources {
				s.vmResourceActionEnd(ctx)
			}
		}
	}()
}

func (s *CRMData) appInstDeleted(ctx context.Context, old *edgeproto.AppInst) {
	if !s.highAvailabilityManager.IsActive() {
		log.SpanLog(ctx, log.DebugLevelInfra, "Ignoring appInst deleted because not active")
		return
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "appInstDeleted", "AppInst", old)
	info := edgeproto.AppInstInfo{Key: old.Key}
	s.AppInstInfoCache.Delete(ctx, &info, 0)
}

func (s *CRMData) appInstInfoCheckState(ctx context.Context, key *edgeproto.AppInstKey, transStates map[edgeproto.TrackedState]struct{}, finalState, errState edgeproto.TrackedState) {
	s.AppInstInfoCache.UpdateModFunc(ctx, key, 0, func(old *edgeproto.AppInstInfo) (newObj *edgeproto.AppInstInfo, changed bool) {
		if old == nil {
			if _, ok := transStates[edgeproto.TrackedState_NOT_PRESENT]; ok || finalState == edgeproto.TrackedState_NOT_PRESENT {
				return old, false
			}
			old = &edgeproto.AppInstInfo{Key: *key}
		}
		if _, ok := transStates[old.State]; !ok && old.State != finalState {
			log.SpanLog(ctx, log.DebugLevelInfra, "inconsistent Controller vs CRM state", "old state", old.State, "transStates", transStates, "final state", finalState)
			new := &edgeproto.AppInstInfo{}
			*new = *old
			new.State = errState
			new.Errors = append(new.Errors, "inconsistent Controller vs CRM state")
			return new, true
		}
		return old, false
	})
}

func (s *CRMData) RefreshAppInstRuntime(ctx context.Context) {
	log.SpanLog(ctx, log.DebugLevelInfra, "Refresh appinst runtime info")
	appInsts := []edgeproto.AppInst{}

	s.AppInstCache.Show(&edgeproto.AppInst{}, func(obj *edgeproto.AppInst) error {
		cp := edgeproto.AppInst{}
		cp.DeepCopyIn(obj)
		appInsts = append(appInsts, cp)
		return nil
	})
	for ii := range appInsts {
		rt, err := s.CRMHandler.GetAppInstRuntime(ctx, s.cloudletKey, &appInsts[ii])
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "unable to get AppInstRuntime", "key", appInsts[ii].Key, "err", err)
		} else if rt != nil {
			s.AppInstInfoCache.SetStateRuntime(ctx, &appInsts[ii].Key, appInsts[ii].State, rt)
		}
	}
}
