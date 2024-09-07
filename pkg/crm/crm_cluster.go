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

func (s *CRMData) clusterInstChanged(ctx context.Context, old *edgeproto.ClusterInst, new *edgeproto.ClusterInst) {
	if !s.highAvailabilityManager.IsActive() {
		log.SpanLog(ctx, log.DebugLevelInfra, "Ignoring cluster change because not active")
		return
	}
	responseSender := edgeproto.NewClusterInstInfoCacheUpdater(ctx, &s.ClusterInstInfoCache, new.Key)

	go func() {
		span, ctx := log.ChildSpan(ctx, log.DebugLevelApi, "clusterInstChanged")
		defer span.Finish()

		if new.State == edgeproto.TrackedState_CREATING {
			transStates := map[edgeproto.TrackedState]struct{}{
				edgeproto.TrackedState_CREATING: struct{}{},
			}
			s.clusterInstInfoCheckState(ctx, &new.Key, transStates,
				edgeproto.TrackedState_READY,
				edgeproto.TrackedState_CREATE_ERROR)
		} else if new.State == edgeproto.TrackedState_UPDATING {
			transStates := map[edgeproto.TrackedState]struct{}{
				edgeproto.TrackedState_UPDATING: struct{}{},
			}
			s.clusterInstInfoCheckState(ctx, &new.Key, transStates,
				edgeproto.TrackedState_READY,
				edgeproto.TrackedState_UPDATE_ERROR)
		} else if new.State == edgeproto.TrackedState_DELETING {
			transStates := map[edgeproto.TrackedState]struct{}{
				edgeproto.TrackedState_DELETING:    struct{}{},
				edgeproto.TrackedState_DELETE_DONE: struct{}{},
			}
			s.clusterInstInfoCheckState(ctx, &new.Key, transStates,
				edgeproto.TrackedState_NOT_PRESENT,
				edgeproto.TrackedState_DELETE_ERROR)
		} else {
			if old == nil {
				// store clusterInstInfo object on CRM bringup, if state is READY
				if new.State == edgeproto.TrackedState_READY {
					s.ClusterInstInfoCache.RefreshObj(ctx, new)
				}
				new.Fields = edgeproto.ClusterInstAllFields
			} else {
				new.Fields = old.GetDiffFields(new).Fields()
				// Special case for dns update - only possible if cluster exists
				fmap := edgeproto.MakeFieldMap(new.Fields)
				if fmap.Has(edgeproto.ClusterInstFieldFqdn) {
					_ = s.ClusterInstDNSChanged(ctx, s.cloudletKey, old, new, responseSender)
					return
				}
			}
			needsUpdate, err := s.ClusterInstChanged(ctx, s.cloudletKey, new, responseSender)
			if err == nil && needsUpdate.Resources {
				s.vmResourceActionEnd(ctx)
			}
			if err == nil && needsUpdate.AppInstRuntime {
				s.refreshAppInstRuntime(ctx, new, nil)
			}
		}
	}()
}

func (s *CRMData) clusterInstDeleted(ctx context.Context, old *edgeproto.ClusterInst) {
	if !s.highAvailabilityManager.IsActive() {
		log.SpanLog(ctx, log.DebugLevelInfra, "Ignoring cluster change because not active")
		return
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "clusterInstDeleted", "ClusterInst", old)
	info := edgeproto.ClusterInstInfo{Key: old.Key}
	s.ClusterInstInfoCache.Delete(ctx, &info, 0)
}

// CheckState checks that the info is either in the transState or finalState.
// If not, it is an unexpected state, so we set it to the error state.
// This is used when the controller sends CRM a state that implies the
// controller is waiting for the CRM to send back the next state, but the
// CRM does not have any change in progress.
func (s *CRMData) clusterInstInfoCheckState(ctx context.Context, key *edgeproto.ClusterKey, transStates map[edgeproto.TrackedState]struct{}, finalState, errState edgeproto.TrackedState) {
	s.ClusterInstInfoCache.UpdateModFunc(ctx, key, 0, func(old *edgeproto.ClusterInstInfo) (newObj *edgeproto.ClusterInstInfo, changed bool) {
		if old == nil {
			if _, ok := transStates[edgeproto.TrackedState_NOT_PRESENT]; ok || finalState == edgeproto.TrackedState_NOT_PRESENT {
				return old, false
			}
			old = &edgeproto.ClusterInstInfo{Key: *key}
		}
		if _, ok := transStates[old.State]; !ok && old.State != finalState {
			log.SpanLog(ctx, log.DebugLevelInfra, "inconsistent Controller vs CRM state", "old state", old.State, "transStates", transStates, "final state", finalState)
			new := &edgeproto.ClusterInstInfo{}
			*new = *old
			new.State = errState
			new.Errors = append(new.Errors, "inconsistent Controller vs CRM state")
			return new, true
		}
		return old, false
	})
}
