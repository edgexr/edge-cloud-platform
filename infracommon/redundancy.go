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

package infracommon

import (
	"context"
	"fmt"

	pf "github.com/edgexr/edge-cloud/cloud-resource-manager/platform"

	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
)

var CloudletPlatformActive = "CloudletPlatformActive"

// mapStateForSwitchover checks the current state and gives the new state to transition to along. Returns state, generateError, needsCleanup
func mapStateForSwitchover(ctx context.Context, state edgeproto.TrackedState) (edgeproto.TrackedState, bool, bool) {
	errorState := edgeproto.TrackedState_TRACKED_STATE_UNKNOWN
	generateError := false
	needsCleanup := false

	switch state {
	case edgeproto.TrackedState_READY:
		return errorState, generateError, needsCleanup
	case edgeproto.TrackedState_CREATE_REQUESTED:
		errorState = edgeproto.TrackedState_CREATE_ERROR
		generateError = true
	case edgeproto.TrackedState_CREATING:
		errorState = edgeproto.TrackedState_CREATE_ERROR
		generateError = true
		needsCleanup = true
	case edgeproto.TrackedState_UPDATE_REQUESTED:
		errorState = edgeproto.TrackedState_UPDATE_ERROR
		generateError = true
	case edgeproto.TrackedState_UPDATING:
		errorState = edgeproto.TrackedState_UPDATE_ERROR
		generateError = true
		needsCleanup = true
	case edgeproto.TrackedState_DELETE_REQUESTED:
		errorState = edgeproto.TrackedState_DELETE_ERROR
		generateError = true
	case edgeproto.TrackedState_DELETING:
		errorState = edgeproto.TrackedState_DELETE_ERROR
		generateError = true
		needsCleanup = true
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "transientStateToErrorState returns", "state", state, "errorState", errorState, "generateError", generateError, "needsCleanup", needsCleanup)
	return errorState, generateError, needsCleanup
}

func handleTransientClusterInsts(ctx context.Context, caches *pf.Caches, cleanupFunc func(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "handleTransientClusterInsts")

	// Retrieve the set of cluster instances in the current thread which is blocking the completion of transitoning to active. We want
	// to block the transition until we have the list
	clusterInstKeys := []edgeproto.ClusterInstKey{}
	clusterInstsToCleanup := make(map[edgeproto.ClusterInstKey]edgeproto.TrackedState)

	caches.ClusterInstCache.GetAllKeys(ctx, func(k *edgeproto.ClusterInstKey, modRev int64) {
		clusterInstKeys = append(clusterInstKeys, *k)
	})
	for _, k := range clusterInstKeys {
		var clusterInst edgeproto.ClusterInst
		if caches.ClusterInstCache.Get(&k, &clusterInst) {
			errorState, generateError, needsCleanup := mapStateForSwitchover(ctx, clusterInst.State)
			immediateErrorState := edgeproto.TrackedState_TRACKED_STATE_UNKNOWN
			if generateError {
				if needsCleanup {
					// cleanup and then error
					clusterInstsToCleanup[k] = errorState
				} else {
					// send an error right away
					caches.ClusterInstInfoCache.SetError(ctx, &k, immediateErrorState, "CRM switched over while Cluster Instance in transient state")
				}
			}
		}
	}

	// do the actual cleanup in a new thread because this can take a while and we do not want to block the transition too long
	go func() {
		for k, e := range clusterInstsToCleanup {
			var clusterInst edgeproto.ClusterInst
			if caches.ClusterInstCache.Get(&k, &clusterInst) {
				log.SpanLog(ctx, log.DebugLevelInfra, "cleaning up cluster inst", "key", k)
				err := cleanupFunc(ctx, &clusterInst, edgeproto.DummyUpdateCallback)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "error cleaning up cluster", "key", k, "error", err)
					caches.ClusterInstInfoCache.SetError(ctx, &k, e, "CRM switched over while Cluster Instance in transient state, cluster cleanup failed")
				} else {
					caches.ClusterInstInfoCache.SetError(ctx, &k, e, "CRM switched over while Cluster Instance in transient state")
				}
			}
		}
	}()

}

func handleTransientAppInsts(ctx context.Context, caches *pf.Caches, cleanupFunc func(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "handleTransientAppInsts")

	// Retrieve the set of app instances in the current thread which is blocking the completion of transitoning to active. We want
	// to block the transition until we have the list
	appInstKeys := []edgeproto.AppInstKey{}
	appInstsToCleanup := make(map[edgeproto.AppInstKey]edgeproto.TrackedState)

	caches.AppInstCache.GetAllKeys(ctx, func(k *edgeproto.AppInstKey, modRev int64) {
		appInstKeys = append(appInstKeys, *k)
	})
	for _, k := range appInstKeys {
		var appInst edgeproto.AppInst
		if caches.AppInstCache.Get(&k, &appInst) {
			errorState, generateError, needsCleanup := mapStateForSwitchover(ctx, appInst.State)
			immediateErrorState := edgeproto.TrackedState_TRACKED_STATE_UNKNOWN
			if generateError {
				if needsCleanup {
					// cleanup and then error
					appInstsToCleanup[k] = errorState
				} else {
					// send an error right away
					caches.AppInstInfoCache.SetError(ctx, &k, immediateErrorState, "CRM switched over while App Instance in transient state")
				}
			}
		}
	}
	// do the actual cleanup in a new thread because this can take a while and we do not want to block the transition too long
	go func() {
		for k, e := range appInstsToCleanup {
			app := edgeproto.App{}
			if !caches.AppCache.Get(&k.AppKey, &app) {
				log.SpanLog(ctx, log.DebugLevelInfra, "failed to find app in cache", "appkey", k.AppKey)
				caches.AppInstInfoCache.SetError(ctx, &k, e, "CRM switched over while App Instance in transient state, unable to cleanup")
				continue
			}
			var appInst edgeproto.AppInst
			if caches.AppInstCache.Get(&k, &appInst) {
				clusterInst := edgeproto.ClusterInst{}
				if cloudcommon.IsClusterInstReqd(&app) {
					clusterInstFound := caches.ClusterInstCache.Get((*edgeproto.ClusterInstKey)(appInst.ClusterInstKey()), &clusterInst)
					if !clusterInstFound {
						log.SpanLog(ctx, log.DebugLevelInfra, "failed to find clusterinst in cache", "clusterkey", k.ClusterInstKey)
						caches.AppInstInfoCache.SetError(ctx, &k, e, "CRM switched over while App Instance in transient state, unable to cleanup")
					}
				}
				log.SpanLog(ctx, log.DebugLevelInfra, "cleaning up appinst", "key", k)
				err := cleanupFunc(ctx, &clusterInst, &app, &appInst, edgeproto.DummyUpdateCallback)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "error cleaning up appinst", "key", k, "error", err)
					caches.AppInstInfoCache.SetError(ctx, &k, e, "CRM switched over while App Instance in transient state, cleanup failed")
				} else {
					caches.AppInstInfoCache.SetError(ctx, &k, e, "CRM switched over while App Instance in transient state")
				}
			}
		}
	}()

}

// HandlePlatformSwitchToActive handles the case when a formerly standby CRM becomes active, including
// in-progress provisioning requests which must be cleaned using the provided functions
func HandlePlatformSwitchToActive(ctx context.Context,
	cloudletKey *edgeproto.CloudletKey,
	caches *pf.Caches,
	clusterInstCleanupFunc func(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error,
	appInstCleanupFunc func(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "HandlePlatformSwitchToActive")
	var cloudletInternal edgeproto.CloudletInternal
	if !caches.CloudletInternalCache.Get(cloudletKey, &cloudletInternal) {
		log.SpanLog(ctx, log.DebugLevelInfra, "Error: unable to find cloudlet key in cache")
	} else {
		// inform Shepherd via the internal cache of the new active state
		log.SpanLog(ctx, log.DebugLevelInfra, "Updating cloudlet internal cache for active state")
		cloudletInternal.Props[CloudletPlatformActive] = fmt.Sprintf("%t", true)
		caches.CloudletInternalCache.Update(ctx, &cloudletInternal, 0)
	}
	handleTransientClusterInsts(ctx, caches, clusterInstCleanupFunc)
	handleTransientAppInsts(ctx, caches, appInstCleanupFunc)

}
