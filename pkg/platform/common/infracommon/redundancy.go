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

	pf "github.com/edgexr/edge-cloud-platform/pkg/platform"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
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
	case edgeproto.TrackedState_UPDATE_REQUESTED:
		errorState = edgeproto.TrackedState_UPDATE_ERROR
		generateError = true
	case edgeproto.TrackedState_UPDATING:
		errorState = edgeproto.TrackedState_UPDATE_ERROR
		generateError = true
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
	clusterKeys := []edgeproto.ClusterKey{}
	clusterInstsToCleanup := make(map[edgeproto.ClusterKey]edgeproto.TrackedState)

	caches.ClusterInstCache.GetAllKeys(ctx, func(k *edgeproto.ClusterKey, modRev int64) {
		clusterKeys = append(clusterKeys, *k)
	})
	for _, k := range clusterKeys {
		var clusterInst edgeproto.ClusterInst
		if caches.ClusterInstCache.Get(&k, &clusterInst) {
			errorState, generateError, needsCleanup := mapStateForSwitchover(ctx, clusterInst.State)
			if generateError {
				if needsCleanup {
					// cleanup and then error
					clusterInstsToCleanup[k] = errorState
				} else {
					// send an error right away
					log.SpanLog(ctx, log.DebugLevelInfra, "CRM switched over while Cluster Instance in transient state", "key", k)
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
					log.SpanLog(ctx, log.DebugLevelInfra, "CRM switched over while Cluster Instance in transient state, cluster cleanup failed", "key", k, "state", e)
				} else {
					log.SpanLog(ctx, log.DebugLevelInfra, "CRM switched over while Cluster Instance in transient state", "key", k, "state", e)
				}
			}
		}
	}()

}

func handleTransientAppInsts(ctx context.Context, caches *pf.Caches, cleanupFunc func(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, updateCallback edgeproto.CacheUpdateCallback) error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "handleTransientAppInsts")

	type AppInstData struct {
		state  edgeproto.TrackedState
		appKey edgeproto.AppKey
	}
	// Retrieve the set of app instances in the current thread which is blocking the completion of transitoning to active. We want
	// to block the transition until we have the list
	appInstKeys := []edgeproto.AppInstKey{}
	appInstsToCleanup := make(map[edgeproto.AppInstKey]*AppInstData)

	caches.AppInstCache.GetAllKeys(ctx, func(k *edgeproto.AppInstKey, modRev int64) {
		appInstKeys = append(appInstKeys, *k)
	})
	for _, k := range appInstKeys {
		var appInst edgeproto.AppInst
		if caches.AppInstCache.Get(&k, &appInst) {
			errorState, generateError, needsCleanup := mapStateForSwitchover(ctx, appInst.State)
			if generateError {
				if needsCleanup {
					// cleanup and then error
					data := AppInstData{
						state:  errorState,
						appKey: appInst.AppKey,
					}
					appInstsToCleanup[k] = &data
				} else {
					log.SpanLog(ctx, log.DebugLevelInfra, "CRM switched over while App Instance in transient state", "key", k)
				}
			}
		}
	}
	// do the actual cleanup in a new thread because this can take a while and we do not want to block the transition too long
	go func() {
		for k, data := range appInstsToCleanup {
			app := edgeproto.App{}
			if !caches.AppCache.Get(&data.appKey, &app) {
				log.SpanLog(ctx, log.DebugLevelInfra, "failed to find app in cache", "appkey", data.appKey)
				log.SpanLog(ctx, log.DebugLevelInfra, "CRM switched over while App Instance in transient state, unable to cleanup", "key", k, "state", data.state)
				continue
			}
			var appInst edgeproto.AppInst
			if caches.AppInstCache.Get(&k, &appInst) {
				clusterInst := edgeproto.ClusterInst{}
				if cloudcommon.IsClusterInstReqd(&app) {
					clusterInstFound := caches.ClusterInstCache.Get((*edgeproto.ClusterKey)(appInst.GetClusterKey()), &clusterInst)
					if !clusterInstFound {
						log.SpanLog(ctx, log.DebugLevelInfra, "failed to find clusterinst in cache", "clusterkey", appInst.GetClusterKey())
						log.SpanLog(ctx, log.DebugLevelInfra, "CRM switched over while App Instance in transient state, unable to cleanup", "key", k, "state", data.state)
					}
				}
				log.SpanLog(ctx, log.DebugLevelInfra, "cleaning up appinst", "key", k)
				err := cleanupFunc(ctx, &clusterInst, &app, &appInst, edgeproto.DummyUpdateCallback)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "error cleaning up appinst", "key", k, "error", err)
					log.SpanLog(ctx, log.DebugLevelInfra, "CRM switched over while App Instance in transient state, cleanup failed", "key", k, "state", data.state)
				} else {
					log.SpanLog(ctx, log.DebugLevelInfra, "CRM switched over while App Instance in transient state", "key", k, "state", data.state)
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
