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

package controller

import (
	"context"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/oklog/ulid/v2"
	"go.etcd.io/etcd/client/v3/concurrency"
)

// TrustPolicyExceptions are tied to an App and a CloudletPool.
// A TPE is only enabled for:
// - cloudlets in the cloudletpool
// - a cloudlet that has cloudlet.TrustPolicy set and is in the READY state
// - all AppInsts that match the TPE AppKey on each cloudlet, and are in READY state
// - the actual change is applied to the ClusterInst for the AppInst, if it is Dedicated

// When an AppInst changes READY state, we need to change the TPE state
func (s *TrustPolicyExceptionApi) applyAllTPEsForAppInst(ctx context.Context, appInst *edgeproto.AppInst) {
	app := edgeproto.App{}
	if !s.all.appApi.cache.Get(&appInst.AppKey, &app) {
		return
	}
	tpes := s.cache.GetForApp(&app.Key)
	for _, tpe := range tpes {
		s.applyTPEForAppInst(ctx, tpe.Key, appInst.Key, *appInst.GetClusterKey(), appInst.CloudletKey)
	}
}

// If a cloudlet changes, update TPEs
func (s *TrustPolicyExceptionApi) applyAllTPEsForCloudlet(ctx context.Context, cloudletKey edgeproto.CloudletKey) {
	// A cloudlet may be part of many cloudlet pools,
	// need cloudletpool key to get TPEs
	log.SpanLog(ctx, log.DebugLevelApi, "applyTPEsForCloudlet", "cloudletKey", cloudletKey)
	cloudletPoolList := s.all.cloudletPoolApi.cache.GetPoolsForCloudletKey(&cloudletKey)
	for _, cloudletPoolKey := range cloudletPoolList {
		s.applyAllTPEsForCloudletInPool(ctx, cloudletKey, cloudletPoolKey)
	}
}

// If cloudlet pool memebership changes, update TPEs
func (s *TrustPolicyExceptionApi) applyAllTPEsForCloudletInPool(ctx context.Context, cloudletKey edgeproto.CloudletKey, cloudletPoolKey edgeproto.CloudletPoolKey) {
	// many TPEs may exist for a cloudlet pool
	log.SpanLog(ctx, log.DebugLevelApi, "applyTPEsForCloudletInPool", "cloudletKey", cloudletKey, "cloudletPoolKey", cloudletPoolKey)
	tpes := s.cache.GetForCloudletPool(&cloudletPoolKey)
	for _, tpe := range tpes {
		s.applyTPEForCloudlet(ctx, tpe.Key, cloudletKey)
	}
}

// If a TPE changes, update it
func (s *TrustPolicyExceptionApi) applyTPE(ctx context.Context, key edgeproto.TrustPolicyExceptionKey) {
	// TPE is specific to a cloudlet pool, apply to all cloudlets in pool
	log.SpanLog(ctx, log.DebugLevelApi, "applyTPEChange", "tpeKey", key)
	cloudletPool := edgeproto.CloudletPool{}
	if s.all.cloudletPoolApi.cache.Get(&key.CloudletPoolKey, &cloudletPool) {
		for _, cloudletKey := range cloudletPool.Cloudlets {
			s.applyTPEForCloudlet(ctx, key, cloudletKey)
		}
	}
}

func (s *TrustPolicyExceptionApi) applyTPEForCloudlet(ctx context.Context, tpeKey edgeproto.TrustPolicyExceptionKey, cloudletKey edgeproto.CloudletKey) {
	// apply TPE for all matching AppInsts on Cloudlet
	log.SpanLog(ctx, log.DebugLevelApi, "applyCloudletTPEChange", "tpeKey", tpeKey, "cloudletKey", cloudletKey)
	// Apply to all matching AppInsts on cloudlet
	filter := edgeproto.AppInst{
		CloudletKey: cloudletKey,
		AppKey:      tpeKey.AppKey,
	}
	appInstKeys := []edgeproto.AppInstKey{}
	clusterKeys := []edgeproto.ClusterKey{}
	s.all.appInstApi.cache.Show(&filter, func(appInst *edgeproto.AppInst) error {
		appInstKeys = append(appInstKeys, appInst.Key)
		clusterKeys = append(clusterKeys, *appInst.GetClusterKey())
		return nil
	})
	for ii := range appInstKeys {
		s.applyTPEForAppInst(ctx, tpeKey, appInstKeys[ii], clusterKeys[ii], cloudletKey)
	}
}

// wrapper function to spawn go thread
func (s *TrustPolicyExceptionApi) applyTPEForAppInst(ctx context.Context, tpeKey edgeproto.TrustPolicyExceptionKey, appInstKey edgeproto.AppInstKey, clusterKey edgeproto.ClusterKey, cloudletKey edgeproto.CloudletKey) {
	log.SpanLog(ctx, log.DebugLevelApi, "applyTPEForAppInst", "tpeKey", tpeKey, "appInstKey", appInstKey)

	go func() {
		span, ctx := log.ChildSpan(ctx, log.DebugLevelApi, "update trustpolicyexception")
		defer span.Finish()
		err := s.runTPEChange(ctx, tpeKey, appInstKey, clusterKey, cloudletKey)
		log.SpanLog(ctx, log.DebugLevelApi, "applyTPEForAppInst result", "err", err, "appInstKey", appInstKey, "tpeKey", tpeKey)
	}()
}

func (s *TrustPolicyExceptionApi) runTPEChange(ctx context.Context, tpeKey edgeproto.TrustPolicyExceptionKey, appInstKey edgeproto.AppInstKey, clusterKey edgeproto.ClusterKey, cloudletKey edgeproto.CloudletKey) error {
	threadID := ulid.Make().String()
	tpeInstKey := edgeproto.TPEInstanceKey{
		TpeKey:      tpeKey,
		AppInstKey:  appInstKey,
		ClusterKey:  clusterKey,
		CloudletKey: cloudletKey,
	}

	log.SpanLog(ctx, log.DebugLevelApi, "runTPEChange", "tpeKey", tpeKey, "appInstKey", appInstKey, "clusterKey", clusterKey, "cloudletKey", cloudletKey)

	// Multiple different changes across different objects can trigger
	// an update to TPEs. To avoid multiple changes running in parallel,
	// we serialize here using etcd. If two changes overlap, the initial thread
	// running the change will rerun again, while the latter thread exits.
	// This holds true across multiple processes since we're using etcd.
	// The drawback here is if a running process dies we'll be stuck with
	// a stale runner until the timeout.
	// TODO: add an API to allow users to see TPEInstanceState, so they can
	// see if their TPE failed to apply somewhere.
	// TODO: add an API to allow the user/admin to delete a stale runner.
	tpeState := edgeproto.TPEInstanceState{}
	err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		tpeState = edgeproto.TPEInstanceState{}
		if !s.instStore.STMGet(stm, &tpeInstKey, &tpeState) {
			tpeState.Key = tpeInstKey
		}
		if tpeState.Owner != "" {
			// another thread running, but check if it's been too long
			// the other owner might have died.
			startTime := dme.TimestampToTime(tpeState.StartedAt)
			if startTime.Add(time.Hour).Before(time.Now()) {
				// likely stale entry, take over
				log.SpanLog(ctx, log.DebugLevelApi, "runCloudletTPEChange stale entry, taking over", "key", tpeInstKey)
			} else {
				// trigger the owner to run again
				tpeState.RunRequested = true
				s.instStore.STMPut(stm, &tpeState)
				return nil
			}
		}
		// register this thread to do the work
		tpeState.Owner = threadID
		tpeState.RunRequested = true
		s.instStore.STMPut(stm, &tpeState)
		return nil
	})
	if err != nil {
		return err
	}
	if tpeState.Owner != threadID {
		log.SpanLog(ctx, log.DebugLevelApi, "runCloudletTPEChange already running, skipping", "key", tpeInstKey)
		return nil
	}

	var applyErr error
	for {
		var curTpe *edgeproto.TrustPolicyException
		var cloudlet *edgeproto.Cloudlet
		var enable bool
		var disableReason string
		var done bool
		platformType := ""
		nodeType := ""
		err := s.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
			tpeState = edgeproto.TPEInstanceState{}
			curTpe = &edgeproto.TrustPolicyException{}
			cloudlet = &edgeproto.Cloudlet{}
			cloudletPool := edgeproto.CloudletPool{}
			appInst := edgeproto.AppInst{}
			clusterInst := edgeproto.ClusterInst{}
			enable = true
			done = false
			if !s.instStore.STMGet(stm, &tpeInstKey, &tpeState) {
				return tpeInstKey.NotFoundError()
			}
			if tpeState.Owner != threadID {
				done = true
				return nil
			}
			// we are the owner
			if !tpeState.RunRequested {
				// we're done, log results
				tpeState.RunCount = 0
				tpeState.Owner = ""
				if applyErr != nil {
					tpeState.Error = applyErr.Error()
				}
				s.instStore.STMPut(stm, &tpeState)
				done = true
				return nil
			}
			var deleteReason error
			if !s.all.cloudletApi.store.STMGet(stm, &cloudletKey, cloudlet) {
				deleteReason = cloudletKey.NotFoundError()
			}
			if !s.all.cloudletPoolApi.store.STMGet(stm, &tpeKey.CloudletPoolKey, &cloudletPool) {
				deleteReason = tpeKey.CloudletPoolKey.NotFoundError()
			}
			if !s.all.appInstApi.store.STMGet(stm, &appInstKey, &appInst) {
				deleteReason = appInstKey.NotFoundError()
			}
			if !s.all.clusterInstApi.store.STMGet(stm, &clusterKey, &clusterInst) {
				deleteReason = clusterKey.NotFoundError()
			}
			if !s.store.STMGet(stm, &tpeKey, curTpe) {
				deleteReason = tpeKey.NotFoundError()
			}
			if deleteReason != nil {
				log.SpanLog(ctx, log.DebugLevelApi, "deleting TPE instance", "key", tpeInstKey, "reason", deleteReason)
				s.instStore.STMDel(stm, &tpeInstKey)
				done = true
				return nil
			}

			platformType = cloudlet.PlatformType
			enable, disableReason = isTPEInstanceEnabled(
				appInst.State,
				curTpe.State,
				clusterInst.IpAccess,
				cloudlet.TrustPolicy,
				&cloudletKey,
				cloudletPool.Cloudlets,
			)
			// Note that RunCount is used to trigger the CRM, as we
			// need something that changes every iteration over the
			// notify framework so the CRM can trigger another apply.
			// We need to commit the RunCount change at the same time
			// as the enable so the CRM knows whether to enable or not.
			tpeState.RunRequested = false
			tpeState.RunCount++
			tpeState.TpeEnable = enable
			tpeState.DisableReason = disableReason
			tpeState.StartedAt = dme.TimeToTimestamp(time.Now())
			s.instStore.STMPut(stm, &tpeState)
			return nil
		})
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		log.SpanLog(ctx, log.DebugLevelApi, "new TPE instance state", "key", tpeState.Key, "state", tpeState)

		if cloudlet.CrmOnEdge {
			// TODO: We need to wait for a "finished" response from CRM
			// to prevent overlapping runs. But right now CRM doesn't send
			// anything back over notify.
			applyErr = nil
		} else {
			if nodeType == "" {
				features, err := s.all.platformFeaturesApi.GetCloudletFeatures(ctx, platformType)
				if err != nil {
					return err
				}
				nodeType = features.NodeType
			}
			conn, err := services.platformServiceConnCache.GetConn(ctx, nodeType)
			if err != nil {
				return err
			}
			api := edgeproto.NewAppInstPlatformAPIClient(conn)
			_, applyErr = api.ApplyTrustPolicyException(ctx, &tpeState)
			applyErr = cloudcommon.GRPCErrorUnwrap(applyErr)
			log.SpanLog(ctx, log.DebugLevelApi, "runCloudletTPEChange done", "err", applyErr, "key", tpeInstKey, "enable", enable)
		}
	}
}

func isTPEInstanceEnabled(
	appInstState edgeproto.TrackedState,
	tpeState edgeproto.TrustPolicyExceptionState,
	clusterInstIPAccess edgeproto.IpAccess,
	cloudletTrustPolicy string,
	cloudletKey *edgeproto.CloudletKey,
	cloudletPoolMembers []edgeproto.CloudletKey,
) (bool, string) {
	// TODO: do we care about cloudlet maintenance state or ready state?
	if appInstState != edgeproto.TrackedState_READY {
		return false, "appInst state not ready"
	}
	if tpeState != edgeproto.TrustPolicyExceptionState_TRUST_POLICY_EXCEPTION_STATE_ACTIVE {
		return false, "trust policy exception state is not active"
	}
	if clusterInstIPAccess != edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		return false, "clusterInst IP Access is not dedicated"
	}
	if cloudletTrustPolicy == "" {
		return false, "cloudlet has no trust policy"
	}
	cloudletInPool := false
	for _, key := range cloudletPoolMembers {
		if key.Matches(cloudletKey) {
			cloudletInPool = true
			break
		}
	}
	if !cloudletInPool {
		return false, "cloudlet not in trust policy exception cloudlet pool"
	}
	return true, ""
}
