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

package main

import (
	"context"
	"strings"
	"sync"

	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
)

type RetryTracker struct {
	allFailures map[edgeproto.AppInstKey]struct{}
	mux         sync.Mutex
}

func newRetryTracker() *RetryTracker {
	s := RetryTracker{}
	s.allFailures = make(map[edgeproto.AppInstKey]struct{})
	return &s
}

func (s *RetryTracker) registerDeployResult(ctx context.Context, key edgeproto.AppInstKey, err error) {
	lookup := key
	// tracking is cluster agnostic. We assume any failures are
	// caused by the App config, or an issue with the Cloudlet, and
	// nothing specific to autoclusters, whose configuration is
	// derived from the App.
	lookup.ClusterInstKey.Organization = ""
	lookup.ClusterInstKey.ClusterKey.Name = ""

	s.mux.Lock()
	defer s.mux.Unlock()

	if ignoreDeployError(key, err) {
		// remove any existing failure status
		delete(s.allFailures, lookup)
		return
	}
	log.SpanLog(ctx, log.DebugLevelApi, "Failed to deploy appInst, track it as part of retryTracker", "key", key, "err", err)
	// track new failure
	s.allFailures[lookup] = struct{}{}
	// Because the retry interval (the aggr thread interval) is so long
	// (default 5 minutes) we don't bother with any back-off from
	// multiple consecutive failures.
}

func (s *RetryTracker) doRetry(ctx context.Context, minmax *MinMaxChecker) {
	s.mux.Lock()
	defer s.mux.Unlock()

	for k, _ := range s.allFailures {
		// Because a retry may not necessarily try to deploy
		// to the same Cloudlet (or may not try to deploy anything
		// at all), we clear the failure state here, and just
		// retry the App. If there is another failure, then
		// the App+Cloudlet will be black-listed again for
		// another retry interval.
		delete(s.allFailures, k)
		// trigger retry
		minmax.workers.NeedsWork(ctx, k.AppKey)
	}
}

func (s *RetryTracker) hasFailure(ctx context.Context, appKey edgeproto.AppKey, cloudletKey edgeproto.CloudletKey) bool {
	key := edgeproto.AppInstKey{}
	key.AppKey = appKey
	key.ClusterInstKey.CloudletKey = cloudletKey

	s.mux.Lock()
	defer s.mux.Unlock()
	_, found := s.allFailures[key]
	return found
}

func ignoreDeployError(key edgeproto.AppInstKey, err error) bool {
	if err == nil {
		return true
	}
	if cloudcommon.IsAppInstBeingCreatedError(err) || cloudcommon.IsAppInstBeingDeletedError(err) {
		return true
	}
	if strings.Contains(err.Error(), key.ExistsError().Error()) ||
		strings.Contains(err.Error(), cloudcommon.AutoProvMinAlreadyMetError.Error()) ||
		strings.Contains(err.Error(), "AppInst against App which is being deleted") {
		return true
	}
	return false
}
